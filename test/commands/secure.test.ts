/**
 * `hush secure`: climbing the ladder, and what it refuses to promise.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { ageAvailable } from "../../src/age.ts";
import { execFileSync } from "node:child_process";
import { tmpdir, platform } from "node:os";
import { biometryReadiness } from "../../src/secure.ts";
import { spawnSync } from "node:child_process";
import { CLI, project } from "../helpers/cli.ts";

describe("hush secure", () => {
  test("--for sets how long an Allow lasts, and works when approvals are already on", () => {
    const p = project();
    try {
      const on = p.run(["secure", "approval", "--for", "30m"]);
      assert.equal(on.code, 0, on.out);
      const written = JSON.parse(readFileSync(join(p.root, ".hush", "policy.json"), "utf8"));
      assert.equal(written.approvalTtlSeconds, 1800);
      assert.match(on.out, /An "Allow" lasts 30 minutes/);

      // The second time is the interesting one: approvals are already on, and
      // "already done" would leave the duration where it was.
      const longer = p.run(["secure", "approval", "--for", "4h"]);
      assert.equal(longer.code, 0, longer.out);
      assert.equal(JSON.parse(readFileSync(join(p.root, ".hush", "policy.json"), "utf8")).approvalTtlSeconds, 14400);
    } finally {
      p.cleanup();
    }
  });

  test("--for refuses a duration outside a minute to a day", () => {
    const p = project();
    try {
      const r = p.run(["secure", "approval", "--for", "5s"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /between 60 and 86400/);
      const nonsense = p.run(["secure", "approval", "--for", "soon"]);
      assert.equal(nonsense.code, 1, nonsense.out);
      assert.match(nonsense.out, /not a duration/);
    } finally {
      p.cleanup();
    }
  });

  test("turning on approval actually rewrites the policy", () => {
    const p = project();
    writeFileSync(join(p.root, ".hush", "policy.json"), JSON.stringify({ requireApproval: [] }));
    p.run(["secure", "approval"]);
    const policy = JSON.parse(readFileSync(join(p.root, ".hush", "policy.json"), "utf8")) as { requireApproval: string[] };
    assert.deepEqual(policy.requireApproval.sort(), ["add", "request", "reveal", "run"]);
    p.cleanup();
  });

  test("it refuses to enable biometry that is not available", () => {
    const p = project();
    const { out } = p.run(["secure", "biometry"]);
    assert.ok(/✗|disabled|unavailable/.test(out), `expected a refusal, got: ${out.slice(0, 200)}`);
    // Refusing means writing nothing at all — an absent policy is itself proof
    // that it did not quietly record a protection it cannot enforce.
    const policyPath = join(p.root, ".hush", "policy.json");
    if (existsSync(policyPath)) {
      const policy = JSON.parse(readFileSync(policyPath, "utf8")) as { biometry?: string };
      assert.notEqual(policy.biometry, "required", "claimed biometry while it was unavailable");
    }
    p.cleanup();
  });

  test("it will not delete a .env without a confirmation it cannot get", () => {
    // Non-interactive: the prompt declines, so the file must survive.
    const p = project();
    const envFile = join(p.root, ".env");
    writeFileSync(envFile, "FOO=bar\n");
    p.run(["secure", "no-plaintext"]);
    assert.ok(existsSync(envFile), "deleted a file without confirmation");
    p.cleanup();
  });

  test("snoozing writes state rather than changing the vault", () => {
    const p = project();
    const before = readFileSync(join(p.root, ".hush", "vault.json"), "utf8");
    p.run(["secure", "--snooze", "1"]);
    assert.equal(readFileSync(join(p.root, ".hush", "vault.json"), "utf8"), before);
    p.cleanup();
  });
});

describe("hush secure — the gaps mutation testing found", () => {
  test("setPolicy edits the policy rather than replacing it", () => {
    // Replacing it wipes every other setting the user had chosen — including
    // the deny-list additions and the allowEnvs pin — while reporting success.
    const p = project();
    try {
      writeFileSync(
        join(p.root, ".hush", "policy.json"),
        JSON.stringify({ requireApproval: [], allowEnvs: ["default"], unsafeAllowCommands: ["jq"], maxRunMs: 5000 }),
      );
      assert.equal(p.run(["secure", "approval"]).code, 0);

      const policy = JSON.parse(readFileSync(join(p.root, ".hush", "policy.json"), "utf8")) as Record<string, unknown>;
      assert.deepEqual((policy.requireApproval as string[]).sort(), ["add", "request", "reveal", "run"]);
      assert.deepEqual(policy.allowEnvs, ["default"], "an unrelated setting was discarded");
      assert.deepEqual(policy.unsafeAllowCommands, ["jq"], "an unrelated setting was discarded");
      assert.equal(policy.maxRunMs, 5000, "an unrelated setting was discarded");
    } finally {
      p.cleanup();
    }
  });

  test(
    "a software age key is not accepted as a hardware upgrade",
    { skip: ageAvailable() ? false : "age binary not installed" },
    () => {
    // The rung that changes the threat model is the one where the key cannot be
    // copied off the machine. A plain age key file can be copied, so counting it
    // would hand out the badge for nothing — which is worse than not offering it.
    const p = project();
    try {
      const keyFile = join(p.home, "age-identity.txt");
      execFileSync("age-keygen", ["-o", keyFile], { stdio: "ignore" });

      const r = p.run(["secure", "hardware"]);
      assert.match(r.out, /software age key|not hardware/i, `a software key was accepted:\n${r.out}`);

      // And it did not quietly add itself to the vault as a member.
      const vault = JSON.parse(readFileSync(join(p.root, ".hush", "vault.json"), "utf8")) as {
        recipients: Record<string, { name: string }>;
      };
      const names = Object.values(vault.recipients).map((x) => x.name);
      assert.deepEqual(names, ["tester"], `a software key was added as a member: ${names.join(", ")}`);
      } finally {
        p.cleanup();
      }
    },
  );

  test("a broken nudge never takes a command down with it", () => {
    // Nudging is decoration. An unreadable state file, a vault it cannot assess
    // — none of it is worth failing `hush ls` over.
    const p = project();
    try {
      writeFileSync(join(p.home, "state.json"), "{ this is not json");
      // `hush ls` no longer lists key names on the overview screen (that
      // information moved to `hush ls <set>`), so check the one that does.
      const r = p.run(["ls", "default"]);
      assert.equal(r.code, 0, `a corrupt nudge state broke an unrelated command:\n${r.out}`);
      assert.match(r.out, /STRIPE_SECRET_KEY/);
    } finally {
      p.cleanup();
    }
  });
});

describe("hush secure --biometry will not promise what the hardware cannot do", () => {
  /**
   * A stub helper, handed in through the parameter seam rather than planted at
   * a path hush would read. Planting one used to be how these tests worked —
   * which is precisely the hole that made this seam necessary: anything running
   * as the user could have written a helper that answers "ok".
   */
  const stub = (script: string): string => {
    const dir = mkdtempSync(join(tmpdir(), "hush-bio-stub-"));
    const path = join(dir, "hush-touchid");
    writeFileSync(path, script, { mode: 0o755 });
    return path;
  };

  test(
    "a working helper with no enrolled finger is still refused",
    { skip: platform() === "darwin" ? false : "macOS only" },
    () => {
      // The case that matters: the helper builds and runs, but nobody has
      // enrolled a finger. hush must not write `biometry: required` on the
      // strength of the first half alone, because the next approval would then
      // refuse rather than fall back and the user would be locked out of their
      // own vault by a protection they thought they had.
      const path = stub('#!/bin/sh\necho "no 0"\nexit 1\n');
      const ready = biometryReadiness({ helperPath: path });
      assert.equal(ready.ok, false);
      assert.match(ready.ok === false ? ready.reason : "", /no fingerprint enrolled/);
    },
  );

  test(
    "with a finger enrolled it does turn the rung on",
    { skip: platform() === "darwin" ? false : "macOS only" },
    () => {
      // The other side, so the refusal above is not just "it always refuses".
      const ready = biometryReadiness({ helperPath: stub('#!/bin/sh\necho "yes 1"\nexit 0\n') });
      assert.equal(ready.ok, true);
      assert.equal(ready.ok === true ? ready.kind : "", "Touch ID");
    },
  );

  test("and the command refuses out loud when biometry is switched off", () => {
    // The wiring, end to end: `hush secure biometry` asks the same question and
    // refuses without writing the policy. Driven through the opt-out because a
    // subprocess cannot be handed a stub helper — by design.
    const p = project();
    try {
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        HUSH_HOME: p.home,
        HUSH_BIOMETRY: "off",
        HUSH_NO_NUDGE: "1",
        HUSH_NO_KEYCHAIN: "1",
        NO_COLOR: "1",
      };
      const r = spawnSync(process.execPath, [CLI, "secure", "biometry"], {
        cwd: p.root, env, encoding: "utf8",
      });
      const out = (r.stdout ?? "") + (r.stderr ?? "");
      assert.match(out, /✗/, `it did not refuse:\n${out}`);

      const policyPath = join(p.root, ".hush", "policy.json");
      if (existsSync(policyPath)) {
        const policy = JSON.parse(readFileSync(policyPath, "utf8")) as { biometry?: string };
        assert.notEqual(
          policy.biometry,
          "required",
          "it required a fingerprint it had just said it could not check",
        );
      }
    } finally {
      p.cleanup();
    }
  });
});

describe("a symlink a repository committed at .hush/policy.json (review F21)", () => {
  test("hush secure refuses to write through it, and the file it points at is untouched", () => {
    const p = project();
    const outside = mkdtempSync(join(tmpdir(), "hush-floor-"));
    try {
      const target = join(outside, "policy.json");
      writeFileSync(target, '{"requireApproval":["run"]}\n');
      const policy = join(p.hushDir, "policy.json");
      rmSync(policy, { force: true });
      symlinkSync(target, policy);
      const r = p.run(["secure", "approval", "--for", "30m"]);
      assert.notEqual(r.code, 0, r.out);
      assert.match(r.out, /not a regular file/);
      assert.equal(readFileSync(target, "utf8"), '{"requireApproval":["run"]}\n', "the write went through the link");
      // A dangling link is a link too: existsSync says false, and a write creates its target.
      const absent = join(outside, "floor-not-made-yet.json");
      rmSync(policy);
      symlinkSync(absent, policy);
      p.run(["secure", "approval", "--for", "30m"]);
      assert.ok(!existsSync(absent), "a dangling link's target was created");
    } finally {
      rmSync(outside, { recursive: true, force: true });
      p.cleanup();
    }
  });
});
