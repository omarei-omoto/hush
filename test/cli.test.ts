/**
 * CLI-level tests for the ladder and verification commands.
 *
 * secure.ts performs the only genuinely destructive operations in hush —
 * deleting a .env, migrating a key out of a file, rewriting policy — and had no
 * automated coverage. These run the real binary in a scratch project.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, existsSync, rmSync, statSync, chmodSync } from "node:fs";
import { tmpdir, platform } from "node:os";
import { join, dirname } from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import { Vault } from "../src/vault.ts";
import { generateIdentity, encodeSecret, encodePub } from "../src/crypto.ts";
import { biometryStatus } from "../src/biometry.ts";
import { ageAvailable } from "../src/age.ts";
import { execFileSync } from "node:child_process";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.ts");

function project() {
  const home = mkdtempSync(join(tmpdir(), "hush-cli-home-"));
  const root = mkdtempSync(join(tmpdir(), "hush-cli-proj-"));
  mkdirSync(join(root, ".hush"), { recursive: true });
  const id = generateIdentity();
  const vault = Vault.create(join(root, ".hush", "vault.json"), "clitest", { name: "tester", pub: id.pub });
  vault.set(id, "default", "STRIPE_SECRET_KEY", "sk_live_cli");
  vault.save();
  const env = {
    ...process.env,
    HUSH_HOME: home,
    HUSH_IDENTITY: encodeSecret(id),
    HUSH_BIOMETRY: "off",
    HUSH_NO_NUDGE: "1",
    NO_COLOR: "1",
  };
  /**
   * @param input piped to the command — `hush set` reads its value from stdin.
   *
   * `out` is stdout and stderr together, on success as well as on failure.
   * Capturing stderr only when the command failed hid every warning hush prints
   * on a successful run, so a test could assert on a message that was never
   * actually reaching the user's terminal.
   */
  const run = (args: string[], input?: string) => {
    const r = spawnSync(process.execPath, [CLI, ...args], {
      cwd: root,
      env,
      encoding: "utf8",
      input,
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
    return { out: (r.stdout ?? "") + (r.stderr ?? ""), code: r.status ?? 1 };
  };
  return { home, root, run, cleanup: () => { for (const d of [home, root]) rmSync(d, { recursive: true, force: true }); } };
}

describe("hush level", () => {
  test("reports a rung, the checklist, and a concrete next step", () => {
    const p = project();
    const { out } = p.run(["level"]);
    assert.match(out, /rung \d of 5/);
    assert.match(out, /secrets are encrypted at rest/);
    assert.match(out, /Next/);
    p.cleanup();
  });

  test("a stray .env caps you at rung 0 no matter what else passes", () => {
    const p = project();
    writeFileSync(join(p.root, ".env"), "FOO=bar\n");
    assert.match(p.run(["level"]).out, /rung 0 of 5/);
    rmSync(join(p.root, ".env"));
    assert.ok(!/rung 0 of 5/.test(p.run(["level"]).out), "removing the .env did not raise the rung");
    p.cleanup();
  });

  test("--json is machine readable", () => {
    const p = project();
    const parsed = JSON.parse(p.run(["level", "--json"]).out) as { rung: number; checks: unknown[] };
    assert.equal(typeof parsed.rung, "number");
    assert.equal(parsed.checks.length, 6);
    p.cleanup();
  });

  test("high-value key names are surfaced, but never their values", () => {
    const p = project();
    const { out } = p.run(["level"]);
    assert.match(out, /STRIPE_SECRET_KEY/);
    assert.ok(!out.includes("sk_live_cli"), "a value leaked into the ladder output");
    p.cleanup();
  });
});

describe("hush secure", () => {
  test("turning on approval actually rewrites the policy", () => {
    const p = project();
    writeFileSync(join(p.root, ".hush", "policy.json"), JSON.stringify({ requireApproval: [] }));
    p.run(["secure", "approval"]);
    const policy = JSON.parse(readFileSync(join(p.root, ".hush", "policy.json"), "utf8")) as { requireApproval: string[] };
    assert.deepEqual(policy.requireApproval.sort(), ["add", "reveal", "run"]);
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

describe("hush verify", () => {
  test("a healthy vault verifies and exits zero", () => {
    const p = project();
    const { out, code } = p.run(["verify"]);
    assert.equal(code, 0);
    assert.match(out, /freshness/);
    assert.match(out, /1 value\(s\) readable/);
    p.cleanup();
  });

  test("a vault you cannot decrypt reports it and exits non-zero", () => {
    const p = project();
    const stranger = encodeSecret(generateIdentity());
    const r = spawnSync(process.execPath, [CLI, "verify"], {
      cwd: p.root,
      env: { ...process.env, HUSH_HOME: p.home, HUSH_IDENTITY: stranger, HUSH_BIOMETRY: "off", NO_COLOR: "1" },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const out = (r.stdout ?? "") + (r.stderr ?? "");
    const code = r.status ?? 1;
    assert.notEqual(code, 0, "a broken vault reported success");
    assert.match(out, /not a recipient/);
    p.cleanup();
  });
});

describe("hush ls separates environments from accounts", () => {
  test("account scopes are not listed as environments", () => {
    // `hush accounts` is where fal/personal belongs; showing it under
    // "other envs" invites treating an account like an environment.
    const p = project();
    p.run(["set", "PROD_KEY", "--env", "prod"], "prod-value\n");
    p.run(["add", "fal", "--account", "personal", "--vars", "FAL_KEY"], "fal-value\n");

    const out = p.run(["ls"]).out;
    const others = out.match(/other envs: (.*)/)?.[1] ?? "";
    assert.ok(others.includes("prod"), `expected prod in "${others}"`);
    assert.ok(!others.includes("/"), `an account scope was listed as an environment: ${others}`);

    // And it does show up where it belongs.
    assert.match(p.run(["accounts"]).out, /personal/);
  });
});

describe("hush doctor reports the whole setup", () => {
  test("it separates environments from service accounts", () => {
    // doctor used to print "envs: default, fal/personal", repeating the same
    // confusion `hush ls` had: an account is not an environment.
    const p = project();
    p.run(["set", "PROD_KEY", "--env", "prod"], "v\n");
    p.run(["add", "fal", "--account", "personal", "--vars", "FAL_KEY"], "v\n");

    const out = p.run(["doctor"]).out;
    const envLine = out.match(/environments\s+(.*)/)?.[1] ?? "";
    assert.ok(envLine.includes("prod"), `expected prod in "${envLine}"`);
    assert.ok(!envLine.includes("/"), `an account was listed as an environment: ${envLine}`);
    assert.match(out, /service accounts\s+1 — fal\/personal/);
    p.cleanup();
  });

  test("it warns when accounts exist but none are pinned", () => {
    // Otherwise `hush run` silently injects none of them.
    const p = project();
    p.run(["add", "fal", "--account", "personal", "--vars", "FAL_KEY"], "v\n");
    assert.match(p.run(["doctor"]).out, /none pinned/);
    p.run(["use", "fal=personal"]);
    assert.ok(!/none pinned/.test(p.run(["doctor"]).out), "still warning after pinning");
    p.cleanup();
  });

  test("it reports the policy actually in force", () => {
    const p = project();
    assert.match(p.run(["doctor"]).out, /approval required\s+run, add, reveal/);
    writeFileSync(join(p.root, ".hush", "policy.json"), JSON.stringify({ requireApproval: [] }));
    assert.match(p.run(["doctor"]).out, /nothing is gated/);
    p.cleanup();
  });

  test("biometry is only ticked when it is actually enforced", { skip: biometryStatus().available ? false : "no biometry on this host" }, () => {
    // Must run with biometry genuinely available, or "preferred" and "required"
    // both come out unticked and the test proves nothing.
    const p = project();
    const withBiometry = (policy: Record<string, unknown>) => {
      writeFileSync(join(p.root, ".hush", "policy.json"), JSON.stringify(policy));
      const env: NodeJS.ProcessEnv = { ...process.env, HUSH_HOME: p.home, HUSH_NO_NUDGE: "1", NO_COLOR: "1" };
      delete env.HUSH_BIOMETRY; // let the real check run
      const r = spawnSync(process.execPath, [CLI, "doctor"], {
        cwd: p.root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
      });
      const out = (r.stdout ?? "") + (r.stderr ?? "");
      return out.split("\n").find((l) => l.includes("biometry")) ?? "";
    };

    const preferred = withBiometry({ biometry: "preferred" });
    assert.ok(!preferred.includes("✓"), `ticked a policy that still allows a click: ${preferred}`);
    assert.match(preferred, /a click still works/);

    const required = withBiometry({ biometry: "required" });
    assert.ok(required.includes("✓"), `did not tick an enforced policy: ${required}`);
    p.cleanup();
  });

  test("it shows where you are on the ladder and what is next", () => {
    const p = project();
    const out = p.run(["doctor"]).out;
    assert.match(out, /rung \d of 5/);
    assert.match(out, /next:/);
    assert.match(out, /hush secure/);
    p.cleanup();
  });

  test("it never prints a secret value", () => {
    const p = project();
    const out = p.run(["doctor"]).out;
    assert.ok(!out.includes("sk_live_cli"), "doctor leaked a value");
    p.cleanup();
  });
});

describe("hush add", () => {
  test("a value piped in one line per variable is stored", () => {
    const p = project();
    try {
      const r = p.run(["add", "twilio", "--account", "main"], "AC_sid_value\nauth_token_value\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /stored 2 value/);

      const accounts = p.run(["accounts", "--json"]);
      const parsed = JSON.parse(accounts.out) as { accounts: { scope: string; vars: string[] }[] };
      const twilio = parsed.accounts.find((a) => a.scope === "twilio/main");
      assert.deepEqual(twilio?.vars.sort(), ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"]);
    } finally {
      p.cleanup();
    }
  });

  test("with no terminal and nothing piped it fails rather than reporting success", () => {
    // It used to print "nothing entered, nothing changed" and exit 0, so a CI
    // job that checked the exit code believed the credential had been stored.
    const p = project();
    try {
      const r = p.run(["add", "gemini", "--account", "team"]);
      assert.equal(r.code, 1, `expected failure, got:\n${r.out}`);
      assert.match(r.out, /no value arrived on stdin/);
      assert.match(r.out, /GEMINI_API_KEY/, "the message does not say what to pipe");

      // And nothing was written.
      const accounts = p.run(["accounts", "--json"]);
      const parsed = JSON.parse(accounts.out) as { accounts: { scope: string }[] };
      assert.equal(parsed.accounts.find((a) => a.scope === "gemini/team"), undefined);
    } finally {
      p.cleanup();
    }
  });

  test("a partial write says which variables were left unset", () => {
    const p = project();
    try {
      const r = p.run(["add", "twilio", "--account", "half"], "AC_sid_only\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /Left unset: TWILIO_AUTH_TOKEN/);
      assert.match(r.out, /stored 1 value/);
    } finally {
      p.cleanup();
    }
  });
});

describe("hush get / import / run — the gaps mutation testing found", () => {
  test("`hush get` will not print a live credential without --yes", () => {
    // Non-interactive, so the confirmation can only decline. Removing the
    // confirmation entirely made every `hush get` print the value.
    const p = project();
    try {
      const r = p.run(["get", "STRIPE_SECRET_KEY"]);
      assert.ok(!r.out.includes("sk_live_cli"), `a credential was printed unasked:\n${r.out}`);
      assert.match(r.out, /aborted|stays in scrollback/);

      // With --yes it does print it — otherwise this proves only that get is broken.
      const yes = p.run(["get", "STRIPE_SECRET_KEY", "--yes"]);
      assert.match(yes.out, /sk_live_cli/);
    } finally {
      p.cleanup();
    }
  });

  test("`hush import` does not overwrite an existing secret unless told to", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.in"), "STRIPE_SECRET_KEY=a_different_value\nNEW_ONE=brand_new_value\n");

      const first = p.run(["import", ".env.in"]);
      assert.equal(first.code, 0, first.out);
      assert.match(first.out, /1 already present/);
      assert.match(p.run(["get", "STRIPE_SECRET_KEY", "--yes"]).out, /sk_live_cli/, "the existing value was replaced");
      assert.match(p.run(["get", "NEW_ONE", "--yes"]).out, /brand_new_value/);

      // --overwrite is the opt-in, and it must actually do it.
      const second = p.run(["import", ".env.in", "--overwrite"]);
      assert.equal(second.code, 0, second.out);
      assert.match(p.run(["get", "STRIPE_SECRET_KEY", "--yes"]).out, /a_different_value/, "--overwrite did nothing");
    } finally {
      p.cleanup();
    }
  });

  test("`hush run` injects the pinned account, and --with overrides the pin", () => {
    const p = project();
    try {
      // Different variable *sets* per account, so which one was chosen is
      // visible without printing a value. Giving both the same single variable
      // made the two cases indistinguishable — the output was
      // "[redacted:FAL_KEY]" either way, and the test proved only that
      // something was injected.
      p.run(["add", "fal", "--account", "personal", "--vars", "FAL_KEY,FAL_PERSONAL_MARKER"],
        "fal_personal_value\npersonal_marker_value\n");
      p.run(["add", "fal", "--account", "work", "--vars", "FAL_KEY,FAL_WORK_MARKER"],
        "fal_work_value\nwork_marker_value\n");
      assert.equal(p.run(["use", "fal=personal"]).code, 0);

      // `hush export --names` resolves exactly what `hush run` would inject.
      const pinned = p.run(["export", "--names"]).out;
      assert.match(pinned, /FAL_PERSONAL_MARKER/, "the pinned account was not injected");
      assert.ok(!pinned.includes("FAL_WORK_MARKER"), `the wrong account was injected:\n${pinned}`);

      const overridden = p.run(["export", "--names", "--with", "fal:work"]).out;
      assert.match(overridden, /FAL_WORK_MARKER/, "--with did not override the pin");
      assert.ok(!overridden.includes("FAL_PERSONAL_MARKER"), `the pin won over --with:\n${overridden}`);

      // And the same choice really reaches a child process.
      const ran = p.run(["run", "--quiet", "--with", "fal:work", "--", "sh", "-c", "echo \"${FAL_WORK_MARKER:-absent}\""]);
      assert.match(ran.out, /redacted:FAL_WORK_MARKER/, `--with did not reach the child:\n${ran.out}`);
    } finally {
      p.cleanup();
    }
  });

  test("an unpinned run injects nothing from an account", () => {
    // The counterpart: without a pin and without --with, an account's keys must
    // not leak into every command.
    const p = project();
    try {
      p.run(["add", "fal", "--account", "personal", "--vars", "FAL_KEY"], "fal_personal_value\n");
      const names = p.run(["export", "--names"]);
      assert.ok(!names.out.includes("FAL_KEY"), `an unpinned account was injected:\n${names.out}`);
    } finally {
      p.cleanup();
    }
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
      assert.deepEqual((policy.requireApproval as string[]).sort(), ["add", "reveal", "run"]);
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
      const r = p.run(["ls"]);
      assert.equal(r.code, 0, `a corrupt nudge state broke an unrelated command:\n${r.out}`);
      assert.match(r.out, /STRIPE_SECRET_KEY/);
    } finally {
      p.cleanup();
    }
  });
});

describe("hush export / use / run — the rest of the CLI gaps", () => {
  test("an exported .env is written mode 0600, even over an existing world-readable file", () => {
    // writeFileSync only applies a mode when it creates the file, so exporting
    // over a stray .env left at 0644 would keep 0644 — every account on the box
    // can then read every credential.
    const p = project();
    try {
      const out = join(p.root, ".env.generated");
      writeFileSync(out, "STALE=1\n", { mode: 0o644 });
      chmodSync(out, 0o644);
      assert.equal((statSync(out).mode & 0o777).toString(8), "644", "the fixture is not world-readable");

      const r = p.run(["export", "--out", ".env.generated"]);
      assert.equal(r.code, 0, r.out);
      assert.equal((statSync(out).mode & 0o777).toString(8), "600", "the exported file is readable by others");
      assert.match(r.out, /Parse it, don't source it/, "the sourcing hazard is not mentioned");

      // Writing plaintext credentials into the repo and not excluding them is
      // exactly how a .env gets committed — which is the thing hush exists to
      // stop. The entry is added whether or not a .gitignore was there already.
      const ignorePath = join(p.root, ".gitignore");
      assert.ok(existsSync(ignorePath), "no .gitignore was created for the exported secrets");
      assert.ok(
        readFileSync(ignorePath, "utf8").split(/\r?\n/).includes(".env.generated"),
        "the exported file was not added to .gitignore",
      );
      assert.match(r.out, /added \.env\.generated to \.gitignore/);

      // And it is not added twice when you export again.
      assert.equal(p.run(["export", "--out", ".env.generated"]).code, 0);
      const lines = readFileSync(ignorePath, "utf8").split(/\r?\n/).filter((l) => l === ".env.generated");
      assert.equal(lines.length, 1, "the .gitignore entry was duplicated on a second export");
    } finally {
      p.cleanup();
    }
  });

  test("`hush use` refuses an account that does not exist", () => {
    // Pinning a typo silently means every later `hush run` quietly injects
    // nothing, and the failure surfaces somewhere else entirely.
    const p = project();
    try {
      p.run(["add", "fal", "--account", "personal", "--vars", "FAL_KEY"], "fal-value\n");

      const bad = p.run(["use", "fal=typo"]);
      assert.equal(bad.code, 1, `a non-existent account was pinned:\n${bad.out}`);
      assert.match(bad.out, /No account "typo"/);
      assert.match(bad.out, /known: personal/, "the message does not say what is available");
      assert.ok(!existsSync(join(p.root, ".hush", "use.json")), "it wrote the bad pin anyway");

      const good = p.run(["use", "fal=personal"]);
      assert.equal(good.code, 0, good.out);
      const use = JSON.parse(readFileSync(join(p.root, ".hush", "use.json"), "utf8")) as Record<string, string>;
      assert.deepEqual(use, { fal: "personal" });
    } finally {
      p.cleanup();
    }
  });

  test("`hush run` exits with the child's status", () => {
    // CI reads the exit code and nothing else. Reporting 0 for a failed command
    // turns a red build green.
    const p = project();
    try {
      assert.equal(p.run(["run", "--quiet", "--", "sh", "-c", "exit 0"]).code, 0);
      assert.equal(p.run(["run", "--quiet", "--", "sh", "-c", "exit 3"]).code, 3, "a failing child reported success");
      assert.equal(p.run(["run", "--quiet", "--", "sh", "-c", "exit 42"]).code, 42);
      // A child killed by a signal exits with code null; 128+n is the convention.
      assert.equal(p.run(["run", "--quiet", "--", "sh", "-c", "kill -TERM $$"]).code, 143);
    } finally {
      p.cleanup();
    }
  });

  test("a vault that has gone backwards is reported before anything else runs", () => {
    // A rolled-back vault decrypts perfectly — authentication says nothing about
    // freshness — so the only thing standing between a revoked member's old copy
    // and full access is this warning.
    const p = project();
    try {
      p.run(["ls"]); // trust on first use records generation 1
      const other = generateIdentity();
      p.run(["team", "add", "colleague", encodePub(other.pub)]);
      p.run(["team", "rm", "colleague", "--yes"]); // generation 2
      p.run(["ls"]); // watermark now 2

      // Restore the old copy, the way a force-push would.
      const path = join(p.root, ".hush", "vault.json");
      const raw = JSON.parse(readFileSync(path, "utf8")) as { dek: { generation: number } };
      raw.dek.generation = 1;
      writeFileSync(path, JSON.stringify(raw, null, 2));

      const out = p.run(["ls"]).out;
      assert.match(out, /ROLLBACK/, `no rollback warning:\n${out}`);
      assert.match(out, /gone BACKWARDS/);
      assert.match(out, /treat every secret in it as compromised/);
    } finally {
      p.cleanup();
    }
  });

  test("hush init makes the vault unmergeable and keeps local state out of git", () => {
    // A three-way merge of two vaults produces valid JSON with a data key from
    // one branch and values sealed under another: unopenable, and it looks fine.
    // And the identity file must never be committable.
    const p = project();
    try {
      const proj = mkdtempSync(join(tmpdir(), "hush-init-"));
      const env = { ...process.env, HUSH_HOME: p.home, HUSH_NO_NUDGE: "1", HUSH_NO_KEYCHAIN: "1", NO_COLOR: "1" };
      const r = spawnSync(process.execPath, [CLI, "init", "gitattrs"], { cwd: proj, env, encoding: "utf8" });
      assert.equal(r.status, 0, (r.stdout ?? "") + (r.stderr ?? ""));

      const attrs = readFileSync(join(proj, ".hush", ".gitattributes"), "utf8");
      assert.match(attrs, /^vault\.json -merge$/m, "git may line-merge the vault");
      assert.match(attrs, /^use\.json -merge$/m);
      assert.ok(!/-diff/.test(attrs), "the diff is how a reviewer notices a new recipient");

      const ignored = readFileSync(join(proj, ".hush", ".gitignore"), "utf8").split(/\r?\n/);
      for (const entry of ["identity", "audit.log", "pending/", "*.local.json"]) {
        assert.ok(ignored.includes(entry), `.hush/.gitignore does not exclude ${entry}`);
      }
      rmSync(proj, { recursive: true, force: true });
    } finally {
      p.cleanup();
    }
  });
});

describe("hush secure --biometry will not promise what the hardware cannot do", () => {
  test(
    "a working helper with no enrolled finger is still refused",
    { skip: platform() === "darwin" ? false : "macOS only" },
    () => {
      // The existing refusal test gets there through `ensureHelper` failing,
      // which leaves the *second* check — "the helper works, but nobody has
      // enrolled a finger" — never reached. That is the case that matters: hush
      // must not write `biometry: required` into a policy it cannot enforce,
      // because the next approval would then refuse rather than fall back, and
      // the user would be locked out by a protection they thought they had.
      const p = project();
      try {
        // A helper whose stamp matches, so ensureHelper accepts it, and which
        // answers --check with "no".
        const src = join(dirname(fileURLToPath(import.meta.url)), "..", "native", "hush-touchid.swift");
        const digest = createHash("sha256").update(readFileSync(src)).digest("hex").slice(0, 16);
        const bin = join(p.home, "bin");
        mkdirSync(bin, { recursive: true, mode: 0o700 });
        writeFileSync(join(bin, "hush-touchid"), '#!/bin/sh\necho "no 0"\nexit 1\n', { mode: 0o755 });
        writeFileSync(join(bin, "hush-touchid.stamp"), digest);

        const env: NodeJS.ProcessEnv = {
          ...process.env,
          HUSH_HOME: p.home,
          HUSH_NO_NUDGE: "1",
          HUSH_NO_KEYCHAIN: "1",
          NO_COLOR: "1",
        };
        delete env.HUSH_BIOMETRY; // let the real check run against the stub

        const r = spawnSync(process.execPath, [CLI, "secure", "biometry"], {
          cwd: p.root, env, encoding: "utf8",
        });
        const out = (r.stdout ?? "") + (r.stderr ?? "");
        assert.match(out, /enrolled|unavailable|✗/, `it did not refuse:\n${out}`);

        const policyPath = join(p.root, ".hush", "policy.json");
        if (existsSync(policyPath)) {
          const policy = JSON.parse(readFileSync(policyPath, "utf8")) as { biometry?: string };
          assert.notEqual(
            policy.biometry,
            "required",
            "it required a fingerprint that nobody has enrolled — the next approval would refuse outright",
          );
        }
      } finally {
        p.cleanup();
      }
    },
  );

  test(
    "with a finger enrolled it does turn the rung on",
    { skip: platform() === "darwin" ? false : "macOS only" },
    () => {
      // The other side, so the refusal above is not just "it always refuses".
      const p = project();
      try {
        const src = join(dirname(fileURLToPath(import.meta.url)), "..", "native", "hush-touchid.swift");
        const digest = createHash("sha256").update(readFileSync(src)).digest("hex").slice(0, 16);
        const bin = join(p.home, "bin");
        mkdirSync(bin, { recursive: true, mode: 0o700 });
        writeFileSync(join(bin, "hush-touchid"), '#!/bin/sh\necho "yes 1"\nexit 0\n', { mode: 0o755 });
        writeFileSync(join(bin, "hush-touchid.stamp"), digest);

        const env: NodeJS.ProcessEnv = {
          ...process.env,
          HUSH_HOME: p.home,
          HUSH_NO_NUDGE: "1",
          HUSH_NO_KEYCHAIN: "1",
          NO_COLOR: "1",
        };
        delete env.HUSH_BIOMETRY;

        const r = spawnSync(process.execPath, [CLI, "secure", "biometry"], {
          cwd: p.root, env, encoding: "utf8",
        });
        const out = (r.stdout ?? "") + (r.stderr ?? "");
        assert.match(out, /Touch ID is now required|now required to approve/, `it did not enable it:\n${out}`);

        const policy = JSON.parse(readFileSync(join(p.root, ".hush", "policy.json"), "utf8")) as { biometry?: string };
        assert.equal(policy.biometry, "required");
      } finally {
        p.cleanup();
      }
    },
  );
});
