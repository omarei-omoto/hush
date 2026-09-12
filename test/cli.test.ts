/**
 * CLI-level tests for the ladder and verification commands.
 *
 * secure.ts performs the only genuinely destructive operations in hush —
 * deleting a .env, migrating a key out of a file, rewriting policy — and had no
 * automated coverage. These run the real binary in a scratch project.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync, spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, existsSync, rmSync, statSync, chmodSync } from "node:fs";
import { tmpdir, platform } from "node:os";
import { join, dirname } from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { once } from "node:events";

import { Vault } from "../src/vault.ts";
import { generateIdentity, encodeSecret, encodePub } from "../src/crypto.ts";
import { biometryStatus } from "../src/biometry.ts";
import { ageAvailable } from "../src/age.ts";
import { pendingRequests, answerRequest } from "../src/approval.ts";
import { execFileSync } from "node:child_process";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.ts");

/**
 * @param envOverride  Merged over the base env — e.g. `{ HUSH_APPROVAL_MODE: "file" }`
 * so a test that turns on `requireApproval` does not hang on a real macOS
 * dialog it has no way to answer.
 */
function project(envOverride: NodeJS.ProcessEnv = {}) {
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
    ...envOverride,
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
  return {
    home, root, env, run,
    hushDir: join(root, ".hush"),
    cleanup: () => { for (const d of [home, root]) rmSync(d, { recursive: true, force: true }); },
  };
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

describe("hush ls treats every set the same, slash or not", () => {
  // Sets unified environments and service accounts into one vocabulary, so
  // the old split view ("environments" vs "other envs" holding accounts) is
  // gone — a name with a "/" in it is listed exactly like any other set. This
  // replaces the old "account scopes are not listed as environments" test,
  // which asserted the opposite of what the unified model intends.
  test("a slash-named set (an old service account) appears in THIS PROJECT like any other set", () => {
    const p = project();
    p.run(["set", "PROD_KEY", "--env", "prod"], "prod-value\n");
    p.run(["add", "fal", "--account", "personal", "--vars", "FAL_KEY"], "fal-value\n");

    const out = p.run(["ls"]).out;
    assert.match(out, /\(prod\)/, `expected the "prod" set in:\n${out}`);
    assert.match(out, /\(fal\/personal\)/, `expected "fal/personal" listed like any other set:\n${out}`);

    // And `hush ls fal/personal` shows its key names, never values.
    const detail = p.run(["ls", "fal/personal"]).out;
    assert.match(detail, /FAL_KEY/);
    assert.ok(!detail.includes("fal-value"), "a value leaked from `hush ls <set>`");
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

      // `hush accounts` is now a deprecated alias for `hush ls`, which never
      // prints a machine-readable per-account shape — read the vault directly.
      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      const twilio = vault.sets().find((s) => s.name === "twilio/main");
      assert.deepEqual(twilio?.keys.sort(), ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"]);
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
      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.equal(vault.hasSet("gemini/team"), false, "a set was created despite the failure");
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

      // A bare `hush import` (no --as, no --env) now requires --as, like `hush
      // add <file>` — the alias's --env shortcut is the one path that still
      // stores straight into an existing literal environment with no name.
      const first = p.run(["import", ".env.in", "--env", "default"]);
      assert.equal(first.code, 0, first.out);
      assert.match(first.out, /1 already present/);
      assert.match(p.run(["get", "STRIPE_SECRET_KEY", "--yes"]).out, /sk_live_cli/, "the existing value was replaced");
      assert.match(p.run(["get", "NEW_ONE", "--yes"]).out, /brand_new_value/);

      // --overwrite is the opt-in, and it must actually do it.
      const second = p.run(["import", ".env.in", "--overwrite", "--env", "default"]);
      assert.equal(second.code, 0, second.out);
      assert.match(p.run(["get", "STRIPE_SECRET_KEY", "--yes"]).out, /a_different_value/, "--overwrite did nothing");
    } finally {
      p.cleanup();
    }
  });

  test("`hush import --as` creates a named set in the project vault, not default", () => {
    // The quick-start command is `hush import`, and without a name every key
    // lands in one unnamed pile under "default" — the exact thing the named
    // env-set feature exists to prevent. `--as` is the way `import` gets there.
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.in"), "ACME_API_KEY=key1\nACME_DB_URL=db1\n");
      const r = p.run(["import", ".env.in", "--as", "Acme Production", "--description", "live keys"]);
      assert.equal(r.code, 0, r.out);

      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      const sets = vault.sets();
      const set = sets.find((s) => s.name === "acme-production");
      assert.ok(set, `no set named acme-production among: ${sets.map((s) => s.name).join(", ")}`);
      assert.equal(set!.label, "Acme Production");
      assert.equal(set!.description, "live keys");
      assert.deepEqual(set!.keys.sort(), ["ACME_API_KEY", "ACME_DB_URL"]);

      const def = sets.find((s) => s.name === "default")!;
      assert.ok(
        !def.keys.includes("ACME_API_KEY") && !def.keys.includes("ACME_DB_URL"),
        `default gained the imported keys: ${def.keys.join(", ")}`,
      );
    } finally {
      p.cleanup();
    }
  });

  test("`hush import` with no flags now requires --as: a run that stores nothing must not look like one that did", () => {
    // This used to default quietly into "default" with a tip; `hush import`
    // is now a pure alias for `hush add <file>`, whose non-TTY rule (same
    // principle `hush add <service>` already applied to an empty stdin pipe)
    // is stricter — see specs/cli.md's `hush add` test list, bullet 1.
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.in"), "PLAIN_ONE=v1\nPLAIN_TWO=v2\n");
      const r = p.run(["import", ".env.in"]);
      assert.equal(r.code, 1, `expected failure, got:\n${r.out}`);
      assert.match(r.out, /--as/);

      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      const def = vault.sets().find((s) => s.name === "default")!;
      assert.ok(!def.keys.includes("PLAIN_ONE") && !def.keys.includes("PLAIN_TWO"), "keys were stored despite the failure");
    } finally {
      p.cleanup();
    }
  });

  test("`hush import --env` is unchanged: no prompt, no --as tip", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.in"), "PROD_ONE=v1\n");
      const r = p.run(["import", ".env.in", "--env", "prod"]);
      assert.equal(r.code, 0, r.out);
      assert.ok(!r.out.includes("--as"), `--env still printed the --as tip:\n${r.out}`);

      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      const set = vault.sets().find((s) => s.name === "prod");
      assert.ok(set && set.keys.includes("PROD_ONE"), "key did not land in the named --env");
    } finally {
      p.cleanup();
    }
  });

  test("`hush import --as` into an existing set adds to it, respecting --overwrite", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.a"), "SHARED_KEY=first_value\nONLY_IN_A=a_value\n");
      writeFileSync(join(p.root, ".env.b"), "SHARED_KEY=second_value\nONLY_IN_B=b_value\n");

      const first = p.run(["import", ".env.a", "--as", "Acme Production"]);
      assert.equal(first.code, 0, first.out);

      // The user is adding to the set they already named — this must not fail.
      const second = p.run(["import", ".env.b", "--as", "Acme Production"]);
      assert.equal(second.code, 0, second.out);
      assert.match(second.out, /1 already present/, second.out);

      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      const set = vault.sets().find((s) => s.name === "acme-production");
      assert.ok(set, "set missing after second import");
      assert.deepEqual(set!.keys.sort(), ["ONLY_IN_A", "ONLY_IN_B", "SHARED_KEY"]);

      assert.match(
        p.run(["get", "SHARED_KEY", "--env", "acme-production", "--yes"]).out,
        /first_value/,
        "the existing value in the named set was replaced without --overwrite",
      );

      const third = p.run(["import", ".env.b", "--as", "Acme Production", "--overwrite"]);
      assert.equal(third.code, 0, third.out);
      assert.match(
        p.run(["get", "SHARED_KEY", "--env", "acme-production", "--yes"]).out,
        /second_value/,
        "--overwrite did nothing for a named set",
      );
    } finally {
      p.cleanup();
    }
  });

  test("`hush import --as` records the source file in the set's metadata", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.prod"), "SRC_KEY=v\n");
      const r = p.run(["import", ".env.prod", "--as", "Acme Production"]);
      assert.equal(r.code, 0, r.out);

      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      const set = vault.sets().find((s) => s.name === "acme-production");
      assert.ok(set && set.source && set.source.endsWith(".env.prod"), `source not recorded: ${JSON.stringify(set)}`);
    } finally {
      p.cleanup();
    }
  });

  test("`hush run` injects the set this project uses, redacted", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=fal_default_value", "--to", "work-fal"]).code, 0);
      assert.equal(p.run(["use", "work-fal"]).code, 0);
      const ran = p.run(["run", "--quiet", "--", "sh", "-c", "echo \"${FAL_KEY:-absent}\""]);
      assert.equal(ran.code, 0, ran.out);
      assert.match(ran.out, /redacted:FAL_KEY/, `the used set's key did not reach the child:\n${ran.out}`);
      assert.ok(!ran.out.includes("fal_default_value"), "a live value leaked into output");
    } finally {
      p.cleanup();
    }
  });

  test("sets are layers, not exclusive choices: --use appended last wins a shared key, but keeps the other layer's own keys", () => {
    // Pre-unification, picking a different "account" replaced the injected
    // keys wholesale — the two accounts here would have had the very same
    // variable name, and choosing one meant the other's value simply could
    // not be observed at the same time. Named sets compose instead: each
    // layer's own keys always show up, and only a key both layers hold is
    // decided by order (later wins). Two different keys plus one shared key
    // is what actually exercises that, which is why this replaces the old
    // "the pin won over --with" test (see specs/cli.md's `hush run` test).
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=work_value", "PROJECT_MARKER=work", "--to", "work-fal"]).code, 0);
      assert.equal(p.run(["add", "FAL_KEY=personal_value", "PERSONAL_MARKER=mine", "--to", "personal-fal"]).code, 0);
      assert.equal(p.run(["use", "work-fal"]).code, 0);

      const first = JSON.parse(p.run(["export", "--format", "json"]).out) as Record<string, string>;
      assert.equal(first.FAL_KEY, "work_value");
      assert.equal(first.PROJECT_MARKER, "work");
      assert.equal(first.PERSONAL_MARKER, undefined, "a set that is not used yet leaked a key");

      // `--use` on a set the project already uses (or a brand new one, as
      // here) is appended last, so it wins for this run.
      const layered = JSON.parse(p.run(["export", "--format", "json", "--use", "personal-fal"]).out) as Record<string, string>;
      assert.equal(layered.FAL_KEY, "personal_value", "the later set did not win the shared key");
      assert.equal(layered.PROJECT_MARKER, "work", "the earlier layer's own key was dropped, not composed");
      assert.equal(layered.PERSONAL_MARKER, "mine");

      const ran = p.run(["run", "--quiet", "--use", "personal-fal", "--", "sh", "-c", "echo \"${FAL_KEY:-absent}\""]);
      assert.equal(ran.code, 0, ran.out);
      assert.match(ran.out, /redacted:FAL_KEY/, `--use did not reach the child:\n${ran.out}`);
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

  test("`hush use` refuses a set that does not exist, and `fal=acme` aliases to `fal/acme`", () => {
    // Using a typo silently means every later `hush run` quietly injects
    // nothing, and the failure surfaces somewhere else entirely. `hush use`
    // now names sets directly and records them in .hush/envs.json, not
    // .hush/use.json — the pre-unification "pin a service=account" model this
    // test used to cover, per the alias table in specs/cli.md.
    const p = project();
    try {
      p.run(["add", "fal", "--account", "personal", "--vars", "FAL_KEY"], "fal-value\n");

      const bad = p.run(["use", "fal=typo"]);
      assert.equal(bad.code, 1, `a non-existent set was used:\n${bad.out}`);
      assert.match(bad.out, /"fal=typo" is deprecated/, "the alias was not translated with a deprecation notice");
      assert.match(bad.out, /No set called "fal\/typo"/);
      assert.match(bad.out, /fal\/personal/, "the message does not say what is available");
      assert.ok(!existsSync(join(p.root, ".hush", "envs.json")), "it wrote the bad link anyway");

      const good = p.run(["use", "fal=personal"]);
      assert.equal(good.code, 0, good.out);
      assert.match(good.out, /"fal=personal" is deprecated/);
      const links = JSON.parse(readFileSync(join(p.root, ".hush", "envs.json"), "utf8")) as { use: string[] };
      assert.deepEqual(links.use, ["fal/personal"]);
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

describe("the CLI enforces .hush/policy.json — an agent's shell must not bypass what the MCP server enforces", () => {
  // Every test in this block that turns on requireApproval also sets
  // HUSH_APPROVAL_MODE=file and a short approvalTimeoutSeconds: on macOS,
  // an enforced approval with neither would open a real osascript dialog and
  // hang the test forever.

  test("reveal denied by biometry: `hush get --yes` still refuses", () => {
    const p = project({ HUSH_APPROVAL_MODE: "file" });
    try {
      writeFileSync(
        join(p.hushDir, "policy.json"),
        JSON.stringify({ requireApproval: ["reveal"], biometry: "required", approvalTimeoutSeconds: 1 }),
      );
      const r = p.run(["get", "STRIPE_SECRET_KEY", "--yes"]);
      assert.equal(r.code, 1, r.out);
      assert.ok(!r.out.includes("sk_live_cli"), `a credential leaked past a denied approval:\n${r.out}`);
      assert.match(r.out, /biometry|denied/i);
    } finally {
      p.cleanup();
    }
  });

  test("export is gated as reveal; --names is not, because it reveals nothing", () => {
    const p = project({ HUSH_APPROVAL_MODE: "file" });
    try {
      writeFileSync(
        join(p.hushDir, "policy.json"),
        JSON.stringify({ requireApproval: ["reveal"], biometry: "required", approvalTimeoutSeconds: 1 }),
      );
      const exported = p.run(["export"]);
      assert.equal(exported.code, 1, exported.out);
      assert.ok(!exported.out.includes("sk_live_cli"), `export leaked a value past a denied approval:\n${exported.out}`);

      const names = p.run(["export", "--names"]);
      assert.equal(names.code, 0, names.out);
      assert.match(names.out, /STRIPE_SECRET_KEY/);
    } finally {
      p.cleanup();
    }
  });

  test("allowCommands is a whitelist enforced by the CLI too", () => {
    // "sh" would be refused by the built-in deny floor regardless of
    // allowCommands (it is one of the built-in denyCommands), which would
    // test the wrong mechanism. "git" is not on that floor, so refusing it
    // can only be allowCommands doing its job.
    const p = project();
    try {
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: [], allowCommands: ["npm"] }));

      const refused = p.run(["run", "--", "git", "--version"]);
      assert.equal(refused.code, 1, refused.out);
      assert.match(refused.out, /allowCommands/);

      const allowed = p.run(["run", "--quiet", "--", "npm", "--version"]);
      assert.equal(allowed.code, 0, allowed.out);
    } finally {
      p.cleanup();
    }
  });

  test("pass-through is refused by allowCommands exactly like `hush run --`", () => {
    // Pass-through (`hush <cmd>` with no `run --`) has to route through the
    // same gate `hush run` does, or it would be a way around a policy an
    // agent's other tools were already refused by.
    const p = project();
    try {
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: [], allowCommands: ["npm"] }));

      const refused = p.run(["echo", "hi"]);
      assert.equal(refused.code, 1, refused.out);
      assert.match(refused.out, /allowCommands/);
      assert.ok(!refused.out.includes("hi"), "the command ran despite being refused");
    } finally {
      p.cleanup();
    }
  });

  test("the deny floor holds even with allowCommands unset", () => {
    const p = project();
    try {
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: [] }));
      const r = p.run(["run", "--", "env"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /denied by default/);
    } finally {
      p.cleanup();
    }
  });

  test("allowEnvs restricts `hush run` to the environments named", () => {
    const p = project();
    try {
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: [], allowEnvs: ["default"] }));
      assert.equal(p.run(["set", "K", "--env", "prod"], "secret_value_1234\n").code, 0);

      const r = p.run(["run", "--env", "prod", "--", "npm", "--version"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /Policy forbids/);
    } finally {
      p.cleanup();
    }
  });

  test("run gated by requireApproval times out with nothing spawned", () => {
    const p = project({ HUSH_APPROVAL_MODE: "file" });
    try {
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: ["run"], approvalTimeoutSeconds: 1 }));
      const r = p.run(["run", "--", "echo", "RAN"]);
      assert.equal(r.code, 1, r.out);
      assert.ok(!r.out.includes("RAN"), `the command ran despite a timed-out approval:\n${r.out}`);
    } finally {
      p.cleanup();
    }
  });

  test("a grant persisted by an earlier process is honoured, and its expiry is respected", () => {
    const p = project({ HUSH_APPROVAL_MODE: "file" });
    try {
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: ["run"], approvalTimeoutSeconds: 1 }));
      const grantsPath = join(p.hushDir, "grants.local.json");

      // "run:default" is exactly the scope `hush run` computes for a plain,
      // default-env run with no service accounts chosen — the same shape
      // mcp.ts's hush_run builds, so a grant either surface hands out is
      // honoured by the other.
      writeFileSync(grantsPath, JSON.stringify({ "run:default": Date.now() + 60_000 }));
      const granted = p.run(["run", "--", "echo", "RAN"]);
      assert.equal(granted.code, 0, granted.out);
      assert.match(granted.out, /RAN/);

      writeFileSync(grantsPath, JSON.stringify({ "run:default": Date.now() - 1000 }));
      const expired = p.run(["run", "--", "echo", "RAN"]);
      assert.equal(expired.code, 1, expired.out);
      assert.ok(!expired.out.includes("RAN"), `an expired grant was honoured:\n${expired.out}`);
    } finally {
      p.cleanup();
    }
  });

  test("with no policy file at all, the CLI is unchanged — the gate is opt-in, not a default refusal", () => {
    const p = project();
    try {
      assert.ok(!existsSync(join(p.hushDir, "policy.json")), "test fixture drifted: a policy file exists");
      assert.match(p.run(["get", "STRIPE_SECRET_KEY", "--yes"]).out, /sk_live_cli/);
      assert.match(p.run(["run", "--", "echo", "RAN"]).out, /RAN/);
    } finally {
      p.cleanup();
    }
  });

  test("a session grant is written to a file only its owner can read", async () => {
    const p = project({ HUSH_APPROVAL_MODE: "file" });
    try {
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: ["run"], approvalTimeoutSeconds: 30 }));

      // Pre-seeded world-readable, the way a stray file (or an earlier hush
      // version) might leave it: writeFileSync only applies `mode` when it
      // creates the file, so this is the case that actually exercises the fix
      // rather than accidentally passing because the file happened to be new.
      const grantsPath = join(p.hushDir, "grants.local.json");
      writeFileSync(grantsPath, "{}", { mode: 0o644 });
      chmodSync(grantsPath, 0o644);
      assert.equal(statSync(grantsPath).mode & 0o777, 0o644, "fixture is not world-readable");

      const child = spawn(process.execPath, [CLI, "run", "--quiet", "--", "echo", "RAN"], {
        cwd: p.root,
        env: p.env,
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = "";
      child.stdout?.on("data", (d) => (stdout += String(d)));
      let stderr = "";
      child.stderr?.on("data", (d) => (stderr += String(d)));

      let seen: ReturnType<typeof pendingRequests> = [];
      for (let i = 0; i < 80 && !seen.length; i++) {
        seen = pendingRequests(p.hushDir);
        if (!seen.length) await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(seen.length, 1, `no pending approval request appeared:\n${stdout}${stderr}`);
      answerRequest(p.hushDir, seen[0].id, "session");

      const [code] = await once(child, "exit");
      assert.equal(code, 0, stdout + stderr);

      assert.ok(existsSync(grantsPath), "no grants file was written for the session approval");
      assert.equal(statSync(grantsPath).mode & 0o777, 0o600);
    } finally {
      p.cleanup();
    }
  });
});

// ===========================================================================
// The new command surface: add / use / run+pass-through / dev / ls / rm.
// See specs/cli.md — each test below corresponds to a bullet in its
// "Tests" section.
// ===========================================================================

describe("hush add <file>", () => {
  test("--as --library creates the set in the library; --project puts it in the project", () => {
    const p = project();
    try {
      assert.equal(p.run(["global", "--create"]).code, 0);
      writeFileSync(join(p.root, ".env.x"), "FAL_KEY=libval\n");

      const lib = p.run(["add", ".env.x", "--as", "Work fal", "--library"]);
      assert.equal(lib.code, 0, lib.out);
      const library = Vault.open(join(p.home, "vaults", "global", "vault.json"));
      const libSet = library.sets().find((s) => s.name === "work-fal");
      assert.ok(libSet, `no "work-fal" in the library: ${library.sets().map((s) => s.name).join(", ")}`);
      assert.equal(libSet!.label, "Work fal");
      assert.deepEqual(libSet!.keys, ["FAL_KEY"]);
      const project_ = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.equal(project_.hasSet("work-fal"), false, "--library also wrote the project vault");

      const proj = p.run(["add", ".env.x", "--as", "Work fal", "--project"]);
      assert.equal(proj.code, 0, proj.out);
      const project2 = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.ok(project2.hasSet("work-fal"), "--project did not create the set in the project vault");
    } finally {
      p.cleanup();
    }
  });

  test("non-TTY with no --as exits 1 and stores nothing", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.y"), "SOME_KEY=v\n");
      const r = p.run(["add", ".env.y"]);
      assert.equal(r.code, 1, `expected failure, got:\n${r.out}`);
      assert.match(r.out, /--as/);

      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.deepEqual(vault.sets().map((s) => s.name), ["default"], "a set was created despite the failure");
    } finally {
      p.cleanup();
    }
  });
});

describe("hush add KEY=value", () => {
  test("--to <set> adds to it; with no --to, non-TTY lands in project default and prints the tip", () => {
    const p = project();
    try {
      const named = p.run(["add", "FAL_KEY=v", "--to", "work-fal"]);
      assert.equal(named.code, 0, named.out);
      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.ok(vault.hasSet("work-fal") && vault.has("work-fal", "FAL_KEY"), "FAL_KEY did not land in work-fal");

      const bare = p.run(["add", "K=v"]);
      assert.equal(bare.code, 0, bare.out);
      assert.match(bare.out, /--to <set>/, `no --to tip in:\n${bare.out}`);
      const vault2 = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.ok(vault2.has("default", "K"), "K did not land in default");
    } finally {
      p.cleanup();
    }
  });
});

describe("hush add <service>", () => {
  test('--as "Personal fal" stores FAL_KEY in personal-fal from one piped line', () => {
    const p = project();
    try {
      const r = p.run(["add", "fal", "--as", "Personal fal"], "one_line_fal_value\n");
      assert.equal(r.code, 0, r.out);
      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      const set = vault.sets().find((s) => s.name === "personal-fal");
      assert.ok(set, `no "personal-fal" among: ${vault.sets().map((s) => s.name).join(", ")}`);
      assert.deepEqual(set!.keys, ["FAL_KEY"]);
    } finally {
      p.cleanup();
    }
  });

  test("--account x is a deprecated alias that produces fal/x and prints a notice", () => {
    const p = project();
    try {
      const r = p.run(["add", "fal", "--account", "x"], "aliased_value\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /--account is deprecated/);
      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.ok(vault.hasSet("fal/x"), `--account did not create "fal/x": ${vault.sets().map((s) => s.name).join(", ")}`);
    } finally {
      p.cleanup();
    }
  });
});

describe("hush use", () => {
  test("using two sets writes envs.json in order; unknown name lists what exists; the list shows sources; --not removes", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=v", "--to", "work-fal"]).code, 0);
      assert.equal(p.run(["add", "DB_URL=v", "--to", "db-prod"]).code, 0);

      const unknown = p.run(["use", "not-a-real-set"]);
      assert.equal(unknown.code, 1, unknown.out);
      assert.match(unknown.out, /No set called "not-a-real-set"/);
      assert.match(unknown.out, /work-fal/, "the message does not say what sets exist");

      const used = p.run(["use", "work-fal", "db-prod"]);
      assert.equal(used.code, 0, used.out);
      const links = JSON.parse(readFileSync(join(p.hushDir, "envs.json"), "utf8")) as { use: string[] };
      assert.deepEqual(links.use, ["work-fal", "db-prod"]);

      const listed = p.run(["use"]).out;
      assert.match(listed, /work-fal\s+project/);
      assert.match(listed, /db-prod\s+project/);
      assert.match(listed, /default\s+project/);

      const removed = p.run(["use", "--not", "db-prod"]);
      assert.equal(removed.code, 0, removed.out);
      const after = JSON.parse(readFileSync(join(p.hushDir, "envs.json"), "utf8")) as { use: string[] };
      assert.deepEqual(after.use, ["work-fal"]);
    } finally {
      p.cleanup();
    }
  });
});

describe("pass-through", () => {
  test("an unrecognised command on PATH runs through hush run, injected and redacted", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=passthroughvalue"]).code, 0);
      const r = p.run(["sh", "-c", "echo $FAL_KEY"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /\[redacted:FAL_KEY\]/, r.out);
      assert.ok(!r.out.includes("passthroughvalue"), "a live value leaked");
    } finally {
      p.cleanup();
    }
  });

  test("`hush ls` is never /bin/ls: a known command always wins over pass-through", () => {
    const p = project();
    try {
      const r = p.run(["ls"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /YOUR LIBRARY/);
      assert.match(r.out, /THIS PROJECT/);
      assert.ok(!/\.hush\b/.test(r.out), "looked like a directory listing, not hush's ls");
    } finally {
      p.cleanup();
    }
  });

  test("an unknown, non-existent command exits 1 with Unknown command", () => {
    const p = project();
    try {
      const r = p.run(["definitely-not-a-real-command-xyz"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /Unknown command/);
    } finally {
      p.cleanup();
    }
  });
});

describe("hush dev", () => {
  // node, npm, pnpm and yarn all live under the same directory as the running
  // node binary on a typical nvm install; bun does not. Restricting PATH to
  // that directory plus the base system bins (for `sh`, which npm's own
  // script runner shells out to) gives every test a real npm and a
  // guaranteed-absent bun, deterministically, rather than depending on what
  // happens to be installed on whichever machine runs the suite.
  const NODE_BIN_DIR = `${dirname(process.execPath)}:/usr/bin:/bin`;

  test("no lockfile runs the script via npm, injected and redacted", () => {
    const p = project({ PATH: NODE_BIN_DIR });
    try {
      assert.equal(p.run(["add", "FAL_KEY=devkeyvalue"]).code, 0);
      writeFileSync(
        join(p.root, "package.json"),
        JSON.stringify({ scripts: { dev: "sh -c 'echo DEV $FAL_KEY'" } }),
      );
      const r = p.run(["dev"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /DEV/);
      assert.match(r.out, /\[redacted:FAL_KEY\]/, r.out);
    } finally {
      p.cleanup();
    }
  });

  test("no lockfile picks npm specifically, not just whichever package manager is on PATH", () => {
    // A fake npm ahead of the real one on PATH proves *which* program was
    // picked — pnpm and yarn can both run a plain npm script perfectly well
    // with no lockfile of their own, so a test that only checks the script
    // ran would pass identically whichever one hush chose.
    const fakeBin = mkdtempSync(join(tmpdir(), "hush-fake-npm-"));
    writeFileSync(join(fakeBin, "npm"), '#!/bin/sh\necho FAKE_NPM_INVOKED "$@"\n', { mode: 0o755 });
    const p = project({ PATH: `${fakeBin}:${NODE_BIN_DIR}` });
    try {
      writeFileSync(join(p.root, "package.json"), JSON.stringify({ scripts: { dev: "true" } }));
      const r = p.run(["dev"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /FAKE_NPM_INVOKED run dev/, `npm was not the program invoked:\n${r.out}`);
    } finally {
      rmSync(fakeBin, { recursive: true, force: true });
      p.cleanup();
    }
  });

  test("a bun.lock with no bun on PATH names bun in the error", () => {
    const p = project({ PATH: NODE_BIN_DIR });
    try {
      writeFileSync(join(p.root, "package.json"), JSON.stringify({ scripts: { dev: "true" } }));
      writeFileSync(join(p.root, "bun.lock"), "");
      const r = p.run(["dev"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /bun/);
    } finally {
      p.cleanup();
    }
  });

  test("no package.json suggests hush run --", () => {
    const p = project({ PATH: NODE_BIN_DIR });
    try {
      const r = p.run(["dev"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /hush run --/);
    } finally {
      p.cleanup();
    }
  });
});

describe("hush ls", () => {
  test("shows both sections with the ● marker for what this project uses", () => {
    const p = project();
    try {
      assert.equal(p.run(["global", "--create"]).code, 0);
      assert.equal(p.run(["add", "FAL_KEY=v", "--to", "work-fal", "--project"]).code, 0);
      assert.equal(p.run(["use", "work-fal"]).code, 0);

      const out = p.run(["ls"]).out;
      assert.match(out, /YOUR LIBRARY/);
      assert.match(out, /THIS PROJECT/);
      assert.match(out, /●[^\n]*work-fal/, `expected work-fal marked used:\n${out}`);
    } finally {
      p.cleanup();
    }
  });

  test("hush ls <set> lists key names and never values", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=a_live_value", "--to", "work-fal"]).code, 0);
      const out = p.run(["ls", "work-fal"]).out;
      assert.match(out, /FAL_KEY/);
      assert.ok(!out.includes("a_live_value"), "a value leaked from `hush ls <set>`");
    } finally {
      p.cleanup();
    }
  });
});

describe("hush rm", () => {
  test("rm KEY --from <set> removes the key; rm <set> --yes removes the whole set", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=v", "--to", "work-fal"]).code, 0);
      const removedKey = p.run(["rm", "FAL_KEY", "--from", "work-fal"]);
      assert.equal(removedKey.code, 0, removedKey.out);
      let vault = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.equal(vault.has("work-fal", "FAL_KEY"), false);
      assert.ok(vault.hasSet("work-fal"), "removing the key also removed the set");

      assert.equal(p.run(["add", "OTHER_KEY=v", "--to", "work-fal"]).code, 0);
      const removedSet = p.run(["rm", "work-fal", "--yes"]);
      assert.equal(removedSet.code, 0, removedSet.out);
      vault = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.equal(vault.hasSet("work-fal"), false, "the set survived `rm <set> --yes`");
    } finally {
      p.cleanup();
    }
  });

  test("a name that is both a key and a set refuses and asks for --from", () => {
    const p = project();
    try {
      // "shared" is both a set name and, once this runs, a key inside "other"
      // — a key name cannot contain a "-", which is why this is not "work-fal".
      assert.equal(p.run(["add", "FAL_KEY=v", "--to", "shared"]).code, 0);
      assert.equal(p.run(["add", "shared=v", "--to", "other"]).code, 0);

      const r = p.run(["rm", "shared"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /both a key and a set/);
      assert.match(r.out, /--from/);
    } finally {
      p.cleanup();
    }
  });
});

describe("deprecated aliases keep working, each with a one-line notice", () => {
  test("`hush set` behaves like `hush add KEY=value`", () => {
    const p = project();
    try {
      const r = p.run(["set", "PLAIN_KEY=v"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /`hush set` is deprecated/);
      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.ok(vault.has("default", "PLAIN_KEY"));
    } finally {
      p.cleanup();
    }
  });

  test("`hush accounts` behaves like `hush ls`", () => {
    const p = project();
    try {
      const r = p.run(["accounts"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /`hush accounts` is deprecated/);
      assert.match(r.out, /THIS PROJECT/);
    } finally {
      p.cleanup();
    }
  });

  test("`hush envs` and `hush env` behave like `hush ls`", () => {
    const p = project();
    try {
      for (const args of [["envs"], ["env"]]) {
        const r = p.run(args);
        assert.equal(r.code, 0, r.out);
        assert.match(r.out, /is deprecated/);
        assert.match(r.out, /THIS PROJECT/);
      }
    } finally {
      p.cleanup();
    }
  });

  test("`hush env use` and `hush env drop` behave like `hush use` / `hush use --not`", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=v", "--to", "work-fal"]).code, 0);
      const used = p.run(["env", "use", "work-fal"]);
      assert.equal(used.code, 0, used.out);
      assert.match(used.out, /`hush env use` is deprecated/);
      assert.deepEqual((JSON.parse(readFileSync(join(p.hushDir, "envs.json"), "utf8")) as { use: string[] }).use, ["work-fal"]);

      const dropped = p.run(["env", "drop", "work-fal"]);
      assert.equal(dropped.code, 0, dropped.out);
      assert.match(dropped.out, /`hush env drop` is deprecated/);
      assert.deepEqual((JSON.parse(readFileSync(join(p.hushDir, "envs.json"), "utf8")) as { use: string[] }).use, []);
    } finally {
      p.cleanup();
    }
  });

  test("`--with a:b` aliases to `--use a/b`", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=v", "--to", "fal/acme"]).code, 0);
      const r = p.run(["export", "--names", "--with", "fal:acme"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /--with fal:acme is deprecated/);
      assert.match(r.out, /FAL_KEY/);
    } finally {
      p.cleanup();
    }
  });
});

// The library is reachable from every add/rm form, not only `add <file>`:
// "save things into the global environment" has to work for one value, for a
// service, and in reverse.
describe("the library from add KEY=value, add <service> and rm", () => {
  const withLibrary = (p: ReturnType<typeof project>) => {
    assert.equal(p.run(["global", "--create"]).code, 0);
    writeFileSync(join(p.root, ".env.x"), "FAL_KEY=libval\n");
    const r = p.run(["add", ".env.x", "--as", "Work fal", "--library"]);
    assert.equal(r.code, 0, r.out);
  };
  const libraryVault = (p: ReturnType<typeof project>) => Vault.open(join(p.home, "vaults", "global", "vault.json"));
  const projectVault = (p: ReturnType<typeof project>) => Vault.open(join(p.root, ".hush", "vault.json"));

  // Bites: a --to taken literally dies on the space in "Work fal"; a --to that
  // only ever targets the project writes a same-named copy there instead.
  test("add KEY=value --to reaches a library set by its label or its slug, with no flag", () => {
    const p = project();
    try {
      withLibrary(p);
      const byLabel = p.run(["add", "EXTRA_KEY=v1", "--to", "Work fal"]);
      assert.equal(byLabel.code, 0, byLabel.out);
      assert.ok(libraryVault(p).has("work-fal", "EXTRA_KEY"), "the key did not land in the library set");
      assert.equal(projectVault(p).hasSet("work-fal"), false, "a copy of the set appeared in the project");

      const bySlug = p.run(["add", "OTHER_KEY=v2", "--to", "work-fal"]);
      assert.equal(bySlug.code, 0, bySlug.out);
      assert.ok(libraryVault(p).has("work-fal", "OTHER_KEY"));
    } finally {
      p.cleanup();
    }
  });

  test("add KEY=value --to <new name> --library creates it there; a new name alone lands in the project", () => {
    const p = project();
    try {
      withLibrary(p);
      const lib = p.run(["add", "K=v", "--to", "Brand new", "--library"]);
      assert.equal(lib.code, 0, lib.out);
      assert.ok(libraryVault(p).has("brand-new", "K"), "--library did not create the set in the library");
      const proj = p.run(["add", "K=v", "--to", "Also new"]);
      assert.equal(proj.code, 0, proj.out);
      assert.ok(projectVault(p).has("also-new", "K"), "a new name did not default to the project");
      assert.equal(libraryVault(p).hasSet("also-new"), false);
    } finally {
      p.cleanup();
    }
  });

  // Bites: a service form that only knows the project vault stores the
  // prompted value there and never touches the library.
  test("add <service> --library stores the prompted values in the library", () => {
    const p = project();
    try {
      withLibrary(p);
      const r = p.run(["add", "fal", "--as", "Personal fal", "--library"], "piped-fal-value\n");
      assert.equal(r.code, 0, r.out);
      assert.ok(libraryVault(p).has("personal-fal", "FAL_KEY"), "FAL_KEY is not in the library set");
      assert.equal(projectVault(p).hasSet("personal-fal"), false, "the set was created in the project instead");
      assert.ok(!r.out.includes("piped-fal-value"), "the value was echoed");
    } finally {
      p.cleanup();
    }
  });

  test("rm KEY --from a library set trims it; rm <set> --yes removes a library set", () => {
    const p = project();
    try {
      withLibrary(p);
      assert.equal(p.run(["add", "EXTRA_KEY=v1", "--to", "work-fal"]).code, 0);
      const key = p.run(["rm", "EXTRA_KEY", "--from", "work-fal"]);
      assert.equal(key.code, 0, key.out);
      assert.equal(libraryVault(p).has("work-fal", "EXTRA_KEY"), false, "the key is still in the library set");
      assert.ok(libraryVault(p).hasSet("work-fal"), "trimming a key removed the whole set");

      const set = p.run(["rm", "work-fal", "--yes"]);
      assert.equal(set.code, 0, set.out);
      assert.equal(libraryVault(p).hasSet("work-fal"), false, "the library set is still there");
    } finally {
      p.cleanup();
    }
  });
});

describe("pass-through by path", () => {
  // Bites: an onPath() that only walks PATH never finds "./dev.sh", so the
  // most natural thing to type after `hush` is "Unknown command".
  test("hush ./script.sh runs a script by relative path, injected and redacted", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=pathvalue"]).code, 0);
      writeFileSync(join(p.root, "dev.sh"), "#!/bin/sh\necho $FAL_KEY\n", { mode: 0o755 });
      const r = p.run(["./dev.sh"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /\[redacted:FAL_KEY\]/, r.out);
      assert.ok(!r.out.includes("pathvalue"), "a live value leaked");
    } finally {
      p.cleanup();
    }
  });
});
