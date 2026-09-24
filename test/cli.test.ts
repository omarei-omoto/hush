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
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, mkdirSync, existsSync, rmSync, statSync, chmodSync, symlinkSync } from "node:fs";
import { tmpdir, platform } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";

import { Vault } from "../src/vault.ts";
import { generateIdentity, encodeSecret, encodePub } from "../src/crypto.ts";
import { biometryStatus } from "../src/biometry.ts";
import { biometryReadiness } from "../src/secure.ts";
import { ageAvailable } from "../src/age.ts";
import { requestApproval, clearApprovalCache } from "../src/approval.ts";
import { runScope } from "../src/policy.ts";
import { DEFAULT_POLICY } from "../src/mcp.ts";
import { execFileSync } from "node:child_process";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.ts");
/** The stand-in desktop dialog, for the approval paths these tests drive in-process. */
const ZENITY = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "zenity");
/** The same "human clicks Allow 15 min" the CLI subprocess tests cannot fake. */
const clickingAllow = {
  authenticate: async () => "unavailable" as const,
  platform: () => "linux",
  resolveDialogProgram: (cmd: "osascript" | "zenity" | "kdialog") => (cmd === "zenity" ? ZENITY : null),
};

/**
 * @param envOverride  Merged over the base env, for the few tests that need to
 * change something about how the CLI is invoked.
 */
function project(envOverride: NodeJS.ProcessEnv = {}) {
  const home = mkdtempSync(join(tmpdir(), "hush-cli-home-"));
  const root = mkdtempSync(join(tmpdir(), "hush-cli-proj-"));
  mkdirSync(join(root, ".hush"), { recursive: true });
  const id = generateIdentity();
  const vault = Vault.create(join(root, ".hush", "vault.json"), "clitest", { name: "tester", pub: id.pub });
  vault.set(id, "default", "STRIPE_SECRET_KEY", "sk_live_cli");
  vault.save();
  // Typed as the full environment, not the literal object, so a test can point
  // HOME at a scratch directory before running (`run` closes over this object).
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HUSH_HOME: home,
    HUSH_IDENTITY: encodeSecret(id),
    HUSH_BIOMETRY: "off",
    // No desktop: on macOS an enforced approval would otherwise open a real
    // osascript dialog on the developer's screen and hang the run. This is the
    // narrowing switch — it can only make an approval fail, never succeed.
    HUSH_NO_DIALOG: "1",
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
  test("it lists every set once, marking the ones this project uses", () => {
    // doctor used to print environments and service accounts as two lists —
    // the same two-vocabulary confusion `hush ls` had. A set is a set.
    const p = project();
    assert.equal(p.run(["add", "PROD_KEY=v", "--to", "prod"]).code, 0);
    assert.equal(p.run(["add", "fal", "--as", "Personal fal", "--no-use"], "v\n").code, 0);

    const out = p.run(["doctor"]).out;
    const line = out.match(/sets\s+(.*)/)?.[1] ?? "";
    assert.match(line, /default ●/, `default is the floor, so it is used: "${line}"`);
    assert.match(line, /prod ●/, `a set made from inside the project is used: "${line}"`);
    assert.match(line, /personal-fal(?! ●)/, `a --no-use set must not be marked: "${line}"`);
    assert.ok(!/environments|service accounts/.test(out), "the old two-list vocabulary is back");
    p.cleanup();
  });

  test("it reports the policy actually in force", () => {
    const p = project();
    assert.match(p.run(["doctor"]).out, /approval required\s+run, add, reveal, request/);
    writeFileSync(join(p.root, ".hush", "policy.json"), JSON.stringify({ requireApproval: [] }));
    assert.match(p.run(["doctor"]).out, /nothing is gated/);
    p.cleanup();
  });

  test("it reports whether a user-level policy floor exists", () => {
    const p = project();
    try {
      assert.match(p.run(["doctor"]).out, /policy floor\s+.*none/);
      writeFileSync(join(p.home, "policy.json"), JSON.stringify({ requireApproval: ["run"] }));
      const out = p.run(["doctor"]).out;
      assert.match(out, /policy floor/);
      assert.ok(!/policy floor\s+.*none/.test(out), "a floor file was present but doctor still reported none");
    } finally {
      p.cleanup();
    }
  });

  test("it flags a repo attempt to weaken the user's floor", () => {
    const p = project();
    try {
      // A floor that never mentions unsafeAllowCommands defaults to allowing
      // none of it — the repo's request below is exactly what the fix (only
      // the user's own file can lower the floor) refuses.
      writeFileSync(join(p.home, "policy.json"), JSON.stringify({ requireApproval: ["run"] }));
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ unsafeAllowCommands: ["node"] }));
      const out = p.run(["doctor"]).out;
      assert.match(out, /unsafeAllowCommands: node — ignored, below your floor/);
    } finally {
      p.cleanup();
    }
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

describe("hush start", () => {
  /** A folder with a .env and nothing else, which is where most people are. */
  function folderWithEnv(body = "STRIPE_SECRET_KEY=sk_live_from_env\nAPI_URL=https://api.example.com\n") {
    const p = project({ HUSH_INTERACTIVE: "1" });
    writeFileSync(join(p.root, ".env"), body);
    return p;
  }

  test("off a terminal it says so, rather than reading answers nobody gave", () => {
    const p = project();
    try {
      const r = p.run(["start"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /needs a terminal/);
      assert.match(r.out, /hush import <file> --as <name>/, "it does not name the non-interactive path");
    } finally {
      p.cleanup();
    }
  });

  test("the .env path: finds the file, stores it, says what to do with the file", () => {
    const p = folderWithEnv();
    try {
      // Answers: where are your keys (1), what to call them, will an agent use
      // them (n). No dev script here, so nothing is offered to run.
      const r = p.run(["start"], "1\nProd\nn\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /I can see \.env in this folder/);
      assert.match(r.out, /stored 2 key\(s\) as Prod/);
      assert.match(r.out, /not in \.gitignore/, "it did not warn about the plaintext file");
      assert.doesNotMatch(r.out, /sk_live_from_env/, "a value was printed");
      // The ending is three commands, not the command list.
      assert.match(r.out, /three commands you'll actually use/);
      assert.match(r.out, /hush ls/);

      // The keys really are in the vault, and the set is used here.
      assert.match(p.run(["get", "STRIPE_SECRET_KEY", "--yes"]).out, /sk_live_from_env/);
      assert.match(p.run(["ls"]).out, /● /);
    } finally {
      p.cleanup();
    }
  });

  test("it says when the file is already ignored, and never deletes it", () => {
    const p = folderWithEnv();
    try {
      writeFileSync(join(p.root, ".gitignore"), ".env\n");
      const r = p.run(["start"], "1\nProd\nn\n");
      assert.match(r.out, /already gitignored/);
      assert.match(r.out, /You can delete it now/);
      assert.equal(existsSync(join(p.root, ".env")), true, "hush deleted the file for them");
    } finally {
      p.cleanup();
    }
  });

  test("the agent question is asked here too, and answering yes gates things", () => {
    const p = folderWithEnv();
    try {
      const r = p.run(["start"], "1\nProd\ny\n");
      assert.match(r.out, /Will an AI agent use secrets here/);
      const policy = JSON.parse(readFileSync(join(p.root, ".hush", "policy.json"), "utf8"));
      assert.ok(policy.requireApproval.includes("run"), "answering yes did not turn approvals on");
    } finally {
      p.cleanup();
    }
  });

  test("'in another tool' prints one command and stores nothing", () => {
    const p = project({ HUSH_INTERACTIVE: "1" });
    try {
      const r = p.run(["start"], "2\ndoppler\nProd\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /doppler secrets download --format json --no-file \| hush import - --as "Prod"/);
      assert.match(r.out, /Then run `hush start` again/);
      assert.equal(existsSync(join(p.root, ".hush", "envs.json")), false, "it set something up anyway");
    } finally {
      p.cleanup();
    }
  });

  test("'add one now' takes the value hidden, and stores it", () => {
    const p = project({ HUSH_INTERACTIVE: "1" });
    try {
      // The secret is piped last because the hidden prompt reads the rest of
      // stdin as one value (a multi-line key has to survive that).
      const r = p.run(["start"], "3\nProd\nstripe\nsk_test_1234567890\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /stored STRIPE_SECRET_KEY as Prod/);
      assert.doesNotMatch(r.out, /sk_test_1234567890/, "the value was echoed");
      assert.match(p.run(["get", "STRIPE_SECRET_KEY", "--yes"]).out, /sk_test_1234567890/);
    } finally {
      p.cleanup();
    }
  });

  test("with a package.json it offers to run the dev script, and does not run it unasked", () => {
    const p = folderWithEnv();
    try {
      writeFileSync(join(p.root, "package.json"), JSON.stringify({ scripts: { dev: "echo DEV-RAN" } }));
      // Answering nothing to the run question means no: a piped run must never
      // start a dev server by accident.
      const r = p.run(["start"], "1\nProd\nn\n");
      assert.match(r.out, /Want to run it now\?/);
      assert.match(r.out, /hush dev/, "the ending did not name hush dev");
      assert.doesNotMatch(r.out, /DEV-RAN/, "it ran the dev script without being asked");

      const yes = p.run(["start"], "1\nProd\nn\ny\n");
      assert.match(yes.out, /DEV-RAN/, "answering yes did not run it");
    } finally {
      p.cleanup();
    }
  });

  test("a folder with no .env asks for the file name and refuses to guess", () => {
    const p = project({ HUSH_INTERACTIVE: "1" });
    try {
      const r = p.run(["start"], "1\nProd\nnope.env\n");
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /I can't find nope\.env/);
      assert.match(r.out, /pick another answer/);
    } finally {
      p.cleanup();
    }
  });

  test("the pointer appears in a folder nobody has set up, and not after", () => {
    const fresh = project({ HUSH_INTERACTIVE: "1" });
    try {
      writeFileSync(join(fresh.root, ".env"), "A_KEY=value\n");
      rmSync(join(fresh.root, ".hush"), { recursive: true, force: true });
      const before = fresh.run([]);
      assert.match(before.out, /New here\? Run hush start/);

      const ran = fresh.run(["start"], "1\nProd\nn\n");
      assert.equal(ran.code, 0, ran.out);
      assert.ok(existsSync(join(fresh.root, ".hush", "envs.json")), "start did not set the folder up");

      // Now that the folder is set up, the eight-command screen is the screen.
      const after = fresh.run([]);
      assert.doesNotMatch(after.out, /New here\?/);
    } finally {
      fresh.cleanup();
    }
  });

  test("the not-set-up error points at the guided run first", () => {
    const p = project();
    try {
      rmSync(join(p.root, ".hush"), { recursive: true, force: true });
      const r = p.run(["run", "--", "echo", "hi"]);
      assert.match(r.out, /isn't set up for hush yet/);
      assert.match(r.out, /hush start/, "the error does not mention the guided run");
    } finally {
      p.cleanup();
    }
  });
});

describe("hush get --copy", () => {
  /**
   * The platform's first clipboard candidate, symlinked to the stub. Doing it
   * per-platform keeps the test honest on macOS and on CI's ubuntu alike.
   */
  function clipboardEnv(): { env: NodeJS.ProcessEnv; read: () => string; dir: string } {
    const dir = mkdtempSync(join(tmpdir(), "hush-clip-"));
    const name = platform() === "darwin" ? "pbcopy" : "wl-copy";
    symlinkSync(join(dirname(fileURLToPath(import.meta.url)), "fixtures", "clipboard-stub"), join(dir, name));
    const out = join(dir, "copied.txt");
    return {
      dir,
      env: { PATH: `${dir}:${process.env.PATH ?? ""}`, HUSH_TEST_CLIPBOARD: out },
      read: () => (existsSync(out) ? readFileSync(out, "utf8") : ""),
    };
  }

  test("the value goes to the clipboard and never to stdout", () => {
    const clip = clipboardEnv();
    const p = project({ ...clip.env });
    try {
      const r = p.run(["get", "STRIPE_SECRET_KEY", "--copy", "--yes"]);
      assert.equal(r.code, 0, r.out);
      assert.equal(clip.read(), "sk_live_cli", "the clipboard did not receive the value");
      assert.doesNotMatch(r.out, /sk_live_cli/, "the value was printed as well as copied");
      assert.match(r.out, /copied STRIPE_SECRET_KEY to the clipboard/);
      assert.match(r.out, /11 characters/, "the confirmation should say how much was copied");
    } finally {
      p.cleanup();
      rmSync(clip.dir, { recursive: true, force: true });
    }
  });

  test("a clipboard tool that fails is reported, not silently ignored", () => {
    const clip = clipboardEnv();
    const p = project({ ...clip.env, HUSH_TEST_CLIPBOARD_EXIT: "3" });
    try {
      const r = p.run(["get", "STRIPE_SECRET_KEY", "--copy", "--yes"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /Could not copy/);
      assert.doesNotMatch(r.out, /sk_live_cli/);
    } finally {
      p.cleanup();
      rmSync(clip.dir, { recursive: true, force: true });
    }
  });

  test("with no clipboard tool at all, it says which ones it looked for", () => {
    const empty = mkdtempSync(join(tmpdir(), "hush-nopath-"));
    const p = project({ PATH: empty });
    try {
      const r = p.run(["get", "STRIPE_SECRET_KEY", "--copy", "--yes"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /No clipboard tool found/);
      assert.match(r.out, /pbcopy|wl-copy/, "the error does not name anything to install");
      assert.match(r.out, /drop --copy/, "the error does not offer the alternative");
    } finally {
      p.cleanup();
      rmSync(empty, { recursive: true, force: true });
    }
  });

  test("printing still works, and still warns about the scrollback", () => {
    const p = project();
    try {
      const r = p.run(["get", "STRIPE_SECRET_KEY", "--yes"]);
      assert.match(r.out, /sk_live_cli/);
    } finally {
      p.cleanup();
    }
  });
});

describe("exposure warnings", () => {
  test("a value too short to mask is called out when it is stored", () => {
    const p = project();
    try {
      const r = p.run(["add", "PIN=1234", "--as", "Short", "--project"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /PIN is 4 character\(s\)/);
      assert.match(r.out, /will not mask a value that short/);
    } finally {
      p.cleanup();
    }
  });

  test("a value long enough to mask is not warned about", () => {
    const p = project();
    try {
      const r = p.run(["add", "TOKEN=long-enough-value", "--as", "Fine", "--project"]);
      assert.equal(r.code, 0, r.out);
      assert.doesNotMatch(r.out, /character\(s\)/);
    } finally {
      p.cleanup();
    }
  });

  test("the warning at import time is one line naming every short key", () => {
    const p = project();
    try {
      const file = join(p.root, "short.json");
      writeFileSync(file, JSON.stringify({ PIN: "1234", CODE: "12", TOKEN: "long-enough" }));
      const r = p.run(["import", file, "--as", "Mixed", "--project", "--format", "json"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /2 value\(s\) are shorter than 5 characters/);
      assert.match(r.out, /PIN, CODE/);
      assert.doesNotMatch(r.out, /TOKEN/, "a long enough value was named in the warning");
    } finally {
      p.cleanup();
    }
  });

  test("a secret value in the command line is called out, by key and not by value", () => {
    const p = project();
    try {
      // The value is in argv rather than in the environment, which is what `ps`
      // would show to every other user on the machine.
      const r = p.run(["run", "--", "echo", "sk_live_cli"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /the value of STRIPE_SECRET_KEY appears in the command line/);
      assert.match(r.out, /ps shows/);
      // The warning names the key; the output still masks the value.
      assert.match(r.out, /\[redacted:STRIPE_SECRET_KEY\]/);
    } finally {
      p.cleanup();
    }
  });

  test("an argument that merely mentions a key does not warn", () => {
    const p = project();
    try {
      const r = p.run(["run", "--", "echo", "STRIPE_SECRET_KEY"]);
      assert.equal(r.code, 0, r.out);
      assert.doesNotMatch(r.out, /appears in the command line/);
    } finally {
      p.cleanup();
    }
  });
});

describe("hush import", () => {
  const SECRET = "sk_live_adopted_1234567890";

  function jsonFile(p: ReturnType<typeof project>, name: string, body: unknown): string {
    const path = join(p.root, name);
    writeFileSync(path, JSON.stringify(body));
    return path;
  }

  test("a JSON export becomes a set, and the values are not printed", () => {
    const p = project();
    try {
      const file = jsonFile(p, "doppler.json", { API_KEY: SECRET, PORT: 3000, DEBUG: true });
      const r = p.run(["import", file, "--as", "Prod", "--project", "--format", "json"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /imported 3 secret\(s\) as Prod/);
      assert.doesNotMatch(r.out, new RegExp(SECRET), "the import printed a value");

      // The names are listed, and one value round-trips.
      assert.match(p.run(["ls", "prod"]).out, /API_KEY/);
      const got = p.run(["get", "API_KEY", "--yes", "--use", "prod"]);
      assert.match(got.out, new RegExp(SECRET));
      // Numbers and booleans arrive as the strings an environment holds.
      assert.match(p.run(["get", "PORT", "--yes", "--use", "prod"]).out, /3000/);
    } finally {
      p.cleanup();
    }
  });

  test("reads from stdin, which is how a provider's CLI is piped in", () => {
    const p = project();
    try {
      const r = p.run(["import", "-", "--as", "Piped", "--project", "--format", "json"], JSON.stringify({ PIPED_KEY: "v" }));
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /imported 1 secret\(s\) as Piped/);
      assert.match(p.run(["ls", "piped"]).out, /PIPED_KEY/);
    } finally {
      p.cleanup();
    }
  });

  test("--format 1password reads an op item", () => {
    const p = project();
    try {
      const item = { title: "Stripe", fields: [{ label: "secret key", value: SECRET }] };
      const r = p.run(["import", "-", "--as", "Work", "--project", "--format", "1password"], JSON.stringify(item));
      assert.equal(r.code, 0, r.out);
      assert.match(p.run(["ls", "work"]).out, /SECRET_KEY/);
    } finally {
      p.cleanup();
    }
  });

  test("--dry-run lists what would be stored and writes nothing", () => {
    const p = project();
    try {
      const file = jsonFile(p, "dry.json", { DRY_KEY: SECRET });
      const r = p.run(["import", file, "--as", "Dry", "--dry-run", "--format", "json"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /1 secret\(s\) would be stored/);
      assert.match(r.out, /DRY_KEY/);
      assert.match(r.out, /Nothing was written/);
      assert.doesNotMatch(r.out, new RegExp(SECRET));
      // It really did not write: the key cannot be fetched afterwards.
      assert.equal(p.run(["get", "DRY_KEY", "--yes"]).code, 1, "a dry run stored something");
    } finally {
      p.cleanup();
    }
  });

  test("a name is required, and its absence says so rather than guessing", () => {
    const p = project();
    try {
      const file = jsonFile(p, "unnamed.json", { A: "1" });
      const r = p.run(["import", file, "--format", "json"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /Give the set a name/);
    } finally {
      p.cleanup();
    }
  });

  test("an unknown format is refused, naming the ones that exist", () => {
    const p = project();
    try {
      const file = jsonFile(p, "x.json", { A: "1" });
      const r = p.run(["import", file, "--as", "X", "--format", "vault"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /Unknown --format "vault".*dotenv, json, 1password/s);
    } finally {
      p.cleanup();
    }
  });

  test("notes about skipped and collided fields reach the user", () => {
    const p = project();
    try {
      const file = jsonFile(p, "messy.json", { GOOD: "1", VENDOR: { nested: true } });
      const r = p.run(["import", file, "--as", "Messy", "--project", "--format", "json"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /skipped VENDOR/);
      assert.match(r.out, /imported 1 secret\(s\)/);
    } finally {
      p.cleanup();
    }
  });

  test("with no --as it asks for a name rather than guessing", () => {
    const p = project();
    try {
      const file = join(p.root, "unnamed2.json");
      writeFileSync(file, JSON.stringify({ A: "1" }));
      const r = p.run(["import", file, "--format", "json"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /Give the set a name/);
    } finally {
      p.cleanup();
    }
  });
});

describe("hush run and .env.schema", () => {
  function echoScript(p: ReturnType<typeof project>, body = 'echo "val=$STRIPE_SECRET_KEY"'): string {
    const path = join(p.root, "echo.sh");
    writeFileSync(path, `#!/bin/sh\n${body}\n`);
    chmodSync(path, 0o755);
    return "./echo.sh";
  }

  test("a value of the wrong shape stops the run before anything is spawned", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.schema"), "# @type=string(startsWith=pk-)\nSTRIPE_SECRET_KEY=\n");
      const r = p.run(["run", "--", echoScript(p)]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /STRIPE_SECRET_KEY does not start with "pk-"/);
      assert.match(r.out, /\.env\.schema rejected 1 value/);
      assert.doesNotMatch(r.out, /val=/, "the command ran despite the schema");
    } finally {
      p.cleanup();
    }
  });

  test("a schema that accepts the value does not get in the way", () => {
    const p = project();
    try {
      // The fixture value is sk_live_cli, so the accepted prefix is sk_.
      writeFileSync(join(p.root, ".env.schema"), "# @type=string(startsWith=sk_)\nSTRIPE_SECRET_KEY=\n");
      const r = p.run(["run", "--", echoScript(p)]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /\[redacted:STRIPE_SECRET_KEY\]/);
    } finally {
      p.cleanup();
    }
  });

  test("--no-validate runs anyway, because it is the user's own schema", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.schema"), "# @type=string(startsWith=pk-)\nSTRIPE_SECRET_KEY=\n");
      const r = p.run(["run", "--no-validate", "--", echoScript(p)]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /\[redacted:STRIPE_SECRET_KEY\]/);
    } finally {
      p.cleanup();
    }
  });

  test("a repo-supplied @sensitive=false cannot unmask a value on its own", () => {
    // The masking decision is the user's, not the repository's. Before this,
    // one line in a committed .env.schema took a key out of the redactor, so a
    // repo (or an agent with repo write access) could read a value it was only
    // supposed to be able to use.
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.schema"), "# @sensitive=false\nSTRIPE_SECRET_KEY=\n");
      const r = p.run(["run", "--", echoScript(p)]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /\[redacted:STRIPE_SECRET_KEY\]/, "a repo-supplied @sensitive=false unmasked a value");
      assert.match(r.out, /asks to leave STRIPE_SECRET_KEY unmasked/);
    } finally {
      p.cleanup();
    }
  });

  test("the user's own floor can allow an unmask", () => {
    // The bit still exists for what it was for: NODE_ENV=production showing as
    // [redacted:…] on every line is how people learn to ignore the mask.
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.schema"), "# @sensitive=false\nSTRIPE_SECRET_KEY=\n");
      writeFileSync(join(p.home, "policy.json"), JSON.stringify({ unmaskKeys: ["STRIPE_SECRET_KEY"] }));
      // The project asks for no approvals, so the run itself is not gated; the
      // floor's unmaskKeys is the thing under test, not the approval path.
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: [] }));
      const r = p.run(["run", "--", echoScript(p)]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /val=sk_live_cli/, "the user's own unmaskKeys entry was ignored");
      assert.doesNotMatch(r.out, /redacted/);
    } finally {
      p.cleanup();
    }
  });

  test("a schema violation in a key this run never uses does not block it", () => {
    const p = project();
    try {
      writeFileSync(
        join(p.root, ".env.schema"),
        "# @type=string(startsWith=sk_)\nSTRIPE_SECRET_KEY=\n\n# @type=url @required\nPROD_ONLY=\n",
      );
      const r = p.run(["run", "--", echoScript(p)]);
      assert.equal(r.code, 0, r.out);
    } finally {
      p.cleanup();
    }
  });

  test("doctor reports the schema, and names the values that do not match", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.schema"), "# @type=string(startsWith=pk-)\nSTRIPE_SECRET_KEY=\n");
      const r = p.run(["doctor"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /\.env\.schema\s+1 value\(s\) do not match/);
      assert.match(r.out, /STRIPE_SECRET_KEY does not start with "pk-"/);
      assert.doesNotMatch(r.out, /sk_live_cli/, "doctor printed the value");
    } finally {
      p.cleanup();
    }
  });

  test("a malformed schema is an error with a line number, not a silent no-op", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.schema"), "# @type=url\n# @required\n");
      const r = p.run(["run", "--", echoScript(p)]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /not attached to any variable/);
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

      const first = p.run(["import", ".env.in", "--as", "default"]);
      assert.equal(first.code, 0, first.out);
      assert.match(first.out, /1 secret\(s\)|1 already present/);
      assert.match(p.run(["get", "STRIPE_SECRET_KEY", "--yes"]).out, /sk_live_cli/, "the existing value was replaced");
      assert.match(p.run(["get", "NEW_ONE", "--yes"]).out, /brand_new_value/);

      // --overwrite is the opt-in, and it must actually do it.
      const second = p.run(["import", ".env.in", "--as", "default", "--overwrite"]);
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

  test("the removed `--env` shortcut fails, naming the exact replacement", () => {
    // The name was given a real job, so the old shortcut must not quietly come
    // to mean something else: a script that means one thing and gets another is
    // worse than one that stops and says what to type instead.
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.in"), "PROD_ONE=v1\n");
      const r = p.run(["import", ".env.in", "--env", "prod"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /--env <set>` was removed/);
      assert.match(r.out, /hush add \.env\.in --to prod/, "the error does not name the replacement");

      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.ok(!vault.sets().some((s) => s.name === "prod"), "the removed form stored something anyway");
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
      // --no-use: a set made from inside a project is used by it, and this
      // one must stay unused so --use below is what brings it in.
      assert.equal(p.run(["add", "FAL_KEY=personal_value", "PERSONAL_MARKER=mine", "--to", "personal-fal", "--no-use"]).code, 0);
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

describe("the CLI enforces .hush/policy.json — an agent's shell must not bypass what the MCP server enforces", () => {
  // The project fixture runs with HUSH_NO_DIALOG=1, so an enforced approval has
  // nothing to show and is refused outright. That is the point of most of these
  // tests — the gate holds with no human present — and it is also why none of
  // them can pop a real macOS dialog on the developer's screen.

  test("reveal denied by biometry: `hush get --yes` still refuses", () => {
    const p = project();
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

  // Red team, 2026-09-12: grants.local.json lives inside .hush/, which an
  // agent has ordinary write access to — it is not the user-level floor. It
  // used to be trusted unconditionally as proof a human already approved,
  // for every action including "reveal" and "add". An agent could write its
  // own future-dated entry for the exact scope string it was about to need
  // (every shape is documented in policy.ts and this file's own comments)
  // and skip approval entirely, including a policy that requires biometry.
  // "run" keeps using this cache deliberately (see the tests above) — the
  // fix is that "reveal" (hands back plaintext) and "add" (writes a secret
  // the agent itself supplied, unreviewed) never consult it.
  test("a forged reveal grant on disk is never honoured, even with biometry required", () => {
    const p = project();
    try {
      writeFileSync(
        join(p.hushDir, "policy.json"),
        JSON.stringify({ requireApproval: ["reveal"], biometry: "required", approvalTimeoutSeconds: 1 }),
      );
      // Exactly the scope string cmdGet computes for this key and env.
      writeFileSync(
        join(p.hushDir, "grants.local.json"),
        JSON.stringify({ "reveal:default/STRIPE_SECRET_KEY": Date.now() + 3_600_000 }),
      );
      const r = p.run(["get", "STRIPE_SECRET_KEY", "--yes"]);
      assert.equal(r.code, 1, r.out);
      assert.ok(!r.out.includes("sk_live_cli"), `a forged grants.local.json leaked a credential:\n${r.out}`);
    } finally {
      p.cleanup();
    }
  });

  // Bites: with run grants read from disk regardless of biometry, the forged
  // entry below lets the command run with no fingerprint and no prompt.
  test("with biometry required, a forged run grant on disk is never honoured either", () => {
    const p = project();
    try {
      writeFileSync(
        join(p.hushDir, "policy.json"),
        JSON.stringify({ requireApproval: ["run"], biometry: "required", approvalTimeoutSeconds: 1 }),
      );
      // Exactly the scope runScope() computes for this command and this project's sets.
      writeFileSync(
        join(p.hushDir, "grants.local.json"),
        JSON.stringify({ "run:npm:default": Date.now() + 3_600_000 }),
      );
      const r = p.run(["run", "--", "npm", "--version"]);
      assert.equal(r.code, 1, `a forged grant stood in for a fingerprint:\n${r.out}`);
    } finally {
      p.cleanup();
    }
  });

  test("a forged add grant on disk is never honoured — an agent cannot pre-approve planting its own secret", () => {
    const p = project();
    try {
      writeFileSync(
        join(p.hushDir, "policy.json"),
        JSON.stringify({ requireApproval: ["add"], biometry: "required", approvalTimeoutSeconds: 1 }),
      );
      // Exactly the scope string cmdAddKeyValue computes for this key and set.
      writeFileSync(
        join(p.hushDir, "grants.local.json"),
        JSON.stringify({ "add:default/PLANTED_KEY": Date.now() + 3_600_000 }),
      );
      const r = p.run(["add", "PLANTED_KEY=malicious-value", "--to", "default"]);
      assert.equal(r.code, 1, r.out);

      const meta = JSON.parse(p.run(["ls", "default", "--json"]).out) as { keys: string[] };
      assert.ok(!meta.keys.includes("PLANTED_KEY"), "a forged grants.local.json let an unapproved secret get planted");
    } finally {
      p.cleanup();
    }
  });

  test("export is gated as reveal; --names is not, because it reveals nothing", () => {
    const p = project();
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

  // The deny list is for the agent's MCP tools (see mcp.test.ts). In a
  // terminal it turns into a warning on the approval prompt, the way
  // `op run` asks rather than refuses: an agent shelling out to `hush run`
  // still has to get past a dialog it cannot click.
  test("an interpreter goes to the approval prompt, not a flat refusal", () => {
    const p = project();
    try {
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: ["run"], approvalTimeoutSeconds: 1 }));
      const gated = p.run(["run", "--", "sh", "-c", "echo RAN"]);
      assert.equal(gated.code, 1, gated.out);
      assert.match(gated.out, /Approval denied/, "not routed through the approval gate");
      assert.doesNotMatch(gated.out, /denied by default/);
      assert.ok(!gated.out.includes("RAN"), "ran without an approval");

      // No approval asked for: the person opted out, and their command runs.
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: [] }));
      const open = p.run(["run", "--quiet", "--", "sh", "-c", "echo RAN"]);
      assert.equal(open.code, 0, open.out);
      assert.match(open.out, /RAN/);
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
    const p = project();
    try {
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: ["run"], approvalTimeoutSeconds: 1 }));
      const r = p.run(["run", "--", "echo", "RAN"]);
      assert.equal(r.code, 1, r.out);
      assert.ok(!r.out.includes("RAN"), `the command ran despite a timed-out approval:\n${r.out}`);
    } finally {
      p.cleanup();
    }
  });

  test("a grant written by an earlier process is not honoured", () => {
    // "Allow 15 min" used to be mirrored into .hush/grants.local.json so the
    // next `hush` process could reuse it. That file sits in the project, which
    // an agent can write, so it was a way to approve yourself. Nothing reads
    // it now — the key below is spelled exactly as the real one would be, and
    // it changes nothing.
    const p = project();
    try {
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: ["run"], approvalTimeoutSeconds: 1 }));
      const grantsPath = join(p.hushDir, "grants.local.json");

      // Exactly what runScope() computes for a plain, default-env `echo` run
      // under the default approvalScope: "command" — the same key mcp.ts's
      // hush_run builds. Computed rather than typed, so the test cannot drift
      // from the implementation.
      const echoScope = runScope(DEFAULT_POLICY, "echo", ["default"]);
      writeFileSync(grantsPath, JSON.stringify({ [echoScope]: Date.now() + 60_000 }));
      const live = p.run(["run", "--", "echo", "RAN"]);
      assert.equal(live.code, 1, live.out);
      assert.ok(!live.out.includes("RAN"), `a project file pre-authorised a run:\n${live.out}`);
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

  test("a user-level policy floor alone gates `hush run`, with no repo policy.json at all", () => {
    // The whole point of a floor outside the repo: it must work even for a
    // project that has never opted into .hush/policy.json.
    const p = project();
    try {
      assert.ok(!existsSync(join(p.hushDir, "policy.json")), "test fixture drifted: a repo policy file exists");
      writeFileSync(join(p.home, "policy.json"), JSON.stringify({ requireApproval: ["run"], approvalTimeoutSeconds: 1 }));
      const r = p.run(["run", "--", "echo", "RAN"]);
      assert.equal(r.code, 1, r.out);
      assert.ok(!r.out.includes("RAN"), `the command ran despite no answer to the floor's approval prompt:\n${r.out}`);
    } finally {
      p.cleanup();
    }
  });

  test("a grant file cannot stand in for an approval, whatever scope shape it uses", () => {
    // Both shapes are exercised here: the default "command" scope and the
    // wider "sets" one. Neither is read from disk any more — the scope-shape
    // itself is covered by policy.test.ts's runScope tests.
    for (const approvalScope of ["command", "sets"] as const) {
      const p = project();
      try {
        writeFileSync(
          join(p.hushDir, "policy.json"),
          JSON.stringify({ requireApproval: ["run"], approvalScope, approvalTimeoutSeconds: 1 }),
        );
        writeFileSync(
          join(p.hushDir, "grants.local.json"),
          JSON.stringify({
            [runScope({ ...DEFAULT_POLICY, approvalScope }, "npm", ["default"])]: Date.now() + 60_000,
          }),
        );
        const r = p.run(["run", "--", "npm", "--version"]);
        assert.equal(r.code, 1, `approvalScope ${approvalScope}: a grant file pre-authorised a run\n${r.out}`);
      } finally {
        p.cleanup();
      }
    }
  });

  test("a run with requireApproval on and nothing to answer it does not run", () => {
    const p = project();
    try {
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: ["run"] }));
      const r = p.run(["run", "--", "echo", "RAN"]);
      assert.equal(r.code, 1, r.out);
      assert.ok(!r.out.includes("RAN"), `the command ran without an approval:\n${r.out}`);
    } finally {
      p.cleanup();
    }
  });

  test("an approval writes no grants file at all, in any location", async () => {
    // The file this test used to check the permissions of is gone. It lived in
    // the project, which an agent can write, so "keep it 0600" was the wrong
    // fix: the answer is that there is nothing there to read or steal. A
    // session approval now lasts exactly as long as this process does.
    clearApprovalCache();
    const dir = mkdtempSync(join(tmpdir(), "hush-cli-grants-"));
    try {
      process.env.DISPLAY = ":0";
      process.env.FAKE_EXIT = "1"; // zenity's extra button: "Allow 15 min"
      process.env.FAKE_STDOUT = "Allow 15 min";
      const r = await requestApproval(dir, {
        action: "run", summary: "Run: echo RAN", scope: runScope(DEFAULT_POLICY, "echo", ["default"]),
        ttlSeconds: 900, timeoutMs: 5000,
      }, clickingAllow);
      assert.equal(r.decision, "session", "the fixture dialog did not return a session approval");

      assert.deepEqual(
        readdirSync(dir),
        [],
        "an approval left something behind in the directory it was asked from",
      );
      // And the grant is in memory only, so a second process would ask again.
      clearApprovalCache(); // what a fresh `hush` process sees: nothing
      const restarted = await requestApproval(dir, {
        action: "run", summary: "Run: echo RAN", scope: runScope(DEFAULT_POLICY, "echo", ["default"]),
        ttlSeconds: 900, timeoutMs: 200,
      }, { authenticate: async () => "unavailable" as const, platform: () => "linux" });
      assert.equal(restarted.cached, false, "a grant survived its process");
    } finally {
      delete process.env.DISPLAY;
      delete process.env.FAKE_EXIT;
      delete process.env.FAKE_STDOUT;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // Red team, 2026-09-12: grants.local.json lived inside .hush/, which an
  // agent confined to the project can write to, and writeFileSync/chmodSync
  // follow symlinks by default — so a symlink planted there turned the next
  // legitimate approval into a rewrite of the user's policy floor. The write
  // is gone (see the test above), and this pins that a session approval still
  // touches nothing at that path, symlink or not.
  test("an approval writes nothing where grants.local.json used to be, even as a symlink", async () => {
    clearApprovalCache();
    const dir = mkdtempSync(join(tmpdir(), "hush-cli-symlink-"));
    try {
      const floorPath = join(dir, "floor.json");
      const floorBefore = JSON.stringify({ requireApproval: ["run", "add", "reveal"], denyCommands: ["node", "bash"] });
      writeFileSync(floorPath, floorBefore);

      const grantsPath = join(dir, "grants.local.json");
      symlinkSync(floorPath, grantsPath);

      // The human legitimately approves — this is not the attack, it is the
      // ordinary path a real session grant is written through.
      process.env.DISPLAY = ":0";
      process.env.FAKE_EXIT = "1";
      process.env.FAKE_STDOUT = "Allow 15 min";
      const r = await requestApproval(dir, {
        action: "run", summary: "Run: echo RAN", scope: runScope(DEFAULT_POLICY, "echo", ["default"]),
        ttlSeconds: 900, timeoutMs: 5000,
      }, clickingAllow);
      assert.equal(r.decision, "session");

      assert.equal(readFileSync(floorPath, "utf8"), floorBefore, "a legitimate approval clobbered the user's policy floor through a symlink");
    } finally {
      delete process.env.DISPLAY;
      delete process.env.FAKE_EXIT;
      delete process.env.FAKE_STDOUT;
      rmSync(dir, { recursive: true, force: true });
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

// The quick start is "hush add .env --as Dev" then "hush npm run dev". A set the
// project does not use is not injected, so making a set from inside a project
// has to make the project use it — or the second line silently does nothing.
describe("a set made from inside a project is used by it", () => {
  const links = (p: ReturnType<typeof project>): string[] => {
    const file = join(p.hushDir, "envs.json");
    if (!existsSync(file)) return [];
    return (JSON.parse(readFileSync(file, "utf8")) as { use: string[] }).use;
  };

  // Bites: without the link, the run below injects nothing and prints no marker.
  test("add <file> --as makes the project use the new set, so the next run injects it", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.x"), "FAL_KEY=quickstartvalue\n");
      const r = p.run(["add", ".env.x", "--as", "Dev", "--project"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /now uses dev/, r.out);
      assert.deepEqual(links(p), ["dev"]);
      const run = p.run(["sh", "-c", "echo $FAL_KEY"]);
      assert.match(run.out, /\[redacted:FAL_KEY\]/, "the new set was not injected:\n" + run.out);
      assert.ok(!run.out.includes("quickstartvalue"), "a live value leaked");
    } finally {
      p.cleanup();
    }
  });

  test("--no-use opts out, and an already-used set keeps its place", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.x"), "FAL_KEY=v\n");
      assert.equal(p.run(["add", ".env.x", "--as", "Later", "--project", "--no-use"]).code, 0);
      assert.deepEqual(links(p), [], "--no-use still linked the set");
      assert.equal(p.run(["use", "later"]).code, 0);
      writeFileSync(join(p.root, ".env.y"), "OTHER=v\n");
      assert.equal(p.run(["add", ".env.y", "--as", "Other", "--project"]).code, 0);
      assert.equal(p.run(["add", ".env.x", "--as", "Later", "--project", "--overwrite"]).code, 0);
      assert.deepEqual(links(p), ["later", "other"], "re-adding to a used set moved it");
    } finally {
      p.cleanup();
    }
  });

  // Bites: a KEY=value that creates a set has its own success path too.
  test("add KEY=value --to <new set> does the same; adding to an existing set changes nothing", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "K=v", "--to", "fresh"]).code, 0);
      assert.deepEqual(links(p), ["fresh"]);
      assert.equal(p.run(["use", "--not", "fresh"]).code, 0);
      assert.equal(p.run(["add", "K2=v", "--to", "fresh"]).code, 0);
      assert.deepEqual(links(p), [], "adding to an existing set re-linked it");
    } finally {
      p.cleanup();
    }
  });

  // Bites: the alias forwarding to cmdAddKeyValue without "no-use" links prod.
  test("the deprecated hush set --env keeps its old meaning: stored, not used", () => {
    const p = project();
    try {
      assert.equal(p.run(["set", "PROD_KEY", "--env", "prod"], "v\n").code, 0);
      assert.deepEqual(links(p), [], "hush set --env made the project use the env");
    } finally {
      p.cleanup();
    }
  });

  // Bites: the service form has its own success path; forgetting the link
  // there leaves "hush add fal" followed by "hush dev" running without FAL_KEY.
  test("add <service> --as does the same", () => {
    const p = project();
    try {
      const r = p.run(["add", "fal", "--as", "Work fal", "--project"], "piped-value\n");
      assert.equal(r.code, 0, r.out);
      assert.deepEqual(links(p), ["work-fal"]);
    } finally {
      p.cleanup();
    }
  });
});

// ===========================================================================
// "In a new folder, if it's run then we need it to work": commands that don't
// need a project vault stop demanding one, and the first run in a folder
// nobody has told hush anything about proposes what to use instead of
// silently doing nothing.
// ===========================================================================

/**
 * A folder hush has never seen: no `.hush` anywhere above it, only a temp
 * HUSH_HOME. `librarySet()` builds a named library set from a *separate*
 * scratch cwd, never `root` — `audit()` in src/vault.ts creates `.hush`
 * unconditionally (even with `--no-use`) the moment any command runs there,
 * so fixture setup done *in* `root` would make a "this folder is untouched"
 * assertion pass by accident even if the code under test were broken.
 */
function bareFolder(envOverride: NodeJS.ProcessEnv = {}) {
  const home = mkdtempSync(join(tmpdir(), "hush-cli-home-"));
  const root = mkdtempSync(join(tmpdir(), "hush-cli-bare-"));
  let setupDir: string | null = null;
  const id = generateIdentity();
  const env = {
    ...process.env,
    HUSH_HOME: home,
    HUSH_IDENTITY: encodeSecret(id),
    HUSH_BIOMETRY: "off",
    // No desktop: on macOS an enforced approval would otherwise open a real
    // osascript dialog on the developer's screen. This is the narrowing switch
    // — it can only make an approval fail, never succeed.
    HUSH_NO_DIALOG: "1",
    HUSH_NO_NUDGE: "1",
    NO_COLOR: "1",
    ...envOverride,
  };
  const runIn = (cwd: string, args: string[], input?: string) => {
    const r = spawnSync(process.execPath, [CLI, ...args], {
      cwd,
      env,
      encoding: "utf8",
      input,
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
    return { out: (r.stdout ?? "") + (r.stderr ?? ""), code: r.status ?? 1 };
  };
  const run = (args: string[], input?: string) => runIn(root, args, input);
  return {
    home, root, env, run,
    hushDir: join(root, ".hush"),
    /** Named library set with a label equal to its slug, so prompt-text assertions stay simple. */
    librarySet(name: string, values: Record<string, string>): void {
      if (!setupDir) setupDir = mkdtempSync(join(tmpdir(), "hush-cli-libsetup-"));
      if (!existsSync(join(home, "vaults", "global", "vault.json"))) {
        const created = runIn(setupDir, ["global", "--create"]);
        assert.equal(created.code, 0, created.out);
      }
      const pairs = Object.entries(values).map(([k, v]) => `${k}=${v}`);
      const r = runIn(setupDir, ["add", ...pairs, "--to", name, "--library", "--no-use"]);
      assert.equal(r.code, 0, r.out);
    },
    cleanup: () => {
      for (const d of [home, root, ...(setupDir ? [setupDir] : [])]) rmSync(d, { recursive: true, force: true });
    },
  };
}

describe("a folder that isn't set up yet", () => {
  test("non-interactive: exits 1, names the library's sets, runs nothing, writes nothing", () => {
    const p = bareFolder();
    try {
      p.librarySet("acme-production", { DATABASE_URL: "x" });
      const marker = join(p.root, "marker.txt");
      const r = p.run(["sh", "-c", `touch ${marker}`]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /isn't set up for hush yet/);
      assert.match(r.out, /acme-production/, `the library's sets are not named:\n${r.out}`);
      assert.ok(!existsSync(marker), "the command ran despite the refusal");
      assert.ok(!existsSync(p.hushDir), "a .hush directory was created for a refused run");
    } finally {
      p.cleanup();
    }
  });

  test("non-interactive with no library at all only offers the two ways in", () => {
    const p = bareFolder();
    try {
      const r = p.run(["sh", "-c", "echo hi"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /hush add \.env --as Dev/);
      assert.match(r.out, /hush global --create/);
    } finally {
      p.cleanup();
    }
  });

  test("interactive: a single unambiguous match is proposed; Y + N (agent) links it and the run is injected", () => {
    const p = bareFolder({ HUSH_INTERACTIVE: "1" });
    try {
      p.librarySet("acme-production", { DATABASE_URL: "dburl", FAL_KEY: "falval" });
      p.librarySet("work-fal", { FAL_KEY: "workval" });
      writeFileSync(join(p.root, "index.js"), "process.env.FAL_KEY; process.env.DATABASE_URL;\n");

      const r = p.run(["sh", "-c", "echo ${FAL_KEY:-absent}"], "y\nn\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /Its code references: DATABASE_URL, FAL_KEY/, r.out);
      assert.match(r.out, /acme-production/);
      assert.ok(!r.out.includes("work-fal"), `a tied-loser set was named in the proposal:\n${r.out}`);
      assert.match(r.out, /redacted:FAL_KEY/, r.out);
      assert.ok(!r.out.includes("falval"), "a live value leaked into output");

      const links = JSON.parse(readFileSync(join(p.hushDir, "envs.json"), "utf8")) as { use: string[] };
      assert.deepEqual(links, { use: ["acme-production"] });
      assert.ok(!existsSync(join(p.hushDir, "policy.json")), "answering N to the agent question still wrote a policy");
      assert.ok(!existsSync(join(p.hushDir, "vault.json")), "a vault was created for a library-only setup");
    } finally {
      p.cleanup();
    }
  });

  test("an ambiguous key is asked about by name, and the numbered answer picks it", () => {
    const p = bareFolder({ HUSH_INTERACTIVE: "1" });
    try {
      p.librarySet("personal-fal", { FAL_KEY: "personalval" });
      p.librarySet("work-fal", { FAL_KEY: "workval" });
      writeFileSync(join(p.root, "index.js"), "process.env.FAL_KEY;\n");

      const r = p.run(["use"], "2\ny\nn\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /FAL_KEY is in personal-fal and work-fal — which one\?/, r.out);

      const links = JSON.parse(readFileSync(join(p.hushDir, "envs.json"), "utf8")) as { use: string[] };
      assert.deepEqual(links, { use: ["work-fal"] }, "option 2 was not the one linked");
    } finally {
      p.cleanup();
    }
  });

  test("n leaves nothing written", () => {
    const p = bareFolder({ HUSH_INTERACTIVE: "1" });
    try {
      p.librarySet("acme-production", { FAL_KEY: "v" });
      writeFileSync(join(p.root, "index.js"), "process.env.FAL_KEY;\n");

      // Declining is an answer, not an error.
      const r = p.run(["use"], "n\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /Nothing saved here/);
      assert.ok(!existsSync(join(p.hushDir, "envs.json")), "envs.json was written despite declining");

      // And a run that was declined still runs — with nothing, and saying so.
      const marker = join(p.root, "ran.txt");
      const run = p.run(["sh", "-c", `touch ${marker}`], "n\n");
      assert.equal(run.code, 0, run.out);
      assert.match(run.out, /running without secrets/);
      assert.ok(existsSync(marker), "the declined run never ran");
      assert.ok(!existsSync(join(p.hushDir, "envs.json")), "a declined run wrote envs.json");
    } finally {
      p.cleanup();
    }
  });

  test("edit replaces the proposal with the typed list", () => {
    const p = bareFolder({ HUSH_INTERACTIVE: "1" });
    try {
      // acme-production covers both keys outright (no tie with work-fal), so
      // this reaches the Y/n/edit question rather than the ambiguity prompt —
      // edit is then what overrides the proposal to work-fal instead.
      p.librarySet("acme-production", { DATABASE_URL: "d", FAL_KEY: "v1" });
      p.librarySet("work-fal", { FAL_KEY: "v2" });
      writeFileSync(join(p.root, "index.js"), "process.env.FAL_KEY; process.env.DATABASE_URL;\n");

      const r = p.run(["use"], "edit\nwork-fal\nn\n");
      assert.equal(r.code, 0, r.out);
      const links = JSON.parse(readFileSync(join(p.hushDir, "envs.json"), "utf8")) as { use: string[] };
      assert.deepEqual(links, { use: ["work-fal"] }, "edit did not replace the proposal");
    } finally {
      p.cleanup();
    }
  });

  test("edit refuses a typo, naming the known sets", () => {
    const p = bareFolder({ HUSH_INTERACTIVE: "1" });
    try {
      p.librarySet("acme-production", { DATABASE_URL: "d", FAL_KEY: "v1" });
      writeFileSync(join(p.root, "index.js"), "process.env.FAL_KEY; process.env.DATABASE_URL;\n");

      const r = p.run(["use"], "edit\nnot-a-real-set\n");
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /No set called "not-a-real-set"/);
      assert.match(r.out, /acme-production/, "the refusal does not name the known sets");
      assert.ok(!existsSync(join(p.hushDir, "envs.json")), "a rejected edit still wrote links");
    } finally {
      p.cleanup();
    }
  });

  test("the agent question, answered y, writes the three approvals", () => {
    const p = bareFolder({ HUSH_INTERACTIVE: "1" });
    try {
      p.librarySet("acme-production", { FAL_KEY: "v" });
      writeFileSync(join(p.root, "index.js"), "process.env.FAL_KEY;\n");

      const r = p.run(["use"], "y\ny\n");
      assert.equal(r.code, 0, r.out);
      const policy = JSON.parse(readFileSync(join(p.hushDir, "policy.json"), "utf8")) as { requireApproval: string[] };
      assert.deepEqual(policy.requireApproval.sort(), ["add", "request", "reveal", "run"]);
    } finally {
      p.cleanup();
    }
  });

  test("--agent and --no-agent answer the question without asking", () => {
    const setUp = () => {
      const p = bareFolder({ HUSH_INTERACTIVE: "1" });
      p.librarySet("acme-production", { FAL_KEY: "v" });
      writeFileSync(join(p.root, "index.js"), "process.env.FAL_KEY;\n");
      return p;
    };

    const withAgent = setUp();
    try {
      // Only one line piped: the agent question is skipped entirely, so a
      // second line here would be left unread — proof it was never asked.
      const r = withAgent.run(["use", "--agent"], "y\n");
      assert.equal(r.code, 0, r.out);
      assert.ok(existsSync(join(withAgent.hushDir, "policy.json")), "--agent did not write a policy");
    } finally {
      withAgent.cleanup();
    }

    const withoutAgent = setUp();
    try {
      const r = withoutAgent.run(["use", "--no-agent"], "y\n");
      assert.equal(r.code, 0, r.out);
      assert.ok(!existsSync(join(withoutAgent.hushDir, "policy.json")), "--no-agent still wrote a policy");
    } finally {
      withoutAgent.cleanup();
    }
  });

  test("hush init --agent writes the policy too, without asking", () => {
    const home = mkdtempSync(join(tmpdir(), "hush-cli-home-"));
    const proj = mkdtempSync(join(tmpdir(), "hush-cli-init-"));
    try {
      const env = { ...process.env, HUSH_HOME: home, HUSH_NO_NUDGE: "1", HUSH_NO_KEYCHAIN: "1", NO_COLOR: "1" };
      const r = spawnSync(process.execPath, [CLI, "init", "agenttest", "--agent"], { cwd: proj, env, encoding: "utf8" });
      assert.equal(r.status, 0, (r.stdout ?? "") + (r.stderr ?? ""));
      const policy = JSON.parse(readFileSync(join(proj, ".hush", "policy.json"), "utf8")) as { requireApproval: string[] };
      assert.deepEqual(policy.requireApproval.sort(), ["add", "request", "reveal", "run"]);
    } finally {
      rmSync(home, { recursive: true, force: true });
      rmSync(proj, { recursive: true, force: true });
    }
  });

  test("hush use <set> in a bare folder creates envs.json and .hush/.gitignore, with no vault", () => {
    const p = bareFolder();
    try {
      p.librarySet("work-fal", { FAL_KEY: "v" });
      const r = p.run(["use", "work-fal"]);
      assert.equal(r.code, 0, r.out);
      assert.ok(existsSync(join(p.hushDir, "envs.json")));
      assert.ok(existsSync(join(p.hushDir, ".gitignore")));
      assert.ok(!existsSync(join(p.hushDir, "vault.json")), "hush use created a vault");
    } finally {
      p.cleanup();
    }
  });

  test("hush ls in a vault-less set-up folder says so and lists what it uses", () => {
    const p = bareFolder();
    try {
      p.librarySet("work-fal", { FAL_KEY: "v" });
      assert.equal(p.run(["use", "work-fal"]).code, 0);
      const out = p.run(["ls"]).out;
      assert.match(out, /no vault yet — this folder uses library sets only/);
      assert.match(out, /work-fal/);
    } finally {
      p.cleanup();
    }
  });

  test("hush ls in a folder not set up at all points at both ways in", () => {
    const p = bareFolder();
    try {
      const out = p.run(["ls"]).out;
      assert.match(out, /not set up yet/);
      assert.match(out, /hush use <set>/);
      assert.match(out, /hush run -- <cmd>/);
    } finally {
      p.cleanup();
    }
  });

  test("add K=v --to <new set> lands in the library when there is no project vault", () => {
    const p = bareFolder();
    try {
      p.librarySet("seed", { SEED_KEY: "v" }); // only to make a library exist
      const r = p.run(["add", "K=v", "--to", "fresh"]);
      assert.equal(r.code, 0, r.out);
      const library = Vault.open(join(p.home, "vaults", "global", "vault.json"));
      assert.ok(library.has("fresh", "K"), "K did not land in the library");
      assert.ok(!existsSync(join(p.hushDir, "vault.json")), "a project vault was created for a plain add");
    } finally {
      p.cleanup();
    }
  });

  test("add K=v --to <new set> --project creates the vault and prints the one-line notice", () => {
    const p = bareFolder();
    try {
      const r = p.run(["add", "K=v", "--to", "fresh", "--project"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /made this folder's own vault at \.hush\/vault\.json — commit it/);
      const vault = Vault.open(join(p.hushDir, "vault.json"));
      assert.ok(vault.has("fresh", "K"));
    } finally {
      p.cleanup();
    }
  });

  test("hush team add on a vault-less project creates the vault", () => {
    const p = bareFolder();
    try {
      const other = generateIdentity();
      const r = p.run(["team", "add", "colleague", encodePub(other.pub)]);
      assert.equal(r.code, 0, r.out);
      const vault = Vault.open(join(p.hushDir, "vault.json"));
      assert.ok(vault.members().some((m) => m.name === "colleague"), "team add did not add the member");
    } finally {
      p.cleanup();
    }
  });

  test("get and export --format json resolve a key from the library in a vault-less set-up folder", () => {
    const p = bareFolder();
    try {
      p.librarySet("acme-production", { FAL_KEY: "libval" });
      assert.equal(p.run(["use", "acme-production"]).code, 0);

      const got = p.run(["get", "FAL_KEY", "--yes"]);
      assert.equal(got.code, 0, got.out);
      assert.match(got.out, /libval/);

      const exported = JSON.parse(p.run(["export", "--format", "json"]).out) as Record<string, string>;
      assert.equal(exported.FAL_KEY, "libval");
    } finally {
      p.cleanup();
    }
  });

  test("a strict command (hush rotate) on a set-up-but-vault-less folder names --project and hush team add", () => {
    const p = bareFolder();
    try {
      p.librarySet("acme-production", { FAL_KEY: "v" });
      assert.equal(p.run(["use", "acme-production"]).code, 0);
      const r = p.run(["rotate"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /no vault of its own yet/);
      assert.match(r.out, /--project/);
      assert.match(r.out, /hush team add/);
    } finally {
      p.cleanup();
    }
  });
});

describe("hush scan reconciles against every used set, not just the literal env", () => {
  test("a key a used library set provides is no longer reported missing", () => {
    const p = project(); // has a vault of its own
    try {
      assert.equal(p.run(["global", "--create"]).code, 0);
      writeFileSync(join(p.root, ".env.fal"), "FAL_KEY=v\n");
      assert.equal(p.run(["add", ".env.fal", "--as", "Work fal", "--library", "--no-use"]).code, 0);
      assert.equal(p.run(["use", "work-fal"]).code, 0);
      writeFileSync(join(p.root, "index.js"), "process.env.FAL_KEY;\n");

      const out = p.run(["scan"]).out;
      assert.match(out, /0 missing/, `FAL_KEY reported missing:\n${out}`);
      assert.ok(!/^\s*FAL_KEY\s/m.test(out.split("Missing:")[1] ?? ""), `FAL_KEY listed under Missing:\n${out}`);
    } finally {
      p.cleanup();
    }
  });
});

// Setup in a vault-less folder ends with "hush install-mcp when you're ready";
// that promise has to hold without a vault.
describe("agent registration in a folder that only uses library sets", () => {
  // Bites: install-mcp/install-skill on the strict ctx() refuse with the
  // "no vault of its own yet" message instead of writing anything.
  test("install-mcp and install-skill work with envs.json and no vault", () => {
    // HOME is pointed at a scratch directory for every test in this describe:
    // registering an agent writes to files that live in the user's home
    // (`~/.codex/config.toml`, `~/.claude/…`), and a test run must never touch
    // the developer's real ones.
    const p = project();
    try {
      const fakeHome = join(p.home, "home");
      mkdirSync(join(fakeHome, ".claude"), { recursive: true });
      p.env.HOME = fakeHome;
      p.env.PATH = "";
      rmSync(join(p.hushDir, "vault.json"));
      writeFileSync(join(p.hushDir, "envs.json"), JSON.stringify({ use: [] }));
      const mcp = p.run(["install-mcp"]);
      assert.equal(mcp.code, 0, mcp.out);
      assert.ok(existsSync(join(p.root, ".mcp.json")), ".mcp.json was not written");
      const skill = p.run(["install-skill"]);
      assert.equal(skill.code, 0, skill.out);
      assert.ok(existsSync(join(p.root, ".claude", "skills", "hush", "SKILL.md")), "the skill was not written");
    } finally {
      p.cleanup();
    }
  });

  test("a Codex session gets Codex's file, not Claude Code's", () => {
    // The bug this pins: install-mcp wrote `.mcp.json` unconditionally and
    // printed a tick. In a Codex session that file is never read, so a new user
    // was told they were set up while their agent knew nothing about hush.
    const p = project();
    try {
      const fakeHome = join(p.home, "home");
      mkdirSync(join(fakeHome, ".codex"), { recursive: true });
      p.env.HOME = fakeHome;
      p.env.PATH = ""; // nothing on PATH, so detection is the directory alone

      const mcp = p.run(["install-mcp"]);
      assert.equal(mcp.code, 0, mcp.out);
      assert.match(mcp.out, /Codex/);

      const config = readFileSync(join(fakeHome, ".codex", "config.toml"), "utf8");
      assert.match(config, /^\[mcp_servers\.hush\]$/m, "no hush section was written for Codex");
      assert.match(config, /^command = "node"$/m);
      assert.match(config, /^args = \[".*cli\.ts", "mcp"\]$/m);
      assert.ok(
        !existsSync(join(p.root, ".mcp.json")),
        "wrote Claude Code's file for a Codex-only machine — the tick would mean nothing",
      );

      const skill = p.run(["install-skill"]);
      assert.equal(skill.code, 0, skill.out);
      const dest = join(p.root, ".agents", "skills", "hush", "SKILL.md");
      assert.ok(existsSync(dest), `the skill did not go where Codex reads it (${dest})`);
      assert.match(readFileSync(dest, "utf8"), /Never ask the user to paste a credential into the chat/);
    } finally {
      p.cleanup();
    }
  });

  test("neither agent here: it says so and prints the line to paste", () => {
    const p = project();
    try {
      const fakeHome = join(p.home, "home");
      mkdirSync(fakeHome, { recursive: true });
      p.env.HOME = fakeHome;
      p.env.PATH = "";

      const r = p.run(["install-mcp"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /No coding agent detected/);
      assert.match(r.out, /codex mcp add hush -- node/);
      assert.ok(!existsSync(join(p.root, ".mcp.json")), "wrote a file no agent reads");
      assert.ok(!existsSync(join(fakeHome, ".codex", "config.toml")), "wrote a config for an agent that is not here");

      // --for is how someone registers an agent hush could not see.
      const forced = p.run(["install-mcp", "--for", "cursor"]);
      assert.equal(forced.code, 0, forced.out);
      const cursor = JSON.parse(readFileSync(join(p.root, ".cursor", "mcp.json"), "utf8")) as {
        mcpServers: { hush: { command: string; args: string[] } };
      };
      assert.equal(cursor.mcpServers.hush.command, "node");
      assert.deepEqual(cursor.mcpServers.hush.args.slice(1), ["mcp"]);
    } finally {
      p.cleanup();
    }
  });

  test("an entry that is already there is left alone", () => {
    const p = project();
    try {
      const fakeHome = join(p.home, "home");
      mkdirSync(join(fakeHome, ".codex"), { recursive: true });
      const configPath = join(fakeHome, ".codex", "config.toml");
      const mine = `[mcp_servers.hush]\ncommand = "my-own-wrapper"\nargs = []\n`;
      writeFileSync(configPath, mine);
      p.env.HOME = fakeHome;
      p.env.PATH = "";

      const r = p.run(["install-mcp"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /already registered/);
      assert.equal(readFileSync(configPath, "utf8"), mine, "an existing entry was rewritten");
    } finally {
      p.cleanup();
    }
  });
});

describe("hush doctor in a folder that only uses library sets", () => {
  // Bites: a doctor that opens the vault unconditionally reports
  // "vault readable ✗ ENOENT" and stops before the policy checks.
  test("reports the missing vault as a state, not a failure, and still checks the policy", () => {
    const p = project();
    try {
      rmSync(join(p.hushDir, "vault.json"));
      writeFileSync(join(p.hushDir, "envs.json"), JSON.stringify({ use: [] }));
      const r = p.run(["doctor"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /no vault yet/, r.out);
      assert.match(r.out, /policy floor/, "the checks after the vault were skipped");
      assert.doesNotMatch(r.out, /ENOENT|vault readable/);
    } finally {
      p.cleanup();
    }
  });
});

describe("hush request", () => {
  /**
   * A loopback server the CLI can actually talk to. http is allowed here
   * without --insecure precisely because it never leaves the machine, which is
   * the rule the transport check encodes.
   *
   * Anything that has to reach it runs through runAsync: the sync runner blocks
   * the test's event loop, so the server living in this same process can never
   * answer and every such call would time out.
   */
  async function withServer(
    handler: (req: IncomingMessage) => { status: number; body: string; headers?: Record<string, string> },
    fn: (base: string, hits: () => string[]) => Promise<void>,
  ): Promise<void> {
    const hits: string[] = [];
    const server = createServer((req, res) => {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", () => {
        hits.push(`${req.method} ${req.url} ${req.headers.authorization ?? ""} ${body}`);
        const out = handler(req);
        res.writeHead(out.status, { "content-type": "text/plain", ...(out.headers ?? {}) });
        res.end(out.body);
      });
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      await fn(base, () => hits);
    } finally {
      server.close();
      await once(server, "close");
    }
  }

  /** The same thing project().run does, without blocking the event loop. */
  function runAsync(p: ReturnType<typeof project>, args: string[]): Promise<{ code: number; out: string }> {
    return new Promise((resolve) => {
      const child = spawn(process.execPath, [CLI, ...args], {
        cwd: p.root,
        env: p.env,
        stdio: ["ignore", "pipe", "pipe"],
      });
      let out = "";
      child.stdout?.on("data", (d) => (out += String(d)));
      child.stderr?.on("data", (d) => (out += String(d)));
      child.on("exit", (code) => resolve({ code: code ?? 1, out }));
    });
  }

  test("the secret reaches the server and comes back masked", async () => {
    await withServer(
      (req) => ({ status: 200, body: `you sent: ${req.headers.authorization ?? ""}` }),
      async (base, hits) => {
        const p = project();
        try {
          const r = await runAsync(p, [
            "request", "POST", `${base}/v1/thing`,
            "--header", "Authorization: Bearer $STRIPE_SECRET_KEY",
          ]);
          assert.equal(r.code, 0, r.out);
          assert.equal(hits().length, 1, "the request never arrived");
          // The wire carried the real value...
          assert.match(hits()[0], /Bearer sk_live_cli/);
          // ...and the caller only ever saw it masked.
          assert.match(r.out, /\[redacted:STRIPE_SECRET_KEY\]/);
          assert.doesNotMatch(r.out, /sk_live_cli/, "the value came back in the output");
        } finally {
          p.cleanup();
        }
      },
    );
  });

  test("a non-2xx is a normal result; --fail turns it into a non-zero exit", async () => {
    await withServer(
      () => ({ status: 404, body: "no such thing" }),
      async (base) => {
        const p = project();
        try {
          const plain = await runAsync(p, ["request", `${base}/missing`]);
          assert.equal(plain.code, 0, "a 404 exit code broke curl-like piping by default");
          assert.match(plain.out, /no such thing/);

          const failed = await runAsync(p, ["request", "--fail", `${base}/missing`]);
          assert.equal(failed.code, 1, "--fail did not set the exit code");
        } finally {
          p.cleanup();
        }
      },
    );
  });

  test("the body is not substituted unless --substitute body says so", async () => {
    await withServer(
      () => ({ status: 200, body: "ok" }),
      async (base, hits) => {
        const p = project();
        try {
          const literal = await runAsync(p, ["request", "POST", `${base}/x`, "--data", "key=$STRIPE_SECRET_KEY"]);
          assert.equal(literal.code, 0, literal.out);
          assert.match(hits()[0], /key=\$STRIPE_SECRET_KEY/, "the body was substituted without being asked");

          const opted = await runAsync(p, [
            "request", "POST", `${base}/x`, "--data", "key=$STRIPE_SECRET_KEY", "--substitute", "body",
          ]);
          assert.equal(opted.code, 0, opted.out);
          assert.match(hits()[1], /key=sk_live_cli/);
        } finally {
          p.cleanup();
        }
      },
    );
  });

  test("cleartext to a real host is refused before anything is sent", () => {
    const p = project();
    try {
      const r = p.run(["request", "http://api.example.com/x", "--header", "Authorization: Bearer $STRIPE_SECRET_KEY"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /cleartext/);
    } finally {
      p.cleanup();
    }
  });

  test("a secret cannot be put in the URL path", () => {
    const p = project();
    try {
      const r = p.run(["request", "https://api.example.com/v1/$STRIPE_SECRET_KEY/x"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /would go in the URL path/);
    } finally {
      p.cleanup();
    }
  });

  test("a placeholder with no matching key is refused, naming it", () => {
    const p = project();
    try {
      const r = p.run(["request", "https://api.example.com/x", "--header", "Authorization: Bearer $TYPO"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /No such secret in these sets: TYPO/);
    } finally {
      p.cleanup();
    }
  });

  test("a host outside allowHosts is refused, and the server is never contacted", async () => {
    await withServer(
      () => ({ status: 200, body: "ok" }),
      async (base, hits) => {
        const p = project();
        try {
          writeFileSync(
            join(p.hushDir, "policy.json"),
            JSON.stringify({ allowHosts: ["api.stripe.com"], requireApproval: [] }),
          );
          const r = p.run(["request", `${base}/x`, "--header", "Authorization: Bearer $STRIPE_SECRET_KEY"]);
          assert.equal(r.code, 1, r.out);
          assert.match(r.out, /Policy forbids requests to/);
          assert.equal(hits().length, 0, "the request went out despite the host policy");
        } finally {
          p.cleanup();
        }
      },
    );
  });

  test("requireApproval stops the request going out when nothing can ask a human", async () => {
    await withServer(
      () => ({ status: 200, body: "ok" }),
      async (base, hits) => {
        const p = project();
        try {
          writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: ["request"] }));
          const r = p.run([
            "request", `${base}/x`, "--header", "Authorization: Bearer $STRIPE_SECRET_KEY",
          ]);
          assert.equal(r.code, 1, r.out);
          // The whole point: a credential did not leave the machine because a
          // human was not there to approve it.
          assert.equal(hits().length, 0, "the gated request was sent anyway");
          assert.ok(!r.out.includes("sk_live_cli"), `the credential leaked into the output:\n${r.out}`);
        } finally {
          p.cleanup();
        }
      },
    );
  });

  // The whole reason `request` is not in approval.ts's on-disk grant set. A
  // forged grants.local.json is a file an agent with ordinary write access to
  // the project can create; for `run` that buys a redacted child process on
  // this machine, but for `request` it would buy a credential sent to whatever
  // host the scope names. So a request grant is never read from disk at all.
  test("a forged grants.local.json cannot pre-authorise a request", async () => {
    await withServer(
      () => ({ status: 200, body: "ok" }),
      async (base, hits) => {
        const p = project();
        try {
          writeFileSync(
            join(p.hushDir, "policy.json"),
            JSON.stringify({ requireApproval: ["request"], approvalTimeoutSeconds: 1 }),
          );
          const host = new URL(base).host;
          // Exactly the scope requestScope() computes for this call.
          writeFileSync(
            join(p.hushDir, "grants.local.json"),
            JSON.stringify({ [`request:${host}:default`]: Date.now() + 60_000 }),
          );

          const r = p.run(["request", `${base}/x`, "--header", "Authorization: Bearer $STRIPE_SECRET_KEY"]);
          assert.equal(r.code, 1, `a forged grant was honoured:\n${r.out}`);
          assert.equal(hits().length, 0, "the request went out on a forged grant");
        } finally {
          p.cleanup();
        }
      },
    );
  });
});

describe("hush run --materialize", () => {
  /**
   * A script rather than `node -e`: with a policy file present the interpreter
   * deny list applies, and the documented way through it is a script, which is
   * also what a real project would have.
   */
  function script(p: ReturnType<typeof project>): string {
    const path = join(p.root, "show.sh");
    writeFileSync(path, '#!/bin/sh\necho "path=$STRIPE_SECRET_KEY"\ncat "$STRIPE_SECRET_KEY"\n');
    chmodSync(path, 0o755);
    return "./show.sh";
  }

  test("the child gets the path, the file holds the value, and it is gone afterwards", () => {
    const p = project();
    try {
      const r = p.run(["run", "--materialize", "STRIPE_SECRET_KEY", "--", script(p)]);
      assert.equal(r.code, 0, r.out);
      // The child saw a path, not the value...
      const shown = r.out.match(/path=(\S+)/);
      assert.ok(shown, `the script never printed the path:\n${r.out}`);
      assert.match(shown[1], /hush-/);
      // ...and the value stays masked in the output, because the key remained
      // in the redaction set even though it left the environment.
      assert.doesNotMatch(r.out, /service_account/, "reading the file leaked the value into output");
      assert.match(r.out, /\[redacted:STRIPE_SECRET_KEY\]/);
      assert.equal(existsSync(shown[1]), false, "the materialised file outlived the command");
    } finally {
      p.cleanup();
    }
  });

  test("the file is removed even when the child fails", () => {
    const p = project();
    try {
      const path = join(p.root, "boom.sh");
      writeFileSync(path, '#!/bin/sh\necho "path=$STRIPE_SECRET_KEY"\nexit 3\n');
      chmodSync(path, 0o755);
      const r = p.run(["run", "--materialize", "STRIPE_SECRET_KEY", "--", "./boom.sh"]);
      assert.equal(r.code, 3, r.out);
      const shown = r.out.match(/path=(\S+)/);
      assert.ok(shown, r.out);
      assert.equal(existsSync(shown[1]), false, "a failed command left the credential on disk");
    } finally {
      p.cleanup();
    }
  });

  test("an explicit path is used as given, and refused if something is there", () => {
    const p = project();
    try {
      const target = join(p.root, "sa.json");

      const ok = p.run(["run", "--materialize", `STRIPE_SECRET_KEY=${target}`, "--", script(p)]);
      assert.equal(ok.code, 0, ok.out);
      assert.equal(existsSync(target), false, "the explicit file was not cleaned up");

      writeFileSync(target, "DO NOT TOUCH");
      const clash = p.run(["run", "--materialize", `STRIPE_SECRET_KEY=${target}`, "--", script(p)]);
      assert.equal(clash.code, 1, clash.out);
      assert.match(clash.out, /something is already there/);
      assert.equal(readFileSync(target, "utf8"), "DO NOT TOUCH", "an existing file was overwritten");
    } finally {
      p.cleanup();
    }
  });

  test("a key that is not in the sets is refused before anything runs", () => {
    const p = project();
    try {
      const r = p.run(["run", "--materialize", "NOPE", "--", script(p)]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /--materialize NOPE: no such secret/);
      assert.doesNotMatch(r.out, /path=/, "the command ran anyway");
    } finally {
      p.cleanup();
    }
  });

  test("materialising is gated on reveal, not on run", () => {
    // The whole design decision: this writes plaintext to a path the caller
    // chose, so it needs the approval `hush get` needs, not the one `hush run`
    // needs. A policy that gates only `run` must not be enough.
    const p = project();
    try {
      writeFileSync(
        join(p.hushDir, "policy.json"),
        JSON.stringify({ requireApproval: ["reveal"], approvalTimeoutSeconds: 1 }),
      );
      const r = p.run(["run", "--materialize", "STRIPE_SECRET_KEY", "--", script(p)]);
      assert.equal(r.code, 1, `a reveal-gated materialise ran unattended:\n${r.out}`);
      assert.doesNotMatch(r.out, /path=/, "the command ran despite the reveal gate");
    } finally {
      p.cleanup();
    }
  });

  test("with no gate at all, it runs unattended like any other run", () => {
    // The other direction of the same decision, so the gate cannot silently
    // become "everything" or "nothing".
    const p = project();
    try {
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: [] }));
      const r = p.run(["run", "--materialize", "STRIPE_SECRET_KEY", "--", script(p)]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /path=/);
    } finally {
      p.cleanup();
    }
  });
});

describe("hush stays out of places it was not asked into", () => {
  // Bites: ~/.hush and a project's .hush share a name, so the upward walk from
  // any folder under $HOME found it. One `hush use` from the home folder wrote
  // ~/.hush/envs.json and every folder beneath became part of that "project".
  test("~/.hush is never a project, and nothing writes project files into it", () => {
    const p = bareFolder();
    const hushHome = join(p.root, ".hush");
    p.env.HUSH_HOME = hushHome;
    try {
      p.librarySet("work", { WORK_KEY: "work_value_1234" });
      const use = p.run(["use", "work"]);
      assert.equal(use.code, 1, use.out);
      assert.match(use.out, /not a project/);
      assert.ok(!existsSync(join(hushHome, "envs.json")), "wrote envs.json into ~/.hush");

      const init = p.run(["init"]);
      assert.equal(init.code, 1, init.out);
      assert.ok(!existsSync(join(hushHome, "vault.json")), "made a project vault in ~/.hush");

      // A folder left in the old state is not picked up either.
      writeFileSync(join(hushHome, "envs.json"), JSON.stringify({ use: ["work"] }));
      const nested = join(p.root, "code", "app");
      mkdirSync(nested, { recursive: true });
      const r = spawnSync(process.execPath, [CLI, "root"], { cwd: nested, env: p.env, encoding: "utf8" });
      assert.notEqual(r.status, 0, `a folder under $HOME resolved to ~/.hush: ${r.stdout}`);
    } finally {
      p.cleanup();
    }
  });

  // Bites: macOS's /var is a link to /private/var, so HUSH_HOME and the
  // folder the walk reaches can be the same directory spelled two ways.
  test("~/.hush is recognised through a symlinked path too", () => {
    const p = bareFolder();
    const real = join(p.root, "real");
    const link = join(p.root, "link");
    try {
      mkdirSync(join(real, ".hush"), { recursive: true });
      mkdirSync(join(real, "code", "app"), { recursive: true });
      writeFileSync(join(real, ".hush", "envs.json"), JSON.stringify({ use: [] }));
      symlinkSync(real, link);
      p.env.HUSH_HOME = join(link, ".hush");
      const r = spawnSync(process.execPath, [CLI, "root"], { cwd: join(real, "code", "app"), env: p.env, encoding: "utf8" });
      assert.notEqual(r.status, 0, `~/.hush reached through a link was taken for a project: ${r.stdout}`);
    } finally {
      p.cleanup();
    }
  });

  // Bites: the absolute path to one machine's node_modules went into the
  // committed .mcp.json, wrong on every teammate's machine.
  test("install-mcp registers a bare `hush mcp` when PATH's hush is this install", () => {
    const p = project();
    try {
      const fakeHome = join(p.home, "home");
      mkdirSync(join(fakeHome, ".claude"), { recursive: true });
      const bin = join(p.home, "bin");
      mkdirSync(bin);
      symlinkSync(join(dirname(CLI), "..", "bin", "hush.js"), join(bin, "hush"));
      p.env.HOME = fakeHome;
      p.env.PATH = bin;
      const r = p.run(["install-mcp"]);
      assert.equal(r.code, 0, r.out);
      const doc = JSON.parse(readFileSync(join(p.root, ".mcp.json"), "utf8")) as {
        mcpServers: { hush: { command: string; args: string[] } };
      };
      assert.deepEqual(doc.mcpServers.hush, { command: "hush", args: ["mcp"] });
    } finally {
      p.cleanup();
    }
  });

  test("writing a policy says what it does to your own runs", () => {
    const p = project();
    try {
      const fakeHome = join(p.home, "home");
      mkdirSync(fakeHome, { recursive: true });
      p.env.HOME = fakeHome;
      p.env.PATH = "";
      const r = p.run(["install-mcp"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /yours too/);
      // HUSH_NO_DIALOG: nothing here can show a prompt, and it has to say so.
      assert.match(r.out, /every hush run here will be refused/);
    } finally {
      p.cleanup();
    }
  });

  // Bites: the ladder only looked for a project vault, so a folder that uses
  // library sets — the recommended model — was told "your secrets are not encrypted".
  test("a folder that only uses library sets counts as encrypted", () => {
    const p = bareFolder();
    try {
      p.librarySet("work", { WORK_KEY: "work_value_1234" });
      assert.equal(p.run(["use", "work"]).code, 0);
      const r = p.run(["level"]);
      assert.match(r.out, /✓ secrets are encrypted at rest/, r.out);
    } finally {
      p.cleanup();
    }
  });
});

describe("the library is a catalog, not a floor", () => {
  test("its default reaches a folder only after `hush use default --library`", () => {
    const p = bareFolder();
    try {
      p.librarySet("default", { CATCH_ALL: "catch_all_value_123" });
      p.librarySet("work", { WORK_KEY: "work_value_1234" });
      assert.equal(p.run(["use", "work"]).code, 0);

      const before = p.run(["run", "--", "sh", "-c", 'echo "[${CATCH_ALL:-unset}]"']);
      assert.equal(before.code, 0, before.out);
      assert.match(before.out, /\[unset\]/, "the library's default leaked into a folder that never asked");

      const use = p.run(["use", "default", "--library"]);
      assert.equal(use.code, 0, use.out);
      const links = JSON.parse(readFileSync(join(p.hushDir, "envs.json"), "utf8")) as { use: string[] };
      assert.deepEqual(links.use, ["work", "library:default"]);

      const after = p.run(["run", "--", "sh", "-c", 'echo "[${CATCH_ALL:-unset}]"']);
      assert.match(after.out, /\[redacted:CATCH_ALL\]/, after.out);
    } finally {
      p.cleanup();
    }
  });
});
