/**
 * Linux desktop dialogs, without a desktop.
 *
 * zenity and kdialog cannot be driven from CI with no display, so
 * test/fixtures/{zenity,kdialog} stand in for them: real argv in, a scripted
 * exit code and stdout out, controlled entirely through environment
 * variables. Scripting through env rather than argv matters here specifically
 * — it means the argv this test inspects is exactly what a real zenity/
 * kdialog invocation would have received, never contaminated by the test's
 * own stage directions. Modelled on test/age-bridge.test.ts's fake `age`.
 */
import { test, describe, before, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, chmodSync, cpSync, readFileSync, existsSync } from "node:fs";
import { tmpdir, platform as realPlatform } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  requestApproval,
  promptForSecretNatively,
  nativeDialogsAvailable,
  clearApprovalCache,
  type ApprovalDeps,
  type ApprovalRequest,
} from "../src/approval.ts";
import { detectBackend, ttlLabel, waitingFor } from "../src/dialogs.ts";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

// Everything a test might poke, saved and restored around every test so one
// test's DISPLAY or FAKE_EXIT can never leak into the next.
const ENV_KEYS = [
  "PATH", "HUSH_NO_DIALOG", "DISPLAY", "WAYLAND_DISPLAY",
  "FAKE_ARGV_LOG", "FAKE_EXIT", "FAKE_STDOUT", "FAKE_STDERR", "FAKE_SLEEP",
  "FAKE_CALL_COUNT", "FAKE_GIVE_UP_TIMES",
] as const;

let saved: Partial<Record<(typeof ENV_KEYS)[number], string>>;
let dir: string;
let argvLog: string;

const noBiometry: ApprovalDeps = { authenticate: () => Promise.resolve("unavailable") };

/**
 * A resolver that reports exactly one dialog as installed, so a test can pin a
 * backend the way a real host would. There is no environment override any more
 * — that was the vulnerability: the gated process could set it.
 */
const onlyDialog =
  (only: "osascript" | "zenity" | "kdialog") =>
  (cmd: "osascript" | "zenity" | "kdialog"): string | null =>
    cmd === only ? join(FIXTURES, cmd) : null;

/** Linux, with a fixture standing in for one real toolkit. */
const linuxWith = (only: "zenity" | "kdialog"): ApprovalDeps => ({
  authenticate: noBiometry.authenticate,
  platform: () => "linux",
  resolveDialogProgram: onlyDialog(only),
});

const base: ApprovalRequest = {
  action: "run",
  summary: "Run: deploy prod.sh",
  detail: ["Using sets:  prod", "Injects:  API_KEY, DB_PASSWORD"],
  scope: "run:prod",
  ttlSeconds: 900, // -> ttlLabel "Allow 15 min", matched against the fixtures' FAKE_STDOUT below
  // Generous on purpose: `npm test` runs every test file as its own process,
  // all in parallel, so a fake dialog's fork+exec can occasionally take a
  // while under load. The dedicated timeout tests below use their own much
  // shorter value instead of this one.
  timeoutMs: 5000,
};

const argvCalls = (): string[][] =>
  existsSync(argvLog)
    ? readFileSync(argvLog, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l))
    : [];

before(() => {
  // git does not reliably preserve the executable bit across a clone/checkout
  // (test/fixtures/age-plugin-mock has the same guard for the same reason).
  chmodSync(join(FIXTURES, "zenity"), 0o755);
  chmodSync(join(FIXTURES, "kdialog"), 0o755);
});

beforeEach(() => {
  saved = {};
  for (const k of ENV_KEYS) saved[k] = process.env[k];

  dir = mkdtempSync(join(tmpdir(), "hush-approval-"));
  argvLog = join(dir, "argv.log");
  process.env.PATH = `${FIXTURES}:${process.env.PATH ?? ""}`;
  process.env.FAKE_ARGV_LOG = argvLog;
  clearApprovalCache();
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  rmSync(dir, { recursive: true, force: true });
  clearApprovalCache();
});

// ------------------------------------------------------------------ ttlLabel

describe("ttlLabel", () => {
  test("renders minutes, hours and a fallback for zero", () => {
    assert.equal(ttlLabel(900), "Allow 15 min");
    assert.equal(ttlLabel(3600), "Allow 1 hr");
    assert.equal(ttlLabel(7200), "Allow 2 hrs");
    assert.equal(ttlLabel(45), "Allow 45 sec");
    assert.equal(ttlLabel(0), "Allow briefly");
  });

  test("waitingFor reads like a person would say it", () => {
    assert.equal(waitingFor(1000), "1 second");
    assert.equal(waitingFor(45_000), "45 seconds");
    assert.equal(waitingFor(60_000), "1 minute");
    assert.equal(waitingFor(120_000), "2 minutes");
    assert.equal(waitingFor(90_000), "1 min 30 s");
    // Never "0 seconds": a dialog that is about to expire still has a moment.
    assert.equal(waitingFor(0), "1 second");
  });
});

// ------------------------------------------------------- approval decisions

for (const dialog of ["zenity", "kdialog"] as const) {
  describe(`${dialog} backend — approval decisions`, () => {
    const deps = linuxWith(dialog);
    beforeEach(() => {
      process.env.DISPLAY = ":0";
    });

    // zenity's "session" button is its --extra-button, identified by its own
    // label on stdout; kdialog's three-way dialog needs no such trick because
    // each button gets its own exit code.
    const scripts: Record<string, Record<string, string>> = {
      zenity: {
        once: "0",
        deny: "1",
        timeout: "5",
      },
      kdialog: {
        once: "0",
        session: "1",
        deny: "2",
      },
    };

    for (const [decision, exit] of Object.entries(scripts[dialog])) {
      test(`${decision} maps from the scripted exit code`, async () => {
        process.env.FAKE_EXIT = exit;
        if (dialog === "zenity" && decision === "session") process.env.FAKE_STDOUT = ttlLabel(base.ttlSeconds);
        const result = await requestApproval(dir, base, deps);
        assert.equal(result.decision, decision);
        assert.equal(result.via, "dialog");
      });
    }

    if (dialog === "zenity") {
      test("session maps from exit 1 + the extra button's own label on stdout, not exit 1 alone", async () => {
        process.env.FAKE_EXIT = "1";
        process.env.FAKE_STDOUT = ttlLabel(base.ttlSeconds);
        const result = await requestApproval(dir, base, deps);
        assert.equal(result.decision, "session");
      });

      test("a one-shot caller is not offered the longer window, and exit 1 cannot buy one", async () => {
        // sessionGrant: false is what the CLI passes: its grant would die with
        // the command, so the dialog shows Deny / Allow once only. The scripted
        // "extra button" exit must therefore be a refusal, not a session.
        process.env.FAKE_EXIT = "1";
        process.env.FAKE_STDOUT = ttlLabel(base.ttlSeconds);
        const result = await requestApproval(dir, { ...base, sessionGrant: false }, deps);
        assert.equal(result.decision, "deny");
        assert.ok(
          !argvCalls().at(-1)!.includes("--extra-button"),
          "a one-shot approval still offered the session button",
        );
      });
    } else {
      test("timeout comes from the child being killed — kdialog has no dialog-native timeout", async () => {
        process.env.FAKE_SLEEP = "5000";
        const result = await requestApproval(dir, { ...base, timeoutMs: 200 }, deps);
        assert.equal(result.decision, "timeout");
      });
    }

    test("argv carries the approval code, the summary, and every detail line", async () => {
      process.env.FAKE_EXIT = "0";
      const result = await requestApproval(dir, base, deps);
      const joined = argvCalls().at(-1)!.join("");
      assert.ok(joined.includes(result.code), "approval code missing from argv");
      assert.ok(joined.includes(base.summary), "summary missing from argv");
      for (const line of base.detail!) assert.ok(joined.includes(line), `detail line missing from argv: ${line}`);
    });

    test("a live session grant is reused without invoking the dialog again", async () => {
      process.env.FAKE_EXIT = "1";
      if (dialog === "zenity") process.env.FAKE_STDOUT = ttlLabel(base.ttlSeconds);
      const first = await requestApproval(dir, base, deps);
      assert.equal(first.decision, "session");

      const callsBefore = argvCalls().length;
      const second = await requestApproval(dir, base, deps);
      assert.equal(second.cached, true);
      assert.equal(argvCalls().length, callsBefore, "the dialog fired again despite a live grant");
    });
  });

  describe(`${dialog} backend — secret entry`, () => {
    const deps = linuxWith(dialog);
    beforeEach(() => {
      process.env.DISPLAY = ":0";
    });

    test("returns the scripted value", async () => {
      process.env.FAKE_EXIT = "0";
      process.env.FAKE_STDOUT = "sk-fake-token-should-not-leak";
      const res = await promptForSecretNatively("API_KEY", ["why: testing"], undefined, deps);
      assert.equal(res.value, "sk-fake-token-should-not-leak");
      assert.equal(res.cancelled, false);
    });

    test("the value travels through stdout only — never through argv", async () => {
      process.env.FAKE_EXIT = "0";
      process.env.FAKE_STDOUT = "super-secret-do-not-log-me";
      const res = await promptForSecretNatively("API_KEY", ["why: testing"], undefined, deps);
      assert.equal(res.value, "super-secret-do-not-log-me");
      for (const call of argvCalls()) {
        assert.ok(!call.some((a) => a.includes("super-secret-do-not-log-me")), "the secret leaked into argv");
      }
    });

    test("stray stderr text from the dialog never reaches the result", async () => {
      process.env.FAKE_EXIT = "0";
      process.env.FAKE_STDOUT = "";
      process.env.FAKE_STDERR = "gtk-warning: theme not found — should never surface";
      const res = await promptForSecretNatively("API_KEY", [], undefined, deps);
      assert.deepEqual(Object.keys(res).sort(), ["cancelled", "value"]);
      assert.ok(!JSON.stringify(res).includes("gtk-warning"), "stderr text leaked into the result");
    });

    test("an empty entry returns no value, not an error", async () => {
      process.env.FAKE_EXIT = "0";
      process.env.FAKE_STDOUT = "";
      const res = await promptForSecretNatively("API_KEY", [], undefined, deps);
      assert.equal(res.value, null);
      assert.equal(res.cancelled, true);
    });

    test("cancel returns no value, not an error", async () => {
      process.env.FAKE_EXIT = "1";
      // Leftover stdout text on a cancel exit is not something a real zenity/
      // kdialog would print, but scripting it here means this test actually
      // exercises the exit-code check rather than passing vacuously because
      // stdout happened to be empty anyway.
      process.env.FAKE_STDOUT = "leftover-text-a-cancel-must-still-ignore";
      const res = await promptForSecretNatively("API_KEY", [], undefined, deps);
      assert.equal(res.value, null);
      assert.equal(res.cancelled, true);
    });
  });
}

// ----------------------------------------------------------------- selection

describe("darwin backend — a prompt you cannot lose", () => {
  const osascriptDeps = {
    env: {},
    platform: () => "darwin",
    resolveProgram: onlyDialog("osascript"),
  };
  const req = { summary: "Run: deploy.sh", detail: ["Using sets:  prod"], code: "1234", ttlLabel: null };

  test("a window that expires unanswered is presented again, not dropped", async () => {
    // What the human sees today: the dialog is app-modal, so clicking outside
    // can never answer (or dismiss) it, but another window *can* cover it and
    // the prompt's own timer ends the script. Re-presenting it is what makes
    // it persistent — a fresh window in front of them, same request, same
    // code. Here the first two windows "expire" and the third is answered.
    process.env.FAKE_CALL_COUNT = join(dir, "calls");
    process.env.FAKE_GIVE_UP_TIMES = "2";
    process.env.FAKE_STDOUT = "button returned:Allow once";
    process.env.FAKE_EXIT = "0";

    const backend = detectBackend({ ...osascriptDeps, reRaiseMs: 5 })!;
    assert.equal(backend.name, "osascript");
    const decision = await backend.approve(req, 4000);

    assert.equal(decision, "once");
    assert.equal(readFileSync(process.env.FAKE_CALL_COUNT, "utf8"), "3", "the prompt was not re-presented");
    const shown = argvCalls();
    assert.equal(shown.length, 3, "three presentations were not made");
    // Same request, same code, every time — an answer to any of them answers
    // the one request.
    for (const call of shown) {
      assert.ok(call.join(" ").includes("1234"), "the approval code changed between presentations");
      assert.ok(call.join(" ").includes("deploy.sh"), "the request changed between presentations");
    }
  });

  test("it stops at the deadline rather than re-presenting forever", async () => {
    process.env.FAKE_CALL_COUNT = join(dir, "calls2");
    process.env.FAKE_GIVE_UP_TIMES = "1000";
    const started = Date.now();
    const backend = detectBackend({ ...osascriptDeps, reRaiseMs: 5 })!;
    const decision = await backend.approve(req, 150);
    assert.equal(decision, "timeout");
    assert.ok(Date.now() - started < 3000, "the deadline did not bound the loop");
  });

  test("the dialog says how long the human still has", async () => {
    process.env.FAKE_CALL_COUNT = join(dir, "calls3");
    process.env.FAKE_GIVE_UP_TIMES = "0";
    process.env.FAKE_STDOUT = "button returned:Deny";
    const backend = detectBackend({ ...osascriptDeps, reRaiseMs: 60_000 })!;
    assert.equal(await backend.approve(req, 120_000), "deny");
    assert.match(argvCalls().at(-1)!.join(" "), /lapses in 2 minutes/);
  });
});

describe("backend selection", () => {
  test("linux + a display + zenity installed is available, and zenity is preferred over kdialog", () => {
    const backend = detectBackend({
      env: { DISPLAY: ":0" },
      platform: () => "linux",
      resolveProgram: (cmd) => (cmd === "zenity" || cmd === "kdialog" ? join(FIXTURES, cmd) : null),
    });
    assert.equal(backend?.name, "zenity");
  });

  test("linux with no display at all is not available — the queue is used instead", () => {
    const both = (cmd: "osascript" | "zenity" | "kdialog") => join(FIXTURES, cmd);
    const backend = detectBackend({ env: {}, platform: () => "linux", resolveProgram: both });
    assert.equal(backend, null);
    // WAYLAND_DISPLAY counts as a display just as much as DISPLAY does.
    const wayland = detectBackend({
      env: { WAYLAND_DISPLAY: "wayland-0" },
      platform: () => "linux",
      resolveProgram: both,
    });
    assert.equal(wayland?.name, "zenity");
  });

  test("kdialog is used when zenity is not available", () => {
    const backend = detectBackend({
      env: { DISPLAY: ":0" },
      platform: () => "linux",
      resolveProgram: onlyDialog("kdialog"),
    });
    assert.equal(backend?.name, "kdialog");
  });

  test("darwin selects the OS-owned osascript, executed by absolute path", () => {
    const backend = detectBackend({
      env: {},
      platform: () => "darwin",
      resolveProgram: () => "/usr/bin/osascript",
    });
    assert.equal(backend?.name, "osascript");
    assert.equal(backend?.program, "/usr/bin/osascript");
  });

  test("a planted PATH entry and HUSH_DIALOG cannot select the dialog program", () => {
    // The forge this closes: an agent spawns hush with PATH pointing at a
    // directory holding its own `osascript`/`zenity`, and that program used to
    // answer the approval (exit 0 becomes "Allow once"). The program now comes
    // from a fixed OS-owned directory only, so an untrusted one means "no
    // dialog" — and a host that can't show one cannot approve at all.
    const backend = detectBackend({
      env: { PATH: FIXTURES, DISPLAY: ":0", HUSH_DIALOG: "zenity" },
      platform: () => "linux",
      resolveProgram: () => null,
    });
    assert.equal(backend, null, "an untrusted program was selected as the dialog");
  });

  test("the real resolver never selects a program from a writable directory", () => {
    // No injected resolver here: this exercises systemProgram() against the
    // real filesystem. On a host that really has /usr/bin/zenity the backend
    // may legitimately be zenity; what must never happen is that the fixture
    // on PATH is the program that runs.
    const untrusted = mkdtempSync(join(tmpdir(), "hush-approval-untrusted-"));
    try {
      cpSync(join(FIXTURES, "zenity"), join(untrusted, "zenity"));
      chmodSync(join(untrusted, "zenity"), 0o755);
      const backend = detectBackend({ env: { PATH: untrusted, DISPLAY: ":0" }, platform: () => "linux" });
      assert.ok(
        !backend || !backend.program.startsWith(untrusted),
        "a program from a PATH directory was selected as the dialog",
      );
    } finally {
      rmSync(untrusted, { recursive: true, force: true });
    }
  });

  test("a dialog program the caller planted cannot be selected, and its absence is a refusal", () => {
    // The bypass this replaces: HUSH_APPROVAL_MODE=file used to let the gated
    // process swap a real dialog for a file it could answer itself. That switch
    // is gone. HUSH_NO_DIALOG is what exists now, and it can only ever subtract:
    // it says "this host has no desktop", which means the request is refused.
    const withDialog = detectBackend({
      env: { DISPLAY: ":0" },
      platform: () => "darwin",
      resolveProgram: () => "/usr/bin/osascript",
    });
    assert.equal(withDialog?.name, "osascript", "an available dialog was not selected");

    const noDialog = detectBackend({
      env: { DISPLAY: ":0", HUSH_NO_DIALOG: "1" },
      platform: () => "darwin",
      resolveProgram: () => "/usr/bin/osascript",
    });
    assert.equal(noDialog, null, "HUSH_NO_DIALOG did not report the host as having no desktop");
  });

  test("nativeDialogsAvailable() reflects the real host; HUSH_NO_DIALOG can only make it false", () => {
    if (realPlatform() === "darwin") {
      // osascript ships with every Mac, so this machine is always "available".
      // nativeDialogsAvailable() takes no platform override, so this is the one
      // assertion this test can only make about the real host it runs on.
      assert.equal(nativeDialogsAvailable(), true);
    }
    process.env.HUSH_NO_DIALOG = "1";
    assert.equal(nativeDialogsAvailable(), false, "HUSH_NO_DIALOG did not report no desktop");
  });

  test("requestApproval actually drives the backend detectBackend selects (platform injected via ApprovalDeps)", async () => {
    process.env.DISPLAY = ":0";
    process.env.FAKE_EXIT = "0";
    const linuxDeps = linuxWith("zenity");
    const result = await requestApproval(dir, base, linuxDeps);
    assert.equal(result.decision, "once");
    assert.ok(argvCalls().at(-1)!.includes("--question"), "requestApproval did not go through the zenity backend");
  });

  test("a host that can show nothing refuses, and says why, instead of writing a file to answer", async () => {
    // The hole this closes: with no display, hush used to write
    // .hush/pending/<id>.json and accept a matching <id>.answer file. A file is
    // not an approval — the gated process writes it itself — so the request is
    // refused outright there.
    const linuxDeps: ApprovalDeps = { authenticate: noBiometry.authenticate, platform: () => "linux" };
    const result = await requestApproval(dir, { ...base, timeoutMs: 200 }, linuxDeps);

    assert.equal(result.decision, "deny");
    assert.equal(result.via, "none");
    assert.match(result.note ?? "", /no prompt is available/);
    assert.equal(argvCalls().length, 0, "a dialog binary was invoked despite there being no display");
    assert.ok(!existsSync(join(dir, "pending")), "a pending-request file was written");
  });
});
