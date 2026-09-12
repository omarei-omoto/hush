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
  pendingRequests,
  answerRequest,
  type ApprovalDeps,
  type ApprovalRequest,
} from "../src/approval.ts";
import { detectBackend, ttlLabel } from "../src/dialogs.ts";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

// Everything a test might poke, saved and restored around every test so one
// test's HUSH_DIALOG or FAKE_EXIT can never leak into the next.
const ENV_KEYS = [
  "PATH", "HUSH_DIALOG", "HUSH_APPROVAL_MODE", "DISPLAY", "WAYLAND_DISPLAY",
  "FAKE_ARGV_LOG", "FAKE_EXIT", "FAKE_STDOUT", "FAKE_STDERR", "FAKE_SLEEP",
] as const;

let saved: Partial<Record<(typeof ENV_KEYS)[number], string>>;
let dir: string;
let argvLog: string;

const noBiometry: ApprovalDeps = { authenticate: () => Promise.resolve("unavailable") };

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
});

// ------------------------------------------------------- approval decisions

for (const dialog of ["zenity", "kdialog"] as const) {
  describe(`${dialog} backend — approval decisions`, () => {
    beforeEach(() => {
      process.env.HUSH_DIALOG = dialog;
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
        const result = await requestApproval(dir, base, noBiometry);
        assert.equal(result.decision, decision);
        assert.equal(result.via, "dialog");
      });
    }

    if (dialog === "zenity") {
      test("session maps from exit 1 + the extra button's own label on stdout, not exit 1 alone", async () => {
        process.env.FAKE_EXIT = "1";
        process.env.FAKE_STDOUT = ttlLabel(base.ttlSeconds);
        const result = await requestApproval(dir, base, noBiometry);
        assert.equal(result.decision, "session");
      });
    } else {
      test("timeout comes from the child being killed — kdialog has no dialog-native timeout", async () => {
        process.env.FAKE_SLEEP = "5000";
        const result = await requestApproval(dir, { ...base, timeoutMs: 200 }, noBiometry);
        assert.equal(result.decision, "timeout");
      });
    }

    test("argv carries the approval code, the summary, and every detail line", async () => {
      process.env.FAKE_EXIT = "0";
      const result = await requestApproval(dir, base, noBiometry);
      const joined = argvCalls().at(-1)!.join("");
      assert.ok(joined.includes(result.code), "approval code missing from argv");
      assert.ok(joined.includes(base.summary), "summary missing from argv");
      for (const line of base.detail!) assert.ok(joined.includes(line), `detail line missing from argv: ${line}`);
    });

    test("a live session grant is reused without invoking the dialog again", async () => {
      process.env.FAKE_EXIT = "1";
      if (dialog === "zenity") process.env.FAKE_STDOUT = ttlLabel(base.ttlSeconds);
      const first = await requestApproval(dir, base, noBiometry);
      assert.equal(first.decision, "session");

      const callsBefore = argvCalls().length;
      const second = await requestApproval(dir, base, noBiometry);
      assert.equal(second.cached, true);
      assert.equal(argvCalls().length, callsBefore, "the dialog fired again despite a live grant");
    });
  });

  describe(`${dialog} backend — secret entry`, () => {
    beforeEach(() => {
      process.env.HUSH_DIALOG = dialog;
      process.env.DISPLAY = ":0";
    });

    test("returns the scripted value", async () => {
      process.env.FAKE_EXIT = "0";
      process.env.FAKE_STDOUT = "sk-fake-token-should-not-leak";
      const res = await promptForSecretNatively("API_KEY", ["why: testing"]);
      assert.equal(res.value, "sk-fake-token-should-not-leak");
      assert.equal(res.cancelled, false);
    });

    test("the value travels through stdout only — never through argv", async () => {
      process.env.FAKE_EXIT = "0";
      process.env.FAKE_STDOUT = "super-secret-do-not-log-me";
      const res = await promptForSecretNatively("API_KEY", ["why: testing"]);
      assert.equal(res.value, "super-secret-do-not-log-me");
      for (const call of argvCalls()) {
        assert.ok(!call.some((a) => a.includes("super-secret-do-not-log-me")), "the secret leaked into argv");
      }
    });

    test("stray stderr text from the dialog never reaches the result", async () => {
      process.env.FAKE_EXIT = "0";
      process.env.FAKE_STDOUT = "";
      process.env.FAKE_STDERR = "gtk-warning: theme not found — should never surface";
      const res = await promptForSecretNatively("API_KEY", []);
      assert.deepEqual(Object.keys(res).sort(), ["cancelled", "value"]);
      assert.ok(!JSON.stringify(res).includes("gtk-warning"), "stderr text leaked into the result");
    });

    test("an empty entry returns no value, not an error", async () => {
      process.env.FAKE_EXIT = "0";
      process.env.FAKE_STDOUT = "";
      const res = await promptForSecretNatively("API_KEY", []);
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
      const res = await promptForSecretNatively("API_KEY", []);
      assert.equal(res.value, null);
      assert.equal(res.cancelled, true);
    });
  });
}

// ----------------------------------------------------------------- selection

describe("backend selection", () => {
  test("linux + a display + zenity on PATH is available, and zenity is preferred over kdialog", () => {
    const backend = detectBackend({ env: { PATH: process.env.PATH, DISPLAY: ":0" }, platform: () => "linux" });
    assert.equal(backend?.name, "zenity");
  });

  test("linux with no display at all is not available — the queue is used instead", () => {
    const backend = detectBackend({ env: { PATH: process.env.PATH }, platform: () => "linux" });
    assert.equal(backend, null);
    // WAYLAND_DISPLAY counts as a display just as much as DISPLAY does.
    const wayland = detectBackend({ env: { PATH: process.env.PATH, WAYLAND_DISPLAY: "wayland-0" }, platform: () => "linux" });
    assert.equal(wayland?.name, "zenity");
  });

  test("HUSH_DIALOG=kdialog picks kdialog even though zenity is also on PATH", () => {
    const backend = detectBackend({
      env: { PATH: process.env.PATH, DISPLAY: ":0", HUSH_DIALOG: "kdialog" },
      platform: () => "linux",
    });
    assert.equal(backend?.name, "kdialog");
  });

  test("darwin selects osascript unconditionally, matching the pre-refactor behaviour", () => {
    // Unlike zenity/kdialog, osascript is never PATH-checked: every Mac ships
    // it, and the original `useNativeDialogs` never checked for it either.
    const backend = detectBackend({ env: {}, platform: () => "darwin" });
    assert.equal(backend?.name, "osascript");
  });

  test("HUSH_DIALOG naming a backend that isn't on PATH falls through to the platform default", () => {
    // A typo'd or half-installed override should degrade to whatever the
    // platform would otherwise pick, not strand the human with no dialog.
    const onlyZenity = mkdtempSync(join(tmpdir(), "hush-approval-onlyzenity-"));
    try {
      cpSync(join(FIXTURES, "zenity"), join(onlyZenity, "zenity"));
      chmodSync(join(onlyZenity, "zenity"), 0o755);
      const backend = detectBackend({
        env: { PATH: onlyZenity, DISPLAY: ":0", HUSH_DIALOG: "kdialog" },
        platform: () => "linux",
      });
      assert.equal(backend?.name, "zenity", "an unavailable forced backend did not fall through");
    } finally {
      rmSync(onlyZenity, { recursive: true, force: true });
    }
  });

  test("HUSH_APPROVAL_MODE=file wins over everything, including an explicit HUSH_DIALOG", () => {
    const backend = detectBackend({
      env: { PATH: process.env.PATH, DISPLAY: ":0", HUSH_DIALOG: "zenity", HUSH_APPROVAL_MODE: "file" },
      platform: () => "darwin",
    });
    assert.equal(backend, null);
  });

  test("nativeDialogsAvailable() reflects the real host, and HUSH_APPROVAL_MODE=file forces it false everywhere", () => {
    if (realPlatform() === "darwin") {
      // osascript ships with every Mac, so this machine is always "available"
      // unless the file mode is forced — nativeDialogsAvailable() takes no
      // platform override, so this is the one assertion this test can only
      // make about the real host it happens to run on.
      assert.equal(nativeDialogsAvailable(), true);
    }
    process.env.HUSH_APPROVAL_MODE = "file";
    assert.equal(nativeDialogsAvailable(), false, "HUSH_APPROVAL_MODE=file did not force the queue");
  });

  test("requestApproval actually drives the backend detectBackend selects (platform injected via ApprovalDeps)", async () => {
    process.env.DISPLAY = ":0";
    process.env.FAKE_EXIT = "0";
    const linuxDeps: ApprovalDeps = { authenticate: noBiometry.authenticate, platform: () => "linux" };
    const result = await requestApproval(dir, base, linuxDeps);
    assert.equal(result.decision, "once");
    assert.ok(argvCalls().at(-1)!.includes("--question"), "requestApproval did not go through the zenity backend");
  });

  test("no display makes requestApproval fall back to the file queue on a simulated Linux host", async () => {
    const linuxDeps: ApprovalDeps = { authenticate: noBiometry.authenticate, platform: () => "linux" };
    const pending = requestApproval(dir, { ...base, timeoutMs: 5000 }, linuxDeps);

    let seen: ReturnType<typeof pendingRequests> = [];
    for (let i = 0; i < 40 && !seen.length; i++) {
      seen = pendingRequests(dir);
      if (!seen.length) await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(seen.length, 1, "no request file appeared — a dialog fired instead of the queue");
    answerRequest(dir, seen[0].id, "once");

    const result = await pending;
    assert.equal(result.decision, "once");
    assert.equal(result.via, "terminal");
    assert.equal(argvCalls().length, 0, "a dialog binary was invoked despite there being no display");
  });
});
