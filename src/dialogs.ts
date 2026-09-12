/**
 * One native dialog backend per desktop toolkit, behind a single shape so
 * approval.ts never has to know which is in front of the human.
 *
 * osascript is macOS's own scripting host. zenity (GNOME/GTK) and kdialog
 * (KDE) are Linux's answers to "pop up a dialog from a shell command" — there
 * is no single standard, so both are supported and picked by what is actually
 * installed. Selection happens in `detectBackend`, which is a pure function of
 * its inputs (env vars, a PATH string, an injected `platform()`) rather than
 * reading `process.env`/`os.platform()` itself, so a test can simulate "Linux
 * with a display" from this Mac and Linux CI can run the same suite with no
 * display at all — see test/approval.test.ts.
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { delimiter, join as joinPath } from "node:path";
import type { Decision, SecretEntryResult } from "./approval.ts";

export interface DialogBackend {
  name: "osascript" | "zenity" | "kdialog";
  approve(
    req: { summary: string; detail: string[]; code: string; ttlLabel: string },
    timeoutMs: number,
  ): Promise<Decision>;
  enterSecret(
    req: { title: string; lines: string[]; label: string },
    timeoutMs: number,
  ): Promise<SecretEntryResult>;
}

interface RunResult {
  /** false for a non-zero exit, a killed process, or a spawn failure. */
  ok: boolean;
  /** The child's exit code, or null when it never produced one (killed / spawn error). */
  code: number | null;
  /** Node's own `timeout` option fired — the one timeout signal every backend shares, since only zenity has a native dialog timeout of its own. */
  killed: boolean;
  out: string;
  err: string;
}

function run(cmd: string, args: string[], timeoutMs: number): Promise<RunResult> {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: timeoutMs, maxBuffer: 1 << 20 }, (err, stdout, stderr) => {
      const e = err as (NodeJS.ErrnoException & { code?: number | string; killed?: boolean }) | null;
      resolve({
        ok: !e,
        code: e && typeof e.code === "number" ? e.code : e ? null : 0,
        killed: Boolean(e?.killed),
        out: String(stdout ?? "").trim(),
        err: String(stderr ?? "").trim(),
      });
    });
  });
}

/**
 * Is `cmd` an executable file somewhere on `pathEnv`? A hand-rolled lookup
 * rather than shelling out to `which` — which is not itself guaranteed to
 * exist — and one that reads its PATH from a parameter rather than
 * `process.env` directly, so `detectBackend` stays a pure function tests can
 * drive with a fake PATH without mutating the real environment.
 */
function onPath(cmd: string, pathEnv: string | undefined): boolean {
  for (const dir of (pathEnv ?? "").split(delimiter)) {
    if (dir && existsSync(joinPath(dir, cmd))) return true;
  }
  return false;
}

/** AppleScript string literal escaping. */
const asStr = (s: string): string => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

// ------------------------------------------------------------- osascript
//
// Byte-for-byte the same two AppleScript strings hush has always sent to
// osascript — only the plumbing around them moved when this file split out
// of approval.ts. `ttlLabel` is deliberately ignored: this script has always
// said "Allow 15 min" regardless of the configured TTL, and changing that
// text now would be a silent behaviour change to the one backend that was
// already shipped, not a fix.

const osascriptBackend: DialogBackend = {
  name: "osascript",
  async approve(req, timeoutMs) {
    const body = [req.summary, "", ...req.detail, "", `Approval code: ${req.code}`].join("\n");
    const script =
      `display dialog ${asStr(body)} with title ${asStr("hush — approve this?")} ` +
      `buttons {"Deny", "Allow once", "Allow 15 min"} default button "Allow once" ` +
      `with icon caution giving up after ${Math.floor(timeoutMs / 1000)}`;

    const { ok, out } = await run("osascript", ["-e", script], timeoutMs + 2000);
    if (!ok) return "timeout";
    if (/gave up:true/.test(out)) return "timeout";
    if (/button returned:Allow 15 min/.test(out)) return "session";
    if (/button returned:Allow once/.test(out)) return "once";
    return "deny";
  },

  async enterSecret(req, timeoutMs) {
    const body = [...req.lines, "", `Paste the value for ${req.label}:`].join("\n");
    const script =
      `display dialog ${asStr(body)} with title ${asStr(req.title)} ` +
      `default answer "" with hidden answer ` +
      `buttons {"Cancel", "Save"} default button "Save" with icon note ` +
      `giving up after ${Math.floor(timeoutMs / 1000)}`;

    const { ok, out } = await run("osascript", ["-e", script], timeoutMs + 2000);
    if (!ok || /gave up:true/.test(out) || /button returned:Cancel/.test(out)) {
      return { value: null, cancelled: true };
    }
    // `button returned:Save, text returned:<value>, gave up:false`
    const m = out.match(/text returned:([\s\S]*?)(?:, gave up:(?:true|false))?$/);
    const value = m ? m[1] : "";
    return { value: value || null, cancelled: !value };
  },
};

// ----------------------------------------------------------------- zenity
//
// `--question` exits 0 for its OK button, 1 for Cancel or the window being
// closed, and 5 when `--timeout` elapses (all three documented on the zenity
// man page). A third choice needs `--extra-button`, whose click is *also*
// reported as exit 1 — zenity's only way to tell "Allow 15 min" apart from a
// plain Deny is that the extra button's own label is written to stdout before
// it exits, so that is what distinguishes the two exit-1 cases below.

const zenityBackend: DialogBackend = {
  name: "zenity",
  async approve(req, timeoutMs) {
    const body = [req.summary, "", ...req.detail, "", `Approval code: ${req.code}`].join("\n");
    const args = [
      "--question",
      "--title", "hush — approve this?",
      "--text", body,
      "--ok-label", "Allow once",
      "--cancel-label", "Deny",
      "--extra-button", req.ttlLabel,
      "--timeout", String(Math.max(1, Math.floor(timeoutMs / 1000))),
    ];
    const { killed, code, out } = await run("zenity", args, timeoutMs + 2000);
    if (killed || code === 5) return "timeout";
    if (code === 0) return "once";
    if (code === 1 && out === req.ttlLabel) return "session";
    return "deny";
  },

  async enterSecret(req, timeoutMs) {
    const body = [...req.lines, "", `Paste the value for ${req.label}:`].join("\n");
    const args = [
      "--entry", "--hide-text",
      "--title", req.title,
      "--text", body,
      "--timeout", String(Math.max(1, Math.floor(timeoutMs / 1000))),
    ];
    const { ok, killed, out } = await run("zenity", args, timeoutMs + 2000);
    if (killed || !ok) return { value: null, cancelled: true };
    return { value: out || null, cancelled: !out };
  },
};

// ---------------------------------------------------------------- kdialog
//
// `--yesnocancel` is KDE's closest three-way dialog: exit 0/1/2 for
// Yes/No/Cancel, relabelled below to the same three actions zenity and
// osascript offer. Unlike zenity, kdialog has no dialog-native timeout (only
// `--passivepopup`, a non-interactive notification, takes one) so a timeout
// here can only ever be node's own `timeout` killing the process.

const kdialogBackend: DialogBackend = {
  name: "kdialog",
  async approve(req, timeoutMs) {
    const body = [req.summary, "", ...req.detail, "", `Approval code: ${req.code}`].join("\n");
    const args = [
      "--title", "hush — approve this?",
      "--yesnocancel", body,
      "--yes-label", "Allow once",
      "--no-label", req.ttlLabel,
      "--cancel-label", "Deny",
    ];
    const { killed, code } = await run("kdialog", args, timeoutMs);
    if (killed) return "timeout";
    if (code === 0) return "once";
    if (code === 1) return "session";
    return "deny"; // code 2 (Cancel), or anything else kdialog might ever return
  },

  async enterSecret(req, timeoutMs) {
    const body = [...req.lines, "", `Paste the value for ${req.label}:`].join("\n");
    const args = ["--title", req.title, "--password", body];
    const { ok, killed, out } = await run("kdialog", args, timeoutMs);
    if (killed || !ok) return { value: null, cancelled: true };
    return { value: out || null, cancelled: !out };
  },
};

const BACKENDS = { osascript: osascriptBackend, zenity: zenityBackend, kdialog: kdialogBackend } as const;

/** The real-world facts `detectBackend` needs, each supplied by the caller rather than read globally — see the file header. */
export interface DialogEnv {
  env: NodeJS.ProcessEnv;
  platform: () => string;
}

/**
 * Which backend answers a dialog request, or null for the file queue.
 *
 * `HUSH_DIALOG` forcing a backend that turns out not to be on PATH falls
 * through to the platform default rather than straight to the queue: a typo'd
 * or half-installed override should degrade, not strand someone who could
 * otherwise still get a dialog.
 */
export function detectBackend(opts: DialogEnv): DialogBackend | null {
  const { env } = opts;
  if (env.HUSH_APPROVAL_MODE === "file") return null;

  const forced = env.HUSH_DIALOG;
  if ((forced === "osascript" || forced === "zenity" || forced === "kdialog") && onPath(forced, env.PATH)) {
    return BACKENDS[forced];
  }

  const plat = opts.platform();
  if (plat === "darwin") return osascriptBackend;
  if (plat === "linux") {
    if (!(env.DISPLAY || env.WAYLAND_DISPLAY)) return null;
    if (onPath("zenity", env.PATH)) return zenityBackend;
    if (onPath("kdialog", env.PATH)) return kdialogBackend;
    return null;
  }
  return null;
}

/** "900 seconds" -> "Allow 15 min", the button text a backend shows for a session grant, computed from the policy's actual TTL rather than a hardcoded guess. */
export function ttlLabel(ttlSeconds: number): string {
  if (ttlSeconds > 0 && ttlSeconds % 3600 === 0) {
    const hours = ttlSeconds / 3600;
    return `Allow ${hours} hr${hours === 1 ? "" : "s"}`;
  }
  if (ttlSeconds > 0 && ttlSeconds % 60 === 0) return `Allow ${ttlSeconds / 60} min`;
  return ttlSeconds > 0 ? `Allow ${ttlSeconds} sec` : "Allow briefly";
}
