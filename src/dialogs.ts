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
import { statSync } from "node:fs";
import { join as joinPath } from "node:path";
import type { Decision, SecretEntryResult } from "./approval.ts";
import { powershellPath } from "./platform.ts";

/** The dialog toolkits hush knows how to drive. */
export type BackendName = "osascript" | "zenity" | "kdialog" | "powershell";

export interface DialogBackend {
  name: BackendName;
  /**
   * The absolute path of the program this backend starts.
   *
   * Absolute on purpose. `execFile` resolves a bare name through the PATH of
   * the process doing the exec, and that process is spawned by whoever asked
   * for the approval — an agent can put a file called `osascript` first on PATH
   * and answer its own gate. See systemProgram().
   */
  program: string;
  approve(
    req: { summary: string; detail: string[]; code: string; ttlLabel: string | null },
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
    execFile(cmd, args, { timeout: timeoutMs, maxBuffer: 1 << 20, windowsHide: true }, (err, stdout, stderr) => {
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
 * Where a dialog program is allowed to live.
 *
 * Fixed, OS-owned directories only. A dialog program looked up on the caller's
 * PATH is a program the caller can supply, and the caller is the process being
 * gated.
 */
const SYSTEM_BIN_DIRS = ["/usr/bin", "/bin", "/usr/local/bin"] as const;

/**
 * Resolve a dialog program to a path this process can trust, or null.
 *
 * An approval is only worth anything if the thing that collects it cannot be
 * chosen by the principal it constrains. A bare name is resolved through PATH,
 * which the gated caller controls, so:
 *
 *   - the lookup is confined to fixed OS-owned directories,
 *   - the file must be a regular file owned by root and not writable by group
 *     or others (so it is not something the user, or the agent running as the
 *     user, could have replaced), and
 *   - it is always executed by absolute path.
 *
 * Anything else returns null, which means "no dialog": the request falls
 * through to the pending-request queue the human answers in their own terminal.
 * That is a worse experience and a much better boundary.
 */
function systemProgram(cmd: BackendName): string | null {
  // Windows: %SystemRoot%\System32, which an ordinary user cannot write.
  if (cmd === "powershell") return process.platform === "win32" ? powershellPath() : null;
  for (const dir of SYSTEM_BIN_DIRS) {
    const path = joinPath(dir, cmd);
    try {
      const st = statSync(path);
      if (!st.isFile()) continue;
      if (st.uid !== 0) continue;
      if ((st.mode & 0o022) !== 0) continue;
      return path;
    } catch {
      /* not installed in this directory */
    }
  }
  return null;
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

/**
 * How long a single macOS dialog is shown before it is re-presented.
 *
 * A dialog reports "gave up" when its own timer expires with nobody having
 * picked a button, and then the script ends. Re-presenting it is what keeps
 * the prompt in front of the human: `display dialog` is app-modal (a click
 * outside never answers it, and never dismisses it) but another window can
 * still cover it, and a prompt quietly behind something is a prompt nobody
 * sees. Each presentation is a fresh window that comes to the front, with the
 * same request, the same code and the same remaining time, so an answer to
 * any of them is the answer.
 */
const RE_RAISE_MS = 45_000;

/** "1 min 30 s" — how much longer the human has, for the dialog's own text. */
export function waitingFor(ms: number): string {
  const s = Math.max(1, Math.round(ms / 1000));
  if (s < 60) return s === 1 ? "1 second" : `${s} seconds`;
  if (s % 60 === 0) return `${s / 60} minute${s / 60 === 1 ? "" : "s"}`;
  return `${Math.floor(s / 60)} min ${s % 60} s`;
}

const makeOsascriptBackend = (program: string, reRaiseMs = RE_RAISE_MS): DialogBackend => ({
  name: "osascript",
  program,
  async approve(req, timeoutMs) {
    // A one-shot caller (sessionGrant false) gets two buttons: offering a
    // longer window it cannot honour would be a lie, not a convenience.
    const buttons = req.ttlLabel
      ? `{"Deny", "Allow once", "Allow 15 min"}`
      : `{"Deny", "Allow once"}`;
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      const left = deadline - Date.now();
      const slice = Math.min(reRaiseMs, left);
      const body = [
        req.summary, "", ...req.detail, "",
        `Approval code: ${req.code}`,
        `Waiting for you — this request lapses in ${waitingFor(left)}.`,
      ].join("\n");
      const script =
        `display dialog ${asStr(body)} with title ${asStr("hush — approve this?")} ` +
        `buttons ${buttons} default button "Allow once" ` +
        `with icon caution giving up after ${Math.max(1, Math.ceil(slice / 1000))}`;

      const { ok, killed, out } = await run(program, ["-e", script], slice + 2000);
      if (ok) {
        // The window expired on its own and nobody has answered, so put it back
        // in front of them rather than letting it disappear.
        if (/gave up:true/.test(out)) continue;
        if (req.ttlLabel && /button returned:Allow 15 min/.test(out)) return "session";
        if (/button returned:Allow once/.test(out)) return "once";
        return "deny";
      }
      // Our own kill of a dialog that outlived its slice: show it again.
      if (killed) continue;
      // osascript itself could not run — no dialog can be shown at all.
      return "timeout";
    }
    return "timeout";
  },

  async enterSecret(req, timeoutMs) {
    // Deliberately not sliced like the approval dialog above: this one is a
    // blank field the human types into, and re-presenting it would throw away
    // whatever they had already entered. One long window is the safe shape.
    const body = [...req.lines, "", `Paste the value for ${req.label}:`].join("\n");
    const script =
      `display dialog ${asStr(body)} with title ${asStr(req.title)} ` +
      `default answer "" with hidden answer ` +
      `buttons {"Cancel", "Save"} default button "Save" with icon note ` +
      `giving up after ${Math.floor(timeoutMs / 1000)}`;

    const { ok, out } = await run(program, ["-e", script], timeoutMs + 2000);
    if (!ok || /gave up:true/.test(out) || /button returned:Cancel/.test(out)) {
      return { value: null, cancelled: true };
    }
    // `button returned:Save, text returned:<value>, gave up:false`
    const m = out.match(/text returned:([\s\S]*?)(?:, gave up:(?:true|false))?$/);
    const value = m ? m[1] : "";
    return { value: value || null, cancelled: !value };
  },
});

// ----------------------------------------------------------------- zenity
//
// `--question` exits 0 for its OK button, 1 for Cancel or the window being
// closed, and 5 when `--timeout` elapses (all three documented on the zenity
// man page). A third choice needs `--extra-button`, whose click is *also*
// reported as exit 1 — zenity's only way to tell "Allow 15 min" apart from a
// plain Deny is that the extra button's own label is written to stdout before
// it exits, so that is what distinguishes the two exit-1 cases below.

const makeZenityBackend = (program: string): DialogBackend => ({
  name: "zenity",
  program,
  async approve(req, timeoutMs) {
    const body = [req.summary, "", ...req.detail, "", `Approval code: ${req.code}`].join("\n");
    const args = [
      "--question",
      "--title", "hush — approve this?",
      "--text", body,
      "--ok-label", "Allow once",
      "--cancel-label", "Deny",
      ...(req.ttlLabel ? ["--extra-button", req.ttlLabel] : []),
      "--timeout", String(Math.max(1, Math.floor(timeoutMs / 1000))),
    ];
    const { killed, code, out } = await run(program, args, timeoutMs + 2000);
    if (killed || code === 5) return "timeout";
    if (code === 0) return "once";
    if (req.ttlLabel && code === 1 && out === req.ttlLabel) return "session";
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
    const { ok, killed, out } = await run(program, args, timeoutMs + 2000);
    if (killed || !ok) return { value: null, cancelled: true };
    return { value: out || null, cancelled: !out };
  },
});

// ---------------------------------------------------------------- kdialog
//
// `--yesnocancel` is KDE's closest three-way dialog: exit 0/1/2 for
// Yes/No/Cancel, relabelled below to the same three actions zenity and
// osascript offer. Unlike zenity, kdialog has no dialog-native timeout (only
// `--passivepopup`, a non-interactive notification, takes one) so a timeout
// here can only ever be node's own `timeout` killing the process.

const makeKdialogBackend = (program: string): DialogBackend => ({
  name: "kdialog",
  program,
  async approve(req, timeoutMs) {
    const body = [req.summary, "", ...req.detail, "", `Approval code: ${req.code}`].join("\n");
    const args = [
      "--title", "hush — approve this?",
      "--yesnocancel", body,
      "--yes-label", "Allow once",
      "--no-label", req.ttlLabel ?? "Deny",
      "--cancel-label", "Deny",
    ];
    const { killed, code } = await run(program, args, timeoutMs);
    if (killed) return "timeout";
    if (code === 0) return "once";
    if (code === 1) return req.ttlLabel ? "session" : "deny";
    return "deny"; // code 2 (Cancel), or anything else kdialog might ever return
  },

  async enterSecret(req, timeoutMs) {
    const body = [...req.lines, "", `Paste the value for ${req.label}:`].join("\n");
    const args = ["--title", req.title, "--password", body];
    const { ok, killed, out } = await run(program, args, timeoutMs);
    if (killed || !ok) return { value: null, cancelled: true };
    return { value: out || null, cancelled: !out };
  },
});

// ------------------------------------------------------------- powershell
//
// Windows (F-7, beta). A WinForms window from Windows PowerShell 5.1, which
// every supported Windows ships. The request travels as base64 JSON inside
// -EncodedCommand, so no text from it is ever quoted into a script or a
// command line; the window is top-most, re-raised if it loses the front, and
// closes itself when the wait runs out. A typed secret comes back on stdout,
// never through argv.

const psPayload = (x: unknown): string => Buffer.from(JSON.stringify(x), "utf8").toString("base64");
const encoded = (script: string): string => Buffer.from(script, "utf16le").toString("base64");

/** The approval script. Prints once, session, deny or timeout. Exported for tests. */
export function powershellApprovalScript(
  req: { summary: string; detail: string[]; code: string; ttlLabel: string | null },
  timeoutMs: number,
): string {
  const payload = psPayload({
    title: "hush — approve this?",
    body: [req.summary, "", ...req.detail, "", `Approval code: ${req.code}`].join("\r\n"),
    ttl: req.ttlLabel,
    ms: Math.max(1000, timeoutMs),
  });
  return `$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
$r = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}')) | ConvertFrom-Json
$f = New-Object Windows.Forms.Form -Property @{ Text=$r.title; TopMost=$true; StartPosition='CenterScreen'; FormBorderStyle='FixedDialog'; MaximizeBox=$false; MinimizeBox=$false; ControlBox=$false; AutoSize=$true; AutoSizeMode='GrowAndShrink'; Padding=12 }
$l = New-Object Windows.Forms.Label -Property @{ Text=$r.body; AutoSize=$true; MaximumSize=(New-Object Drawing.Size 520,0) }
$p = New-Object Windows.Forms.FlowLayoutPanel -Property @{ FlowDirection='TopDown'; AutoSize=$true }
$b = New-Object Windows.Forms.FlowLayoutPanel -Property @{ FlowDirection='RightToLeft'; AutoSize=$true; Dock='Fill' }
$script:answer = 'timeout'
function Add-Choice($text, $value) { $x = New-Object Windows.Forms.Button -Property @{ Text=$text; AutoSize=$true }; $x.Add_Click({ $script:answer = $value; $f.Close() }.GetNewClosure()); $b.Controls.Add($x) | Out-Null; $x }
if ($r.ttl) { Add-Choice $r.ttl 'session' | Out-Null }
$once = Add-Choice 'Allow once' 'once'
Add-Choice 'Deny' 'deny' | Out-Null
$p.Controls.Add($l) | Out-Null; $p.Controls.Add($b) | Out-Null; $f.Controls.Add($p) | Out-Null
$f.AcceptButton = $once
$t = New-Object Windows.Forms.Timer -Property @{ Interval=$r.ms }
$t.Add_Tick({ $t.Stop(); $f.Close() })
$raise = New-Object Windows.Forms.Timer -Property @{ Interval=45000 }
$raise.Add_Tick({ $f.TopMost = $true; $f.Activate() })
$f.Add_Shown({ $t.Start(); $raise.Start(); $f.Activate() })
[void]$f.ShowDialog()
[Console]::Out.Write($script:answer)`;
}

/** The secret-entry script. Prints the value, or nothing when cancelled. Exported for tests. */
export function powershellSecretScript(req: { title: string; lines: string[]; label: string }, timeoutMs: number): string {
  const payload = psPayload({
    title: req.title,
    body: [...req.lines, "", `Paste the value for ${req.label}:`].join("\r\n"),
    ms: Math.max(1000, timeoutMs),
  });
  return `$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
$r = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payload}')) | ConvertFrom-Json
$f = New-Object Windows.Forms.Form -Property @{ Text=$r.title; TopMost=$true; StartPosition='CenterScreen'; FormBorderStyle='FixedDialog'; MaximizeBox=$false; MinimizeBox=$false; AutoSize=$true; AutoSizeMode='GrowAndShrink'; Padding=12 }
$p = New-Object Windows.Forms.FlowLayoutPanel -Property @{ FlowDirection='TopDown'; AutoSize=$true }
$l = New-Object Windows.Forms.Label -Property @{ Text=$r.body; AutoSize=$true; MaximumSize=(New-Object Drawing.Size 520,0) }
$x = New-Object Windows.Forms.TextBox -Property @{ UseSystemPasswordChar=$true; Width=480 }
$save = New-Object Windows.Forms.Button -Property @{ Text='Save'; DialogResult='OK' }
$cancel = New-Object Windows.Forms.Button -Property @{ Text='Cancel'; DialogResult='Cancel' }
$p.Controls.AddRange(@($l, $x, $save, $cancel)); $f.Controls.Add($p) | Out-Null
$f.AcceptButton = $save; $f.CancelButton = $cancel
$t = New-Object Windows.Forms.Timer -Property @{ Interval=$r.ms }
$t.Add_Tick({ $t.Stop(); $f.DialogResult = 'Cancel'; $f.Close() })
$f.Add_Shown({ $t.Start(); $f.Activate(); $x.Focus() })
if ($f.ShowDialog() -eq 'OK') { [Console]::Out.Write($x.Text) }`;
}

const psArgs = (script: string): string[] =>
  ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-STA", "-EncodedCommand", encoded(script)];

const makePowershellBackend = (program: string): DialogBackend => ({
  name: "powershell",
  program,
  async approve(req, timeoutMs) {
    const { ok, killed, out } = await run(program, psArgs(powershellApprovalScript(req, timeoutMs)), timeoutMs + 15_000);
    if (killed || !ok) return "timeout";
    if (out === "once") return "once";
    if (out === "session" && req.ttlLabel) return "session";
    if (out === "timeout") return "timeout";
    return "deny";
  },
  async enterSecret(req, timeoutMs) {
    const { ok, killed, out } = await run(program, psArgs(powershellSecretScript(req, timeoutMs)), timeoutMs + 15_000);
    // run() trims; a secret's own surrounding whitespace is not something a
    // pasted API key carries.
    if (killed || !ok || !out) return { value: null, cancelled: true };
    return { value: out, cancelled: false };
  },
});

/** The real-world facts `detectBackend` needs, each supplied by the caller rather than read globally — see the file header. */
export interface DialogEnv {
  env: NodeJS.ProcessEnv;
  platform: () => string;
  /**
   * Seam for tests, never for production: resolve a program name to a trusted
   * absolute path.
   *
   * A parameter rather than an environment variable on purpose. `HUSH_DIALOG`
   * used to force a backend, which meant `HUSH_DIALOG=zenity` plus a planted
   * file on PATH was enough for the gated process to answer its own approval —
   * an ambient switch that anything running as the user, an agent included,
   * could set. Tests can still drive every branch by passing this in.
   */
  resolveProgram?: (cmd: BackendName) => string | null;
  /**
   * Seam for tests: how long one macOS presentation lasts before it is shown
   * again. Production uses RE_RAISE_MS.
   */
  reRaiseMs?: number;
}

/**
 * Which backend answers a dialog request, or null for "nothing can".
 *
 * The program is resolved by `systemProgram` (or by the injected test seam), so
 * a caller-supplied PATH entry or binary can never be the thing that draws the
 * approval dialog. When no trusted program exists the answer is null, and
 * approval.ts refuses the request: there is no second channel that could prove
 * a human was there, and a file the gated process can write is not one.
 */
export function detectBackend(opts: DialogEnv): DialogBackend | null {
  const { env } = opts;

  // HUSH_APPROVAL_MODE=file used to live here, and it was a bypass: the only
  // process that can set the environment is the one being gated, so "force the
  // terminal flow" meant "swap the dialog for a file I can answer myself".
  //
  // What replaces it narrows rather than widens. HUSH_NO_DIALOG says "this host
  // has no desktop": hush then has nothing to put in front of a human and
  // refuses the request. Setting it can only make an approval fail, never
  // succeed, which is the property HUSH_APPROVAL_MODE never had.
  if (env.HUSH_NO_DIALOG === "1") return null;

  const resolve = opts.resolveProgram ?? systemProgram;
  const plat = opts.platform();
  if (plat === "darwin") {
    const program = resolve("osascript");
    return program ? makeOsascriptBackend(program, opts.reRaiseMs) : null;
  }
  if (plat === "linux") {
    if (!(env.DISPLAY || env.WAYLAND_DISPLAY)) return null;
    const zenity = resolve("zenity");
    if (zenity) return makeZenityBackend(zenity);
    const kdialog = resolve("kdialog");
    if (kdialog) return makeKdialogBackend(kdialog);
    return null;
  }
  if (plat === "win32") {
    const ps = resolve("powershell");
    return ps ? makePowershellBackend(ps) : null;
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
