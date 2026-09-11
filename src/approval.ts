/**
 * Human-in-the-loop approval, and secret entry that bypasses the chat.
 *
 * Two problems this solves:
 *
 *  1. An agent asking for a credential normally means the human pastes it into
 *     the conversation — where it is now in the transcript, the provider's logs,
 *     and anything downstream. Instead the agent asks hush, hush opens a native
 *     secure-input dialog on the human's screen, and the value goes from the
 *     keyboard into the vault without passing through the model at all.
 *
 *  2. A tool call that uses a live credential should be a decision the human
 *     makes, not something that happens silently. Every gated action shows a
 *     dialog naming exactly what will run, with a short code that also appears
 *     in the agent's tool result — so the transcript and the screen can be
 *     checked against each other.
 *
 * macOS gets native dialogs. Everywhere else falls back to a pending-request
 * file that the human resolves with `hush approve` in their own terminal.
 */
import { execFile } from "node:child_process";
import { randomInt } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { platform } from "node:os";
import { authenticate, type BiometryMode, type BiometryResult } from "./biometry.ts";

export type Decision = "once" | "session" | "deny" | "timeout";

export interface ApprovalRequest {
  /** "run" | "add" | "reveal" — matched against policy.requireApproval. */
  action: string;
  /** One line naming exactly what will happen. */
  summary: string;
  /** Extra context lines shown in the dialog. */
  detail?: string[];
  /** Grace-cache key, e.g. "run:fal/acme". */
  scope: string;
  /** How long a "session" approval lasts. */
  ttlSeconds: number;
  timeoutMs?: number;
  /**
   * "required" — only a fingerprint approves; refuse if biometry is unavailable.
   * "preferred" — fingerprint if possible, otherwise the click dialog.
   * "off" — click dialog only.
   */
  biometry?: BiometryMode;
}

export interface ApprovalResult {
  decision: Decision;
  code: string;
  cached: boolean;
  /** How the human actually approved, for the audit log. */
  via: "biometry" | "dialog" | "terminal" | "cache" | "none";
  note?: string;
}

/**
 * Evaluated per call, not at import: HUSH_APPROVAL_MODE=file forces the terminal
 * flow, and tests set it after this module is already loaded.
 */
const useNativeDialogs = (): boolean =>
  platform() === "darwin" && process.env.HUSH_APPROVAL_MODE !== "file";

/**
 * scope -> epoch ms when the session approval lapses. Process-lifetime only.
 * Keys include the vault directory: two vaults both using scope "run:default"
 * must not share a grant.
 */
const granted = new Map<string, number>();

const grantKey = (hushDir: string, scope: string): string => `${hushDir}\u0000${scope}`;

/** Test seam: forget every cached approval. */
export const clearApprovalCache = (): void => void granted.clear();

const newCode = (): string => String(randomInt(1000, 10000));

function run(cmd: string, args: string[], timeoutMs: number): Promise<{ ok: boolean; out: string }> {
  return new Promise((res) => {
    execFile(cmd, args, { timeout: timeoutMs, maxBuffer: 1 << 20 }, (err, stdout) => {
      res({ ok: !err, out: String(stdout ?? "").trim() });
    });
  });
}

/** AppleScript string literal escaping. */
const asStr = (s: string): string => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

// ------------------------------------------------------------------ approval

async function askMac(req: ApprovalRequest, code: string, timeoutMs: number): Promise<Decision> {
  const body = [
    req.summary,
    "",
    ...(req.detail ?? []),
    "",
    `Approval code: ${code}`,
  ].join("\n");

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
}

/** Fallback: drop a request file and wait for `hush approve` to answer it. */
async function askViaFile(
  hushDir: string,
  req: ApprovalRequest,
  code: string,
  timeoutMs: number,
): Promise<Decision> {
  const dir = join(hushDir, "pending");
  mkdirSync(dir, { recursive: true });
  const id = `${Date.now()}-${code}`;
  const file = join(dir, `${id}.json`);
  writeFileSync(
    file,
    JSON.stringify({ id, code, action: req.action, summary: req.summary, detail: req.detail ?? [], at: new Date().toISOString() }, null, 2),
  );

  const answer = join(dir, `${id}.answer`);
  const deadline = Date.now() + timeoutMs;
  try {
    while (Date.now() < deadline) {
      if (existsSync(answer)) {
        const a = readFileSync(answer, "utf8").trim();
        return a === "session" ? "session" : a === "once" ? "once" : "deny";
      }
      await new Promise((r) => setTimeout(r, 300));
    }
    return "timeout";
  } finally {
    for (const f of [file, answer]) if (existsSync(f)) unlinkSync(f);
  }
}

/**
 * Seam for tests, and only for tests.
 *
 * The biometric outcomes that matter most — a human pressing *cancel*, and a
 * machine with no enrolled finger — cannot be produced on demand from a test.
 * Injecting the prompt is the only way to cover them. Deliberately *not* an
 * environment variable: `HUSH_BIOMETRY_FAKE=ok` would be an ambient switch that
 * makes every fingerprint check succeed, which anything running as you — an
 * agent included — could set. A parameter can only be supplied by a caller
 * inside this process, and no production caller supplies one.
 */
export interface ApprovalDeps {
  authenticate: (reason: string, timeoutMs: number) => Promise<BiometryResult>;
}

export async function requestApproval(
  hushDir: string,
  req: ApprovalRequest,
  deps: ApprovalDeps = { authenticate },
): Promise<ApprovalResult> {
  const code = newCode();

  const key = grantKey(hushDir, req.scope);
  const until = granted.get(key);
  if (until && until > Date.now()) {
    return { decision: "session", code, cached: true, via: "cache" };
  }

  const timeoutMs = req.timeoutMs ?? 120_000;
  const mode: BiometryMode = req.biometry ?? "off";

  if (mode !== "off") {
    // The reason string is the only thing the system sheet shows, so it has to
    // name the real action rather than say "authenticate".
    const reason = [req.summary, (req.detail ?? [])[0]].filter(Boolean).join(" — ");
    const bio = await deps.authenticate(reason, Math.min(timeoutMs, 60_000));

    if (bio === "ok") {
      granted.set(key, Date.now() + req.ttlSeconds * 1000);
      return { decision: "session", code, cached: false, via: "biometry" };
    }
    if (bio === "denied") {
      return { decision: "deny", code, cached: false, via: "biometry" };
    }
    if (mode === "required") {
      return {
        decision: "deny",
        code,
        cached: false,
        via: "none",
        note: "policy requires biometry, but it is unavailable on this machine",
      };
    }
    // "preferred" and unavailable: fall through to the click dialog.
  }

  const native = useNativeDialogs();
  const decision = native
    ? await askMac(req, code, timeoutMs)
    : await askViaFile(hushDir, req, code, timeoutMs);

  if (decision === "session") {
    granted.set(key, Date.now() + req.ttlSeconds * 1000);
  }
  return { decision, code, cached: false, via: native ? "dialog" : "terminal" };
}

/** For `hush approve`: list and answer pending requests on non-macOS hosts. */
export function pendingRequests(hushDir: string): { id: string; code: string; summary: string; detail: string[] }[] {
  const dir = join(hushDir, "pending");
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")));
}

export function answerRequest(hushDir: string, id: string, decision: "once" | "session" | "deny"): void {
  writeFileSync(join(hushDir, "pending", `${id}.answer`), decision);
}

// ------------------------------------------------------------- secret entry

export interface SecretEntryResult {
  value: string | null;
  cancelled: boolean;
}

/**
 * Ask the human for a secret value on their own screen.
 * The value is returned to the caller in-process and never rendered anywhere
 * the model can see it.
 */
export async function promptForSecretNatively(
  label: string,
  context: string[],
  timeoutMs = 180_000,
): Promise<SecretEntryResult> {
  if (!useNativeDialogs()) return { value: null, cancelled: false };

  const body = [...context, "", `Paste the value for ${label}:`].join("\n");
  const script =
    `display dialog ${asStr(body)} with title ${asStr("hush — add a secret")} ` +
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
}

export const nativeDialogsAvailable = (): boolean => useNativeDialogs();
