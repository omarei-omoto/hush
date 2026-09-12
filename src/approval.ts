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
 * macOS, GNOME and KDE desktops get native dialogs (see dialogs.ts for how a
 * backend is picked). Everywhere else falls back to a pending-request file
 * that the human resolves with `hush approve` in their own terminal.
 */
import { randomInt } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync, readdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { platform } from "node:os";
import { authenticate, type BiometryMode, type BiometryResult } from "./biometry.ts";
import { detectBackend, ttlLabel } from "./dialogs.ts";

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
 * Evaluated per call, not at import: HUSH_APPROVAL_MODE=file forces the
 * terminal flow, tests set it (and HUSH_DIALOG, PATH, DISPLAY) after this
 * module is already loaded, and a `platformFn` override — real callers never
 * pass one — lets tests exercise the Linux branches of dialogs.ts's
 * `detectBackend` from any host. See `ApprovalDeps.platform`.
 */
const currentBackend = (platformFn: () => string = platform) =>
  detectBackend({ env: process.env, platform: platformFn });

/**
 * scope -> epoch ms when the session approval lapses. Process-lifetime only.
 * Keys include the vault directory: two vaults both using scope "run:default"
 * must not share a grant.
 */
const granted = new Map<string, number>();

const grantKey = (hushDir: string, scope: string): string => `${hushDir}\u0000${scope}`;

const grantsFilePath = (hushDir: string): string => join(hushDir, "grants.local.json");

/**
 * Every grants file this process has written, so `clearApprovalCache()` can be
 * called with no argument (as every existing test does) and still undo them.
 */
const writtenGrantFiles = new Set<string>();

/**
 * A CLI invocation is a new process every time, so the in-memory `granted` map
 * above never survives from one command to the next: "Allow 15 min" would in
 * practice mean "allow this one command", and the user would be re-prompted
 * every single time. Mirroring session grants to a file next to the policy
 * lets the next `hush` process (and the long-lived MCP server, which shares
 * this module) see what an earlier process was told.
 *
 * This is a convenience cache, not the source of truth for whether an action
 * is allowed, so a corrupt or unreadable file is treated as "no grants"
 * rather than a crash, and expired entries are simply not returned.
 */
function readGrantsFile(hushDir: string): Record<string, number> {
  try {
    const raw = JSON.parse(readFileSync(grantsFilePath(hushDir), "utf8")) as Record<string, unknown>;
    const now = Date.now();
    const live: Record<string, number> = {};
    for (const [scope, expiresAt] of Object.entries(raw)) {
      if (typeof expiresAt === "number" && expiresAt > now) live[scope] = expiresAt;
    }
    return live;
  } catch {
    return {};
  }
}

function writeGrant(hushDir: string, scope: string, expiresAt: number): void {
  const path = grantsFilePath(hushDir);
  try {
    const grants = readGrantsFile(hushDir);
    grants[scope] = expiresAt;
    writeFileSync(path, JSON.stringify(grants), { mode: 0o600 });
    // writeFileSync only applies `mode` on creation, so a grants file left over
    // from an earlier run would otherwise keep whatever mode it started with;
    // the same fix is in cli.ts's `hush export --out`.
    chmodSync(path, 0o600);
    writtenGrantFiles.add(path);
  } catch {
    // Best-effort: worst case the next process re-prompts instead of reusing
    // a grant that never made it to disk, which is the safe direction to fail.
  }
}

/**
 * Test seam: forget every cached approval, in memory and on disk.
 *
 * With a `hushDir`, only that project's grants are cleared: memory entries
 * keyed to it, and its grants file. With none, every grant this process has
 * ever handed out is cleared, which is what every existing caller wants: they
 * run inside a single node:test process and expect a clean slate between
 * tests without knowing which scratch directory a previous test used (which
 * may already be deleted, hence the try/catch rather than asserting it
 * existed).
 */
export function clearApprovalCache(hushDir?: string): void {
  if (hushDir) {
    const prefix = `${hushDir}\u0000`;
    for (const k of granted.keys()) if (k.startsWith(prefix)) granted.delete(k);
    const path = grantsFilePath(hushDir);
    try { unlinkSync(path); } catch { /* nothing to remove */ }
    writtenGrantFiles.delete(path);
    return;
  }
  granted.clear();
  for (const path of writtenGrantFiles) {
    try { unlinkSync(path); } catch { /* already gone, e.g. its scratch dir was rmSync'd */ }
  }
  writtenGrantFiles.clear();
}

const newCode = (): string => String(randomInt(1000, 10000));

// ------------------------------------------------------------------ approval

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
 *
 * `platform` is the same idea applied to dialog-backend selection: real code
 * never sets it (the default is node:os's actual `platform()`), but a test
 * can claim to be "linux" while running on this Mac to exercise the zenity/
 * kdialog branches of dialogs.ts's `detectBackend` — again a parameter rather
 * than an env var, for the same reason.
 */
export interface ApprovalDeps {
  authenticate: (reason: string, timeoutMs: number) => Promise<BiometryResult>;
  platform?: () => string;
}

export async function requestApproval(
  hushDir: string,
  req: ApprovalRequest,
  deps: ApprovalDeps = { authenticate },
): Promise<ApprovalResult> {
  const code = newCode();

  const key = grantKey(hushDir, req.scope);
  // Memory first (cheap, and always current within this process), then the
  // file another process — most often an earlier `hush` invocation — may have
  // written. Found-on-disk is backfilled into memory so the rest of this
  // process does not re-read the file for the same scope.
  const until = granted.get(key) ?? readGrantsFile(hushDir)[req.scope];
  if (until && until > Date.now()) {
    granted.set(key, until);
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
      const expiresAt = Date.now() + req.ttlSeconds * 1000;
      granted.set(key, expiresAt);
      writeGrant(hushDir, req.scope, expiresAt);
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

  const backend = currentBackend(deps.platform);
  const decision = backend
    ? await backend.approve(
        { summary: req.summary, detail: req.detail ?? [], code, ttlLabel: ttlLabel(req.ttlSeconds) },
        timeoutMs,
      )
    : await askViaFile(hushDir, req, code, timeoutMs);

  if (decision === "session") {
    const expiresAt = Date.now() + req.ttlSeconds * 1000;
    granted.set(key, expiresAt);
    writeGrant(hushDir, req.scope, expiresAt);
  }
  return { decision, code, cached: false, via: backend ? "dialog" : "terminal" };
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
  const backend = currentBackend();
  if (!backend) return { value: null, cancelled: false };
  return backend.enterSecret({ title: "hush — add a secret", lines: context, label }, timeoutMs);
}

export const nativeDialogsAvailable = (): boolean => currentBackend() !== null;
