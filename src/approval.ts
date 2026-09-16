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
 * backend is picked). A machine that cannot put an approval in front of a human
 * — no desktop, no fingerprint helper — is refused rather than handed a file
 * to answer: the answer has to be *something the gated caller cannot supply*,
 * and a file in the project is something an agent with a shell can write.
 */
import { randomInt } from "node:crypto";
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
  /**
   * Whether the answer may include "allow for a while" as well as "allow once".
   *
   * Defaults to true, which suits a long-lived process (the MCP server, `hush
   * ui`): the grant lives in that process's memory and covers the next request
   * with the same scope. A one-shot command passes false, because its grant
   * dies with it and offering the longer option would be a promise it cannot
   * keep.
   */
  sessionGrant?: boolean;
}

export interface ApprovalResult {
  decision: Decision;
  code: string;
  cached: boolean;
  /** How the human actually approved, for the audit log. */
  via: "biometry" | "dialog" | "cache" | "none";
  note?: string;
}

/**
 * Evaluated per call, not at import: the optional seams on `ApprovalDeps` —
 * real callers never pass them — let tests exercise the Linux branches of
 * dialogs.ts's `detectBackend` from any host and resolve a dialog program to a
 * fixture.
 *
 * Note what is *not* here: a way for the environment to choose the dialog
 * program. That is the whole point of dialogs.ts's `systemProgram`.
 */
const currentBackend = (deps: Pick<ApprovalDeps, "platform" | "resolveDialogProgram"> = {}) =>
  detectBackend({
    env: process.env,
    platform: deps.platform ?? platform,
    ...(deps.resolveDialogProgram ? { resolveProgram: deps.resolveDialogProgram } : {}),
  });

/**
 * scope -> epoch ms when the session approval lapses. Process-lifetime only.
 * Keys include the vault directory: two vaults both using scope "run:default"
 * must not share a grant.
 */
const granted = new Map<string, number>();

const grantKey = (hushDir: string, scope: string): string => `${hushDir}\u0000${scope}`;


/**
 * Nothing here is written to disk, and that is the point.
 *
 * An approval used to be mirrored into `.hush/grants.local.json` so that
 * "Allow 15 min" survived the next `hush` invocation being a new process. That
 * file lives inside the project, which is exactly the directory an agent with
 * a shell can write, so the agent could pre-authorise its own approval — the
 * same defect as the pending-request queue, in a different file. A grant is
 * only worth something if the process reading it is the process the human
 * answered, so that is where it lives now: the map above, gone when the
 * process is.
 *
 * The practical effect: the long-lived surfaces (the MCP server, `hush ui`)
 * still honour "Allow 15 min" for as long as they are running, and a fresh
 * `hush` command asks again. A one-shot command is offered "Allow once" only,
 * because that is all it can honestly promise — see `sessionGrant`.
 */

/**
 * Test seam: forget every cached approval.
 *
 * With a `hushDir`, only that project's grants are cleared. With none, every
 * grant this process has handed out is cleared, which is what every existing
 * caller wants: they run inside a single node:test process and expect a clean
 * slate between tests without knowing which scratch directory a previous test
 * used.
 */
export function clearApprovalCache(hushDir?: string): void {
  if (!hushDir) return void granted.clear();
  const prefix = `${hushDir}\u0000`;
  for (const k of granted.keys()) if (k.startsWith(prefix)) granted.delete(k);
}

const newCode = (): string => String(randomInt(1000, 10000));

// ------------------------------------------------------------------ approval

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
  /**
   * Same idea applied to the dialog program: real callers never supply one, so
   * the program is always resolved by dialogs.ts's `systemProgram` (fixed
   * OS-owned paths, root-owned, not group/world-writable). A test supplies a
   * resolver to point at a fixture.
   */
  resolveDialogProgram?: (cmd: "osascript" | "zenity" | "kdialog") => string | null;
}

export async function requestApproval(
  hushDir: string,
  req: ApprovalRequest,
  deps: ApprovalDeps = { authenticate },
): Promise<ApprovalResult> {
  const code = newCode();

  // One place a grant can live: this process's map. Nothing is read from the
  // project, so there is nothing there for an agent to write — see the comment
  // above `granted` for why "run" was not exempted from that.
  const key = grantKey(hushDir, req.scope);
  const until = granted.get(key);
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

  const backend = currentBackend(deps);
  if (!backend) {
    // Nothing can put this request in front of a human: no dialog program, and
    // no fingerprint helper was available a moment ago. The old fallback wrote
    // the request to a file and accepted a matching answer file, which is not
    // an approval — an agent with a shell writes that file itself, and the
    // whole gate becomes a formality. Refusing is the honest answer, and the
    // note says which of the two things would make it work.
    return {
      decision: "deny",
      code,
      cached: false,
      via: "none",
      note: "no prompt is available on this machine (no dialog program and no fingerprint helper)",
    };
  }

  // A one-shot caller passes sessionGrant: false. Offering "Allow 15 min" from
  // a process that exits with the command would be a promise it cannot keep,
  // now that a grant is not written anywhere it could survive the process.
  const sessionGrant = req.sessionGrant !== false;
  const decision = await backend.approve(
    {
      summary: req.summary,
      detail: req.detail ?? [],
      code,
      ttlLabel: sessionGrant ? ttlLabel(req.ttlSeconds) : null,
    },
    timeoutMs,
  );

  if (decision === "session") {
    const expiresAt = Date.now() + req.ttlSeconds * 1000;
    granted.set(key, expiresAt);
  }
  return { decision, code, cached: false, via: "dialog" };
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
  deps: Pick<ApprovalDeps, "platform" | "resolveDialogProgram"> = {},
): Promise<SecretEntryResult> {
  const backend = currentBackend(deps);
  if (!backend) return { value: null, cancelled: false };
  return backend.enterSecret({ title: "hush — add a secret", lines: context, label }, timeoutMs);
}

export const nativeDialogsAvailable = (): boolean => currentBackend() !== null;
