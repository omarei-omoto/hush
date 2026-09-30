/**
 * What this machine has seen of each vault, and what it refuses to be surprised by.
 *
 * Two jobs, one store (`~/.hush/seen/`):
 *
 * **Rollback detection.** The vault file is authenticated against tampering —
 * every value carries a GCM tag — but authentication says nothing about
 * *freshness*. A member who is revoked keeps their old checkout, in which they
 * are still a recipient and the values are the same ones that are still live.
 * Force-push that file back and they are in again. So a high-water mark of the
 * data-key generation is kept per vault, and going backwards is shouted about.
 *
 * **Pinning (V-1).** Nothing in a vault file says who chose its data key.
 * Anyone who can get a change to `vault.json` merged — without being a member —
 * can mint a new key, wrap it to every member's public key (they are in the
 * file) and to themselves, and seal values they chose. Every member's hush used
 * to open that without a word: planted values were injected, and the next
 * secret anyone added was sealed to a key the attacker holds. So each machine
 * pins, per vault:
 *
 *   - the recipients it has accepted, by fingerprint (names are free text);
 *   - a commitment to the data key behind each generation it has seen;
 *   - which vault lives at which path.
 *
 * A new recipient this machine did not add, a different key for a generation
 * already seen, or a different vault where a known one was, is refused until a
 * person runs `hush team accept`. A member being *removed* is accepted quietly —
 * it only takes access away — and a rotation by someone else is accepted and
 * said once. What pinning cannot tell apart is a teammate's `hush rotate` from a
 * non-member re-keying the vault *without* adding themselves; they learn nothing
 * new that way, but a planted value could still steer a real key somewhere. The
 * signed vault header (hush/v3) closes that.
 *
 * Trust on first use: the first time a machine sees a vault, it is pinned as it
 * stands. Same idea as an SSH host key — it cannot vouch for the first look, but
 * it makes every later substitution loud.
 */
import { mkdirSync, readFileSync, writeFileSync, renameSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { homedir } from "node:os";
import { dekCommit } from "./crypto.ts";
import { safeText, type Vault, type TrustView } from "./vault.ts";

/**
 * Resolved per call, not at import. A module-level constant captures HUSH_HOME
 * before a caller (or a test) can set it — the same trap that made the biometry
 * platform check untestable.
 */
const seenDir = (): string => join(process.env.HUSH_HOME || join(homedir(), ".hush"), "seen");

interface PinnedRecipient {
  name: string;
  pk: string;
}

interface Seen {
  vaultId: string;
  /** High-water mark: the newest data-key generation ever seen. */
  generation: number;
  /** Member names at the high-water mark, for "who reappeared" in a rollback. */
  members: string[];
  at: string;
  /** Accepted recipients, by fingerprint. Absent in marks written before pinning. */
  recipients?: Record<string, PinnedRecipient>;
  /** Generation → commitment to the data key seen behind it. */
  commits?: Record<string, string>;
  /** The last generation a "rotated by someone else" notice was shown for. */
  noticed?: number;
}

const seenPath = (vaultId: string): string =>
  join(seenDir(), `${vaultId.replace(/[^A-Za-z0-9_-]/g, "_")}.json`);

const pathsFile = (): string => join(seenDir(), "paths.json");

function readJson<T>(path: string): T | null {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch {
    return null;
  }
}

/** Temp file and rename, so a crash never leaves a half-written pin behind. */
function writeJson(path: string, value: unknown): void {
  mkdirSync(seenDir(), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
  renameSync(tmp, path);
}

function readSeen(vaultId: string): Seen | null {
  const s = readJson<Seen>(seenPath(vaultId));
  return s && typeof s === "object" && typeof s.generation === "number" ? s : null;
}

/**
 * Merged, never replaced: the rollback mark and the pins share a file, and a
 * writer that knew about only one of them used to erase the other.
 */
function writeSeen(vaultId: string, patch: Partial<Seen>): void {
  try {
    const current = readSeen(vaultId);
    writeJson(seenPath(vaultId), { ...(current ?? {}), ...patch, vaultId, at: new Date().toISOString() });
  } catch {
    /* a mark is advisory for rollback; pinning re-checks on every open */
  }
}

/** Real paths, not spellings: /var and /private/var are the same file on macOS. */
function realOf(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return resolve(path);
  }
}

function readPaths(): Record<string, string> {
  const p = readJson<Record<string, string>>(pathsFile());
  return p && typeof p === "object" ? p : {};
}

function bindPath(path: string, vaultId: string): void {
  const paths = readPaths();
  const key = realOf(path);
  if (paths[key] === vaultId) return;
  paths[key] = vaultId;
  try {
    writeJson(pathsFile(), paths);
  } catch {
    /* unwritable home: the id and roster pins still hold */
  }
}

// ----------------------------------------------------------------- rollback

export interface RollbackWarning {
  vaultId: string;
  seenGeneration: number;
  nowGeneration: number;
  /** Members present now who were gone the last time we looked. */
  reappeared: string[];
}

/**
 * Compare against the high-water mark and advance it.
 *
 * The mark only ever moves forward: observing a rolled-back vault must not
 * quietly accept the lower number, or the warning would fire once and never
 * again.
 */
export function checkAndRecord(vault: Vault): RollbackWarning | null {
  const vaultId = vault.data.id;
  const generation = vault.data.dek.generation;
  const members = vault.members().map((m) => m.name).sort();
  const seen = readSeen(vaultId);

  if (!seen) {
    // Trust on first use. The roster and the key are pinned on the first
    // decryption, where the data key is in hand to commit to.
    writeSeen(vaultId, { generation, members });
    return null;
  }

  if (generation < seen.generation) {
    return {
      vaultId,
      seenGeneration: seen.generation,
      nowGeneration: generation,
      reappeared: members.filter((m) => !seen.members.includes(m)),
    };
  }

  // Once a vault is pinned, the mark moves only after a decryption has checked
  // the vault (recordTrusted). Advancing it here, on a bare open, let a forged
  // vault claiming generation 999999 poison the mark before anything looked at
  // whether it was genuine — every real vault afterwards read as rolled back.
  if (seen.commits) return null;

  // Membership is compared by content, not by length: adding a member does not
  // mint a new key generation, so a vault whose roster changed without growing
  // — a rename, or one member swapped for another — would otherwise leave a
  // stale name list behind, and `reappeared` would then name the wrong people.
  const sameMembers = members.length === seen.members.length && members.every((m, i) => m === seen.members[i]);
  if (generation > seen.generation || !sameMembers) {
    writeSeen(vaultId, { generation, members });
  }
  return null;
}

/** Read-only check, for `hush verify` and for callers that must not advance the mark. */
export function inspect(vault: Vault): RollbackWarning | null {
  const seen = readSeen(vault.data.id);
  if (!seen) return null;
  const generation = vault.data.dek.generation;
  if (generation >= seen.generation) return null;
  return {
    vaultId: vault.data.id,
    seenGeneration: seen.generation,
    nowGeneration: generation,
    reappeared: vault.members().map((m) => m.name).filter((m) => !seen.members.includes(m)),
  };
}

/** Deliberately accept the current state — for a real restore from backup. */
export function acceptCurrent(vault: Vault): void {
  // The high-water mark is *set*, not merged upward: accepting a restore means
  // accepting its lower generation as the newest this machine has seen.
  writeSeen(vault.data.id, {
    generation: vault.data.dek.generation,
    members: vault.members().map((m) => m.name).sort(),
  });
}

export function describeRollback(w: RollbackWarning): string[] {
  const lines = [
    `This vault has gone BACKWARDS: key generation ${w.nowGeneration}, but ${w.seenGeneration} was seen before.`,
    "",
    "A revoked member's old copy would restore their access to every secret in it.",
  ];
  if (w.reappeared.length) {
    lines.push(`Members present again who were gone: ${w.reappeared.join(", ")}`);
  }
  lines.push(
    "",
    "If someone force-pushed the vault, treat every secret in it as compromised.",
    "If you restored a backup on purpose:  hush verify --accept",
  );
  return lines;
}

// ------------------------------------------------------------------ pinning

export interface AddedMember {
  fingerprint: string;
  name: string;
  pk: string;
}

/** Everything about a vault that differs from what this machine has accepted. */
export interface Pending {
  vaultId: string;
  path: string;
  generation: number;
  commit: string;
  /** A different vault now sits where this one was. */
  replaced?: { was: string };
  /** The data key behind a generation already seen is not the one seen then. */
  keyChanged?: { generation: number };
  /** Recipients present now that this machine never accepted. */
  added: AddedMember[];
  /** Recipients accepted before and gone now. Never a problem on its own. */
  removed: string[];
  /** The generation moved on since the last look, for a notice rather than a refusal. */
  rotated: boolean;
  /** Nothing pinned for this vault yet: this is the first look. */
  firstUse: boolean;
}

export const hasProblems = (p: Pending): boolean => Boolean(p.replaced || p.keyChanged || p.added.length);

/**
 * Raised instead of decrypting anything from a vault that changed in a way no
 * person on this machine has accepted.
 *
 * Its own class rather than a ValidationError: nothing about the caller's
 * input is wrong, and the UI and the MCP server both need to tell this apart
 * from an ordinary failure so they can say what to do about it.
 */
export class TrustError extends Error {
  readonly trust = true;
  readonly pending: Pending;
  constructor(pending: Pending) {
    super(describeTrustProblems(pending).join("\n"));
    this.name = "TrustError";
    this.pending = pending;
  }
}

export const isTrustError = (e: unknown): e is TrustError =>
  e instanceof TrustError || (e as { trust?: boolean })?.trust === true;

/** What differs, without recording anything. Needs the data key to commit to. */
export function pendingChanges(view: TrustView): Pending {
  const seen = readSeen(view.vaultId);
  const commit = dekCommit(view.dek, view.vaultId, view.generation);
  const bound = readPaths()[realOf(view.path)];

  const pending: Pending = {
    vaultId: view.vaultId,
    path: view.path,
    generation: view.generation,
    commit,
    added: [],
    removed: [],
    rotated: false,
    firstUse: !seen?.recipients && !seen?.commits,
  };

  if (bound && bound !== view.vaultId) pending.replaced = { was: bound };

  const pinnedCommit = seen?.commits?.[String(view.generation)];
  if (pinnedCommit && pinnedCommit !== commit) pending.keyChanged = { generation: view.generation };

  if (seen?.recipients) {
    for (const [fp, r] of Object.entries(view.recipients)) {
      if (!seen.recipients[fp]) pending.added.push({ fingerprint: fp, name: r.name, pk: r.pk });
    }
    for (const [fp, r] of Object.entries(seen.recipients)) {
      if (!view.recipients[fp]) pending.removed.push(r.name);
    }
  }

  // A newer generation than any whose key was checked here is a rotation (or a
  // removal, which rotates). Said once per generation, not on every command.
  if (seen?.commits) {
    const newestChecked = Math.max(...Object.keys(seen.commits).map(Number));
    if (view.generation > newestChecked && (seen.noticed ?? 0) < view.generation) pending.rotated = true;
  }
  return pending;
}

/**
 * Pin the vault as it stands. Called on first use, after a check that found
 * nothing to object to, when this machine itself wrote the change, and when a
 * person accepted what `hush team accept` showed them.
 */
export function recordTrusted(view: TrustView, opts: { noticed?: boolean } = {}): void {
  const seen = readSeen(view.vaultId);
  const commits = { ...(seen?.commits ?? {}), [String(view.generation)]: dekCommit(view.dek, view.vaultId, view.generation) };
  const recipients: Record<string, PinnedRecipient> = {};
  for (const [fp, r] of Object.entries(view.recipients)) recipients[fp] = { name: r.name, pk: r.pk };
  const newer = !seen || view.generation >= seen.generation;
  writeSeen(view.vaultId, {
    recipients,
    commits,
    // The rollback mark only moves forward here; `hush verify --accept` is the
    // one deliberate way down.
    generation: newer ? view.generation : seen!.generation,
    members: newer ? Object.values(view.recipients).map((r) => r.name).sort() : seen!.members,
    ...(opts.noticed || !seen ? { noticed: Math.max(seen?.noticed ?? 0, view.generation) } : {}),
  });
  bindPath(view.path, view.vaultId);
}

/**
 * The check every decryption goes through (see Vault.dek). Throws TrustError
 * for anything a person has to accept; otherwise pins what it saw and returns
 * what is worth telling them.
 */
export function verifyTrust(view: TrustView): string[] {
  const pending = pendingChanges(view);
  if (hasProblems(pending)) throw new TrustError(pending);
  const notices: string[] = [];
  if (pending.rotated) {
    notices.push(
      pending.removed.length
        ? `the vault key was rotated by someone else (removed: ${pending.removed.map((n) => safeText(n, 64)).join(", ")})`
        : "the vault key was rotated by someone else",
    );
  }
  recordTrusted(view, { noticed: pending.rotated });
  return notices;
}

/**
 * Accept exactly what was shown. If the vault changed again between being
 * shown and being accepted — another pull, another process — nothing is
 * recorded: an acceptance covers the members a person actually looked at.
 */
export function acceptPending(view: TrustView, shown: Pending): void {
  const now = pendingChanges(view);
  const same =
    now.commit === shown.commit &&
    now.generation === shown.generation &&
    now.added.map((a) => a.fingerprint).sort().join() === shown.added.map((a) => a.fingerprint).sort().join() &&
    (now.replaced?.was ?? "") === (shown.replaced?.was ?? "");
  if (!same) {
    throw new Error("The vault changed again while you were looking at it. Run `hush team accept` again.");
  }
  recordTrusted(view, { noticed: true });
}

/**
 * Fingerprints listed in a vault that this machine has not accepted — without
 * the data key, for `hush team ls`. Empty on a first look, which is accepted
 * the moment anything is decrypted.
 */
export function unacceptedMembers(vault: Vault): string[] {
  const seen = readSeen(vault.data.id);
  if (!seen?.recipients) return [];
  return Object.keys(vault.data.recipients).filter((fp) => !seen.recipients![fp]);
}

/** Plain sentences a person can act on. Never a value; names go through safeText. */
export function describeTrustProblems(p: Pending): string[] {
  const lines: string[] = [];
  if (p.replaced) {
    lines.push(
      `A different vault is now at ${p.path} (${p.vaultId}, where ${p.replaced.was} was).`,
      "  Someone replaced this project's vault. Nothing will be decrypted or added until you accept it.",
    );
  }
  if (p.keyChanged) {
    lines.push(
      `The data key behind generation ${p.keyChanged.generation} of this vault is not the one this machine saw before.`,
      "  No hush command does that: re-keying always moves to a new generation. Treat this vault as forged.",
    );
  }
  if (p.added.length) {
    lines.push("This vault's membership changed, and nobody on this machine accepted it:");
    for (const a of p.added) {
      lines.push(`  new: ${safeText(a.name, 64) ?? "unknown"}  ${a.pk.slice(0, 24)}…  (fingerprint ${a.fingerprint})`);
    }
    lines.push(
      "  A member added by someone who is not a real teammate would read every secret added from now on,",
      "  so hush will not decrypt or add anything here until you have checked with whoever added them.",
    );
  }
  lines.push("  If you expected this:  hush team accept", "  If you did not:        hush team reject   (how to undo it)");
  return lines;
}
