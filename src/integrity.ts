/**
 * Rollback detection.
 *
 * The vault file is authenticated against tampering — every value carries a GCM
 * tag — but authentication says nothing about *freshness*. A member who is
 * revoked keeps their old checkout, in which they are still a recipient and the
 * values are the same ones that are still live. Force-push that file back and
 * they are in again. Nothing in the ciphertext is wrong; it is simply old.
 *
 * Git branch protection is the real defence. This is the cheap local one: keep
 * a high-water mark of the data-key generation per vault, and shout when a
 * vault goes backwards. Same idea as a TOFU host key — it cannot stop the
 * attack, but it makes it impossible to perform quietly.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { Vault } from "./vault.ts";

/**
 * Resolved per call, not at import. A module-level constant captures HUSH_HOME
 * before a caller (or a test) can set it — the same trap that made the biometry
 * platform check untestable.
 */
const seenDir = (): string => join(process.env.HUSH_HOME || join(homedir(), ".hush"), "seen");

interface Seen {
  vaultId: string;
  generation: number;
  members: string[];
  at: string;
}

const seenPath = (vaultId: string): string =>
  join(seenDir(), `${vaultId.replace(/[^A-Za-z0-9_-]/g, "_")}.json`);

function readSeen(vaultId: string): Seen | null {
  try {
    return JSON.parse(readFileSync(seenPath(vaultId), "utf8")) as Seen;
  } catch {
    return null;
  }
}

function writeSeen(s: Seen): void {
  try {
    mkdirSync(seenDir(), { recursive: true, mode: 0o700 });
    writeFileSync(seenPath(s.vaultId), JSON.stringify(s, null, 2) + "\n");
  } catch {
    /* a watermark is advisory; never fail a command over it */
  }
}

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
    // Trust on first use.
    writeSeen({ vaultId, generation, members, at: new Date().toISOString() });
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

  // Membership is compared by content, not by length: adding a member does not
  // mint a new key generation, so a vault whose roster changed without growing
  // — a rename, or one member swapped for another — would otherwise leave a
  // stale name list behind, and `reappeared` would then name the wrong people.
  const sameMembers = members.length === seen.members.length && members.every((m, i) => m === seen.members[i]);
  if (generation > seen.generation || !sameMembers) {
    writeSeen({ vaultId, generation, members, at: new Date().toISOString() });
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
  writeSeen({
    vaultId: vault.data.id,
    generation: vault.data.dek.generation,
    members: vault.members().map((m) => m.name).sort(),
    at: new Date().toISOString(),
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
