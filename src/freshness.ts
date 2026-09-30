/**
 * How old each value is, which are overdue for rotation, and which were
 * readable by someone who has since been removed (F-6).
 *
 * Read from metadata beside the ciphertext — `updatedAt` and `exposed` — so
 * none of it needs a key, and none of it can say anything about a value.
 */
import type { Vault } from "./vault.ts";
import { rotationUrl } from "./services.ts";
import { rotationDaysFor } from "./policy.ts";
import type { Policy } from "./mcp.ts";

export interface KeyAge {
  set: string;
  key: string;
  updatedAt: string;
  /** Whole days since it was last set; null when the date is unreadable. */
  days: number | null;
  /** The policy's limit for this set, if any. */
  limit: number | null;
  overdue: boolean;
  /** Members removed while they could read it, until it is set again. */
  exposed: string[];
  /** Where to replace it at the provider, when hush knows. */
  rotate: string | null;
}

const DAY = 86_400_000;

export function keyAges(vault: Vault, policy: Pick<Policy, "rotateAfterDays"> | null, now = Date.now()): KeyAge[] {
  const out: KeyAge[] = [];
  for (const set of vault.envNames()) {
    const limit = policy ? rotationDaysFor(policy, set) : null;
    for (const item of vault.list(set)) {
      const t = Date.parse(item.updatedAt);
      const days = Number.isFinite(t) ? Math.max(0, Math.floor((now - t) / DAY)) : null;
      out.push({
        set,
        key: item.key,
        updatedAt: item.updatedAt,
        days,
        limit,
        overdue: limit !== null && days !== null && days > limit,
        exposed: item.exposed ?? [],
        rotate: rotationUrl(item.key),
      });
    }
  }
  return out;
}

/** "3 days", "5 months", for a line a person reads. */
export function describeAge(days: number | null): string {
  if (days === null) return "unknown age";
  if (days < 1) return "today";
  if (days < 60) return `${days} day${days === 1 ? "" : "s"}`;
  if (days < 730) return `${Math.round(days / 30)} months`;
  return `${Math.round(days / 365)} years`;
}
