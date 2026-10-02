/**
 * Leases: the values of some sets, handed by a tailnet broker to one enrolled
 * machine, for one command (docs/TAILNET.md, step 3).
 *
 * This is the one broker path where a real value leaves the broker, so it is
 * fenced on every side:
 *
 * - It is sealed to the requesting machine's hush key: a fresh data key
 *   wrapped for that key (the vault's own X25519 wrap), and the payload sealed
 *   under it with the lease id bound in. An agent that calls the endpoint
 *   itself gets ciphertext.
 * - That key must be enrolled first, by a person, and is tied to the tailnet
 *   user and device that enrolled it. A key made up on the spot is refused.
 * - The broker asks before every lease, showing the exact command.
 * - The payload names the command, its arguments and an expiry a minute
 *   out. The client refuses one that does not match what it asked for.
 *
 * What it cannot do is take a value back. Once the child process has it, it
 * has it — a lease of a long-lived key is "given once, logged". Real expiry
 * needs keys minted per use (a later step).
 */
import { randomBytes } from "node:crypto";
import { newDek, openValue, sealValue, unwrapDek, wrapDek, type Identity } from "./crypto.ts";

export const LEASE_VERSION = 1;
/** How long a sealed lease may sit unopened. */
export const LEASE_TTL_MS = 60_000;

export interface LeasePayload {
  v: typeof LEASE_VERSION;
  id: string;
  command: string;
  args: string[];
  sets: string[];
  secrets: Record<string, string>;
  /** ms since the epoch after which the client refuses it. */
  exp: number;
}

export interface SealedLease {
  id: string;
  wrap: ReturnType<typeof wrapDek>;
  sealed: ReturnType<typeof sealValue>;
}

/** The AAD context: a lease's ciphertext is only ever a lease with this id. */
const CONTEXT = "hush-lease";

export function sealLease(
  fields: Omit<LeasePayload, "v" | "id" | "exp">,
  recipientPub: Buffer,
  now = Date.now(),
): SealedLease {
  const id = randomBytes(16).toString("hex");
  const payload: LeasePayload = { v: LEASE_VERSION, id, exp: now + LEASE_TTL_MS, ...fields };
  const dek = newDek();
  try {
    return { id, wrap: wrapDek(dek, recipientPub), sealed: sealValue(dek, CONTEXT, id, JSON.stringify(payload), LEASE_VERSION) };
  } finally {
    dek.fill(0);
  }
}

/**
 * Open a lease on the machine it was sealed for, and check it is the one that
 * was asked for: same command, same arguments, not expired. Throws otherwise.
 */
export function openLease(
  lease: SealedLease,
  id: Identity,
  expect: { command: string; args: string[] },
  now = Date.now(),
): LeasePayload {
  if (!lease || typeof lease.id !== "string" || !/^[0-9a-f]{32}$/.test(lease.id)) throw new Error("the broker's answer is not a lease");
  const dek = unwrapDek(lease.wrap, id);
  let payload: LeasePayload;
  try {
    payload = JSON.parse(openValue(dek, CONTEXT, lease.id, lease.sealed, LEASE_VERSION)) as LeasePayload;
  } finally {
    dek.fill(0);
  }
  if (payload.v !== LEASE_VERSION || payload.id !== lease.id) throw new Error("the lease does not match its own id");
  if (payload.exp < now) throw new Error("the lease expired before it was used");
  if (payload.command !== expect.command || JSON.stringify(payload.args) !== JSON.stringify(expect.args)) {
    throw new Error("the lease is for a different command than the one asked for");
  }
  if (!payload.secrets || typeof payload.secrets !== "object") throw new Error("the lease carries no values");
  return payload;
}
