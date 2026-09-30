/**
 * The signed vault header (hush/v3, V-1b).
 *
 * Encrypting to a public key says nothing about who did it, and every member's
 * public key is in the committed file — so before v3, anyone who could get a
 * change merged could build a vault that opened for the whole team. v3 adds a
 * header an admin signs:
 *
 *   - who can read the vault: every member's keys, role, and — for a scoped
 *     member — the sets they may read;
 *   - the vault key's generation and a commitment to it;
 *   - for each set with a key of its own, its generation, a commitment to that
 *     key, and exactly who is wrapped in.
 *
 * A member checks the signature against an admin their machine already knows
 * (integrity.ts), and checks that the key they unwrapped matches the signed
 * commitment. A non-member can no longer add themselves, swap the key, or
 * plant values under a key of their own choosing: all three change the header,
 * and they cannot sign it.
 *
 * Deliberately not covered: the values themselves. Any member holding a key
 * can write a value; the header decides *who* holds keys, not what they write.
 */
import { canonicalJson, dekCommit, decodeSpk, verifySignature, type Signer } from "./crypto.ts";
import type { VaultFile } from "./vault-files.ts";

const DOMAIN = "hush/v3/header\n";

/** The commitment to a set's own key. Bound to the set's name as well as its generation. */
export const setKeyCommit = (key: Buffer, vaultId: string, env: string, generation: number): string =>
  dekCommit(key, `${vaultId}/set/${env}`, generation);

export const vaultKeyCommit = (key: Buffer, vaultId: string, generation: number): string =>
  dekCommit(key, vaultId, generation);

/** Exactly what a signature covers. */
export function headerOf(data: VaultFile): unknown {
  const recipients: Record<string, unknown> = {};
  for (const [fp, r] of Object.entries(data.recipients)) {
    recipients[fp] = {
      name: r.name,
      pk: r.pk,
      spk: r.spk,
      role: r.role,
      type: r.type ?? "x25519",
      ci: r.ci === true ? true : undefined,
      sets: r.sets ? [...r.sets].sort() : undefined,
    };
  }
  const setKeys: Record<string, unknown> = {};
  for (const [env, k] of Object.entries(data.setKeys ?? {})) {
    setKeys[env] = { generation: k.generation, commit: k.commit, members: Object.keys(k.wraps).sort() };
  }
  return {
    v: 3,
    id: data.id,
    name: data.name,
    recipients,
    dek: { generation: data.dek.generation, commit: data.dek.commit, members: Object.keys(data.dek.wraps).sort() },
    setKeys,
  };
}

export const headerBytes = (data: VaultFile): Buffer => Buffer.from(DOMAIN + canonicalJson(headerOf(data)), "utf8");

/**
 * Sign the header as it stands. The caller has already checked the signer is
 * an admin of this vault; this only refuses a header that cannot be checked.
 */
export function signHeader(data: VaultFile, byFingerprint: string, signer: Signer): void {
  if (!data.dek.commit) throw new Error("the vault key has no commitment to sign");
  for (const [env, k] of Object.entries(data.setKeys ?? {})) {
    if (!k.commit) throw new Error(`the key of set "${env}" has no commitment to sign`);
  }
  data.signature = { by: byFingerprint, sig: signer.sign(headerBytes(data)).toString("base64") };
}

export type HeaderCheck = { ok: true; by: string } | { ok: false; why: string };

/**
 * Is the header signed, by an admin listed in it, with the key listed for
 * them? Whether that admin is one *this machine* trusts is integrity.ts's
 * question; this is the part that needs no memory.
 */
export function verifyHeader(data: VaultFile): HeaderCheck {
  const sig = data.signature;
  if (!sig) return { ok: false, why: "it is not signed" };
  const signer = data.recipients[sig.by];
  if (!signer) return { ok: false, why: "it is signed by someone who is not a member" };
  if (signer.role !== "admin" || signer.ci) return { ok: false, why: `it is signed by ${signer.name}, who is not an admin` };
  if (!signer.spk) return { ok: false, why: `${signer.name} has no signing key in the vault` };
  let spk: Buffer;
  try {
    spk = decodeSpk(signer.spk);
  } catch {
    return { ok: false, why: `${signer.name}'s signing key is malformed` };
  }
  if (!verifySignature(spk, headerBytes(data), Buffer.from(sig.sig, "base64"))) {
    return { ok: false, why: "the signature does not match the header — it was changed after it was signed" };
  }
  // Every key wrap must belong to someone the signed header lists as able to
  // hold it; anything else is a way in the signature never saw.
  for (const fp of Object.keys(data.dek.wraps)) {
    const r = data.recipients[fp];
    if (!r || r.sets) return { ok: false, why: "a wrap of the vault key belongs to no full member" };
  }
  for (const [env, k] of Object.entries(data.setKeys ?? {})) {
    for (const fp of Object.keys(k.wraps)) {
      const r = data.recipients[fp];
      if (!r || (r.sets && !r.sets.includes(env))) return { ok: false, why: `a wrap of set "${env}"'s key belongs to no member of it` };
    }
  }
  return { ok: true, by: sig.by };
}
