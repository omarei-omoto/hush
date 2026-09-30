/**
 * The part of a vault that is about keys and the file, not about values.
 *
 * Reading and writing the file atomically under a lock, replaying value edits
 * onto a copy someone else wrote meanwhile, unwrapping the vault key and set
 * keys — each checked against what this machine accepted (integrity.ts) — and
 * signing the header of a hush/v3 vault. `Vault` (vault.ts) builds the values,
 * sets and membership on top.
 */
import { existsSync, mkdirSync, readFileSync, openSync, writeSync, fsyncSync, closeSync, renameSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";

import { SCHEME, SCHEME_V2, SCHEME_V3, wrapDek, unwrapDek, decodePub, encodePub, encodeSpk, fingerprint, ValidationError, type Opener } from "./crypto.ts";
import { isAgeRecipient, ageFingerprint, wrapDekWithAge, unwrapDekWithAge } from "./age.ts";
import { signerFor } from "./identity.ts";
import { signHeader, verifyHeader, vaultKeyCommit } from "./header.ts";
import { withVaultLock, assertVaultShape, hashOf, describeOpener, candidatesOf, safeText, isAgeWrap, type VaultFile, type Recipient, type EnvMeta, type DekWrap } from "./vault-files.ts";

export const SCHEMES = [SCHEME, SCHEME_V2, SCHEME_V3];

/**
 * What a trust check needs to see of a vault: who can open it, the data key
 * behind its current generation — the vault key, or one set's own key — and
 * the whole document, for the signed header. See integrity.ts.
 */
export interface TrustView {
  vaultId: string;
  path: string;
  /** The generation of the key in `dek`: the vault key's, or the set's. */
  generation: number;
  recipients: Record<string, { name: string; pk: string }>;
  dek: Buffer;
  data: VaultFile;
  /** Present when `dek` is a restricted set's own key rather than the vault key. */
  set?: string;
}

/**
 * How the vault asks "has a person on this machine accepted this?".
 *
 * Injected rather than imported, so the check applies wherever `hush` itself
 * runs (the CLI turns it on in main(), and the MCP server and the app run under
 * that same main) while code that uses this module as a library — tests, a
 * script — never writes pins into somebody's real ~/.hush as a side effect.
 */
export interface TrustHook {
  /** Throw (TrustError) rather than let an unaccepted vault be decrypted. */
  verify(view: TrustView): void;
  /** This machine itself wrote the vault as it now stands: pin it. */
  record(view: TrustView): void;
}

let trustHook: TrustHook | null = null;

export function setTrustHook(hook: TrustHook | null): void {
  trustHook = hook;
}

/**
 * A member's public key, in any of the shapes it arrives in: `hush_pk_` with
 * 32 bytes (encryption only, as before 1.0), `hush_pk_` with 64 bytes (the
 * encryption key and the signing key together — what `hush id` prints since
 * 1.0), or an age recipient.
 */
export function parseMemberKey(input: string): { type: "x25519" | "age"; pk: string; fp: string; pub?: Buffer; spk?: string } {
  const t = input.trim();
  if (isAgeRecipient(t)) return { type: "age", pk: t, fp: ageFingerprint(t) };
  if (!t.startsWith("hush_pk_")) throw new ValidationError(`not a hush public key or an age recipient: ${t.slice(0, 16)}…`);
  const raw = Buffer.from(t.slice(8), "base64url");
  if (raw.length === 64) {
    const pub = raw.subarray(0, 32);
    return { type: "x25519", pk: encodePub(pub), fp: fingerprint(pub), pub, spk: encodeSpk(raw.subarray(32)) };
  }
  const pub = decodePub(t);
  return { type: "x25519", pk: encodePub(pub), fp: fingerprint(pub), pub };
}

/** The one string a person hands an admin: encryption and signing key together. */
export function memberKeyString(id: Opener): string {
  const signer = signerFor(id);
  if (id.pub && signer) return "hush_pk_" + Buffer.concat([id.pub, signer.spk]).toString("base64url");
  return describeOpener(id);
}

/**
 * The signing key that goes with one recipient: the key derived from an
 * X25519 identity, or — for an age (hardware) recipient, which cannot sign —
 * this machine's stored signing key. An opener can hold both at once, mid-way
 * through moving to hardware, so the recipient decides which.
 */
function signerOf(id: Opener, r: Recipient, create = false) {
  if (r.type === "age" || isAgeRecipient(r.pk)) return signerFor({ age: id.age }, create);
  return id.pub && id.priv ? signerFor({ pub: id.pub, priv: id.priv }) : null;
}

export const wrapFor = (key: Buffer, r: Recipient): DekWrap =>
  r.type === "age" || isAgeRecipient(r.pk) ? { age: wrapDekWithAge(key, r.pk) } : wrapDek(key, decodePub(r.pk));

export abstract class VaultCore {
  readonly path: string;
  data: VaultFile;
  /**
   * Keyed by recipient fingerprint. Never a bare Buffer: an unkeyed cache would
   * hand the DEK to whichever identity asked second, which is exactly the bug
   * that makes revocation meaningless inside a long-lived process.
   */
  protected dekCache: { fp: string; dek: Buffer } | null = null;
  protected setKeyCache = new Map<string, { fp: string; key: Buffer }>();

  /** Hash of the bytes this instance was read from, to detect a concurrent write. */
  protected baseline: string | null = null;
  /** Value-level edits, replayable onto a newer copy if someone else wrote first. */
  protected journal: (
    | { op: "set"; env: string; key: string; value: string; note?: string }
    | { op: "delete"; env: string; key: string }
    | { op: "retag"; env: string; key: string; note?: string }
    | { op: "describe"; env: string; meta: EnvMeta }
  )[] = [];
  /** Set by membership or key-rotation changes, which are not safely replayable. */
  protected structural = false;
  /** Remembered so a replay can re-seal under the newer data key, and a save can sign. */
  protected opener: Opener | null = null;
  /**
   * A data key this instance knows is legitimate for `data.dek.generation`:
   * one it minted itself, or one that passed the trust check. What a save pins,
   * since a vault this machine just wrote is by definition one it accepts.
   */
  protected trusted: { generation: number; dek: Buffer } | null = null;
  /** The same, per restricted set. */
  protected trustedSets = new Map<string, { generation: number; key: Buffer }>();

  /** True when at least one member uses age, so hardware is worth waking. */
  protected get usesAge(): boolean {
    return (
      Object.values(this.data.dek.wraps).some(isAgeWrap) ||
      Object.values(this.data.setKeys ?? {}).some((k) => Object.values(k.wraps).some(isAgeWrap))
    );
  }

  protected myCandidates(id: Opener) {
    return candidatesOf(id, this.usesAge);
  }

  protected constructor(path: string, data: VaultFile) {
    this.path = path;
    this.data = data;
  }

  /** hush/v3: the header is signed by an admin. */
  get signed(): boolean {
    return this.data.scheme === SCHEME_V3;
  }

  /**
   * Write atomically: full contents to a temp file, fsync, then rename.
   *
   * A plain writeFileSync truncates first, so a crash, a full disk, or two
   * concurrent commands mid-write leaves a truncated vault — which means every
   * secret in it is gone. rename(2) on the same filesystem is atomic, so a
   * reader sees either the old file or the new one, never a half-written one.
   */
  save(): void {
    mkdirSync(dirname(this.path), { recursive: true });
    withVaultLock(this.path, () => this.saveLocked());
    // What this machine just wrote is what it accepts: a member it added, a
    // rotation it made. Only when the key in hand belongs to the generation on
    // disk — a save that never touched a data key pins nothing.
    if (!trustHook) return;
    if (this.trusted && this.trusted.generation === this.data.dek.generation) {
      trustHook.record(this.trustView(this.trusted.dek));
    }
    for (const [env, t] of this.trustedSets) {
      if (this.data.setKeys?.[env]?.generation === t.generation) trustHook.record(this.trustView(t.key, env));
    }
  }

  /** The shape the trust check reads. See integrity.ts. */
  trustView(dek: Buffer, set?: string): TrustView {
    const recipients: TrustView["recipients"] = {};
    for (const [fp, r] of Object.entries(this.data.recipients)) recipients[fp] = { name: r.name, pk: r.pk };
    const generation = set ? this.data.setKeys![set].generation : this.data.dek.generation;
    return { vaultId: this.data.id, path: this.path, generation, recipients, dek, data: this.data, ...(set ? { set } : {}) };
  }

  /**
   * The key this identity can review the vault with *without* the trust check,
   * for showing a person what changed (`hush team accept`, `hush verify`): the
   * vault key for a full member, otherwise one of their sets' keys. Never used
   * to open or seal a value: that is exactly what the check exists to stop.
   */
  reviewView(id: Opener): TrustView {
    for (const c of this.myCandidates(id)) {
      const wrap = this.data.dek.wraps[c.fp];
      if (wrap) return this.trustView(this.unwrap(wrap, id));
    }
    for (const [env, k] of Object.entries(this.data.setKeys ?? {})) {
      for (const c of this.myCandidates(id)) {
        const wrap = k.wraps[c.fp];
        if (wrap) return this.trustView(this.unwrap(wrap, id), env);
      }
    }
    throw new Error(`Your key is not a recipient of vault "${this.data.name}".`);
  }

  /**
   * A restricted set's key without the trust check, for a merge or a review —
   * never to open or seal a value in place. Null when this identity is not
   * wrapped into that set.
   */
  setKeyForReview(id: Opener, env: string): Buffer | null {
    const k = this.data.setKeys?.[env];
    if (!k) return null;
    for (const c of this.myCandidates(id)) {
      const wrap = k.wraps[c.fp];
      if (wrap) return this.unwrap(wrap, id);
    }
    return null;
  }

  /**
   * Sign the header as it stands, as `id` — for a document assembled outside
   * the usual edits (a merge). Refuses unless `id` is an admin whose signing
   * key the vault lists.
   */
  signAs(id: Opener): void {
    this.opener = id;
    this.signIfNeeded();
  }

  /** The vault key without the trust check — for a full member's review only. */
  dekForReview(id: Opener): Buffer {
    const view = this.reviewView(id);
    if (view.set) throw new Error(`You can read only some sets of vault "${this.data.name}", not its vault key.`);
    return view.dek;
  }

  protected unwrap(wrap: DekWrap, id: Opener): Buffer {
    // An age wrap may be backed by a YubiKey or the Secure Enclave, so this
    // line is where the human gets prompted to touch something.
    return isAgeWrap(wrap) ? unwrapDekWithAge(wrap.age, id.age!.identityPath) : unwrapDek(wrap, { pub: id.pub!, priv: id.priv! });
  }

  /**
   * Reconcile with whatever is on disk, then write.
   *
   * If another process wrote while we were thinking, our in-memory copy is
   * stale and writing it would erase their work. Value edits are replayed onto
   * the newer copy so both survive; membership and rotation changes are not
   * replayable, so those refuse rather than guess.
   */
  protected saveLocked(): void {
    const onDisk = existsSync(this.path) ? readFileSync(this.path, "utf8") : null;

    if (this.baseline !== null && onDisk !== null && hashOf(onDisk) !== this.baseline) {
      // Deletions replay without an identity; only re-sealing a value needs one.
      const needsOpener = this.journal.some((e) => e.op === "set");
      if (this.structural || this.journal.length === 0 || (needsOpener && !this.opener)) {
        throw new Error(
          "The vault changed on disk while this command was running, and this change " +
            "cannot be merged automatically. Re-run the command.",
        );
      }
      // Validated, not just parsed. This is the one path that adopts a vault
      // file without going through open(), and it adopts it wholesale — so a
      // malformed file landing here would replace our in-memory copy and then
      // be written straight back out, laundering it into the repo.
      const parsed = JSON.parse(onDisk) as VaultFile;
      assertVaultShape(parsed, this.path);
      const fresh = this.replay(parsed);
      this.data = fresh.data;
      this.dekCache = null;
      this.setKeyCache.clear();
      // The copy on disk is someone else's write. Its keys count as checked
      // only if replaying a value onto it went through the trust check.
      this.trusted = fresh.trusted;
      this.trustedSets = fresh.trustedSets;
    }

    this.signIfNeeded();
    this.writeAtomically();
    this.journal = [];
    this.structural = false;
  }

  /**
   * A v3 vault's header must carry a valid admin signature when it is written.
   * Value edits leave the header alone, so the existing signature still holds;
   * anything that changed who holds which key needs a fresh one, and only an
   * admin — with the signing key the vault lists for them — can give it.
   */
  protected signIfNeeded(): void {
    if (!this.signed) return;
    if (verifyHeader(this.data).ok) return;
    const me = this.opener ? this.myRecipient(this.opener) : null;
    if (!this.opener || !me || me[1].role !== "admin" || me[1].ci) {
      throw new ValidationError(
        `Only an admin can change who can read vault "${safeText(this.data.name, 64)}" — its members, its keys, ` +
          `or who may read a set. Admins: ${this.adminNames().join(", ") || "none"}.`,
      );
    }
    const signer = signerOf(this.opener, me[1], true);
    if (!signer || !me[1].spk || encodeSpk(signer.spk) !== me[1].spk) {
      throw new ValidationError(
        `You are an admin of "${safeText(this.data.name, 64)}", but the signing key it lists for you is not this machine's. ` +
          `Another admin can re-add you with the key \`hush id\` prints.`,
      );
    }
    signHeader(this.data, me[0], signer);
  }

  protected adminNames(): string[] {
    return Object.values(this.data.recipients)
      .filter((r) => r.role === "admin" && !r.ci)
      .map((r) => safeText(r.name, 64) ?? "unknown");
  }

  protected writeAtomically(): void {
    // A vault that now holds generation-bound values must not keep claiming to
    // be v1: an older hush reading it would fail those values with a bare AEAD
    // error instead of a clear "this build is too old" message.
    if (this.data.scheme === SCHEME && Object.values(this.data.envs).some((m) => Object.values(m).some((e) => e.v === 2))) {
      this.data.scheme = SCHEME_V2;
    }
    const body = JSON.stringify(this.data, null, 2) + "\n";
    const tmp = `${this.path}.${process.pid}.tmp`;

    let fd: number | undefined;
    try {
      fd = openSync(tmp, "w", 0o600);
      writeSync(fd, body);
      fsyncSync(fd);
      closeSync(fd);
      fd = undefined;
      renameSync(tmp, this.path);
      this.baseline = hashOf(body);
    } catch (e) {
      if (fd !== undefined) {
        try { closeSync(fd); } catch { /* already closed */ }
      }
      if (existsSync(tmp)) {
        try { unlinkSync(tmp); } catch { /* best effort */ }
      }
      throw e;
    }
  }

  // ------------------------------------------------------------ key access

  /**
   * Unwrap the vault key with the caller's identity. Throws if they were
   * revoked, or are a scoped member (who holds set keys, not this one).
   * Membership is re-checked on every call, before the cache is consulted.
   */
  dek(id: Opener): Buffer {
    for (const c of this.myCandidates(id)) {
      const wrap = this.data.dek.wraps[c.fp];
      if (!wrap) continue;
      if (this.dekCache?.fp === c.fp) return this.dekCache.dek;
      const dek = this.unwrap(wrap, id);

      // Unwrapping proves the key was wrapped *to* you, not *by* a member: a
      // non-member can wrap a key of their choosing to every public key in the
      // file. So before anything is opened or sealed with it, the vault has to
      // be one a person on this machine accepted (V-1, integrity.ts).
      const generation = this.data.dek.generation;
      const known = this.trusted?.generation === generation && this.trusted.dek.equals(dek);
      if (trustHook && !known) trustHook.verify(this.trustView(dek));
      this.trusted = { generation, dek };

      this.dekCache = { fp: c.fp, dek };
      return dek;
    }
    const scoped = this.myRecipient(id)?.[1].sets;
    throw new Error(
      scoped
        ? `You can read only these sets of vault "${this.data.name}": ${scoped.join(", ") || "none"}.`
        : `Your key is not a recipient of vault "${this.data.name}".\n` +
            `Ask an admin to run:  hush team add <you> ${describeOpener(id)}`,
    );
  }

  /** A restricted set's own key, checked the same way the vault key is. */
  protected setKey(id: Opener, env: string): Buffer {
    const k = this.data.setKeys?.[env];
    if (!k) throw new Error(`"${env}" has no key of its own.`);
    for (const c of this.myCandidates(id)) {
      const wrap = k.wraps[c.fp];
      if (!wrap) continue;
      const cached = this.setKeyCache.get(env);
      if (cached?.fp === c.fp) return cached.key;
      const key = this.unwrap(wrap, id);
      const t = this.trustedSets.get(env);
      const known = t?.generation === k.generation && t.key.equals(key);
      if (trustHook && !known) trustHook.verify(this.trustView(key, env));
      this.trustedSets.set(env, { generation: k.generation, key });
      this.setKeyCache.set(env, { fp: c.fp, key });
      return key;
    }
    throw new ValidationError(
      `You are not a member of set "${env}" in vault "${safeText(this.data.name, 64)}". ` +
        `An admin can add you: hush team add <you> <your key> --sets ${env}`,
    );
  }

  /** The key a set's values are sealed under, and its generation. */
  protected keyFor(id: Opener, env: string): Buffer {
    return this.isRestricted(env) ? this.setKey(id, env) : this.dek(id);
  }

  protected genFor(env: string): number {
    return this.data.setKeys?.[env]?.generation ?? this.data.dek.generation;
  }

  /** The set has a key of its own (hush/v3). */
  isRestricted(env: string): boolean {
    return Boolean(this.data.setKeys?.[env]);
  }

  /** Can this identity open anything in this vault at all? */
  canRead(id: Opener): boolean {
    const cands = this.myCandidates(id);
    if (cands.some((c) => Boolean(this.data.dek.wraps[c.fp]))) return true;
    return Object.values(this.data.setKeys ?? {}).some((k) => cands.some((c) => Boolean(k.wraps[c.fp])));
  }

  /** Can this identity open this particular set? */
  canReadSet(id: Opener, env: string): boolean {
    const cands = this.myCandidates(id);
    const wraps = this.data.setKeys?.[env]?.wraps ?? this.data.dek.wraps;
    return cands.some((c) => Boolean(wraps[c.fp]));
  }

  meFingerprint(id: Opener): string {
    return this.myRecipient(id)?.[0] ?? "";
  }

  protected myRecipient(id: Opener): [string, Recipient] | null {
    for (const c of this.myCandidates(id)) {
      const r = this.data.recipients[c.fp];
      if (r) return [c.fp, r];
    }
    return null;
  }

  memberName(id: Opener): string {
    const me = this.myRecipient(id);
    return me ? (safeText(me[1].name, 64) ?? "unknown") : "unknown";
  }

  /** Is this identity an admin who could sign a change to the header? */
  isAdmin(id: Opener): boolean {
    const me = this.myRecipient(id);
    return Boolean(me && me[1].role === "admin" && !me[1].ci && !me[1].sets);
  }

  // --------------------------------------------------------------- members

  /**
   * In a signed (v3) vault, only an admin may change who holds which key. A v2
   * vault an admin touches this way is signed on the spot — the upgrade that
   * makes their role mean something.
   */
  protected beginHeaderChange(id: Opener): void {
    // Every key this identity holds is unwrapped — and so checked against what
    // this machine accepted — *before* the header changes. Checked afterwards,
    // the check would see this very edit and call it unsigned.
    if (this.myCandidates(id).some((c) => this.data.dek.wraps[c.fp])) this.dek(id);
    for (const env of Object.keys(this.data.setKeys ?? {})) if (this.canReadSet(id, env)) this.setKey(id, env);
    this.opener = id;
    this.structural = true;
    if (this.signed) {
      if (!this.isAdmin(id)) {
        throw new ValidationError(
          `Only an admin can change who can read vault "${safeText(this.data.name, 64)}". ` +
            `Admins: ${this.adminNames().join(", ") || "none"}.`,
        );
      }
      return;
    }
    const me = this.myRecipient(id);
    if (me && this.isAdmin(id) && signerOf(id, me[1])) this.upgradeToV3(id);
  }

  /**
   * Sign this vault (hush/v3). The opener must be a full admin; their own
   * signing key is recorded, and a commitment to every data key is added so
   * the signature covers which keys members should find.
   */
  upgradeToV3(id: Opener): void {
    if (this.signed) return;
    const me = this.myRecipient(id);
    if (!me || me[1].role !== "admin" || me[1].sets) {
      throw new ValidationError(`Only an admin can sign vault "${safeText(this.data.name, 64)}".`);
    }
    const signer = signerOf(id, me[1], true);
    if (!signer) throw new ValidationError("This identity has no signing key.");
    this.opener = id;
    this.structural = true;
    const dek = this.dek(id);
    this.data.dek.commit = vaultKeyCommit(dek, this.data.id, this.data.dek.generation);
    me[1].spk = encodeSpk(signer.spk);
    this.data.scheme = SCHEME_V3;
  }

  /** A fresh instance over `parsed` with this instance's value edits applied — see saveLocked. */
  protected abstract replay(parsed: VaultFile): VaultCore;
}
