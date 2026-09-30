/**
 * The vault file. Safe to commit — it contains only ciphertext and public keys.
 *
 * A vault can live in the repo (`.hush/vault.json`, committed) or outside it
 * (`~/.hush/vaults/<name>/vault.json`) with the repo holding a `.hush/link.json`
 * pointer. The second form is how one team vault serves many repos.
 *
 * This module is the Vault class; the file's shapes, names and locations are
 * in vault-files.ts and re-exported from here, so callers import one module.
 *
 * **Keys (hush/v3).** Every vault has one vault key, wrapped for each *full*
 * member, which seals every set that has no key of its own. A set can have a
 * key of its own — a *restricted* set — so that a *scoped* member (a junior who
 * gets `dev` but not `prod`, a CI identity that gets `ci`) can read it without
 * holding the vault key. Full members are wrapped into every restricted set
 * too, so for them nothing changes. Who holds which key is the header, and in
 * hush/v3 an admin signs it (header.ts).
 */
import { existsSync, mkdirSync, readFileSync, openSync, writeSync, fsyncSync, closeSync, renameSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import {
  SCHEME,
  SCHEME_V2,
  SCHEME_V3,
  newDek,
  wrapDek,
  unwrapDek,
  sealValue,
  openValue,
  decodePub,
  encodePub,
  encodeSpk,
  decodeSpk,
  fingerprint,
  ValidationError,
  type Opener,
} from "./crypto.ts";
import { isAgeRecipient, ageFingerprint, wrapDekWithAge, unwrapDekWithAge } from "./age.ts";
import { signerFor } from "./identity.ts";
import { signHeader, verifyHeader, setKeyCommit, vaultKeyCommit } from "./header.ts";
import {
  withVaultLock, assertVaultShape, hashOf, jsonErrorSummary, describeOpener, candidatesOf,
  assertScopeName, assertKeyName, assertValueSize, trimNote, safeText, isAgeWrap,
  type VaultFile, type Recipient, type SecretEntry, type EnvMeta, type DekWrap,
} from "./vault-files.ts";

export * from "./vault-files.ts";

const SCHEMES = [SCHEME, SCHEME_V2, SCHEME_V3];

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

const wrapFor = (key: Buffer, r: Recipient): DekWrap =>
  r.type === "age" || isAgeRecipient(r.pk) ? { age: wrapDekWithAge(key, r.pk) } : wrapDek(key, decodePub(r.pk));

export class Vault {
  readonly path: string;
  data: VaultFile;
  /**
   * Keyed by recipient fingerprint. Never a bare Buffer: an unkeyed cache would
   * hand the DEK to whichever identity asked second, which is exactly the bug
   * that makes revocation meaningless inside a long-lived process.
   */
  private dekCache: { fp: string; dek: Buffer } | null = null;
  private setKeyCache = new Map<string, { fp: string; key: Buffer }>();

  /** Hash of the bytes this instance was read from, to detect a concurrent write. */
  private baseline: string | null = null;
  /** Value-level edits, replayable onto a newer copy if someone else wrote first. */
  private journal: (
    | { op: "set"; env: string; key: string; value: string; note?: string }
    | { op: "delete"; env: string; key: string }
    | { op: "retag"; env: string; key: string; note?: string }
    | { op: "describe"; env: string; meta: EnvMeta }
  )[] = [];
  /** Set by membership or key-rotation changes, which are not safely replayable. */
  private structural = false;
  /** Remembered so a replay can re-seal under the newer data key, and a save can sign. */
  private opener: Opener | null = null;
  /**
   * A data key this instance knows is legitimate for `data.dek.generation`:
   * one it minted itself, or one that passed the trust check. What a save pins,
   * since a vault this machine just wrote is by definition one it accepts.
   */
  private trusted: { generation: number; dek: Buffer } | null = null;
  /** The same, per restricted set. */
  private trustedSets = new Map<string, { generation: number; key: Buffer }>();

  /** True when at least one member uses age, so hardware is worth waking. */
  private get usesAge(): boolean {
    return (
      Object.values(this.data.dek.wraps).some(isAgeWrap) ||
      Object.values(this.data.setKeys ?? {}).some((k) => Object.values(k.wraps).some(isAgeWrap))
    );
  }

  private myCandidates(id: Opener) {
    return candidatesOf(id, this.usesAge);
  }

  private constructor(path: string, data: VaultFile) {
    this.path = path;
    this.data = data;
  }

  /**
   * The founding member is either an X25519 key or an age recipient.
   *
   * An X25519 founder gets a signed hush/v3 vault from the start. An age-only
   * founder (a hardware key) gets v2 until `hush team sign`: signing needs a
   * key the hardware cannot provide, and making one is not something a library
   * call should do behind anyone's back.
   */
  static create(
    path: string,
    name: string,
    owner: { name: string; pub?: Buffer; ageRecipient?: string; priv?: Buffer },
  ): Vault {
    const dek = newDek();
    const now = new Date().toISOString();

    let fp: string;
    let wrap: DekWrap;
    let recipient: Recipient;

    if (owner.ageRecipient && !owner.pub) {
      const r = owner.ageRecipient.trim();
      fp = ageFingerprint(r);
      wrap = { age: wrapDekWithAge(dek, r) };
      recipient = { name: owner.name, pk: r, role: "admin", addedAt: now, type: "age" };
    } else if (owner.pub) {
      fp = fingerprint(owner.pub);
      wrap = wrapDek(dek, owner.pub);
      recipient = { name: owner.name, pk: encodePub(owner.pub), role: "admin", addedAt: now, type: "x25519" };
    } else {
      throw new Error("A vault needs a founding member: pass either pub or ageRecipient.");
    }

    const id = `vlt_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const data: VaultFile = {
      scheme: SCHEME_V2,
      id,
      name,
      createdAt: now,
      dek: { generation: 1, wraps: { [fp]: wrap }, commit: vaultKeyCommit(dek, id, 1) },
      recipients: { [fp]: recipient },
      envs: { default: {} },
    };
    const v = new Vault(path, data);
    v.dekCache = { fp, dek };
    v.trusted = { generation: 1, dek };
    // Signed from birth when the founder can sign: the whole point of v3 is
    // that there is never an unsigned moment for someone to slip into.
    if (owner.pub && owner.priv) {
      v.opener = { pub: owner.pub, priv: owner.priv };
      v.upgradeToV3(v.opener);
    }
    v.save();
    return v;
  }

  /**
   * A vault from a document already in memory — one side of a merge, say —
   * checked exactly as a file would be. Never saved unless the caller does.
   */
  static fromData(path: string, data: VaultFile): Vault {
    if (!SCHEMES.includes(data?.scheme)) {
      throw new Error(`Unsupported vault scheme ${data?.scheme ?? "(none)"} in ${path}.`);
    }
    assertVaultShape(data, path);
    return new Vault(path, data);
  }

  static open(path: string): Vault {
    if (!existsSync(path)) throw new Error(`No vault at ${path}. Run \`hush init\`.`);
    const raw = readFileSync(path, "utf8");

    let data: VaultFile;
    try {
      data = JSON.parse(raw) as VaultFile;
    } catch (e) {
      // By far the likeliest cause: two people added secrets, git conflicted,
      // and the markers were committed. "Unexpected token '<'" helps nobody.
      const conflicted = /^<{7} |^={7}$|^>{7} /m.test(raw);
      throw new Error(
        conflicted
          ? `The vault at ${path} still contains git conflict markers.\n` +
            `  A vault cannot be merged line by line. Run \`hush merge\` — it merges it key by key —\n` +
            `  and \`hush merge-driver --install\` so git does that itself next time.`
          : `The vault at ${path} is not valid JSON (${jsonErrorSummary(e)}).\n` +
            `  Restore it from git history: git checkout HEAD -- ${path}`,
      );
    }

    if (!SCHEMES.includes(data?.scheme)) {
      throw new Error(
        `Unsupported vault scheme ${data?.scheme ?? "(none)"} (this build speaks ${SCHEMES.join(", ")}).\n` +
          `  Upgrade hush, or check that ${path} really is a vault file.`,
      );
    }
    assertVaultShape(data, path);
    const v = new Vault(path, data);
    v.baseline = hashOf(raw);
    return v;
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

  private unwrap(wrap: DekWrap, id: Opener): Buffer {
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
  private saveLocked(): void {
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
      const fresh = new Vault(this.path, parsed);
      for (const entry of this.journal) {
        if (entry.op === "set") fresh.set(this.opener!, entry.env, entry.key, entry.value, entry.note);
        else if (entry.op === "retag") fresh.retag(entry.env, entry.key, entry.note);
        else if (entry.op === "describe") {
          // Metadata replays without a key, like a retag: it is plaintext beside
          // the ciphertext, not inside it.
          if (fresh.data.envs[entry.env]) fresh.describeEnv(entry.env, entry.meta);
        } else fresh.delete(entry.env, entry.key);
      }
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
  private signIfNeeded(): void {
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

  private adminNames(): string[] {
    return Object.values(this.data.recipients)
      .filter((r) => r.role === "admin" && !r.ci)
      .map((r) => safeText(r.name, 64) ?? "unknown");
  }

  private writeAtomically(): void {
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
  private setKey(id: Opener, env: string): Buffer {
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
  private keyFor(id: Opener, env: string): Buffer {
    return this.isRestricted(env) ? this.setKey(id, env) : this.dek(id);
  }

  private genFor(env: string): number {
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

  private myRecipient(id: Opener): [string, Recipient] | null {
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

  // -------------------------------------------------------------- secrets

  envNames(): string[] {
    return Object.keys(this.data.envs).sort();
  }

  /**
   * Merge named sets in order, later wins per key. The unified replacement
   * for resolve(): `resolveSets(id, ["default", "fal/acme"])` is what
   * `resolve(id, "default", [{service:"fal",account:"acme"}])` used to be —
   * one flat list instead of a base env plus a pile of (service, account)
   * pairs, because a name with a "/" in it was never anything but a name.
   *
   * Unlike resolve(), a missing name always throws rather than being skipped
   * silently — "default" gets no special treatment, so silence for one name
   * and a hard failure for another would just be arbitrary.
   */
  resolveSets(id: Opener, names: string[]): { secrets: Record<string, string>; layers: string[] } {
    const secrets: Record<string, string> = {};
    const layers: string[] = [];
    for (const name of names) {
      if (!this.data.envs[name]) {
        const known = this.envNames();
        throw new ValidationError(
          `No set called "${name}". You have: ${known.length ? known.join(", ") : "none yet"}.`,
        );
      }
      Object.assign(secrets, this.materialize(id, name));
      layers.push(name);
    }
    return { secrets, layers };
  }

  ensureEnv(env: string): Record<string, SecretEntry> {
    this.data.envs[env] ??= {};
    return this.data.envs[env];
  }

  /** Key names only. Safe to show an agent. */
  list(env: string): { key: string; updatedAt: string; updatedBy: string; note?: string; exposed?: string[] }[] {
    const slot = this.data.envs[env] ?? {};
    return Object.entries(slot)
      // Sanitised here rather than at each call site: every renderer reads this,
      // and one that forgot would be a terminal-escape hole, not a cosmetic slip.
      .map(([key, e]) => ({
        key: safeText(key, 64) ?? "<unprintable>",
        updatedAt: safeText(e.updatedAt, 32) ?? "",
        updatedBy: safeText(e.updatedBy, 64) ?? "unknown",
        note: safeText(e.note),
        ...(e.exposed?.length ? { exposed: e.exposed.map((n) => safeText(n, 64) ?? "unknown") } : {}),
      }))
      .sort((a, b) => a.key.localeCompare(b.key));
  }

  /**
   * Declare that this change cannot be replayed onto a newer copy.
   *
   * Value edits merge; anything that adds, removes or renames an environment
   * does not, because there is no sensible way to blend two of those. Callers
   * that reach into `data.envs` directly have to say so themselves.
   */
  markStructural(): void {
    this.structural = true;
  }

  /** Create an environment with nothing in it yet. */
  ensureEnvExists(env: string): void {
    assertScopeName(env);
    this.ensureEnv(env);
  }

  /**
   * Remove a whole set. A restricted set takes its key with it, and scoped
   * members lose it from their list — which changes the header, so in a v3
   * vault only an admin can do it.
   */
  removeSet(id: Opener | null, env: string): void {
    this.opener = id ?? this.opener;
    this.structural = true;
    delete this.data.envs[env];
    if (this.data.meta) delete this.data.meta[env];
    if (this.data.setKeys?.[env]) {
      delete this.data.setKeys[env];
      if (!Object.keys(this.data.setKeys).length) delete this.data.setKeys;
    }
    for (const r of Object.values(this.data.recipients)) {
      if (r.sets?.includes(env)) r.sets = r.sets.filter((s) => s !== env);
    }
    this.trustedSets.delete(env);
    this.setKeyCache.delete(env);
  }

  /** What this environment is called and what it is for. Never throws. */
  envMeta(env: string): EnvMeta {
    return this.data.meta?.[env] ?? {};
  }

  /** The display name: what they typed, falling back to the name itself. */
  envLabel(env: string): string {
    return safeText(this.data.meta?.[env]?.label, 80) ?? env;
  }

  /**
   * Every environment as a named set, which is how a person thinks about them:
   * a thing with a name, a purpose, and some keys in it. A name with a "/" in
   * it — "fal/acme" — is not treated specially; it is just a name someone chose.
   */
  sets(): {
    name: string;
    label: string;
    description?: string;
    whenToUse?: string;
    source?: string;
    keys: string[];
    /** Has a key of its own, so scoped members can be given it (or kept out). */
    restricted: boolean;
    /** Who can read it, when restricted: every full member plus the scoped members given it. */
    readers?: string[];
  }[] {
    return this.envNames()
      .map((name) => {
        const meta = this.envMeta(name);
        const k = this.data.setKeys?.[name];
        return {
          // Scrubbed for the same reason a key name is: this is the shape every
          // renderer reads, and a name that arrived in a hand-edited or
          // git-merged vault file is shown, not looked up. `envNames()` and
          // `hasSet()` keep the exact bytes for identity.
          name: safeText(name, 80) ?? "<unprintable>",
          label: this.envLabel(name),
          description: safeText(meta.description, 500),
          whenToUse: safeText(meta.whenToUse, 500),
          source: safeText(meta.source, 200),
          keys: Object.keys(this.data.envs[name] ?? {})
            .sort()
            .map((key) => safeText(key, 64) ?? "<unprintable>"),
          restricted: Boolean(k),
          ...(k
            ? {
                readers: Object.keys(k.wraps)
                  .map((fp) => safeText(this.data.recipients[fp]?.name, 64) ?? "unknown")
                  .sort(),
              }
            : {}),
        };
      })
      .sort((a, b) => a.label.localeCompare(b.label));
  }

  /** A set by this name exists, whether or not it holds anything yet. */
  hasSet(name: string): boolean {
    return Boolean(this.data.envs[name]);
  }

  /**
   * Describe an environment. Metadata only — no data key needed, so this never
   * prompts a hardware identity.
   */
  describeEnv(env: string, meta: Partial<EnvMeta>): void {
    assertScopeName(env);
    if (!this.data.envs[env]) throw new ValidationError(`No environment "${env}".`);
    this.data.meta ??= {};
    const current = this.data.meta[env] ?? {};
    const next: EnvMeta = { ...current };
    for (const field of ["label", "description", "whenToUse", "source"] as const) {
      if (!(field in meta)) continue;
      const value = safeText(meta[field], field === "label" ? 80 : 500);
      if (value) next[field] = value;
      else delete next[field];
    }
    next.createdAt ??= new Date().toISOString();
    this.data.meta[env] = next;
    this.journal.push({ op: "describe", env, meta: next });
  }

  has(env: string, key: string): boolean {
    return Boolean(this.data.envs[env]?.[key]);
  }

  /**
   * Data-key wraps with no member entry behind them.
   *
   * The wraps map is what actually grants decryption; `recipients` is the list
   * people read. A wrap whose fingerprint is absent from `recipients` therefore
   * opens every secret in the vault while `hush team ls` shows no such member —
   * which is exactly the shape a revoked member would add if they still held the
   * data key and wanted quiet access. hush never writes one.
   */
  unlistedWraps(): string[] {
    const fps = new Set(Object.keys(this.data.dek.wraps));
    for (const k of Object.values(this.data.setKeys ?? {})) for (const fp of Object.keys(k.wraps)) fps.add(fp);
    return [...fps].filter((fp) => !this.data.recipients[fp]).sort();
  }

  /**
   * Values sealed under a data key older than the one their set uses now.
   *
   * `rotate()` and `removeRecipient()` re-seal everything, so in a vault hush
   * wrote this is always empty. It will not be empty if a rotation was
   * interrupted, or if two branches were merged by hand and one side's values
   * were kept next to the other side's key — in which case a revoked member's
   * old key still opens the values that were left behind, and the revocation
   * only looks complete.
   */
  staleValues(): { env: string; key: string; gen: number }[] {
    const out: { env: string; key: string; gen: number }[] = [];
    for (const [env, values] of Object.entries(this.data.envs)) {
      const current = this.genFor(env);
      for (const [key, entry] of Object.entries(values)) {
        if (entry.gen < current) out.push({ env, key, gen: entry.gen });
      }
    }
    return out.sort((a, b) => a.env.localeCompare(b.env) || a.key.localeCompare(b.key));
  }

  /**
   * The generation bound into an entry's AAD, or undefined for a value this
   * build did not seal. One place, so every reader makes the same decision
   * about a vault that was upgraded value by value.
   */
  private aadGen(entry: SecretEntry): number | undefined {
    return entry.v === 2 ? entry.gen : undefined;
  }

  private sealEntry(key: Buffer, env: string, name: string, value: string, prev?: Partial<SecretEntry>): SecretEntry {
    const gen = this.genFor(env);
    return {
      ...sealValue(key, env, name, value, gen),
      gen,
      v: 2,
      updatedAt: prev?.updatedAt ?? new Date().toISOString(),
      updatedBy: prev?.updatedBy ?? "unknown",
      ...(prev?.note ? { note: prev.note } : {}),
      ...(prev?.exposed?.length ? { exposed: prev.exposed } : {}),
    };
  }

  set(id: Opener, env: string, key: string, value: string, note?: string): void {
    assertScopeName(env);
    assertKeyName(key);
    assertValueSize(key, value);
    this.opener = id;
    this.journal.push({ op: "set", env, key, value, ...(note ? { note } : {}) });
    const k = this.keyFor(id, env);
    const slot = this.ensureEnv(env);
    // A new value is not the one someone removed could read: the exposure
    // marker (F-6) goes with the old value.
    slot[key] = this.sealEntry(k, env, key, value, {
      updatedAt: new Date().toISOString(),
      updatedBy: this.memberName(id),
      note: trimNote(note),
    });
  }

  get(id: Opener, env: string, key: string): string {
    const entry = this.data.envs[env]?.[key];
    if (!entry) throw new ValidationError(`No secret "${key}" in env "${env}".`);
    return openValue(this.keyFor(id, env), env, key, entry, this.aadGen(entry));
  }

  /**
   * Move a value from one set to another.
   *
   * Not a map-key edit: the environment name is bound into every value's AAD —
   * the thing that stops a staging URL being pasted into the prod slot — so the
   * value is opened and re-sealed under its new home (and its key, when the
   * two sets have different ones). That also means this needs an identity, and
   * that it is not mergeable with a concurrent write.
   *
   * It exists because the state everybody actually starts in is one big pile of
   * keys under "default", and carving that into named sets is the whole point of
   * naming them.
   */
  moveSecret(id: Opener, key: string, from: string, to: string): void {
    assertScopeName(from);
    assertScopeName(to);
    assertKeyName(key);
    if (from === to) return;

    const entry = this.data.envs[from]?.[key];
    if (!entry) throw new ValidationError(`No secret "${key}" in "${from}".`);
    if (this.data.envs[to]?.[key]) {
      throw new ValidationError(`"${to}" already has a ${key}. Delete one of them first.`);
    }

    this.structural = true;
    this.opener = id;

    const value = openValue(this.keyFor(id, from), from, key, entry, this.aadGen(entry));
    this.ensureEnv(to);
    this.data.envs[to][key] = this.sealEntry(this.keyFor(id, to), to, key, value, entry);
    delete this.data.envs[from][key];
  }

  /**
   * Change a secret's label without unsealing it.
   *
   * The note is plaintext metadata beside the ciphertext — not inside it, and
   * not part of the AAD — so relabelling needs no data key. Doing this through
   * set() meant decrypting and re-sealing, which for a hardware-backed identity
   * asked the user to touch their key just to rename a tag.
   */
  retag(env: string, key: string, note?: string): boolean {
    const entry = this.data.envs[env]?.[key];
    if (!entry) return false;
    const label = trimNote(note);
    if (label) entry.note = label;
    else delete entry.note;
    this.journal.push({ op: "retag", env, key, ...(label ? { note: label } : {}) });
    return true;
  }

  delete(env: string, key: string): boolean {
    const slot = this.data.envs[env];
    if (!slot?.[key]) return false;
    delete slot[key];
    this.journal.push({ op: "delete", env, key });
    return true;
  }

  /** Decrypt an entire environment. Only ever called in-process, never written out by default. */
  materialize(id: Opener, env: string): Record<string, string> {
    const entries = Object.entries(this.data.envs[env] ?? {});
    if (!entries.length) return {};
    const k = this.keyFor(id, env);
    const out: Record<string, string> = {};
    for (const [key, entry] of entries) out[key] = openValue(k, env, key, entry, this.aadGen(entry));
    return out;
  }

  // --------------------------------------------------------------- members

  /**
   * In a signed (v3) vault, only an admin may change who holds which key. A v2
   * vault an admin touches this way is signed on the spot — the upgrade that
   * makes their role mean something.
   */
  private beginHeaderChange(id: Opener): void {
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

  /**
   * Add a member, or change one: a new key for an existing name is refused, but
   * the same key again can add a signing key, change a role, or grant sets.
   *
   * `sets` makes a *scoped* member: no vault key, only the keys of those sets
   * (each becomes restricted, with a key of its own, if it was not already).
   * `ci` marks a machine identity: always scoped, never an admin.
   */
  addRecipient(
    id: Opener,
    name: string,
    pkString: string,
    role: "admin" | "member" = "member",
    opts: { sets?: string[]; ci?: boolean; spk?: string } = {},
  ): string {
    const parsed = parseMemberKey(pkString);
    // Your own hardware key, added by you (the `hush secure --hardware` step):
    // it cannot sign, so it carries this machine's signing key, which is what
    // will sign for it once the software key is retired.
    const ownAge = parsed.type === "age" && Boolean(id.age?.recipients.includes(parsed.pk));
    const spk =
      opts.spk ?? parsed.spk ?? (ownAge && role === "admin" ? encodeSpk(signerFor({ age: id.age }, true)!.spk) : undefined);
    if (spk) decodeSpk(spk);
    const scoped = Boolean(opts.sets?.length);
    if (role === "admin" && (scoped || opts.ci)) {
      throw new ValidationError("An admin can read every set, and a CI identity is never an admin.");
    }
    if (opts.ci && !scoped) throw new ValidationError("A CI identity is given specific sets: --sets ci,staging.");

    // Names must be unique, because `hush team rm <name>` is how access is
    // revoked. Two members called "bob" meant removing one, being told it
    // worked, and leaving the other with full access — the exact failure
    // revocation exists to prevent.
    const clash = Object.entries(this.data.recipients).find(([fp, r]) => r.name === name && fp !== parsed.fp);
    if (clash) {
      throw new ValidationError(
        `"${name}" is already a member with a different key (${clash[1].pk.slice(0, 20)}…). ` +
          `Pick a distinct name, or remove the existing one first.`,
      );
    }
    const existing = this.data.recipients[parsed.fp];
    if (existing && scoped && !existing.sets) {
      throw new ValidationError(`${existing.name} is already a full member and can read every set.`);
    }
    if (existing?.sets && !scoped) {
      throw new ValidationError(
        `${existing.name} is a scoped member. To make them a full member, remove them and add them again without --sets.`,
      );
    }

    this.beginHeaderChange(id);
    const now = new Date().toISOString();
    const recipient: Recipient = {
      name,
      pk: parsed.pk,
      role,
      addedAt: existing?.addedAt ?? now,
      type: parsed.type,
      ...(spk ? { spk } : existing?.spk ? { spk: existing.spk } : {}),
      ...(opts.ci || existing?.ci ? { ci: true as const } : {}),
    };

    if (scoped) {
      if (!this.signed) {
        throw new ValidationError(
          "Giving someone only some sets needs a signed vault — each of those sets gets a key of its own, and " +
            "an admin signs who holds it. Run `hush team sign` first (an admin).",
        );
      }
      const sets = [...new Set([...(existing?.sets ?? []), ...opts.sets!])].sort();
      for (const env of opts.sets!) {
        assertScopeName(env);
        if (!this.data.envs[env]) throw new ValidationError(`No set called "${env}" in this vault.`);
      }
      recipient.sets = sets;
      this.data.recipients[parsed.fp] = recipient;
      for (const env of opts.sets!) {
        this.restrict(id, env);
        const key = this.setKey(id, env);
        this.data.setKeys![env].wraps[parsed.fp] = wrapFor(key, recipient);
      }
      return parsed.fp;
    }

    const dek = this.dek(id);
    this.data.recipients[parsed.fp] = recipient;
    this.data.dek.wraps[parsed.fp] = wrapFor(dek, recipient);
    // A full member reads every set, including those with keys of their own.
    for (const env of Object.keys(this.data.setKeys ?? {})) {
      this.data.setKeys![env].wraps[parsed.fp] = wrapFor(this.setKey(id, env), recipient);
    }
    return parsed.fp;
  }

  /**
   * Give a set a key of its own, if it does not have one: its values are
   * re-sealed under it, and every full member is wrapped in, so nothing
   * changes for them. Scoped members can then be given it one at a time.
   */
  restrict(id: Opener, env: string): void {
    if (this.data.setKeys?.[env]) return;
    if (!this.signed) throw new ValidationError("A set with a key of its own needs a signed vault: hush team sign.");
    this.opener = id;
    this.structural = true;
    const values = this.materialize(id, env);
    const key = newDek();
    const generation = 1;
    const wraps: Record<string, DekWrap> = {};
    for (const [fp, r] of Object.entries(this.data.recipients)) if (!r.sets) wraps[fp] = wrapFor(key, r);
    this.data.setKeys ??= {};
    this.data.setKeys[env] = { generation, wraps, commit: setKeyCommit(key, this.data.id, env, generation) };
    this.trustedSets.set(env, { generation, key });
    this.setKeyCache.delete(env);
    for (const [name, value] of Object.entries(values)) {
      this.data.envs[env][name] = this.sealEntry(key, env, name, value, this.data.envs[env][name]);
    }
  }

  /**
   * Remove a member and mint fresh keys for everything they could read,
   * re-sealing it. Past values they already read stay compromised — rotate
   * those upstream; every value they could read is marked exposed (F-6)
   * until it is set again.
   */
  removeRecipient(id: Opener, name: string): { removed: Recipient; reEncrypted: number; exposed: number } {
    // Remove *every* entry with this name. New vaults cannot contain duplicates,
    // but one written before that rule could, and revoking half of someone is
    // worse than refusing outright.
    const matches = Object.entries(this.data.recipients).filter(([, r]) => r.name === name);
    if (matches.length === 0) throw new ValidationError(`No member named "${name}".`);
    const [, removed] = matches[0];

    // The guard is about lock-out, not about identity. Retiring your *software*
    // key once a hardware one is in the vault is the final step of the upgrade
    // hush recommends — refusing it outright made the top rung unreachable.
    const doomed = new Set(matches.map(([f]) => f));
    const mine = this.myCandidates(id);
    if (mine.some((c) => doomed.has(c.fp))) {
      const survives = mine.some((c) => !doomed.has(c.fp) && this.data.dek.wraps[c.fp]);
      if (!survives) {
        throw new ValidationError(
          `Removing "${name}" would remove your own last key, locking you out of this vault.\n` +
            `  Add another identity first — e.g. a hardware key via \`hush secure --hardware\`.`,
        );
      }
    }

    this.beginHeaderChange(id);
    if (this.signed) {
      // Someone has to be able to sign what is left, and it has to be whoever
      // is doing this: the save that follows needs their signature.
      const signers = Object.entries(this.data.recipients).filter(
        ([fp, r]) => !doomed.has(fp) && r.role === "admin" && !r.ci && !r.sets && r.spk,
      );
      if (!signers.length) {
        throw new ValidationError(
          `Removing "${name}" would leave no admin who can sign changes to this vault. Make someone else an admin first.`,
        );
      }
      if (!signers.some(([fp]) => mine.some((c) => c.fp === fp))) {
        throw new ValidationError(
          `After removing "${name}", none of your keys is an admin that can sign. ` +
            `Add your other key as an admin first (hush team add <name> <key> --role admin).`,
        );
      }
    }

    // What they could read, decided before anything changes.
    const heldVaultKey = matches.some(([fp]) => this.data.dek.wraps[fp]);
    const heldSets = Object.entries(this.data.setKeys ?? {})
      .filter(([, k]) => matches.some(([fp]) => k.wraps[fp]))
      .map(([env]) => env);
    const readable = [
      ...(heldVaultKey ? this.envNames().filter((e) => !this.isRestricted(e)) : []),
      ...heldSets,
    ];

    // Decrypt everything first: if that fails we have changed nothing.
    const openPlain = heldVaultKey ? this.snapshotOpen(id) : {};
    const setPlain: Record<string, Record<string, string>> = {};
    for (const env of heldSets) setPlain[env] = this.materialize(id, env);

    const previous = JSON.parse(JSON.stringify(this.data)) as VaultFile;
    try {
      for (const [f] of matches) {
        delete this.data.recipients[f];
        delete this.data.dek.wraps[f];
        for (const k of Object.values(this.data.setKeys ?? {})) delete k.wraps[f];
      }
      let reEncrypted = 0;
      if (heldVaultKey) reEncrypted += this.reseal(openPlain);
      for (const env of heldSets) reEncrypted += this.resealSet(env, setPlain[env]);
      let exposed = 0;
      for (const env of readable) {
        for (const entry of Object.values(this.data.envs[env] ?? {})) {
          entry.exposed = [...new Set([...(entry.exposed ?? []), removed.name])];
          exposed++;
        }
      }
      return { removed, reEncrypted, exposed };
    } catch (e) {
      // A failing age plugin must not leave a member dropped and the key not
      // actually rotated.
      this.data = previous;
      throw e;
    }
  }

  /**
   * Take some sets away from a scoped member, rotating those sets' keys. With
   * none left they are removed from the vault altogether.
   */
  removeFromSets(id: Opener, name: string, sets: string[]): { remaining: string[]; reEncrypted: number } {
    const match = Object.entries(this.data.recipients).find(([, r]) => r.name === name);
    if (!match) throw new ValidationError(`No member named "${name}".`);
    const [fp, r] = match;
    if (!r.sets) {
      throw new ValidationError(
        `${r.name} is a full member and reads every set. Remove them (hush team rm ${r.name}) and add them back with --sets.`,
      );
    }
    for (const env of sets) if (!r.sets.includes(env)) throw new ValidationError(`${r.name} cannot read "${env}" now.`);
    this.beginHeaderChange(id);
    const plain: Record<string, Record<string, string>> = {};
    for (const env of sets) plain[env] = this.materialize(id, env);
    let reEncrypted = 0;
    for (const env of sets) {
      delete this.data.setKeys![env].wraps[fp];
      reEncrypted += this.resealSet(env, plain[env]);
      for (const entry of Object.values(this.data.envs[env] ?? {})) {
        entry.exposed = [...new Set([...(entry.exposed ?? []), r.name])];
      }
    }
    r.sets = r.sets.filter((s) => !sets.includes(s));
    if (!r.sets.length) delete this.data.recipients[fp];
    return { remaining: r.sets, reEncrypted };
  }

  /**
   * Rename an environment, values and all.
   *
   * The name is bound into every value's AAD — that is what stops a staging URL
   * being pasted into the prod slot — so a rename is not a map-key edit. Every
   * value has to be opened and re-sealed under the new name, which is why this
   * needs an identity and why it is structural: it cannot be merged with a
   * concurrent write. A restricted set keeps its key, whose commitment names
   * the set, so it is re-committed; scoped members keep it under its new name.
   */
  renameEnv(id: Opener, from: string, to: string): { moved: number } {
    assertScopeName(from);
    assertScopeName(to);
    if (from === to) return { moved: 0 };
    if (!this.data.envs[from]) throw new ValidationError(`No environment "${from}".`);
    if (this.data.envs[to]) {
      throw new ValidationError(
        `"${to}" already exists. Pick another name, or move the keys across one at a time.`,
      );
    }

    const restricted = this.isRestricted(from);
    if (restricted) this.beginHeaderChange(id);
    this.structural = true;
    this.opener = id;

    // Open everything first: if any of it fails we have changed nothing.
    const plaintext = this.materialize(id, from);
    const previous = this.data.envs[from];
    const key = this.keyFor(id, from);

    if (restricted) {
      const k = this.data.setKeys![from];
      this.data.setKeys![to] = { ...k, commit: setKeyCommit(key, this.data.id, to, k.generation) };
      delete this.data.setKeys![from];
      const t = this.trustedSets.get(from);
      if (t) this.trustedSets.set(to, t);
      this.trustedSets.delete(from);
      this.setKeyCache.delete(from);
      for (const r of Object.values(this.data.recipients)) {
        if (r.sets?.includes(from)) r.sets = r.sets.map((s) => (s === from ? to : s)).sort();
      }
    }

    const moved: Record<string, SecretEntry> = {};
    this.data.envs[to] = moved;
    for (const [name, value] of Object.entries(plaintext)) {
      moved[name] = this.sealEntry(key, to, name, value, previous[name]);
    }
    delete this.data.envs[from];

    if (this.data.meta?.[from]) {
      this.data.meta[to] = this.data.meta[from];
      delete this.data.meta[from];
    }
    return { moved: Object.keys(moved).length };
  }

  /** New keys for everything this identity can read. Used by `hush rotate`. */
  rotate(id: Opener): number {
    this.beginHeaderChange(id);
    const plaintext = this.snapshotOpen(id);
    const sets: Record<string, Record<string, string>> = {};
    for (const env of Object.keys(this.data.setKeys ?? {})) sets[env] = this.materialize(id, env);
    let n = this.reseal(plaintext);
    for (const [env, values] of Object.entries(sets)) n += this.resealSet(env, values);
    return n;
  }

  /** Every set sealed under the vault key, decrypted. */
  private snapshotOpen(id: Opener): Record<string, Record<string, string>> {
    const out: Record<string, Record<string, string>> = {};
    for (const env of this.envNames()) if (!this.isRestricted(env)) out[env] = this.materialize(id, env);
    return out;
  }

  /** A new vault key, wrapped for every full member, and every open set re-sealed under it. */
  private reseal(plaintext: Record<string, Record<string, string>>): number {
    const dek = newDek();
    const wraps: Record<string, DekWrap> = {};
    for (const [fp, r] of Object.entries(this.data.recipients)) if (!r.sets) wraps[fp] = wrapFor(dek, r);
    const generation = this.data.dek.generation + 1;
    this.data.dek = { generation, wraps, commit: vaultKeyCommit(dek, this.data.id, generation) };

    let count = 0;
    for (const [env, values] of Object.entries(plaintext)) {
      for (const [key, value] of Object.entries(values)) {
        this.data.envs[env][key] = this.sealEntry(dek, env, key, value, this.data.envs[env][key]);
        count++;
      }
    }
    // Drop the cache: the next reader re-derives from their own wrap.
    this.dekCache = null;
    // Minted here, so it needs no check — and the save that follows pins it.
    this.trusted = { generation, dek };
    return count;
  }

  /** A new key for one restricted set, for everyone still wrapped in it. */
  private resealSet(env: string, values: Record<string, string>): number {
    const k = this.data.setKeys![env];
    const key = newDek();
    const generation = k.generation + 1;
    const wraps: Record<string, DekWrap> = {};
    for (const fp of Object.keys(k.wraps)) {
      const r = this.data.recipients[fp];
      if (r) wraps[fp] = wrapFor(key, r);
    }
    this.data.setKeys![env] = { generation, wraps, commit: setKeyCommit(key, this.data.id, env, generation) };
    this.setKeyCache.delete(env);
    this.trustedSets.set(env, { generation, key });
    let count = 0;
    for (const [name, value] of Object.entries(values)) {
      this.data.envs[env][name] = this.sealEntry(key, env, name, value, this.data.envs[env][name]);
      count++;
    }
    return count;
  }

  members(): (Recipient & { fingerprint: string; canDecrypt: boolean; kind: string })[] {
    return Object.entries(this.data.recipients)
      .map(([fp, r]) => ({
        ...r,
        name: safeText(r.name, 64) ?? "unknown",
        fingerprint: fp,
        canDecrypt: r.sets
          ? r.sets.some((env) => Boolean(this.data.setKeys?.[env]?.wraps[fp]))
          : Boolean(this.data.dek.wraps[fp]),
        kind: r.type === "age" || isAgeRecipient(r.pk) ? "age" : "x25519",
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }
}

// -------------------------------------------------------------------- audit

/**
 * The audit log moved to src/audit.ts when it became a hash chain. Re-exported
 * here because every surface already imports it from the vault module.
 */
export { audit } from "./audit.ts";
