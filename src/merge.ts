/**
 * Three-way merge of a vault file (F-1).
 *
 * Two branches that both touched `.hush/vault.json` used to conflict every
 * time, as a wall of base64, and the usual way out — take one side whole —
 * silently dropped the other side's secrets. This merges them the way a person
 * would if they could read both: key by key, and membership by membership.
 *
 * What makes it more than a JSON merge:
 *
 *   - **Values are compared by what they say, not by their bytes.** A rotation
 *     re-seals every value, so on the rotating branch every ciphertext changes
 *     while no value does. With your identity, the three versions are opened
 *     and compared as plaintext; without it, only branches that share their
 *     keys can be merged, byte for byte.
 *   - **One vault key wins.** If only one branch rotated (a rotation, or a
 *     member removed), its key is the result's, and anything the other branch
 *     added is re-sealed under it — members included: someone added on the
 *     other branch gets the new key wrapped to them. Both branches rotating
 *     differently is a structural conflict: that is two revocations, and
 *     choosing between them is not a merge's call.
 *   - **Sets with keys of their own (hush/v3) merge the same way:** which sets
 *     are restricted, and who holds each, is taken from the branch that changed
 *     it; both changing it differently is refused.
 *   - **The result is signed.** A v3 vault's header must carry an admin's
 *     signature. The merge keeps a branch's signature when the merged header is
 *     exactly that branch's; otherwise the admin doing the merge signs it, and
 *     a merge that changes who can read the vault with nobody able to sign is
 *     refused rather than written unsigned.
 *   - **Nothing is ever printed or written in the clear.** Conflicts are
 *     described by set, key, who and when; the conflict record holds the two
 *     sealed entries, never a value.
 *
 * A conflicted key keeps *our* side in the merged file and is listed, so the
 * file stays a working vault while the choice is made (`hush merge pick`).
 */
import { wrapDek, decodePub, sealValue, openValue, newDek, SCHEME_V3, type Opener } from "./crypto.ts";
import { isAgeRecipient, wrapDekWithAge } from "./age.ts";
import { verifyHeader, setKeyCommit } from "./header.ts";
import { Vault, type VaultFile, type SecretEntry, type EnvMeta, type DekWrap, type Recipient, type SetKey } from "./vault.ts";

export interface SideInfo {
  updatedBy?: string;
  updatedAt?: string;
  deleted?: boolean;
  /** The sealed entry itself — ciphertext only — so `hush merge pick` can use it. */
  entry?: SecretEntry;
}

export interface MergeConflict {
  set: string;
  key: string;
  kind: "both-changed" | "changed-vs-deleted";
  ours: SideInfo;
  theirs: SideInfo;
}

export interface MergeResult {
  /** The merged document. Conflicted keys hold our side. Absent on a structural refusal. */
  data?: VaultFile;
  conflicts: MergeConflict[];
  /** Why the vaults could not be merged at all. */
  structural?: string;
  /** Values re-sealed under the result's data key. */
  resealed: number;
  /** Members wrapped the result's key because the other branch added them. */
  rewrapped: string[];
  notes: string[];
}

type Plain = { value: string; note?: string } | null;

const same = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);

export class MergeNeedsIdentity extends Error {}

/** Everything a merge needs to know about one side. */
class Side {
  readonly data: VaultFile;
  private readonly vault: Vault;
  private readonly id: Opener | null;
  private keys = new Map<string, Buffer | null>();

  constructor(data: VaultFile, id: Opener | null, label: string) {
    this.data = data;
    this.id = id;
    this.vault = Vault.fromData(`(${label})`, data);
  }

  /** The key that seals `env` on this side — its own key if restricted, else the vault key. */
  keyFor(env: string | null): Buffer | null {
    const slot = env && this.data.setKeys?.[env] ? `set:${env}` : "vault";
    if (this.keys.has(slot)) return this.keys.get(slot)!;
    let key: Buffer | null = null;
    if (this.id) {
      try {
        key = slot === "vault" ? this.vault.dekForReview(this.id) : this.vault.setKeyForReview(this.id, env!);
      } catch {
        key = null;
      }
    }
    this.keys.set(slot, key);
    return key;
  }

  /** The generation `env`'s values are sealed under on this side. */
  genFor(env: string): number {
    return this.data.setKeys?.[env]?.generation ?? this.data.dek.generation;
  }

  entry(env: string, key: string): SecretEntry | undefined {
    return this.data.envs[env]?.[key];
  }

  /** The plaintext of one entry, or undefined when this side cannot be opened. */
  plain(env: string, key: string): Plain | undefined {
    const e = this.entry(env, key);
    if (!e) return null;
    const k = this.keyFor(env);
    if (!k) return undefined;
    try {
      return { value: openValue(k, env, key, e, e.v === 2 ? e.gen : undefined), note: e.note };
    } catch {
      return undefined;
    }
  }
}

/** A vault with nothing in it, standing in for "no common ancestor". */
function emptyLike(v: VaultFile): VaultFile {
  return { ...v, envs: {}, meta: {}, recipients: {}, setKeys: {}, dek: { generation: v.dek.generation, wraps: {} } };
}

const wrapFor = (key: Buffer, r: Recipient): DekWrap =>
  r.type === "age" || isAgeRecipient(r.pk) ? { age: wrapDekWithAge(key, r.pk) } : wrapDek(key, decodePub(r.pk));

export function mergeVaults(
  baseData: VaultFile | null,
  oursData: VaultFile,
  theirsData: VaultFile,
  id: Opener | null,
): MergeResult {
  const result: MergeResult = { conflicts: [], resealed: 0, rewrapped: [], notes: [] };
  const refuse = (why: string): MergeResult => ({ ...result, structural: why });

  if (oursData.id !== theirsData.id) {
    return refuse(
      `the two branches hold different vaults (${oursData.id} and ${theirsData.id}) — one of them was re-created or replaced`,
    );
  }
  const baseIsReal = Boolean(baseData && baseData.id === oursData.id);
  const O = new Side(baseIsReal ? baseData! : emptyLike(oursData), id, "base");
  const A = new Side(oursData, id, "ours");
  const B = new Side(theirsData, id, "theirs");

  // ------------------------------------------------------------ structure
  const gO = O.data.dek.generation;
  const gA = A.data.dek.generation;
  const gB = B.data.dek.generation;
  // With no common ancestor (the file was created on both branches), the
  // branch further along in key generations leads.
  const rotatedA = baseIsReal ? gA !== gO : gA > gB;
  const rotatedB = baseIsReal ? gB !== gO : gB > gA;

  let lead: Side; // the side whose vault key the result keeps
  let other: Side;
  if (rotatedA && rotatedB) {
    if (!same(A.data.dek, B.data.dek) || !same(A.data.recipients, B.data.recipients)) {
      return refuse(
        "both branches changed the vault key (a rotation or a member removed on each). " +
          "That is two revocations; pick one branch's vault, then redo the other's change on top of it",
      );
    }
    lead = A;
    other = B;
  } else if (rotatedB) {
    lead = B;
    other = A;
  } else {
    lead = A;
    other = B;
  }
  const rotation = rotatedA !== rotatedB;

  // Members: the lead's roster, plus anyone the other branch added, minus
  // anyone the other branch removed without a rotation (hand edits).
  const recipients: Record<string, Recipient> = { ...lead.data.recipients };
  const wraps: Record<string, DekWrap> = { ...lead.data.dek.wraps };
  const addedByOther = Object.keys(other.data.recipients).filter((fp) => !O.data.recipients[fp] && !recipients[fp]);
  const removedByOther = Object.keys(O.data.recipients).filter((fp) => !other.data.recipients[fp]);
  for (const fp of removedByOther) {
    if (!rotation) {
      delete recipients[fp];
      delete wraps[fp];
    }
  }

  const generation = lead.data.dek.generation;
  const needKey = (side: Side, env: string | null, why: string): Buffer => {
    const k = side.keyFor(env);
    if (!k) {
      throw new MergeNeedsIdentity(
        `${why}, which needs a key that can open the vault — hush found no identity here that holds it`,
      );
    }
    return k;
  };

  try {
    for (const fp of addedByOther) recipients[fp] = other.data.recipients[fp];
    for (const fp of Object.keys(recipients)) {
      const a = A.data.recipients[fp];
      const b = B.data.recipients[fp];
      const o = O.data.recipients[fp];
      if (a && b && !same(a, b)) {
        if (same(a, o)) recipients[fp] = b;
        else if (same(b, o)) recipients[fp] = a;
        else result.notes.push(`member ${a.name} was edited on both branches; kept this branch's record`);
      }
    }

    // The vault key: every full member holds a wrap of the lead's key, and
    // nobody else does. A wrap carried over from the other branch is a wrap of
    // the same key only when neither branch rotated.
    for (const fp of Object.keys(wraps)) if (!recipients[fp] || recipients[fp].sets) delete wraps[fp];
    for (const [fp, r] of Object.entries(recipients)) {
      if (r.sets || wraps[fp]) continue;
      if (!rotation && other.data.dek.wraps[fp]) {
        wraps[fp] = other.data.dek.wraps[fp];
      } else {
        wraps[fp] = wrapFor(needKey(lead, null, `${r.name} was added on one branch while the other rotated the key`), r);
        result.rewrapped.push(r.name);
      }
    }

    // Sets with keys of their own. For each set restricted on either branch:
    // take one branch's key (the newer generation, the lead on a tie), wrap in
    // everyone entitled to it — every full member, and scoped members given
    // it — and if anyone who holds that key is no longer entitled (removed on
    // the other branch, say), mint a new one: they could have unwrapped the old.
    const entitled = (env: string): string[] =>
      Object.entries(recipients).filter(([, r]) => !r.sets || r.sets.includes(env)).map(([fp]) => fp);
    const setKeys: Record<string, SetKey> = {};
    const resultSets = new Map<string, { gen: number; keep: Side | null; key: () => Buffer }>();
    const restrictedEnvs = new Set([...Object.keys(A.data.setKeys ?? {}), ...Object.keys(B.data.setKeys ?? {})]);
    for (const env of restrictedEnvs) {
      const ka = A.data.setKeys?.[env];
      const kb = B.data.setKeys?.[env];
      const source: Side = !ka ? B : !kb ? A : kb.generation > ka.generation ? B : ka.generation > kb.generation ? A : lead === B ? B : A;
      const src = source.data.setKeys![env];
      const who = entitled(env);
      const mustRotate = Object.keys(src.wraps).some((fp) => !who.includes(fp));
      let fresh: Buffer | null = null;
      const key = (): Buffer => {
        if (mustRotate) return (fresh ??= newDek());
        return needKey(source, env, `the key of set "${env}" has to be given to someone the other branch added`);
      };
      const gen = mustRotate ? Math.max(ka?.generation ?? 0, kb?.generation ?? 0) + 1 : src.generation;
      const setWraps: Record<string, DekWrap> = {};
      for (const fp of who) {
        if (!mustRotate && src.wraps[fp]) setWraps[fp] = src.wraps[fp];
        else {
          setWraps[fp] = wrapFor(key(), recipients[fp]);
          if (!mustRotate && !result.rewrapped.includes(recipients[fp].name)) result.rewrapped.push(recipients[fp].name);
        }
      }
      setKeys[env] = {
        generation: gen,
        wraps: setWraps,
        commit: mustRotate ? setKeyCommit(key(), oursData.id, env, gen) : src.commit,
      };
      if (mustRotate) result.notes.push(`gave set "${env}" a new key: someone who held its old one can no longer read it`);
      resultSets.set(env, { gen, keep: mustRotate ? null : source, key });
    }

    // --------------------------------------------------------------- values
    const envs: Record<string, Record<string, SecretEntry>> = {};
    const allEnvs = new Set([...Object.keys(O.data.envs), ...Object.keys(A.data.envs), ...Object.keys(B.data.envs)]);

    /** Where `env`'s values live in the result: a set's own key, or the lead's vault key. */
    const target = (env: string): { side: Side | null; set: boolean; gen: number } => {
      const rs = resultSets.get(env);
      return rs ? { side: rs.keep, set: true, gen: rs.gen } : { side: lead, set: false, gen: generation };
    };

    /** Equal as far as anyone can tell: identical bytes, or identical plaintext and note. */
    const eq = (env: string, key: string, x: Side, y: Side): boolean => {
      const ex = x.entry(env, key);
      const ey = y.entry(env, key);
      if (!ex || !ey) return !ex && !ey;
      if (same(ex, ey)) return true;
      const px = x.plain(env, key);
      const py = y.plain(env, key);
      if (px === undefined || py === undefined) {
        if (x.genFor(env) !== y.genFor(env) || Boolean(x.data.setKeys?.[env]) !== Boolean(y.data.setKeys?.[env])) {
          throw new MergeNeedsIdentity(
            `the key sealing "${env}" changed on one branch, so its values changed their bytes there; telling a real ` +
              `change from a re-seal needs a key that can open the vault`,
          );
        }
        return false;
      }
      return same(px, py);
    };

    /** One side's entry as it has to stand in the result: under the result's key for its set. */
    const sealedFor = (env: string, key: string, from: Side): SecretEntry => {
      const e = from.entry(env, key)!;
      const t = target(env);
      const fromRestricted = Boolean(from.data.setKeys?.[env]);
      // Kept byte for byte when it is already sealed under the result's key.
      if (from === t.side && fromRestricted === t.set && e.gen === t.gen) return e;
      if (!t.set && !fromRestricted && !rotation && from.data.dek.generation === t.gen && e.gen === t.gen) return e;
      if (t.set && t.side && fromRestricted && same(from.data.setKeys?.[env]?.commit, setKeys[env].commit) && e.gen === t.gen) return e;
      const p = from.plain(env, key);
      if (!p) throw new MergeNeedsIdentity(`${env}/${key} has to be re-sealed under the newer key`);
      const k = t.set
        ? resultSets.get(env)!.key()
        : needKey(lead, null, `${env}/${key} has to be re-sealed under the newer key`);
      result.resealed++;
      return {
        ...sealValue(k, env, key, p.value, t.gen),
        gen: t.gen,
        v: 2,
        updatedAt: e.updatedAt,
        updatedBy: e.updatedBy,
        ...(e.note ? { note: e.note } : {}),
        ...(e.exposed?.length ? { exposed: e.exposed } : {}),
      };
    };
    const place = (env: string, key: string, from: Side): void => {
      envs[env] ??= {};
      envs[env][key] = sealedFor(env, key, from);
    };

    for (const env of allEnvs) {
      const inA = Boolean(A.data.envs[env]);
      const inB = Boolean(B.data.envs[env]);
      const inO = Boolean(O.data.envs[env]);
      const keys = new Set([
        ...Object.keys(O.data.envs[env] ?? {}),
        ...Object.keys(A.data.envs[env] ?? {}),
        ...Object.keys(B.data.envs[env] ?? {}),
      ]);
      for (const key of keys) {
        const aSame = eq(env, key, A, O);
        const bSame = eq(env, key, B, O);
        const ab = eq(env, key, A, B);
        const a = A.entry(env, key);
        const b = B.entry(env, key);
        if (ab) {
          // The same on both: take the copy already under the result's key.
          const keep = target(env).side;
          if (a) place(env, key, keep?.entry(env, key) ? keep : A);
        } else if (aSame) {
          if (b) place(env, key, B);
        } else if (bSame) {
          if (a) place(env, key, A);
        } else {
          // Both changed it, differently. Ours stays in the file until a pick;
          // both sides are recorded already sealed under the result's key, so
          // choosing theirs later needs no key that has since been rotated away.
          const ours = a ? sealedFor(env, key, A) : undefined;
          const theirs = b ? sealedFor(env, key, B) : undefined;
          result.conflicts.push({
            set: env,
            key,
            kind: a && b ? "both-changed" : "changed-vs-deleted",
            ours: ours ? { updatedBy: a!.updatedBy, updatedAt: a!.updatedAt, entry: ours } : { deleted: true },
            theirs: theirs ? { updatedBy: b!.updatedBy, updatedAt: b!.updatedAt, entry: theirs } : { deleted: true },
          });
          if (ours) {
            envs[env] ??= {};
            envs[env][key] = ours;
          }
        }
      }
      // A set with keys left in it exists; an empty one exists by the same
      // three-way rule as a key — made or removed on one branch, it follows.
      const present = inA === inB ? inA : inA === inO ? inB : inA;
      if (present) envs[env] ??= {};
    }
    // A set's own key goes with the set.
    for (const env of Object.keys(setKeys)) if (!envs[env]) delete setKeys[env];

    // Descriptions: plaintext metadata, merged per set the same three ways.
    const meta: Record<string, EnvMeta> = {};
    for (const env of Object.keys(envs)) {
      const ma = A.data.meta?.[env];
      const mb = B.data.meta?.[env];
      const mo = O.data.meta?.[env];
      const pick = same(ma, mb) ? ma : same(ma, mo) ? mb : ma;
      if (!same(ma, mb) && !same(ma, mo) && !same(mb, mo)) {
        result.notes.push(`the description of "${env}" was changed on both branches; kept this branch's`);
      }
      if (pick) meta[env] = pick;
    }

    const data: VaultFile = {
      ...lead.data,
      scheme: [A.data.scheme, B.data.scheme].sort().at(-1)!,
      name: same(A.data.name, O.data.name) ? B.data.name : A.data.name,
      dek: { ...lead.data.dek, generation, wraps },
      recipients,
      envs,
    };
    delete data.meta;
    delete data.setKeys;
    delete data.signature;
    if (Object.keys(meta).length) data.meta = meta;
    if (Object.keys(setKeys).length) data.setKeys = setKeys;

    // ------------------------------------------------------------ signature
    if (data.scheme === SCHEME_V3) {
      // A branch's signature still holds if the merged header is exactly that
      // branch's — the common case, where only values differed.
      for (const sig of [lead.data.signature, other.data.signature]) {
        if (!sig) continue;
        data.signature = sig;
        if (verifyHeader(data).ok) break;
        delete data.signature;
      }
      if (!data.signature) {
        const v = Vault.fromData("(merged)", data);
        if (!id || !v.isAdmin(id)) {
          return refuse(
            "this merge changes who can read the vault in a way neither branch signed, and only an admin can sign it — " +
              "have an admin run the merge (hush merge)",
          );
        }
        try {
          v.signAs(id);
        } catch (e) {
          return refuse((e as Error).message);
        }
        result.notes.push("signed the merged vault's header as you (an admin): it combines both branches' membership");
      }
    }

    result.data = data;
    return result;
  } catch (e) {
    if (e instanceof MergeNeedsIdentity) return refuse(e.message);
    throw e;
  }
}
