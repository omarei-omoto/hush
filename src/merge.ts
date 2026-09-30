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
 *     and compared as plaintext; without it, only branches that share a data
 *     key can be merged, byte for byte.
 *   - **One data key wins.** If only one branch rotated (a rotation, or a member
 *     removed), its key is the result's, and anything the other branch added is
 *     re-sealed under it — members included: someone added on the other branch
 *     gets the new key wrapped to them. Both branches rotating differently is a
 *     structural conflict: that is two revocations, and choosing between them
 *     is not a merge's call.
 *   - **Nothing is ever printed or written in the clear.** Conflicts are
 *     described by set, key, who and when; the conflict record holds the two
 *     sealed entries, never a value.
 *
 * A conflicted key keeps *our* side in the merged file and is listed, so the
 * file stays a working vault while the choice is made (`hush merge pick`).
 */
import { wrapDek, decodePub, sealValue, openValue, type Opener } from "./crypto.ts";
import { isAgeRecipient, wrapDekWithAge } from "./age.ts";
import { Vault, type VaultFile, type SecretEntry, type EnvMeta, type DekWrap, type Recipient } from "./vault.ts";

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

/** Everything a merge needs to know about one side. */
class Side {
  readonly data: VaultFile;
  private vault: Vault | null;
  private dek: Buffer | null = null;
  private opened = false;

  private readonly id: Opener | null;

  constructor(data: VaultFile, id: Opener | null, label: string) {
    this.data = data;
    this.id = id;
    this.vault = Vault.fromData(`(${label})`, data);
  }

  /** This side's data key, when the identity is a member of it. */
  key(): Buffer | null {
    if (this.opened) return this.dek;
    this.opened = true;
    if (!this.id || !this.vault || !this.vault.canRead(this.id)) return null;
    try {
      this.dek = this.vault.dekForReview(this.id);
    } catch {
      this.dek = null;
    }
    return this.dek;
  }

  entry(env: string, key: string): SecretEntry | undefined {
    return this.data.envs[env]?.[key];
  }

  /** The plaintext of one entry, or undefined when this side cannot be opened. */
  plain(env: string, key: string): Plain | undefined {
    const e = this.entry(env, key);
    if (!e) return null;
    const dek = this.key();
    if (!dek) return undefined;
    try {
      return { value: openValue(dek, env, key, e, e.v === 2 ? e.gen : undefined), note: e.note };
    } catch {
      return undefined;
    }
  }
}

/** A vault with nothing in it, standing in for "no common ancestor". */
function emptyLike(v: VaultFile): VaultFile {
  return { ...v, envs: {}, meta: {}, recipients: {}, dek: { generation: v.dek.generation, wraps: {} } };
}

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

  let lead: Side; // the side whose data key the result keeps
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

  let resultKey: Buffer | null = null;
  const needKey = (why: string): Buffer => {
    resultKey ??= lead.key();
    if (!resultKey) {
      throw new MergeNeedsIdentity(
        `${why}, which needs a key that can open the vault — hush found no identity here that is a member`,
      );
    }
    return resultKey;
  };

  try {
    for (const fp of addedByOther) {
      const r = other.data.recipients[fp];
      if (!rotation && other.data.dek.wraps[fp]) {
        // Same key on both branches: their wrap is already a wrap of ours.
        wraps[fp] = other.data.dek.wraps[fp];
      } else {
        const dek = needKey(`${r.name} was added on one branch while the other rotated the key`);
        wraps[fp] = r.type === "age" || isAgeRecipient(r.pk) ? { age: wrapDekWithAge(dek, r.pk) } : wrapDek(dek, decodePub(r.pk));
        result.rewrapped.push(r.name);
      }
      recipients[fp] = r;
    }
    for (const fp of Object.keys(recipients)) {
      const a = A.data.recipients[fp];
      const b = B.data.recipients[fp];
      const o = O.data.recipients[fp];
      if (a && b && !same(a, b)) {
        if (same(a, o)) recipients[fp] = b;
        else if (!same(b, o)) result.notes.push(`member ${a.name} was edited on both branches; kept this branch's record`);
      }
    }

    // --------------------------------------------------------------- values
    const envs: Record<string, Record<string, SecretEntry>> = {};
    const allEnvs = new Set([...Object.keys(O.data.envs), ...Object.keys(A.data.envs), ...Object.keys(B.data.envs)]);
    const generation = lead.data.dek.generation;

    /** Equal as far as anyone can tell: identical bytes, or identical plaintext and note. */
    const eq = (env: string, key: string, x: Side, y: Side): boolean => {
      const ex = x.entry(env, key);
      const ey = y.entry(env, key);
      if (!ex || !ey) return !ex && !ey;
      if (same(ex, ey)) return true;
      const px = x.plain(env, key);
      const py = y.plain(env, key);
      if (px === undefined || py === undefined) {
        if (x.data.dek.generation !== y.data.dek.generation) {
          throw new MergeNeedsIdentity(
            `the vault key was rotated on one branch, so every value changed its bytes there; telling a real change ` +
              `from a re-seal needs a key that can open the vault`,
          );
        }
        return false;
      }
      return same(px, py);
    };

    /** One side's entry as it has to stand in the result: under the result's key. */
    const sealedFor = (env: string, key: string, from: Side): SecretEntry => {
      const e = from.entry(env, key)!;
      // Kept byte for byte when it is already sealed under the result's key.
      if (from === lead && e.gen === generation) return e;
      if (!rotation && from.data.dek.generation === generation && e.gen === generation) return e;
      const p = from.plain(env, key);
      if (!p) throw new MergeNeedsIdentity(`${env}/${key} has to be re-sealed under the newer key`);
      const dek = needKey(`${env}/${key} has to be re-sealed under the newer key`);
      result.resealed++;
      return {
        ...sealValue(dek, env, key, p.value, generation),
        gen: generation,
        v: 2,
        updatedAt: e.updatedAt,
        updatedBy: e.updatedBy,
        ...(e.note ? { note: e.note } : {}),
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
          if (a) place(env, key, lead.entry(env, key) ? lead : A);
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

    // Descriptions: plaintext metadata, merged per set the same three ways.
    const meta: Record<string, EnvMeta> = {};
    for (const env of Object.keys(envs)) {
      const ma = A.data.meta?.[env];
      const mb = B.data.meta?.[env];
      const mo = O.data.meta?.[env];
      const pick = same(ma, mb) ? ma : same(ma, mo) ? mb : same(mb, mo) ? ma : ma;
      if (!same(ma, mb) && !same(ma, mo) && !same(mb, mo)) {
        result.notes.push(`the description of "${env}" was changed on both branches; kept this branch's`);
      }
      if (pick) meta[env] = pick;
    }

    result.data = {
      ...lead.data,
      scheme: [A.data.scheme, B.data.scheme].sort().at(-1)!,
      name: same(A.data.name, O.data.name) ? B.data.name : A.data.name,
      dek: { generation, wraps },
      recipients,
      envs,
      ...(Object.keys(meta).length ? { meta } : {}),
    };
    if (!Object.keys(meta).length) delete (result.data as { meta?: unknown }).meta;
    return result;
  } catch (e) {
    if (e instanceof MergeNeedsIdentity) return refuse(e.message);
    throw e;
  }
}

export class MergeNeedsIdentity extends Error {}

