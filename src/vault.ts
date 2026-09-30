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
import { existsSync, readFileSync } from "node:fs";

import { randomUUID } from "node:crypto";
import { SCHEME_V2, newDek, wrapDek, encodePub, encodeSpk, decodeSpk, fingerprint, ValidationError, type Opener } from "./crypto.ts";
import { isAgeRecipient, ageFingerprint, wrapDekWithAge } from "./age.ts";
import { signerFor } from "./identity.ts";
import { setKeyCommit, vaultKeyCommit } from "./header.ts";
import { assertVaultShape, hashOf, jsonErrorSummary, assertScopeName, safeText, type VaultFile, type Recipient, type SecretEntry, type DekWrap } from "./vault-files.ts";
import { SCHEMES, wrapFor, parseMemberKey } from "./vault-core.ts";
import { VaultValues } from "./vault-values.ts";

export * from "./vault-files.ts";

// -------------------------------------------------------------------- audit

/**
 * The audit log moved to src/audit.ts when it became a hash chain. Re-exported
 * here because every surface already imports it from the vault module.
 */
export { audit } from "./audit.ts";
export { setTrustHook, parseMemberKey, memberKeyString, type TrustView, type TrustHook } from "./vault-core.ts";

export class Vault extends VaultValues {

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

  protected replay(parsed: VaultFile): Vault {
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
    return fresh;
  }
}
