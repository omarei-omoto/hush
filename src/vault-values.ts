/**
 * The values and sets of a vault: what is in each set, sealing and opening
 * one value, moving it, describing a set. Built on VaultCore (keys and the
 * file); `Vault` (vault.ts) adds how a vault is made and who can read it.
 */
import { sealValue, openValue, ValidationError, type Opener } from "./crypto.ts";
import { assertScopeName, assertKeyName, assertValueSize, trimNote, safeText, type SecretEntry, type EnvMeta } from "./vault-files.ts";
import { VaultCore } from "./vault-core.ts";

export abstract class VaultValues extends VaultCore {

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
  protected aadGen(entry: SecretEntry): number | undefined {
    return entry.v === 2 ? entry.gen : undefined;
  }

  protected sealEntry(key: Buffer, env: string, name: string, value: string, prev?: Partial<SecretEntry>): SecretEntry {
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
}
