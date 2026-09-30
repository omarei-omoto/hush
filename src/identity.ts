/**
 * Where your private key lives.
 *
 * Resolution order:
 *   1. $HUSH_IDENTITY            — for CI. The key itself, not a path.
 *   2. $HUSH_IDENTITY_FILE       — path to a key file.
 *   3. The OS's secure store     — the macOS Keychain, or on Windows a DPAPI-protected
 *                                  file (`~/.hush/<account>.dpapi`) only this user can open.
 *   4. ~/.hush/identity          — chmod 600 fallback.
 *
 * The private key never enters a vault file, never enters a repo, and is never
 * returned by any MCP tool.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync, unlinkSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import {
  generateIdentity, encodeSecret, decodeSecret, encodePub, encodeSePub, signerForIdentity, signerFromSeed,
  type Identity, type Opener, type Signer,
} from "./crypto.ts";
import { ageIdentityPath, recipientsForIdentity, ageAvailable } from "./age.ts";
import { powershellPath, restrictToOwner } from "./platform.ts";
import { loadEnclaveIdentity } from "./enclave.ts";

/**
 * Resolved per call. As a module constant this captured HUSH_HOME at import,
 * which made it invisible to anything that set the variable later and left the
 * three modules that derived paths from it silently inconsistent.
 */
export const hushHome = (): string => process.env.HUSH_HOME || join(homedir(), ".hush");
const identityFile = (): string => join(hushHome(), "identity");
const KEYCHAIN_SERVICE = "hush-identity";

/**
 * HUSH_NO_KEYCHAIN=1 keeps the key in a file instead of the OS keychain — for
 * Linux, CI images, and anyone who would rather manage the file themselves. It
 * is also the seam that lets the migration's failure path be tested, which
 * matters because that path is the only one in hush that can destroy a key.
 */
const keychainUsable = (): boolean =>
  (platform() === "darwin" || platform() === "win32") && process.env.HUSH_NO_KEYCHAIN !== "1";

/** What the secure store is called here, for `hush doctor` and the ladder. */
export const storeLabel = (): string => (platform() === "win32" ? "Windows DPAPI" : "macOS Keychain");

/** Whether an identity's source is the OS's secure store rather than a loose file. */
export const isSecureStore = (source: string | undefined): boolean =>
  source === "macOS Keychain" || source === "Windows DPAPI";

// ------------------------------------------------------------ Windows DPAPI
//
// DPAPI encrypts with a key tied to this Windows user's logon: the file can
// sit in ~/.hush and nobody else — another user, a copy of the disk — can
// open it. The secret travels to PowerShell on stdin, never in argv, and the
// scripts carry no data of their own.

const DPAPI_PROTECT =
  "$s=[Console]::In.ReadToEnd(); Add-Type -AssemblyName System.Security; " +
  "$b=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($s),$null,'CurrentUser'); " +
  "[Console]::Out.Write([Convert]::ToBase64String($b))";
const DPAPI_UNPROTECT =
  "$s=[Console]::In.ReadToEnd().Trim(); Add-Type -AssemblyName System.Security; " +
  "$b=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($s),$null,'CurrentUser'); " +
  "[Console]::Out.Write([Text.Encoding]::UTF8.GetString($b))";

const dpapiFile = (account: string): string => join(hushHome(), `${account.replace(/[^A-Za-z0-9_-]/g, "_")}.dpapi`);

function powershell(script: string, input: string): string | null {
  const ps = powershellPath();
  if (!ps) return null;
  const r = spawnSync(ps, ["-NoProfile", "-NonInteractive", "-Command", script], {
    input,
    encoding: "utf8",
    windowsHide: true,
    stdio: ["pipe", "pipe", "ignore"],
  });
  return r.status === 0 ? r.stdout : null;
}

function dpapiGet(account: string): string | null {
  const file = dpapiFile(account);
  if (!existsSync(file)) return null;
  const plain = powershell(DPAPI_UNPROTECT, readFileSync(file, "utf8"));
  return plain ? plain.trim() : null;
}

function dpapiSet(account: string, secret: string): boolean {
  const sealed = powershell(DPAPI_PROTECT, secret);
  if (!sealed) return false;
  mkdirSync(hushHome(), { recursive: true, mode: 0o700 });
  writeFileSync(dpapiFile(account), sealed.trim(), { mode: 0o600 });
  restrictToOwner(dpapiFile(account));
  return dpapiGet(account) === secret;
}

function keychainGet(account: string): string | null {
  if (!keychainUsable()) return null;
  if (platform() === "win32") return dpapiGet(account);
  try {
    return execFileSync(
      "security",
      ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"],
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
    ).trim();
  } catch {
    return null;
  }
}

function keychainSet(account: string, secret: string): boolean {
  if (!keychainUsable()) return false;
  if (platform() === "win32") return dpapiSet(account, secret);
  try {
    // `-w` with no value makes security read the password from stdin. Passing
    // it as an argument would expose the private key in the process table to
    // every other process on the machine for the life of the call.
    execFileSync(
      "security",
      ["add-generic-password", "-U", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"],
      { input: secret, stdio: ["pipe", "ignore", "ignore"] },
    );
    return true;
  } catch {
    return false;
  }
}

function readFileIdentity(path: string): Identity {
  return decodeSecret(readFileSync(path, "utf8"));
}

export interface ResolvedIdentity extends Opener {
  /** Human-readable source, for `hush doctor`. Never includes key material. */
  source: string;
}

/**
 * An age identity, if this machine has one. It may be a plain key file or a
 * plugin identity backed by a YubiKey or the Secure Enclave — hush cannot tell
 * and does not need to.
 */
function loadAgeOpener(): { recipients: string[]; identityPath: string } | undefined {
  if (!ageAvailable()) return undefined;
  const path = ageIdentityPath();
  if (!path) return undefined;
  const recipients = recipientsForIdentity(path);
  return recipients.length ? { recipients, identityPath: path } : undefined;
}

export function loadIdentity(account = "default"): ResolvedIdentity | null {
  const x25519 = ((): { id: Identity; source: string } | null => {
    if (process.env.HUSH_IDENTITY) {
      return { id: decodeSecret(process.env.HUSH_IDENTITY), source: "$HUSH_IDENTITY" };
    }
    if (process.env.HUSH_IDENTITY_FILE) {
      const p = process.env.HUSH_IDENTITY_FILE;
      if (!existsSync(p)) throw new Error(`HUSH_IDENTITY_FILE not found: ${p}`);
      return { id: readFileIdentity(p), source: `$HUSH_IDENTITY_FILE (${p})` };
    }
    const fromKeychain = keychainGet(account);
    if (fromKeychain) return { id: decodeSecret(fromKeychain), source: storeLabel() };
    if (existsSync(identityFile())) return { id: readFileIdentity(identityFile()), source: identityFile() };
    return null;
  })();

  // `age` is a lazy, memoised getter: reading it may shell out to age and, for
  // a hardware-backed identity, make the key prompt. The vault only touches it
  // when it actually holds age recipients, so `hush ls` never blinks a YubiKey.
  let ageCache: ReturnType<typeof loadAgeOpener> | undefined;
  const ageProp = {
    get(): ReturnType<typeof loadAgeOpener> {
      if (ageCache === undefined) ageCache = loadAgeOpener();
      return ageCache;
    },
    enumerable: true,
    configurable: true,
  };

  // A Secure Enclave identity, if this Mac has made one: only its public half
  // and the path of the sealed blob. Reading them wakes nothing.
  const se = platform() === "darwin" ? loadEnclaveIdentity() ?? undefined : undefined;

  if (x25519) {
    return Object.defineProperty(
      { ...x25519.id, ...(se ? { se } : {}), source: x25519.source } as ResolvedIdentity,
      "age",
      ageProp,
    );
  }

  // No software key: an age identity or the enclave is the only way in.
  const age = loadAgeOpener();
  if (age) return { age, ...(se ? { se } : {}), source: `age identity (${age.identityPath})` };
  if (se) return { se, source: "Secure Enclave" };
  return null;
}

export function requireIdentity(account = "default"): ResolvedIdentity {
  const id = loadIdentity(account);
  if (!id) {
    throw new Error("No hush identity on this machine. Run `hush id --create` first.");
  }
  return id;
}

export function createIdentity(account = "default", force = false): ResolvedIdentity {
  if (!force && loadIdentity(account)) {
    throw new Error("An identity already exists. Pass --force to replace it (this is destructive).");
  }
  const id = generateIdentity();
  const encoded = encodeSecret(id);

  if (keychainSet(account, encoded)) {
    return { ...id, source: storeLabel() };
  }
  mkdirSync(hushHome(), { recursive: true, mode: 0o700 });
  writeFileSync(identityFile(), encoded, { mode: 0o600 });
  chmodSync(identityFile(), 0o600);
  restrictToOwner(identityFile());
  return { ...id, source: identityFile() };
}

/**
 * Move an on-disk identity into the OS keychain — rung 1 → 2 of the ladder.
 *
 * The public key is unchanged, so vault membership survives. The file is only
 * deleted after reading the value back out of the keychain: a failed write
 * followed by an eager unlink would destroy the one copy of the key, and with
 * it access to every vault this machine belongs to.
 */
/**
 * The decision half of the migration, separated so every combination can be
 * checked without a real keychain.
 *
 * This is the only operation in hush that can destroy a key. The file is
 * deleted ONLY when the keychain has been read back and matches — a write that
 * reported success but stored nothing must never cost you the original.
 */
export interface MigrationFacts {
  keychainUsable: boolean;
  fromEnvironment: boolean;
  fileExists: boolean;
  fileParses: boolean;
  keychainAlreadyHas: boolean;
  writeSucceeded: boolean;
  readBackMatches: boolean;
}

export interface MigrationDecision {
  ok: boolean;
  deleteFile: boolean;
  message: string;
}

export function decideMigration(f: MigrationFacts): MigrationDecision {
  // Checked before the keychain, deliberately. If your key comes from
  // $HUSH_IDENTITY there is nothing on disk to move, and that is true whether or
  // not this machine has a keychain — so it is both the more specific answer and
  // the same answer everywhere. Asking about the keychain first meant Linux and
  // macOS gave different explanations for the identical situation.
  if (f.fromEnvironment) {
    return { ok: false, deleteFile: false, message: "your identity comes from an environment variable; nothing to migrate" };
  }
  if (!f.keychainUsable) {
    return { ok: false, deleteFile: false, message: "no OS keychain available here (or HUSH_NO_KEYCHAIN=1)" };
  }
  if (!f.fileExists) {
    return f.keychainAlreadyHas
      ? { ok: true, deleteFile: false, message: "already in the keychain" }
      : { ok: false, deleteFile: false, message: "no identity file found to migrate" };
  }
  if (!f.fileParses) {
    return { ok: false, deleteFile: false, message: "that file is not a valid hush key; left alone" };
  }
  if (!f.writeSucceeded) {
    return { ok: false, deleteFile: false, message: "keychain write failed; the file was left in place" };
  }
  if (!f.readBackMatches) {
    return { ok: false, deleteFile: false, message: "keychain read-back did not match; the file was left in place" };
  }
  return { ok: true, deleteFile: true, message: `key moved into the ${storeLabel()}` };
}

export function migrateIdentityToKeychain(account = "default"): { ok: boolean; message: string } {
  const path = identityFile();
  const fileExists = existsSync(path);

  let encoded = "";
  let fileParses = false;
  if (fileExists) {
    encoded = readFileSync(path, "utf8").trim();
    try {
      decodeSecret(encoded);
      fileParses = true;
    } catch {
      fileParses = false;
    }
  }

  const usable = keychainUsable();
  const facts: MigrationFacts = {
    keychainUsable: usable,
    fromEnvironment: Boolean(process.env.HUSH_IDENTITY || process.env.HUSH_IDENTITY_FILE),
    fileExists,
    fileParses,
    keychainAlreadyHas: usable && !fileExists ? keychainGet(account) !== null : false,
    writeSucceeded: false,
    readBackMatches: false,
  };

  // Only touch the keychain once the cheap checks have passed.
  if (usable && !facts.fromEnvironment && fileExists && fileParses) {
    facts.writeSucceeded = keychainSet(account, encoded);
    facts.readBackMatches = facts.writeSucceeded && keychainGet(account) === encoded;
  }

  const decision = decideMigration(facts);
  if (!decision.deleteFile) return { ok: decision.ok, message: decision.message };

  try {
    unlinkSync(path);
  } catch {
    return { ok: true, message: `copied into the Keychain, but ${path} could not be deleted — remove it yourself` };
  }
  return { ok: true, message: `${decision.message}; ${path} deleted` };
}

/** How to show this identity to a human. An age identity shows its recipient. */
export const publicKeyOf = (id: Opener): string =>
  id.pub ? encodePub(id.pub) : id.se ? encodeSePub(id.se.pub) : (id.age?.recipients[0] ?? "(no identity)");

// ------------------------------------------------------------------ signing

const SSK_PREFIX = "hush_ssk_";
const signingFile = (): string => join(hushHome(), "signing-key");

/**
 * The key this identity signs vault headers with (hush/v3).
 *
 * An X25519 identity derives it (crypto.ts signerForIdentity), so it exists
 * wherever the identity does. An identity that is only an age recipient — a
 * YubiKey, the Secure Enclave — cannot sign with the hardware, so it keeps a
 * separate Ed25519 key: in the keychain where there is one, otherwise a 0600
 * file beside where the identity would be. `create` makes one on first need.
 *
 * Losing that key costs the ability to *change* a vault's membership, never
 * the ability to read it; any other admin can take over (`hush team add … --role
 * admin`), and a new key is made the next time this one is needed.
 */
export function signerFor(id: Opener, create = false): Signer | null {
  if (id.pub && id.priv) return signerForIdentity({ pub: id.pub, priv: id.priv });
  const stored = keychainGet("signing") ?? (existsSync(signingFile()) ? readFileSync(signingFile(), "utf8").trim() : null);
  if (stored?.startsWith(SSK_PREFIX)) {
    const seed = Buffer.from(stored.slice(SSK_PREFIX.length), "base64url");
    if (seed.length === 32) return signerFromSeed(seed);
  }
  if (!create) return null;
  const encoded = SSK_PREFIX + randomBytes(32).toString("base64url");
  if (!keychainSet("signing", encoded)) {
    mkdirSync(hushHome(), { recursive: true, mode: 0o700 });
    writeFileSync(signingFile(), encoded, { mode: 0o600 });
    chmodSync(signingFile(), 0o600);
    restrictToOwner(signingFile());
  }
  return signerFor(id, false);
}
