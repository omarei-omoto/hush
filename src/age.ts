/**
 * age bridge — hardware-backed identities without writing a single hardware
 * integration.
 *
 * The insight: age already defines a plugin protocol, and people have already
 * written the plugins — age-plugin-yubikey (PIV), age-plugin-se (Apple Secure
 * Enclave, already signed and notarized), age-plugin-tpm, age-plugin-fido2-hmac.
 * Rather than implement that protocol, hush shells out to `age` itself, which
 * invokes whichever plugin the recipient belongs to.
 *
 * So this is one small adapter instead of four native integrations, and every
 * plugin that exists today or ships tomorrow works without a hush release.
 *
 * What hush hands age is only the 32-byte data key, never a secret value.
 */
import { execFileSync, execFileSync as run } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { onPath, isExecutableFile } from "./which.ts";

/** Duplicated from identity.ts on purpose: importing it would make a cycle. */
const hushHome = (): string => process.env.HUSH_HOME || join(homedir(), ".hush");

/** An age recipient: `age1…` for native keys, `age1<plugin>1…` for hardware. */
export const AGE_RECIPIENT_RE = /^age1[0-9a-z]{8,}$/;

export const isAgeRecipient = (s: string): boolean => AGE_RECIPIENT_RE.test(s.trim());

/** Stable id for an age recipient, so it can key the same maps as an X25519 one. */
export const ageFingerprint = (recipient: string): string =>
  createHash("sha256").update(`age:${recipient.trim()}`).digest("hex").slice(0, 16);

let cachedBin: string | undefined;
let missingUntil = 0;

/** How long to trust "age is not installed" before looking again. */
const MISSING_TTL_MS = 5_000;

/**
 * Locate the `age` binary. HUSH_AGE_BIN wins, for pinned or vendored copies.
 *
 * A positive result is memoised forever; a negative one only briefly. The MCP
 * server is long-lived, and telling someone to `brew install age` and then never
 * noticing that they did — for the rest of the session — is a bad answer.
 */
export function ageBinary(): string | null {
  if (cachedBin) return cachedBin;

  // Same requirement as the PATH search below: a file, and executable. Merely
  // existing is satisfied by a directory, and then every age call fails with
  // EACCES instead of saying the pinned path is not a program.
  const explicit = process.env.HUSH_AGE_BIN;
  if (explicit && isExecutableFile(explicit)) return (cachedBin = explicit);

  if (Date.now() < missingUntil) return null;

  const found = onPath("age");
  if (found) return (cachedBin = found);

  missingUntil = Date.now() + MISSING_TTL_MS;
  return null;
}

/** Test seam: forget where age was found. */
export const resetAgeBinaryCache = (): void => {
  cachedBin = undefined;
  missingUntil = 0;
};

export const ageAvailable = (): boolean => ageBinary() !== null;

export function ageVersion(): string | null {
  const bin = ageBinary();
  if (!bin) return null;
  try {
    return run(bin, ["--version"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
}

/**
 * Where this machine's age identity lives. It may be a plain key file or a
 * plugin identity (`AGE-PLUGIN-YUBIKEY-1…`), which is the whole point — hush
 * cannot tell the difference and does not need to.
 */
export function ageIdentityPath(): string | null {
  const candidates = [
    process.env.HUSH_AGE_IDENTITY,
    join(hushHome(), "age-identity.txt"),
    join(homedir(), ".config", "age", "keys.txt"),
    join(homedir(), "Library", "Application Support", "age", "keys.txt"),
  ].filter(Boolean) as string[];
  return candidates.find((p) => existsSync(p)) ?? null;
}

/** Which plugin an identity file needs, if any. Used for diagnostics only. */
export function identityPlugin(path: string): string | null {
  try {
    const text = readFileSync(path, "utf8");
    const m = text.match(/AGE-PLUGIN-([A-Z0-9-]+)-1/i);
    if (!m) return null;
    const name = m[1].toLowerCase();
    // This becomes an executable name. Keep it to a conservative shape so a
    // crafted identity file cannot point us at an arbitrary path.
    return /^[a-z][a-z0-9-]{0,31}$/.test(name) ? name : null;
  } catch {
    return null;
  }
}

const recipientsIn = (out: string): string[] =>
  out.split(/\r?\n/).map((l) => l.trim()).filter(isAgeRecipient);

/**
 * Read the recipient(s) an identity file corresponds to.
 *
 * Two sources are tried, and the second runs whenever the first yields nothing —
 * not only when it throws. `age-keygen -y` does not always fail on a plugin
 * identity; it can exit zero having printed something that is not a recipient,
 * in which case treating success as the answer silently reported "no hardware
 * key here" and dropped the user back to a software identity.
 */
export function recipientsForIdentity(path: string): string[] {
  const bin = ageBinary();
  if (!bin) throw new Error("`age` is not installed.");

  const keygen = bin.replace(/age$/, "age-keygen");
  try {
    const found = recipientsIn(
      run(existsSync(keygen) ? keygen : bin, ["-y", path], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }),
    );
    if (found.length) return found;
  } catch {
    /* expected for a plugin identity; fall through */
  }

  // Plugin identities answer through the plugin binary instead.
  const plugin = identityPlugin(path);
  if (plugin) {
    try {
      return recipientsIn(
        run(`age-plugin-${plugin}`, ["--identity", path], {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        }),
      );
    } catch {
      /* plugin missing or refused */
    }
  }
  return [];
}

function requireBin(): string {
  const bin = ageBinary();
  if (!bin) {
    throw new Error(
      "`age` is not installed, and this vault has age recipients.\n" +
        "  Install it:  brew install age   (or https://age-encryption.org)",
    );
  }
  return bin;
}

/**
 * Wrap the data key for an age recipient. Returns ASCII-armored ciphertext, so
 * the vault file stays plain JSON and diffs stay readable.
 */
export function wrapDekWithAge(dek: Buffer, recipient: string): string {
  const bin = requireBin();
  try {
    return execFileSync(bin, ["-a", "-r", recipient.trim()], {
      input: dek,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      maxBuffer: 1 << 20,
    }).trim();
  } catch (e) {
    const err = e as { stderr?: Buffer | string };
    throw new Error(`age could not encrypt to ${recipient.slice(0, 20)}…: ${String(err.stderr ?? e).trim()}`);
  }
}

/**
 * Unwrap the data key. For a hardware-backed identity this is the call that
 * makes the YubiKey blink or the Secure Enclave ask for a fingerprint — age
 * drives the plugin, hush just waits.
 */
export function unwrapDekWithAge(armored: string, identityPath: string): Buffer {
  const bin = requireBin();
  if (!existsSync(identityPath)) {
    throw new Error(`age identity file not found: ${identityPath}`);
  }
  try {
    const out = execFileSync(bin, ["-d", "-i", identityPath], {
      input: armored,
      stdio: ["pipe", "pipe", "pipe"],
      maxBuffer: 1 << 20,
      // Hardware plugins prompt the human; give them room to touch the key.
      timeout: 120_000,
    });
    const dek = Buffer.from(out);
    if (dek.length !== 32) throw new Error(`expected a 32-byte data key, got ${dek.length}`);
    return dek;
  } catch (e) {
    const err = e as { stderr?: Buffer | string };
    const detail = String(err.stderr ?? (e as Error).message).trim();
    throw new Error(`age could not decrypt with ${identityPath}: ${detail}`);
  }
}
