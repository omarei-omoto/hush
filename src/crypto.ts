/**
 * Envelope encryption for hush.
 *
 * Scheme (v1), modelled on age/ECIES:
 *   - Every vault has one 32-byte DEK (data encryption key), with a generation number.
 *   - Each secret value is sealed with AES-256-GCM under the DEK.
 *     AAD binds the ciphertext to `env|KEY`, so a ciphertext cannot be moved
 *     between slots (e.g. staging DB url swapped into the prod slot).
 *   - The DEK is wrapped once per recipient: ephemeral X25519 -> ECDH ->
 *     HKDF-SHA256 -> AES-256-GCM. Adding a member re-wraps; removing a member
 *     mints a new DEK generation and re-seals every value.
 *
 * No third-party crypto. Everything here is node:crypto.
 */
import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  generateKeyPairSync,
  createPublicKey,
  createPrivateKey,
  diffieHellman,
  hkdfSync,
  createHash,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";

/**
 * Raised when the *input* is wrong, as opposed to something going wrong.
 *
 * Without the distinction, a mistyped key name and a corrupt vault both came
 * back as a 500 — which reads as a server fault and buries the real ones.
 */
export class ValidationError extends Error {
  readonly validation = true;
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

export const isValidationError = (e: unknown): boolean =>
  e instanceof ValidationError || (e as { validation?: boolean })?.validation === true;

export const PK_PREFIX = "hush_pk_";
export const SK_PREFIX = "hush_sk_";
export const SCHEME = "hush/v1";
/**
 * The value-AAD version that binds a sealed value to the generation it was
 * sealed under.
 *
 * In v1 the AAD carried only `env|KEY`, so `dek.generation` and each entry's
 * `gen` were plaintext siblings that no AEAD covered — and freshness was
 * decided from those numbers. Two integer edits in a committed vault file
 * therefore silenced the rollback warning, let a removed member read every
 * value they could still unwrap, and poisoned the local watermark. Binding the
 * generation into the tag means an inflated label simply fails to decrypt:
 * loud instead of silent.
 *
 * The wrap/KDF context deliberately keeps the v1 label (see deriveKek), so
 * existing key wraps keep unwrapping.
 */
export const SCHEME_V2 = "hush/v2";
/**
 * The signed format (V-1b, 1.0): the vault's header — who can read it, and a
 * commitment to every data key — is signed by an admin, so a vault rebuilt by
 * someone who is not one no longer opens anywhere. Values seal exactly as in
 * v2; only the header is new.
 */
export const SCHEME_V3 = "hush/v3";

const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");
const ub64 = (s: string) => Buffer.from(s, "base64");
const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const ub64u = (s: string) => Buffer.from(s, "base64url");

/** AES-256-GCM ciphertext. */
export interface Sealed {
  iv: string;
  ct: string;
  tag: string;
}

/** A DEK wrapped for one recipient. `epk` is the ephemeral X25519 public key. */
export interface Wrap extends Sealed {
  epk: string;
}

/** Raw X25519 keypair, 32 bytes each. */
export interface Identity {
  pub: Buffer;
  priv: Buffer;
}

/**
 * Whoever is trying to open a vault. A plain X25519 Identity satisfies this
 * structurally, so every existing caller keeps working; an age-backed user has
 * no software key at all and carries only `age`.
 */
export interface Opener {
  pub?: Buffer;
  priv?: Buffer;
  age?: { recipients: string[]; identityPath: string };
  /** A Secure Enclave identity: its public key, and the sealed blob only this Mac's enclave can use. */
  se?: { pub: Buffer; blobPath: string };
}

// ---------------------------------------------------------------- identities

export function generateIdentity(): Identity {
  const { privateKey } = generateKeyPairSync("x25519");
  const jwk = privateKey.export({ format: "jwk" }) as { x: string; d: string };
  return { pub: ub64u(jwk.x), priv: ub64u(jwk.d) };
}

function pubKeyObject(pub: Buffer): KeyObject {
  return createPublicKey({
    key: { kty: "OKP", crv: "X25519", x: b64u(pub) },
    format: "jwk",
  });
}

function privKeyObject(id: Identity): KeyObject {
  return createPrivateKey({
    key: { kty: "OKP", crv: "X25519", x: b64u(id.pub), d: b64u(id.priv) },
    format: "jwk",
  });
}

export const encodePub = (pub: Buffer): string => PK_PREFIX + b64u(pub);

export function decodePub(s: string): Buffer {
  const t = s.trim();
  if (!t.startsWith(PK_PREFIX)) throw new ValidationError(`not a hush public key: ${t.slice(0, 16)}…`);
  const raw = ub64u(t.slice(PK_PREFIX.length));
  if (raw.length !== 32) throw new ValidationError("public key must be 32 bytes");
  return raw;
}

/** Secret encoding is pub||priv so we can rebuild the JWK without a scalarmult. */
export const encodeSecret = (id: Identity): string =>
  SK_PREFIX + b64u(Buffer.concat([id.pub, id.priv]));

export function decodeSecret(s: string): Identity {
  const t = s.trim();
  if (!t.startsWith(SK_PREFIX)) throw new ValidationError("not a hush secret key");
  const raw = ub64u(t.slice(SK_PREFIX.length));
  if (raw.length !== 64) throw new ValidationError("secret key must be 64 bytes");
  return { pub: raw.subarray(0, 32), priv: raw.subarray(32) };
}

/** Short stable id for a recipient, used as the map key in the vault. */
export const fingerprint = (pub: Buffer): string =>
  createHash("sha256").update(pub).digest("hex").slice(0, 16);

// ------------------------------------------------------------ value sealing

/** The pre-binding AAD, read-only, for values written by an older hush. */
const valueAadLegacy = (env: string, key: string) => Buffer.from(`${SCHEME}|${env}|${key}`, "utf8");

const valueAadBound = (env: string, key: string, generation: number) =>
  Buffer.from(`${SCHEME_V2}|${generation}|${env}|${key}`, "utf8");

export function sealValue(dek: Buffer, env: string, key: string, plaintext: string, generation: number): Sealed {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", dek, iv);
  c.setAAD(valueAadBound(env, key, generation));
  const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
  return { iv: b64(iv), ct: b64(ct), tag: b64(c.getAuthTag()) };
}

/**
 * Open a sealed value.
 *
 * Pass `generation` for a value this build sealed (its entry carries `v: 2`);
 * omit it for a value written by an older hush, whose AAD carried only
 * `env|KEY`. The vault records which per entry, so a file that was upgraded
 * value by value still opens.
 */
export function openValue(dek: Buffer, env: string, key: string, s: Sealed, generation?: number): string {
  const d = createDecipheriv("aes-256-gcm", dek, ub64(s.iv));
  d.setAAD(generation === undefined ? valueAadLegacy(env, key) : valueAadBound(env, key, generation));
  d.setAuthTag(ub64(s.tag));
  return Buffer.concat([d.update(ub64(s.ct)), d.final()]).toString("utf8");
}

// --------------------------------------------------------------- DEK wrapping

function deriveKek(shared: Buffer, ephPub: Buffer, recipientPub: Buffer): Buffer {
  const salt = Buffer.concat([ephPub, recipientPub]);
  return Buffer.from(hkdfSync("sha256", shared, salt, Buffer.from(`${SCHEME}/kek`), 32));
}

export function wrapDek(dek: Buffer, recipientPub: Buffer): Wrap {
  const eph = generateKeyPairSync("x25519");
  const ephJwk = eph.privateKey.export({ format: "jwk" }) as { x: string };
  const ephPub = ub64u(ephJwk.x);

  const shared = diffieHellman({
    privateKey: eph.privateKey,
    publicKey: pubKeyObject(recipientPub),
  });
  const kek = deriveKek(shared, ephPub, recipientPub);

  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", kek, iv);
  c.setAAD(recipientPub);
  const ct = Buffer.concat([c.update(dek), c.final()]);
  return { epk: b64(ephPub), iv: b64(iv), ct: b64(ct), tag: b64(c.getAuthTag()) };
}

export function unwrapDek(w: Wrap, id: Identity): Buffer {
  const ephPub = ub64(w.epk);
  const shared = diffieHellman({
    privateKey: privKeyObject(id),
    publicKey: pubKeyObject(ephPub),
  });
  const kek = deriveKek(shared, ephPub, id.pub);

  const d = createDecipheriv("aes-256-gcm", kek, ub64(w.iv));
  d.setAAD(id.pub);
  d.setAuthTag(ub64(w.tag));
  return Buffer.concat([d.update(ub64(w.ct)), d.final()]);
}

export const newDek = (): Buffer => randomBytes(32);

/**
 * A commitment to one generation of a vault's data key, safe to store and show.
 *
 * The vault file does not say who chose its data key: anyone can mint one and
 * wrap it to every member's public key, since those are in the file. What a
 * member *can* notice is that the key behind a given (vault, generation) is not
 * the one it was the last time they looked — no legitimate operation re-keys a
 * vault without moving to a new generation. HKDF output reveals nothing about
 * its input, so the commitment can sit in `~/.hush/seen/` and, later, in a
 * signed vault header.
 */
export function dekCommit(dek: Buffer, vaultId: string, generation: number): string {
  return Buffer.from(
    hkdfSync("sha256", dek, Buffer.from(vaultId, "utf8"), Buffer.from(`hush/dek-commit/${generation}`), 16),
  ).toString("hex");
}

// ------------------------------------------------------------------ signing

export const SPK_PREFIX = "hush_spk_";

/** An Ed25519 key that signs vault headers. */
export interface Signer {
  /** Raw 32-byte Ed25519 public key. */
  spk: Buffer;
  sign: (message: Buffer) => Buffer;
}

/** PKCS#8 wrapping for a raw Ed25519 seed (RFC 8410): a fixed 16-byte prefix. */
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function signerFromSeed(seed: Buffer): Signer {
  if (seed.length !== 32) throw new Error("an Ed25519 seed is 32 bytes");
  const priv = createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
  const jwk = createPublicKey(priv).export({ format: "jwk" }) as { x: string };
  return { spk: ub64u(jwk.x), sign: (message) => edSign(null, message, priv) };
}

/**
 * The signing key that belongs to an X25519 identity.
 *
 * Derived, not stored: HKDF with its own label keeps it independent of the
 * encryption key, and every identity that already exists — in a keychain, a
 * file, an environment variable — has one without anything moving. A
 * hardware-only (age) identity has no software key to derive from and keeps a
 * separate one (identity.ts).
 */
export function signerForIdentity(id: Identity): Signer {
  const seed = Buffer.from(hkdfSync("sha256", id.priv, Buffer.from("hush/v3"), Buffer.from("hush/v3/signing"), 32));
  return signerFromSeed(seed);
}

export const encodeSpk = (spk: Buffer): string => SPK_PREFIX + b64u(spk);

export function decodeSpk(s: string): Buffer {
  const t = s.trim();
  if (!t.startsWith(SPK_PREFIX)) throw new ValidationError(`not a hush signing key: ${t.slice(0, 16)}…`);
  const raw = ub64u(t.slice(SPK_PREFIX.length));
  if (raw.length !== 32) throw new ValidationError("a signing key is 32 bytes");
  return raw;
}

export function verifySignature(spk: Buffer, message: Buffer, signature: Buffer): boolean {
  try {
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: b64u(spk) }, format: "jwk" });
    return edVerify(null, message, key, signature);
  } catch {
    return false;
  }
}

/**
 * JSON with its keys sorted at every level and no whitespace — the bytes a
 * signature covers. Two writers that build the same header in a different
 * order, or pretty-print it differently, produce the same bytes.
 */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/**
 * A safety number for two signing keys: sixty digits both people can read to
 * each other and compare. Order-independent, so both compute the same one.
 */
export function safetyNumber(a: Buffer, b: Buffer): string {
  const [x, y] = [a, b].sort(Buffer.compare);
  const digest = createHash("sha512").update("hush/safety-number/v1").update(x).update(y).digest();
  const groups: string[] = [];
  for (let i = 0; i < 12; i++) {
    groups.push(String(digest.readUInt32BE(i * 4) % 100000).padStart(5, "0"));
  }
  return groups.join(" ");
}

// ------------------------------------------------------- Secure Enclave keys
//
// An enclave identity is a P-256 key agreement key (see native/hush-enclave.swift).
// Wrapping the data key for one is the same construction as for X25519 —
// ephemeral key agreement, HKDF-SHA256, AES-256-GCM with the recipient's key as
// AAD — on the curve the enclave supports. The unwrap half needs the enclave's
// shared secret, which only the helper can produce, so it takes that as input.

export const SE_PREFIX = "hush_se_";

/** An enclave recipient: `hush_se_` + the 65-byte X9.63 P-256 public key. */
export const encodeSePub = (pub: Buffer): string => SE_PREFIX + b64u(pub);

export function decodeSePub(s: string): Buffer {
  const t = s.trim();
  if (!t.startsWith(SE_PREFIX)) throw new ValidationError(`not a hush enclave key: ${t.slice(0, 16)}…`);
  const raw = ub64u(t.slice(SE_PREFIX.length));
  if (raw.length !== 65 || raw[0] !== 0x04) throw new ValidationError("an enclave key is a 65-byte uncompressed P-256 point");
  return raw;
}

export const isSeRecipient = (s: string): boolean => s.trim().startsWith(SE_PREFIX);

const p256Public = (x963: Buffer): KeyObject =>
  createPublicKey({ key: { kty: "EC", crv: "P-256", x: b64u(x963.subarray(1, 33)), y: b64u(x963.subarray(33, 65)) }, format: "jwk" });

function deriveSeKek(shared: Buffer, ephPub: Buffer, recipientPub: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", shared, Buffer.concat([ephPub, recipientPub]), Buffer.from("hush/v3/se-kek"), 32));
}

/** A data key wrapped for an enclave recipient. `epk` is the ephemeral P-256 key, X9.63. */
export interface SeWrap extends Wrap {
  se: true;
}

export function wrapDekP256(dek: Buffer, recipientPub: Buffer): SeWrap {
  const eph = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = eph.publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const ephPub = Buffer.concat([Buffer.from([0x04]), ub64u(jwk.x), ub64u(jwk.y)]);
  const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: p256Public(recipientPub) });
  const kek = deriveSeKek(shared, ephPub, recipientPub);
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", kek, iv);
  c.setAAD(recipientPub);
  const ct = Buffer.concat([c.update(dek), c.final()]);
  return { se: true, epk: b64(ephPub), iv: b64(iv), ct: b64(ct), tag: b64(c.getAuthTag()) };
}

/** Open an enclave wrap, given the shared secret the enclave agreed with `wrap.epk`. */
export function unwrapDekP256(wrap: SeWrap, shared: Buffer, recipientPub: Buffer): Buffer {
  const kek = deriveSeKek(shared, ub64(wrap.epk), recipientPub);
  const d = createDecipheriv("aes-256-gcm", kek, ub64(wrap.iv));
  d.setAAD(recipientPub);
  d.setAuthTag(ub64(wrap.tag));
  return Buffer.concat([d.update(ub64(wrap.ct)), d.final()]);
}

export const seFingerprint = (pub: Buffer): string => createHash("sha256").update(pub).digest("hex").slice(0, 16);
