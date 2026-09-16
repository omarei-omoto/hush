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
