/**
 * An independent reimplementation of the hush/v1 envelope scheme, written
 * against the documented description rather than against src/crypto.ts, using
 * WebCrypto instead of node:crypto.
 *
 * If this can open what hush produced, two things hold that no amount of
 * testing hush against itself could show: the scheme is specified precisely
 * enough for someone else to implement, and hush's implementation matches that
 * specification rather than merely being self-consistent.
 *
 * The spec, in full:
 *   value  = AES-256-GCM(key = DEK, iv = random 96 bits,
 *                        aad = "hush/v1|" + env + "|" + key)
 *   wrap   = AES-256-GCM(key = KEK, iv = random 96 bits, aad = recipientPub)
 *   KEK    = HKDF-SHA256(ikm  = X25519(ephemeralPriv, recipientPub),
 *                        salt = ephemeralPub || recipientPub,
 *                        info = "hush/v1/kek",
 *                        len  = 32)
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";

import {
  generateIdentity, newDek, wrapDek, sealValue, type Identity, type Wrap, type Sealed,
} from "../src/crypto.ts";

const subtle = globalThis.crypto.subtle;
const b64 = (s: string) => Buffer.from(s, "base64");
const b64u = (b: Buffer) => b.toString("base64url");

/** Independent AES-256-GCM open, built from the spec above. */
async function openGcm(key: Buffer, iv: Buffer, ct: Buffer, tag: Buffer, aad: Buffer): Promise<Buffer> {
  const k = await subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  const plain = await subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    k,
    Buffer.concat([ct, tag]),
  );
  return Buffer.from(plain);
}

/** Independent DEK unwrap: X25519 -> HKDF -> AES-GCM, per the spec. */
async function unwrapIndependently(wrap: Wrap, id: Identity): Promise<Buffer> {
  const ephPub = b64(wrap.epk);

  const priv = await subtle.importKey(
    "jwk",
    { kty: "OKP", crv: "X25519", d: b64u(id.priv), x: b64u(id.pub) },
    { name: "X25519" },
    false,
    ["deriveBits"],
  );
  const pub = await subtle.importKey(
    "jwk",
    { kty: "OKP", crv: "X25519", x: b64u(ephPub) },
    { name: "X25519" },
    false,
    [],
  );
  const shared = Buffer.from(await subtle.deriveBits({ name: "X25519", public: pub }, priv, 256));

  const hkdfKey = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const kek = Buffer.from(
    await subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: Buffer.concat([ephPub, id.pub]),
        info: Buffer.from("hush/v1/kek"),
      },
      hkdfKey,
      256,
    ),
  );

  return openGcm(kek, b64(wrap.iv), b64(wrap.ct), b64(wrap.tag), id.pub);
}

/**
 * Independent value open, per the spec.
 *
 * The AAD is `hush/v2|<generation>|<env>|<key>`: the generation is bound into
 * the tag so a vault file whose plaintext generation was edited no longer
 * decrypts. (The key wrap keeps the v1 KDF context, which is why "hush/v1/kek"
 * still appears below.)
 */
const openValueIndependently = (dek: Buffer, env: string, key: string, s: Sealed, generation: number) =>
  openGcm(dek, b64(s.iv), b64(s.ct), b64(s.tag), Buffer.from(`hush/v2|${generation}|${env}|${key}`, "utf8"));

describe("hush/v2 value AAD conformance (independent WebCrypto implementation)", () => {
  test("an independent implementation unwraps a data key hush produced", async () => {
    const id = generateIdentity();
    const dek = newDek();
    const wrap = wrapDek(dek, id.pub);
    assert.deepEqual(await unwrapIndependently(wrap, id), dek);
  });

  test("an independent implementation opens a value hush sealed", async () => {
    const dek = newDek();
    const sealed = sealValue(dek, "prod", "STRIPE_SECRET_KEY", "sk_live_conformance", 1);
    const out = await openValueIndependently(dek, "prod", "STRIPE_SECRET_KEY", sealed, 1);
    assert.equal(out.toString("utf8"), "sk_live_conformance");
  });

  test("the whole envelope opens end to end, independently", async () => {
    const id = generateIdentity();
    const dek = newDek();
    const wrap = wrapDek(dek, id.pub);
    const sealed = sealValue(dek, "default", "DATABASE_URL", "postgres://u:p@h/db", 2);

    const recoveredDek = await unwrapIndependently(wrap, id);
    const value = await openValueIndependently(recoveredDek, "default", "DATABASE_URL", sealed, 2);
    assert.equal(value.toString("utf8"), "postgres://u:p@h/db");
  });

  test("the AAD binding is part of the spec, not an accident of one library", async () => {
    const dek = newDek();
    const sealed = sealValue(dek, "staging", "K", "v", 1);
    // The independent implementation must also refuse the wrong slot.
    await assert.rejects(() => openValueIndependently(dek, "prod", "K", sealed, 1));
    await assert.rejects(() => openValueIndependently(dek, "staging", "OTHER", sealed, 1));
    // And the generation is part of the binding: raising it must fail here too,
    // which is what makes the rollback warning impossible to silence quietly.
    await assert.rejects(() => openValueIndependently(dek, "staging", "K", sealed, 9));
  });

  test("the KDF salt really is ephemeralPub || recipientPub", async () => {
    // Swapping the salt order must fail, which pins the byte order in the spec.
    const id = generateIdentity();
    const dek = newDek();
    const wrap = wrapDek(dek, id.pub);
    const ephPub = b64(wrap.epk);

    const priv = await subtle.importKey(
      "jwk", { kty: "OKP", crv: "X25519", d: b64u(id.priv), x: b64u(id.pub) },
      { name: "X25519" }, false, ["deriveBits"],
    );
    const pub = await subtle.importKey(
      "jwk", { kty: "OKP", crv: "X25519", x: b64u(ephPub) }, { name: "X25519" }, false, [],
    );
    const shared = Buffer.from(await subtle.deriveBits({ name: "X25519", public: pub }, priv, 256));
    const hkdfKey = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
    const wrongKek = Buffer.from(
      await subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: Buffer.concat([id.pub, ephPub]), info: Buffer.from("hush/v1/kek") },
        hkdfKey, 256,
      ),
    );
    await assert.rejects(() => openGcm(wrongKek, b64(wrap.iv), b64(wrap.ct), b64(wrap.tag), id.pub));
  });

  test("node and WebCrypto agree on every primitive the scheme uses", async () => {
    const { hkdfSync, createCipheriv, randomBytes, generateKeyPairSync, diffieHellman } =
      await import("node:crypto");

    const ikm = randomBytes(32), salt = randomBytes(64), info = Buffer.from("hush/v1/kek");
    const nodeHkdf = Buffer.from(hkdfSync("sha256", ikm, salt, info, 32));
    const wcIkm = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    const wcHkdf = Buffer.from(
      await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, wcIkm, 256),
    );
    assert.deepEqual(nodeHkdf, wcHkdf, "HKDF-SHA256 differs between implementations");

    const key = randomBytes(32), iv = randomBytes(12), aad = Buffer.from("hush/v2|1|prod|K");
    const c = createCipheriv("aes-256-gcm", key, iv);
    c.setAAD(aad);
    const nodeSealed = Buffer.concat([c.update(Buffer.from("value")), c.final(), c.getAuthTag()]);
    const wcKey = await subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
    const wcSealed = Buffer.from(
      await subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, wcKey, Buffer.from("value")),
    );
    assert.deepEqual(nodeSealed, wcSealed, "AES-256-GCM differs between implementations");

    const a = generateKeyPairSync("x25519"), b = generateKeyPairSync("x25519");
    const nodeShared = diffieHellman({ privateKey: a.privateKey, publicKey: b.publicKey });
    const aJwk = a.privateKey.export({ format: "jwk" }) as { d: string; x: string };
    const bJwk = b.privateKey.export({ format: "jwk" }) as { x: string };
    const wcPriv = await subtle.importKey(
      "jwk", { kty: "OKP", crv: "X25519", d: aJwk.d, x: aJwk.x }, { name: "X25519" }, false, ["deriveBits"],
    );
    const wcPub = await subtle.importKey(
      "jwk", { kty: "OKP", crv: "X25519", x: bJwk.x }, { name: "X25519" }, false, [],
    );
    const wcShared = Buffer.from(await subtle.deriveBits({ name: "X25519", public: wcPub }, wcPriv, 256));
    assert.deepEqual(nodeShared, wcShared, "X25519 differs between implementations");
  });
});
