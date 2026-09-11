/**
 * Adversarial properties of the envelope scheme.
 *
 * These assert things the code does not itself enforce — they are inherited
 * from node/OpenSSL, or emerge from how the pieces are wired. That is exactly
 * why they need pinning: swapping the crypto backend, or "simplifying" a KDF
 * input, would break them silently and the functional tests would still pass.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, diffieHellman, generateKeyPairSync } from "node:crypto";

import {
  generateIdentity, newDek, wrapDek, unwrapDek, sealValue, openValue,
  encodePub, decodePub, fingerprint,
} from "../src/crypto.ts";

describe("crypto properties", () => {
  test("a low-order public key cannot produce a predictable shared secret", () => {
    // If ECDH silently returned all zeros for these, anyone holding the vault
    // file could derive the key-wrapping key for a recipient added with a
    // crafted "public key" — no private key required.
    const lowOrder = [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0100000000000000000000000000000000000000000000000000000000000000",
      "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
      "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];
    const { privateKey } = generateKeyPairSync("x25519");

    /** The exact code path under test, reduced to "did it refuse?". */
    const agree = (raw: Buffer): { threw: boolean; shared?: Buffer } => {
      try {
        const publicKey = createPublicKey({
          key: { kty: "OKP", crv: "X25519", x: raw.toString("base64url") },
          format: "jwk",
        });
        return { threw: false, shared: diffieHellman({ privateKey, publicKey }) };
      } catch {
        return { threw: true };
      }
    };

    // Control first. Without it, this test passes just as happily if the JWK
    // shape is wrong or Node changes an unrelated error — "it threw" would then
    // be about the harness rather than about the point being low-order, and the
    // whole test would assert nothing while looking like it asserted a lot.
    const honest = agree(
      Buffer.from(
        (generateKeyPairSync("x25519").publicKey.export({ format: "jwk" }) as { x: string }).x,
        "base64url",
      ),
    );
    assert.equal(honest.threw, false, "the control key was refused — this test is measuring the harness");
    assert.equal(honest.shared?.length, 32);

    for (const hex of lowOrder) {
      const r = agree(Buffer.from(hex, "hex"));
      if (!r.threw) {
        assert.ok(
          !r.shared!.every((b) => b === 0),
          `all-zero shared secret for ${hex.slice(0, 8)}`,
        );
      }
      assert.ok(r.threw, `low-order point ${hex.slice(0, 8)}… was accepted without error`);
    }
  });

  test("wrapping to a low-order key fails loudly rather than producing a usable wrap", () => {
    const dek = newDek();
    const bad = Buffer.from("0100000000000000000000000000000000000000000000000000000000000000", "hex");
    assert.throws(() => wrapDek(dek, bad));
  });

  test("every seal uses a fresh IV", () => {
    const dek = newDek();
    const ivs = new Set<string>();
    for (let i = 0; i < 2000; i++) ivs.add(sealValue(dek, "default", "K", "same value").iv);
    assert.equal(ivs.size, 2000, "an IV repeated under one key — GCM loses all guarantees");
  });

  test("the same value sealed twice yields different ciphertext", () => {
    const dek = newDek();
    const a = sealValue(dek, "default", "K", "value");
    const b = sealValue(dek, "default", "K", "value");
    assert.notEqual(a.ct, b.ct);
    assert.notEqual(a.iv, b.iv);
  });

  test("each data key generation is independent", () => {
    const keys = new Set<string>();
    for (let i = 0; i < 500; i++) keys.add(newDek().toString("hex"));
    assert.equal(keys.size, 500);
  });

  test("tampering with any part of a sealed value is detected", () => {
    const dek = newDek();
    const sealed = sealValue(dek, "default", "K", "the value");
    const flip = (field: "iv" | "ct" | "tag") => {
      const buf = Buffer.from(sealed[field], "base64");
      buf[0] ^= 0xff;
      return { ...sealed, [field]: buf.toString("base64") };
    };
    for (const field of ["iv", "ct", "tag"] as const) {
      assert.throws(() => openValue(dek, "default", "K", flip(field)), /./, `${field} tamper undetected`);
    }
  });

  test("tampering with any part of a wrap is detected", () => {
    const dek = newDek();
    const id = generateIdentity();
    const wrap = wrapDek(dek, id.pub);
    const flip = (field: "epk" | "iv" | "ct" | "tag") => {
      const buf = Buffer.from(wrap[field], "base64");
      buf[0] ^= 0xff;
      return { ...wrap, [field]: buf.toString("base64") };
    };
    for (const field of ["epk", "iv", "ct", "tag"] as const) {
      assert.throws(() => unwrapDek(flip(field), id), /./, `${field} tamper undetected`);
    }
  });

  test("a wrap cannot be moved to another recipient", () => {
    // The wrap AAD binds it to one public key, so a vault editor cannot hand
    // someone else's wrap to a member and have it open.
    const dek = newDek();
    const alice = generateIdentity();
    const mallory = generateIdentity();
    const forAlice = wrapDek(dek, alice.pub);
    assert.throws(() => unwrapDek(forAlice, mallory));
    // Even with mallory's own public bytes swapped in, the ECDH will not match.
    assert.throws(() => unwrapDek(forAlice, { pub: mallory.pub, priv: alice.priv }));
  });

  test("the KDF is domain-separated by both public keys", () => {
    // Two wraps of the same DEK to the same recipient must not share a KEK,
    // which shows the ephemeral key really participates in the derivation.
    const dek = newDek();
    const id = generateIdentity();
    const a = wrapDek(dek, id.pub);
    const b = wrapDek(dek, id.pub);
    assert.notEqual(a.epk, b.epk);
    assert.notEqual(a.ct, b.ct);
    assert.deepEqual(unwrapDek(a, id), dek);
    assert.deepEqual(unwrapDek(b, id), dek);
  });

  test("public key encoding rejects anything of the wrong shape", () => {
    for (const bad of [
      "", "hush_pk_", "hush_pk_!!!!", "age1abc", "hush_sk_" + "A".repeat(86),
      "hush_pk_" + Buffer.alloc(31).toString("base64url"),
      "hush_pk_" + Buffer.alloc(33).toString("base64url"),
    ]) {
      assert.throws(() => decodePub(bad), /./, `accepted ${JSON.stringify(bad.slice(0, 20))}`);
    }
    const id = generateIdentity();
    assert.doesNotThrow(() => decodePub(encodePub(id.pub)));
  });

  test("fingerprints do not collide across many identities", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 3000; i++) seen.add(fingerprint(generateIdentity().pub));
    assert.equal(seen.size, 3000);
  });

  test("a generated identity is never the all-zero key", () => {
    for (let i = 0; i < 100; i++) {
      const id = generateIdentity();
      assert.ok(!id.pub.every((b) => b === 0));
      assert.ok(!id.priv.every((b) => b === 0));
      assert.equal(id.pub.length, 32);
      assert.equal(id.priv.length, 32);
    }
  });
});
