/**
 * A Secure Enclave identity (F-8): a P-256 key made inside this Mac's enclave,
 * of which hush only ever holds a sealed blob and the public half.
 *
 * The enclave itself cannot run in CI, so the key agreement goes through the
 * test seam in enclave.ts (setEnclaveForTests) to a software P-256 key whose
 * "blob" is its PEM. Everything around the agreement — the wrap, the key
 * derivation, membership, signing, posture — is hush's own code, unchanged.
 * The wrap format is also checked against an independent WebCrypto
 * implementation, so a mistake cannot be mirrored on both sides.
 */
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, randomBytes, webcrypto } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { platform, tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HOME = mkdtempSync(join(tmpdir(), "hush-enclave-home-"));
process.env.HUSH_HOME = HOME;
process.env.HUSH_NO_KEYCHAIN = "1";

import { setEnclaveForTests, loadEnclaveIdentity } from "../src/enclave.ts";
import { Vault } from "../src/vault.ts";
import { generateIdentity, encodeSecret, encodeSePub, wrapDekP256, unwrapDekP256, isSeRecipient } from "../src/crypto.ts";
import { verifyHeader } from "../src/header.ts";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.ts");

/** A stand-in enclave: a software P-256 key, its PEM as the "blob". */
function fakeEnclave(dir: string, name: string): { pub: Buffer; blobPath: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const blobPath = join(dir, `${name}.blob`);
  writeFileSync(blobPath, privateKey.export({ format: "pem", type: "pkcs8" }));
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const pub = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]);
  return { pub, blobPath };
}

const x963ToKey = (raw: Buffer) =>
  createPublicKey({
    key: { kty: "EC", crv: "P-256", x: raw.subarray(1, 33).toString("base64url"), y: raw.subarray(33).toString("base64url") },
    format: "jwk",
  });

const reasons: string[] = [];
before(() => {
  setEnclaveForTests((blobPath, peerPub, reason) => {
    reasons.push(reason);
    const privateKey = createPrivateKey(readFileSync(blobPath, "utf8"));
    return diffieHellman({ privateKey, publicKey: x963ToKey(peerPub) });
  });
});
after(() => {
  setEnclaveForTests(null);
  rmSync(HOME, { recursive: true, force: true });
});

describe("the enclave wrap", () => {
  test("an independent WebCrypto implementation opens it", async () => {
    // ECDH(P-256) → HKDF-SHA256(salt = epk ‖ recipient, info "hush/v3/se-kek")
    // → AES-256-GCM with the recipient's public key as AAD.
    const subtle = webcrypto.subtle;
    const pair = (await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as webcrypto.CryptoKeyPair;
    const recipientPub = Buffer.from(await subtle.exportKey("raw", pair.publicKey));
    const dek = randomBytes(32);
    const wrap = wrapDekP256(dek, recipientPub);

    const epk = Buffer.from(wrap.epk, "base64");
    const peer = await subtle.importKey("raw", epk, { name: "ECDH", namedCurve: "P-256" }, false, []);
    const shared = await subtle.deriveBits({ name: "ECDH", public: peer }, pair.privateKey, 256);
    const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    const kek = await subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: Buffer.concat([epk, recipientPub]), info: Buffer.from("hush/v3/se-kek") },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    const opened = await subtle.decrypt(
      { name: "AES-GCM", iv: Buffer.from(wrap.iv, "base64"), additionalData: recipientPub },
      kek,
      Buffer.concat([Buffer.from(wrap.ct, "base64"), Buffer.from(wrap.tag, "base64")]),
    );
    assert.ok(Buffer.from(opened).equals(dek));
  });

  test("a wrap made for one enclave key does not open with another", () => {
    const dir = mkdtempSync(join(tmpdir(), "hush-se-"));
    const a = fakeEnclave(dir, "a");
    const b = fakeEnclave(dir, "b");
    const wrap = wrapDekP256(randomBytes(32), a.pub);
    const privB = createPrivateKey(readFileSync(b.blobPath, "utf8"));
    const wrongShared = diffieHellman({ privateKey: privB, publicKey: x963ToKey(Buffer.from(wrap.epk, "base64")) });
    assert.throws(() => unwrapDekP256(wrap, wrongShared, a.pub));
    // Nor with the right secret but someone else's public key in the derivation.
    const privA = createPrivateKey(readFileSync(a.blobPath, "utf8"));
    const shared = diffieHellman({ privateKey: privA, publicKey: x963ToKey(Buffer.from(wrap.epk, "base64")) });
    assert.throws(() => unwrapDekP256(wrap, shared, b.pub));
    rmSync(dir, { recursive: true, force: true });
  });

  test("the key string is hush_se_ and round-trips as a recipient", () => {
    const dir = mkdtempSync(join(tmpdir(), "hush-se-"));
    const k = fakeEnclave(dir, "k");
    const s = encodeSePub(k.pub);
    assert.match(s, /^hush_se_/);
    assert.ok(isSeRecipient(s));
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("an enclave key as a vault member", () => {
  test("the upgrade path: add your enclave key, read with it alone, retire the software key", () => {
    const dir = mkdtempSync(join(tmpdir(), "hush-se-vault-"));
    const path = join(dir, "vault.json");
    const alice = generateIdentity();
    const se = fakeEnclave(dir, "alice");
    const both = { pub: alice.pub, priv: alice.priv, se };

    const v = Vault.create(path, "acme", { name: "alice", pub: alice.pub, priv: alice.priv });
    v.set(alice, "prod", "STRIPE_SECRET_KEY", "sk_live_enclave");
    v.save();

    // What `hush secure --hardware` does: add your own enclave key as an admin.
    const v2 = Vault.open(path);
    v2.addRecipient(both, "alice-enclave", encodeSePub(se.pub), "admin");
    v2.save();

    const withEnclave = Vault.open(path);
    const member = withEnclave.members().find((m) => m.name === "alice-enclave")!;
    assert.equal(member.kind, "se");
    assert.equal(member.role, "admin");
    assert.ok(member.spk, "your own enclave key did not get a signing key, so it could never sign");
    assert.ok(verifyHeader(withEnclave.data).ok, "the header no longer verifies");

    // The enclave alone opens it — and the agreement was asked for with a reason.
    reasons.length = 0;
    assert.equal(withEnclave.get({ se }, "prod", "STRIPE_SECRET_KEY"), "sk_live_enclave");
    assert.ok(reasons.length >= 1 && reasons[0].length > 0, "the enclave was not given a reason to show");

    // Retire the software key, signed by the enclave member's key.
    const v3 = Vault.open(path);
    v3.removeRecipient({ se }, "alice");
    v3.save();

    const after = Vault.open(path);
    assert.ok(verifyHeader(after.data).ok, "the enclave member could not sign the change");
    assert.equal(after.members().map((m) => m.name).join(","), "alice-enclave");
    assert.equal(after.get({ se }, "prod", "STRIPE_SECRET_KEY"), "sk_live_enclave");
    assert.throws(() => after.get(alice, "prod", "STRIPE_SECRET_KEY"), "the retired software key can still read");
    rmSync(dir, { recursive: true, force: true });
  });

  test("another enclave's key cannot open a vault it was not added to", () => {
    const dir = mkdtempSync(join(tmpdir(), "hush-se-vault-"));
    const path = join(dir, "vault.json");
    const alice = generateIdentity();
    const se = fakeEnclave(dir, "alice");
    const other = fakeEnclave(dir, "other");
    const v = Vault.create(path, "acme", { name: "alice", pub: alice.pub, priv: alice.priv });
    v.set(alice, "prod", "K", "v");
    v.addRecipient(alice, "alice-enclave", encodeSePub(se.pub), "admin");
    v.save();
    // The other enclave's blob, presented with alice's public key: the agreement
    // yields the wrong secret and the wrap refuses.
    assert.throws(() => Vault.open(path).get({ se: { pub: se.pub, blobPath: other.blobPath } }, "prod", "K"));
    assert.throws(() => Vault.open(path).get({ se: other }, "prod", "K"));
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("on this machine", { skip: platform() !== "darwin" && "the enclave identity is loaded on macOS only" }, () => {
  test("an enclave identity counts as hardware, and `hush id` shows it", () => {
    const home = mkdtempSync(join(tmpdir(), "hush-se-id-"));
    const se = fakeEnclave(home, "enclave-identity");
    writeFileSync(join(home, "enclave-identity"), JSON.stringify({ pub: se.pub.toString("base64"), presence: "touch" }));
    const saved = process.env.HUSH_HOME;
    process.env.HUSH_HOME = home;
    try {
      assert.ok(loadEnclaveIdentity()?.pub.equals(se.pub));
    } finally {
      process.env.HUSH_HOME = saved;
    }

    const env = {
      ...process.env, HOME: home, HUSH_HOME: home, HUSH_NO_KEYCHAIN: "1", HUSH_BIOMETRY: "off", HUSH_NO_DIALOG: "1",
      HUSH_NO_NUDGE: "1", NO_COLOR: "1",
    };
    // Beside a software key: both are shown.
    const withKey = spawnSync(process.execPath, [CLI, "id"], {
      env: { ...env, HUSH_IDENTITY: encodeSecret(generateIdentity()) },
      encoding: "utf8",
    });
    assert.match(withKey.stdout + withKey.stderr, /Secure Enclave key/);
    assert.ok((withKey.stdout + withKey.stderr).includes(encodeSePub(se.pub)));

    // Alone: it is the identity.
    const alone = spawnSync(process.execPath, [CLI, "id", "--quiet"], { env, encoding: "utf8" });
    assert.equal(alone.stdout.trim(), encodeSePub(se.pub));
    rmSync(home, { recursive: true, force: true });
  });

  test("--presence takes only touch or none", () => {
    const home = mkdtempSync(join(tmpdir(), "hush-se-id-"));
    const r = spawnSync(process.execPath, [CLI, "id", "--enclave", "--presence", "maybe"], {
      env: { ...process.env, HOME: home, HUSH_HOME: home, HUSH_NO_KEYCHAIN: "1", NO_COLOR: "1" },
      encoding: "utf8",
    });
    assert.notEqual(r.status, 0);
    assert.match(r.stdout + r.stderr, /--presence/);
    rmSync(home, { recursive: true, force: true });
  });
});
