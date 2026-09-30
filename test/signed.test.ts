/**
 * hush/v3: the signed header (V-1b), sets with keys of their own (F-2), and CI
 * identities (F-3).
 *
 * The attack V-1a could not stop is the headline here: a non-member re-keys a
 * vault *without* adding themselves — same roster, a new data key, generation
 * plus one — and plants a value. Pinning cannot tell that from a teammate's
 * rotation. A signature can.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { Vault, memberKeyString, type VaultFile } from "../src/vault.ts";
import {
  generateIdentity, encodeSecret, encodePub, decodePub, newDek, wrapDek, sealValue, dekCommit,
  signerForIdentity, canonicalJson, encodeSpk,
} from "../src/crypto.ts";
import { verifyHeader, headerBytes } from "../src/header.ts";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.ts");

function who(name: string, cwd: () => string) {
  const id = generateIdentity();
  const home = mkdtempSync(join(tmpdir(), `hush-v3-${name}-`));
  const run = (args: string[], opts: { input?: string; env?: NodeJS.ProcessEnv; cwd?: string } = {}) => {
    const r = spawnSync(process.execPath, [CLI, ...args], {
      cwd: opts.cwd ?? cwd(),
      env: {
        ...process.env, HOME: home, HUSH_HOME: home, HUSH_IDENTITY: encodeSecret(id), HUSH_NO_KEYCHAIN: "1",
        HUSH_BIOMETRY: "off", HUSH_NO_DIALOG: "1", HUSH_NO_NUDGE: "1", NO_COLOR: "1", USER: name, ...opts.env,
      },
      encoding: "utf8",
      input: opts.input,
      stdio: [opts.input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
    return { out: (r.stdout ?? "") + (r.stderr ?? ""), stdout: r.stdout ?? "", code: r.status ?? 1 };
  };
  return { name, id, home, run, key: memberKeyString(id) };
}

/** A signed team vault: Alice (admin) founded it through the CLI. */
function signedTeam() {
  const root = mkdtempSync(join(tmpdir(), "hush-v3-proj-"));
  const alice = who("alice", () => root);
  const bob = who("bob", () => root);
  const mallory = who("mallory", () => root);
  alice.run(["init", "acme", "--as", "alice", "--no-agent"]);
  const path = join(root, ".hush", "vault.json");
  alice.run(["add", "API_BASE=https://api.stripe.com", "--to", "default"]);
  alice.run(["add", "PROD_KEY=sk_live_prod_value", "--to", "prod"]);
  alice.run(["add", "DEV_KEY=sk_test_dev_value", "--to", "dev"]);
  return {
    root, path, alice, bob, mallory,
    data: () => JSON.parse(readFileSync(path, "utf8")) as VaultFile,
    write: (d: VaultFile) => writeFileSync(path, JSON.stringify(d, null, 2) + "\n"),
    cleanup: () => { for (const d of [root, alice.home, bob.home, mallory.home]) rmSync(d, { recursive: true, force: true }); },
  };
}

const printBase = ["run", "--", process.execPath, "-e", "process.stdout.write('API_BASE=' + process.env.API_BASE)"];

describe("V-1b: the header is signed", () => {
  test("hush init makes a signed vault, and the admin's signing key is in it", () => {
    const t = signedTeam();
    const d = t.data();
    assert.equal(d.scheme, "hush/v3");
    assert.ok(verifyHeader(d).ok, JSON.stringify(verifyHeader(d)));
    const alice = Object.values(d.recipients).find((r) => r.name === "alice")!;
    assert.equal(alice.role, "admin");
    assert.equal(alice.spk, encodeSpk(signerForIdentity(t.alice.id).spk));
    t.cleanup();
  });

  test("the attack pinning could not stop: same members, a new key, a planted value — refused", () => {
    const t = signedTeam();
    t.alice.run(["team", "add", "bob", t.bob.key]);
    assert.match(t.bob.run(printBase).out, /API_BASE=\[redacted:API_BASE\]/);

    // Mallory, not a member: re-key everything to a key of her choosing,
    // wrapped for exactly the members already listed, generation + 1.
    const d = t.data();
    const dek = newDek();
    const gen = d.dek.generation + 1;
    for (const [fp, r] of Object.entries(d.recipients)) d.dek.wraps[fp] = wrapDek(dek, decodePub(r.pk));
    d.dek.generation = gen;
    d.dek.commit = dekCommit(dek, d.id, gen);
    d.envs.default = {
      API_BASE: { ...sealValue(dek, "default", "API_BASE", "https://evil.example", gen), gen, v: 2, updatedAt: "x", updatedBy: "alice" },
    };
    delete d.setKeys;
    t.write(d);

    const ran = t.bob.run(printBase);
    assert.notEqual(ran.code, 0, "a re-keyed vault nobody signed was used:\n" + ran.out);
    assert.doesNotMatch(ran.out, /API_BASE=/);
    assert.match(ran.out, /signed header does not hold/);
    // A forged signature is not something a person can vouch for: no "accept".
    assert.doesNotMatch(ran.out, /If you expected this/);
    assert.match(ran.out, /cannot be accepted/);
    assert.notEqual(t.bob.run(["team", "accept", "--yes"]).code, 0, "a forged vault was accepted");
    t.cleanup();
  });

  test("a signature by a non-admin, or a stripped signature, is refused", () => {
    const t = signedTeam();
    t.alice.run(["team", "add", "bob", t.bob.key]);
    t.bob.run(["verify"]);
    const d = t.data();
    // Bob, a member, adds Mallory and signs it himself.
    const mfp = Object.keys(d.recipients).length.toString(16).padStart(16, "a");
    d.recipients[mfp] = { name: "mallory", pk: encodePub(t.mallory.id.pub), role: "admin", addedAt: "x" };
    const bobFp = Object.entries(d.recipients).find(([, r]) => r.name === "bob")![0];
    d.signature = { by: bobFp, sig: signerForIdentity(t.bob.id).sign(headerBytes(d)).toString("base64") };
    t.write(d);
    assert.match(t.bob.run(printBase).out, /not an admin/);

    // Now strip the signature and call it v2.
    delete d.signature;
    d.scheme = "hush/v2";
    delete d.recipients[mfp];
    t.write(d);
    const stripped = t.bob.run(printBase);
    assert.notEqual(stripped.code, 0);
    assert.match(stripped.out, /was signed by an admin when this machine last saw it/);
    t.cleanup();
  });

  test("a change signed by an admin this machine has never seen is held for a person to check", () => {
    const t = signedTeam();
    t.alice.run(["team", "add", "bob", t.bob.key]);
    t.bob.run(["verify"]);
    // Mallory builds a whole new signed vault with herself as admin — it
    // verifies on its own terms, and bob has never trusted her.
    const d = t.data();
    const mid = t.mallory.id;
    const mfp = "f".repeat(16);
    d.recipients[mfp] = { name: "mallory", pk: encodePub(mid.pub), role: "admin", addedAt: "x", spk: encodeSpk(signerForIdentity(mid).spk) };
    d.signature = { by: mfp, sig: signerForIdentity(mid).sign(headerBytes(d)).toString("base64") };
    t.write(d);
    assert.ok(verifyHeader(d).ok, "the forged vault should be internally consistent");
    const r = t.bob.run(printBase);
    assert.notEqual(r.code, 0);
    assert.match(r.out, /admin this machine has not seen before/);
    t.cleanup();
  });

  test("a changed key commitment breaks the signature; key order and whitespace do not", () => {
    const t = signedTeam();
    const d = t.data();
    // Every object's keys in reverse order, all the way down.
    const reverse = (x: unknown): unknown =>
      Array.isArray(x) ? x.map(reverse) : x && typeof x === "object"
        ? Object.fromEntries(Object.entries(x).reverse().map(([k, v]) => [k, reverse(v)]))
        : x;
    const reordered = reverse(d) as VaultFile;
    assert.notEqual(JSON.stringify(reordered), JSON.stringify(d), "the reorder changed nothing");
    assert.ok(verifyHeader(reordered).ok, "reordering keys broke the signature");
    assert.ok(verifyHeader(JSON.parse(JSON.stringify(d, null, 7))).ok);
    const bad = JSON.parse(JSON.stringify(d)) as VaultFile;
    bad.dek.commit = "0".repeat(32);
    assert.equal(verifyHeader(bad).ok, false);
    assert.equal(canonicalJson({ b: 1, a: { d: [2, 1], c: null } }), '{"a":{"c":null,"d":[2,1]},"b":1}');
    t.cleanup();
  });

  test("members cannot change who can read a signed vault; admins' changes arrive signed", () => {
    const t = signedTeam();
    t.alice.run(["team", "add", "bob", t.bob.key]);
    const denied = t.bob.run(["team", "add", "mallory", t.mallory.key]);
    assert.notEqual(denied.code, 0);
    assert.match(denied.out, /Only an admin/);
    const rot = t.bob.run(["rotate"]);
    assert.notEqual(rot.code, 0);
    // Values are not the header: a member still writes them.
    assert.equal(t.bob.run(["add", "BOBS=bob-wrote-this-value", "--to", "default"]).code, 0);
    assert.ok(verifyHeader(t.data()).ok);
    t.cleanup();
  });

  test("a v2 vault still opens, and is signed on its admin's first change to it", () => {
    const root = mkdtempSync(join(tmpdir(), "hush-v3-v2-"));
    mkdirSync(join(root, ".hush"));
    const alice = who("alice", () => root);
    const v = Vault.create(join(root, ".hush", "vault.json"), "old", { name: "alice", pub: alice.id.pub });
    v.set(alice.id, "default", "OLD", "old-value-here");
    v.save();
    assert.equal(v.data.scheme, "hush/v2", "a library-created vault without a signer should stay v2");
    assert.match(alice.run(["run", "--", "sh", "-c", "echo $OLD"]).out, /redacted:OLD/);
    assert.equal(JSON.parse(readFileSync(join(root, ".hush", "vault.json"), "utf8")).scheme, "hush/v2", "a read upgraded it");
    const bob = generateIdentity();
    alice.run(["team", "add", "bob", encodePub(bob.pub)]);
    const d = JSON.parse(readFileSync(join(root, ".hush", "vault.json"), "utf8"));
    assert.equal(d.scheme, "hush/v3");
    assert.ok(verifyHeader(d).ok);
    for (const dir of [root, alice.home]) rmSync(dir, { recursive: true, force: true });
  });

  test("safety numbers match from both ends", () => {
    const t = signedTeam();
    t.alice.run(["team", "add", "bob", t.bob.key]);
    const fromAlice = t.alice.run(["team", "verify", "bob"]).out.match(/(\d{5}\s+){3}\d{5}/g)!.join(" ");
    const fromBob = t.bob.run(["team", "verify", "alice"]).out.match(/(\d{5}\s+){3}\d{5}/g)!.join(" ");
    assert.equal(fromAlice.replace(/\s+/g, " "), fromBob.replace(/\s+/g, " "));
    assert.equal(fromAlice.replace(/\s+/g, "").length, 60);
    t.cleanup();
  });
});

describe("F-2: a member who reads only some sets", () => {
  test("a scoped member reads dev, not prod — not even with the vault file and their own key", () => {
    const t = signedTeam();
    const added = t.alice.run(["team", "add", "bob", t.bob.key, "--sets", "dev"]);
    assert.equal(added.code, 0, added.out);
    const d = t.data();
    assert.ok(d.setKeys?.dev, "dev did not get a key of its own");
    assert.ok(!d.setKeys?.prod, "prod was restricted for no reason");

    const dev = t.bob.run(["run", "--use", "dev", "--", "sh", "-c", "echo $DEV_KEY"]);
    assert.equal(dev.code, 0, dev.out);
    assert.match(dev.out, /redacted:DEV_KEY/);
    const prod = t.bob.run(["run", "--use", "prod", "--", "sh", "-c", "echo $PROD_KEY"]);
    assert.notEqual(prod.code, 0);
    assert.match(prod.out, /cannot read set "prod"/);
    assert.match(prod.out, /--sets prod/, "the refusal does not say how to get it");

    // Straight through the library, with the file in hand: still nothing.
    const v = Vault.fromData("x", d);
    assert.throws(() => v.materialize(t.bob.id, "prod"));
    assert.throws(() => v.materialize(t.bob.id, "default"));

    // And `hush verify` does not call a scoped member orphaned: holding no vault
    // key is what scoped means.
    const verified = t.alice.run(["verify"]);
    assert.match(verified.out, /2 listed, 0 without a key wrap/, verified.out);
    t.cleanup();
  });

  test("full members, including ones added later, still read everything", () => {
    const t = signedTeam();
    t.alice.run(["team", "add", "bob", t.bob.key, "--sets", "dev"]);
    const carol = who("carol", () => t.root);
    t.alice.run(["team", "add", "carol", carol.key]);
    for (const env of ["dev", "prod", "default"]) {
      const r = carol.run(["run", "--use", env, "--", "true"]);
      assert.equal(r.code, 0, `${env}: ${r.out}`);
    }
    rmSync(carol.home, { recursive: true, force: true });
    t.cleanup();
  });

  test("taking one set away rotates only that set's key, and marks its values exposed", () => {
    const t = signedTeam();
    t.alice.run(["team", "add", "bob", t.bob.key, "--sets", "dev,prod"]);
    const before = t.data();
    const r = t.alice.run(["team", "rm", "bob", "--from", "prod"]);
    assert.equal(r.code, 0, r.out);
    const after = t.data();
    assert.equal(after.setKeys!.prod.generation, before.setKeys!.prod.generation + 1);
    assert.equal(after.setKeys!.dev.generation, before.setKeys!.dev.generation, "dev was rotated too");
    assert.equal(after.dek.generation, before.dek.generation, "the vault key was rotated for a set change");
    assert.deepEqual(after.envs.prod.PROD_KEY.exposed, ["bob"]);
    assert.notEqual(t.bob.run(["run", "--use", "prod", "--", "true"]).code, 0);
    assert.equal(t.bob.run(["run", "--use", "dev", "--", "true"]).code, 0);
    t.cleanup();
  });

  test("a run in a project that also uses sets a scoped member was not given skips them, and says so", () => {
    const t = signedTeam();
    t.alice.run(["team", "add", "bob", t.bob.key, "--sets", "dev"]);
    t.alice.run(["use", "dev"]);
    const r = t.bob.run(["run", "--", "sh", "-c", "echo $DEV_KEY"]);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /not yours to read, skipped: default/);
    t.cleanup();
  });
});

describe("F-3: CI identities", () => {
  test("created scoped, piped out as the key alone, and never an admin", () => {
    const t = signedTeam();
    const made = t.alice.run(["ci", "create", "github", "--sets", "dev"]);
    assert.equal(made.code, 0, made.out);
    const secret = made.stdout.trim();
    assert.match(secret, /^hush_sk_[A-Za-z0-9_-]+$/, "piped output was not the key alone:\n" + made.stdout);
    const d = t.data();
    const ci = Object.values(d.recipients).find((r) => r.name === "github")!;
    assert.equal(ci.ci, true);
    assert.deepEqual(ci.sets, ["dev"]);
    assert.equal(ci.role, "member");

    const env = { HUSH_IDENTITY: secret };
    const home = mkdtempSync(join(tmpdir(), "hush-v3-ci-"));
    const runAsCi = (args: string[]) => t.alice.run(args, { env: { ...env, HOME: home, HUSH_HOME: home } });
    assert.equal(runAsCi(["run", "--use", "dev", "--", "true"]).code, 0);
    assert.notEqual(runAsCi(["run", "--use", "prod", "--", "true"]).code, 0);
    const promote = runAsCi(["team", "add", "x", t.mallory.key]);
    assert.notEqual(promote.code, 0, "a CI identity changed the membership");
    assert.throws(() => Vault.fromData("x", d).addRecipient(generateIdentity(), "y", t.mallory.key, "admin", { ci: true, sets: ["dev"] }));
    rmSync(home, { recursive: true, force: true });
    t.cleanup();
  });

  test("in GitHub Actions, a CI identity has every injected line masked; a person's identity never prints them", () => {
    const t = signedTeam();
    t.alice.run(["add", "PEM=line-one-of-key\nline-two-of-key", "--to", "dev"]);
    const secret = t.alice.run(["ci", "create", "github", "--sets", "dev"]).stdout.trim();
    const home = mkdtempSync(join(tmpdir(), "hush-v3-gh-"));
    const ci = t.alice.run(["run", "--use", "dev", "--", "true"], {
      env: { HUSH_IDENTITY: secret, HOME: home, HUSH_HOME: home, GITHUB_ACTIONS: "true" },
    });
    assert.match(ci.stdout, /^::add-mask::line-one-of-key$/m);
    assert.match(ci.stdout, /^::add-mask::line-two-of-key$/m);
    assert.match(ci.stdout, /^::add-mask::sk_test_dev_value$/m);

    // An agent on Alice's machine setting GITHUB_ACTIONS itself gets nothing.
    const person = t.alice.run(["run", "--use", "dev", "--", "true"], { env: { GITHUB_ACTIONS: "true" } });
    assert.doesNotMatch(person.stdout, /add-mask|sk_test_dev_value|line-one/);
    rmSync(home, { recursive: true, force: true });
    t.cleanup();
  });
});
