/**
 * Properties nothing was checking.
 *
 * Every test here exists because the code was deliberately broken in a way that
 * mattered and the whole suite still passed. A passing suite is not evidence
 * that a property holds; it is only evidence that something would notice if it
 * stopped holding, and that is a claim you have to test by breaking the code.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync, readdirSync } from "node:fs";
import { tmpdir, platform } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

import { generateIdentity, decodeSecret, newDek, wrapDek, unwrapDek, encodeSecret, encodePub, SK_PREFIX } from "../src/crypto.ts";
import { Vault, resolveVaultPath, slugifyEnv, assertScopeName } from "../src/vault.ts";
import { requestApproval, clearApprovalCache, type ApprovalDeps } from "../src/approval.ts";
import { parseScope, scopeOf } from "../src/services.ts";
import { scanRepo } from "../src/scan.ts";
import { checkAndRecord } from "../src/integrity.ts";
import { createIdentity } from "../src/identity.ts";
import { ensureHelper } from "../src/biometry.ts";
import { maybeNudge } from "../src/secure.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const scratch = () => mkdtempSync(join(tmpdir(), "hush-inv-"));
const b64 = (s: string) => Buffer.from(s, "base64");

describe("crypto: nonce and length discipline", () => {
  test("wrapping the same key for the same recipient twice reuses nothing", () => {
    // Each wrap derives a fresh KEK from a fresh ephemeral, so a repeated IV is
    // not immediately fatal — but "not immediately fatal" is exactly the kind of
    // reasoning that stops holding after a refactor. The IV and the ephemeral
    // public key are both required to be fresh, so both are asserted.
    const dek = newDek();
    const me = generateIdentity();
    const seen = { epk: new Set<string>(), iv: new Set<string>(), ct: new Set<string>() };

    for (let i = 0; i < 64; i++) {
      const w = wrapDek(dek, me.pub);
      seen.epk.add(w.epk);
      seen.iv.add(w.iv);
      seen.ct.add(w.ct);
      assert.deepEqual(unwrapDek(w, me), dek, "every wrap still opens to the same key");
    }
    assert.equal(seen.epk.size, 64, "an ephemeral public key was reused");
    assert.equal(seen.iv.size, 64, "a wrap IV was reused");
    assert.equal(seen.ct.size, 64, "two wraps of one key produced identical ciphertext");
    assert.equal(b64(([...seen.iv][0])).length, 12, "the IV is not 96 bits");
  });

  test("a secret key of the wrong length is refused, not truncated", () => {
    const id = generateIdentity();
    const good = encodeSecret(id);
    const raw = Buffer.from(good.slice(SK_PREFIX.length), "base64url");
    assert.equal(raw.length, 64);

    for (const n of [0, 1, 31, 32, 33, 63, 65, 128]) {
      const truncated = Buffer.concat([raw, Buffer.alloc(Math.max(0, n - raw.length))]).subarray(0, n);
      const encoded = SK_PREFIX + truncated.toString("base64url");
      assert.throws(
        () => decodeSecret(encoded),
        /64 bytes/,
        `a ${n}-byte secret key was accepted`,
      );
    }
    // The real one still works, so the check is not simply refusing everything.
    assert.deepEqual(decodeSecret(good).pub, id.pub);
  });
});

describe("scopes", () => {
  test("a scope with no service is not a scope", () => {
    assert.equal(parseScope("/personal"), null, '"/personal" has an empty service');
    assert.equal(parseScope("fal"), null, "no separator at all");
    assert.equal(parseScope(""), null);
    assert.deepEqual(parseScope("fal/acme"), { service: "fal", account: "acme" });
    // An account may itself contain the separator; the split is at the first one.
    assert.deepEqual(parseScope("aws/team/prod"), { service: "aws", account: "team/prod" });
    assert.equal(scopeOf("fal", "acme"), "fal/acme");
  });
});

describe("repo scan", () => {
  test("shell-style ${VAR} counts only in files that are shell-shaped", () => {
    const dir = scratch();
    try {
      // A template literal in TypeScript is not a variable reference. Trusting
      // the shell pattern everywhere turns every `${foo}` in the codebase into a
      // "missing secret", which is how a provisioning prompt becomes unusable.
      writeFileSync(join(dir, "app.ts"), "const url = `${NOT_A_SECRET}/path`;\nprocess.env.REAL_ONE;\n");
      writeFileSync(join(dir, "deploy.sh"), 'curl -H "Bearer ${DEPLOY_TOKEN}" $URL\n');

      const names = scanRepo(dir).map((u) => u.name);
      assert.ok(names.includes("REAL_ONE"), "an explicit process.env read was missed");
      assert.ok(names.includes("DEPLOY_TOKEN"), "a shell variable in a .sh file was missed");
      assert.ok(!names.includes("NOT_A_SECRET"), "a TypeScript template literal was read as a variable");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("approval", () => {
  const base = { action: "run", summary: "Run: deploy.sh", scope: "run:prod", timeoutMs: 400 };
  const bio = (result: "ok" | "denied" | "unavailable"): ApprovalDeps => ({
    authenticate: () => Promise.resolve(result),
  });

  test("a session grant that has lapsed is not honoured", async () => {
    process.env.HUSH_APPROVAL_MODE = "file";
    clearApprovalCache();
    const dir = scratch();
    try {
      // A zero-second TTL is expired the instant it is granted.
      const first = await requestApproval(dir, { ...base, ttlSeconds: 0, biometry: "preferred" }, bio("ok"));
      assert.equal(first.decision, "session");
      assert.equal(first.via, "biometry");

      await new Promise((r) => setTimeout(r, 5));

      // Nothing answers this one, so it can only end in "timeout" — unless the
      // expired grant was served from the cache, which is the bug.
      const second = await requestApproval(dir, { ...base, ttlSeconds: 0 }, bio("unavailable"));
      assert.equal(second.cached, false, "an expired grant was served from the cache");
      assert.equal(second.decision, "timeout");

      // A live grant, by contrast, is reused.
      clearApprovalCache();
      const live = await requestApproval(dir, { ...base, ttlSeconds: 900, biometry: "preferred" }, bio("ok"));
      assert.equal(live.decision, "session");
      const reused = await requestApproval(dir, { ...base, ttlSeconds: 900 }, bio("unavailable"));
      assert.equal(reused.cached, true, "a live grant was not reused");
    } finally {
      rmSync(dir, { recursive: true, force: true });
      delete process.env.HUSH_APPROVAL_MODE;
    }
  });

  test("a fingerprint that says no is final — there is no second chance at a dialog", async () => {
    process.env.HUSH_APPROVAL_MODE = "file";
    clearApprovalCache();
    const dir = scratch();
    try {
      for (const mode of ["preferred", "required"] as const) {
        clearApprovalCache();
        const r = await requestApproval(
          dir,
          { ...base, ttlSeconds: 900, biometry: mode },
          bio("denied"),
        );
        assert.equal(r.decision, "deny", `${mode}: a denial did not deny`);
        assert.equal(r.via, "biometry", `${mode}: the denial was attributed to the wrong prompt`);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
      delete process.env.HUSH_APPROVAL_MODE;
    }
  });

  test("a fingerprint that says yes grants without ever opening a dialog", async () => {
    // The machine running this has no enrolled finger, so the only way to cover
    // the success path at all is to inject the prompt.
    process.env.HUSH_APPROVAL_MODE = "file";
    clearApprovalCache();
    const dir = scratch();
    try {
      const r = await requestApproval(dir, { ...base, ttlSeconds: 900, biometry: "required" }, bio("ok"));
      assert.equal(r.decision, "session");
      assert.equal(r.via, "biometry");
      assert.equal(r.cached, false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      delete process.env.HUSH_APPROVAL_MODE;
    }
  });
});

describe("re-seal completeness", () => {
  test("every value carries the current key generation, and a straggler is reported", () => {
    const dir = scratch();
    try {
      const me = generateIdentity();
      const path = join(dir, "vault.json");
      const v = Vault.create(path, "inv", { name: "me", pub: me.pub });
      v.set(me, "default", "A", "one");
      v.set(me, "default", "B", "two");
      v.save();

      assert.deepEqual(v.staleValues(), [], "a fresh vault has no stragglers");

      const other = generateIdentity();
      v.addRecipient(me, "them", encodePub(other.pub));
      v.save();
      v.removeRecipient(me, "them");
      v.save();
      assert.deepEqual(v.staleValues(), [], "revocation left a value on the old key");
      assert.equal(v.data.dek.generation, 2);

      // Hand-edit one value back to the old generation: the shape a bad merge or
      // an interrupted rotation leaves behind.
      const raw = JSON.parse(readFileSync(path, "utf8"));
      raw.envs.default.B.gen = 1;
      writeFileSync(path, JSON.stringify(raw, null, 2));

      const reloaded = Vault.open(path);
      assert.deepEqual(reloaded.staleValues(), [{ env: "default", key: "B", gen: 1 }]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("hush verify fails on a vault whose re-seal did not finish", () => {
    const home = scratch();
    const proj = scratch();
    try {
      const me = generateIdentity();
      const env = {
        ...process.env,
        HUSH_HOME: home,
        HUSH_IDENTITY: encodeSecret(me),
        HUSH_NO_NUDGE: "1",
        HUSH_NO_KEYCHAIN: "1",
        NO_COLOR: "1",
      };
      const hush = (...args: string[]) =>
        spawnSync(process.execPath, [join(root, "src/cli.ts"), ...args], {
          cwd: proj, env, encoding: "utf8",
        });

      const init = hush("init", "inv");
      assert.equal(init.status, 0, init.stdout + init.stderr);
      const set = hush("set", "A=one");
      assert.equal(set.status, 0, set.stdout + set.stderr);
      // Rotate so there is a *valid* older generation to fall behind to. Zero is
      // not one: `Vault.open` refuses a generation below 1 outright, so writing
      // 0 here would test the load-time shape check rather than the re-seal one.
      const rotate = hush("rotate", "--yes");
      assert.equal(rotate.status, 0, rotate.stdout + rotate.stderr);

      const clean = hush("verify");
      assert.equal(clean.status, 0, clean.stdout + clean.stderr);
      assert.match(clean.stdout + clean.stderr, /re-seal/);

      const path = join(proj, ".hush", "vault.json");
      const raw = JSON.parse(readFileSync(path, "utf8"));
      assert.equal(raw.dek.generation, 2, "rotate did not advance the generation");
      raw.envs.default.A.gen = 1;
      writeFileSync(path, JSON.stringify(raw, null, 2));

      const dirty = hush("verify");
      assert.equal(dirty.status, 1, "a straggler did not fail the command");
      assert.match(dirty.stdout + dirty.stderr, /older key/);
      assert.match(dirty.stdout + dirty.stderr, /default\/A/);
    } finally {
      for (const d of [home, proj]) rmSync(d, { recursive: true, force: true });
    }
  });
});

describe("rollback watermark", () => {
  test("a roster that changes without growing still advances the mark", () => {
    const home = scratch();
    const dir = scratch();
    const saved = process.env.HUSH_HOME;
    process.env.HUSH_HOME = home;
    try {
      const me = generateIdentity();
      const a = generateIdentity();
      const path = join(dir, "vault.json");
      const v = Vault.create(path, "roster", { name: "me", pub: me.pub });
      v.addRecipient(me, "alice", encodePub(a.pub));
      assert.equal(checkAndRecord(v), null, "first sight is trust-on-first-use");

      const seenPath = join(home, "seen", `${v.data.id.replace(/[^A-Za-z0-9_-]/g, "_")}.json`);
      const readSeen = () => JSON.parse(readFileSync(seenPath, "utf8")) as { members: string[]; generation: number };
      assert.deepEqual(readSeen().members, ["alice", "me"]);

      // The isolating case: the roster changes but neither its length nor the
      // key generation does. Going through removeRecipient would re-seal and
      // bump the generation, and the mark would then advance for that reason
      // instead — proving nothing about the member comparison.
      const fp = Object.keys(v.data.recipients).find((f) => v.data.recipients[f].name === "alice")!;
      const before = v.data.dek.generation;
      v.data.recipients[fp] = { ...v.data.recipients[fp], name: "mallory" };

      assert.equal(checkAndRecord(v), null);
      assert.equal(v.data.dek.generation, before, "the generation moved, so this tests the wrong thing");

      const seen = readSeen();
      assert.deepEqual(seen.members, ["mallory", "me"], "the recorded roster is stale");
      assert.equal(seen.generation, before);
    } finally {
      if (saved === undefined) delete process.env.HUSH_HOME;
      else process.env.HUSH_HOME = saved;
      for (const d of [home, dir]) rmSync(d, { recursive: true, force: true });
    }
  });
});

describe("the vault file is untrusted input", () => {
  // It arrives over git — from a teammate, or from whoever opened the pull
  // request. `Vault.open` used to check the scheme string and take every other
  // field on faith.
  const build = (mutate: (v: any) => void): string => {
    const dir = scratch();
    try {
      const me = generateIdentity();
      const path = join(dir, "vault.json");
      const v = Vault.create(path, "hostile", { name: "me", pub: me.pub });
      v.set(me, "default", "GOOD_KEY", "good_value_1234567890");
      v.save();
      const raw = JSON.parse(readFileSync(path, "utf8"));
      mutate(raw);
      const out = join(scratch(), "vault.json");
      writeFileSync(out, JSON.stringify(raw, null, 2));
      return out;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };

  test("a key generation that is not a positive whole number is refused", () => {
    for (const [label, gen] of [
      ["a string", "lots"],
      ["negative", -1],
      ["zero", 0],
      ["fractional", 1.5],
      ["null", null],
      // Decrypts perfectly and poisons the rollback watermark for good: every
      // genuine vault afterwards reads as rolled back, so the warning that is
      // meant to matter fires constantly and `hush verify` never passes again.
      ["absurdly large", Number.MAX_SAFE_INTEGER],
    ] as const) {
      const path = build((v) => { v.dek.generation = gen; });
      assert.throws(() => Vault.open(path), /malformed/i, `a ${label} key generation was accepted`);
    }
  });

  test("a value recording a nonsense generation is refused", () => {
    // The same hole one level down: it would defeat the re-seal check the way a
    // bad data-key generation defeats rollback detection.
    for (const gen of ["soon", -3, 0, null]) {
      const path = build((v) => { v.envs.default.GOOD_KEY.gen = gen; });
      assert.throws(() => Vault.open(path), /malformed/i, `gen ${JSON.stringify(gen)} was accepted`);
    }
  });

  test("a member whose public key is neither a hush key nor an age recipient is refused", () => {
    // Caught on load rather than part-way through a later revocation, which is
    // the worst moment to discover the file was malformed all along.
    for (const pk of ["../../../etc/passwd", "", "hush_pk_not-base64!!", "age1short"]) {
      const path = build((v) => { v.recipients[Object.keys(v.recipients)[0]].pk = pk; });
      assert.throws(() => Vault.open(path), /malformed/i, `pk ${JSON.stringify(pk)} was accepted`);
    }
  });

  test("structurally broken files are refused rather than half-read", () => {
    for (const [label, mutate] of [
      ["no data key", (v: any) => { delete v.dek; }],
      ["no wraps", (v: any) => { v.dek.wraps = "nope"; }],
      ["members are an array", (v: any) => { v.recipients = []; }],
      ["envs are an array", (v: any) => { v.envs = []; }],
      ["an environment is a string", (v: any) => { v.envs.default = "nope"; }],
      ["a value is a string", (v: any) => { v.envs.default.GOOD_KEY = "plaintext!"; }],
      ["a value has no tag", (v: any) => { delete v.envs.default.GOOD_KEY.tag; }],
    ] as const) {
      assert.throws(() => Vault.open(build(mutate)), /malformed/i, `${label} was accepted`);
    }
  });

  test("a valid vault still opens, and a newer one with extra fields does too", () => {
    // A shape check, not a schema: refusing unknown fields would mean a vault
    // written by a newer hush could not be read by an older one at all.
    assert.doesNotThrow(() => Vault.open(build(() => {})));
    assert.doesNotThrow(() =>
      Vault.open(build((v) => {
        v.somethingFromTheFuture = { a: 1 };
        v.envs.default.GOOD_KEY.futureField = "x";
        v.recipients[Object.keys(v.recipients)[0]].futureField = "x";
      })),
    );
  });
});

describe("strings out of the vault file are never rendered raw", () => {
  test("a control sequence in a note or a member name cannot reach the terminal", () => {
    const dir = scratch();
    try {
      const me = generateIdentity();
      const path = join(dir, "vault.json");
      const v = Vault.create(path, "esc", { name: "me", pub: me.pub });
      v.set(me, "default", "K", "value-here-long-enough");
      v.save();

      // An escape sequence is interpreted by the terminal rather than shown by
      // it, so it can erase the lines above and rewrite what a reviewer thinks
      // they are looking at.
      const raw = JSON.parse(readFileSync(path, "utf8"));
      const nasty = "\u001b[2J\u001b[1;1Hall clear";
      raw.envs.default.K.note = nasty;
      raw.envs.default.K.updatedBy = nasty;
      raw.recipients[Object.keys(raw.recipients)[0]].name = nasty;
      writeFileSync(path, JSON.stringify(raw, null, 2));

      const reopened = Vault.open(path);
      // The strings themselves, not JSON.stringify of them: JSON escapes every
      // control character as \u001b, so a regex over the encoded form can never
      // see one and passes just as happily with the sanitiser removed.
      const entry = reopened.list("default")[0];
      const strings = [entry.note ?? "", entry.updatedBy, ...reopened.members().map((m) => m.name)];
      const control = new RegExp("[\u0000-\u001f\u007f-\u009f]");
      for (const str of strings) {
        assert.ok(!control.test(str), `a control character survived in ${JSON.stringify(str)}`);
      }
      assert.ok(strings.every((x) => x.includes("all clear")), "the printable text was thrown away too");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a note far longer than the write-time cap is truncated on the way out", () => {
    // A five-megabyte note rendered by `hush ls` killed the process.
    const dir = scratch();
    try {
      const me = generateIdentity();
      const path = join(dir, "vault.json");
      const v = Vault.create(path, "big", { name: "me", pub: me.pub });
      v.set(me, "default", "K", "value-here-long-enough");
      v.save();
      const raw = JSON.parse(readFileSync(path, "utf8"));
      raw.envs.default.K.note = "x".repeat(5_000_000);
      writeFileSync(path, JSON.stringify(raw, null, 2));

      const note = Vault.open(path).list("default")[0].note ?? "";
      assert.ok(note.length <= 256, `a ${note.length}-character note was handed to the renderer`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("a data-key wrap with no member behind it", () => {
  test("is reported, because it decrypts everything while team ls shows nobody", () => {
    const dir = scratch();
    try {
      const me = generateIdentity();
      const ghost = generateIdentity();
      const path = join(dir, "vault.json");
      const v = Vault.create(path, "ghost", { name: "me", pub: me.pub });
      v.set(me, "default", "K", "value-here-long-enough");
      v.addRecipient(me, "ghost", encodePub(ghost.pub));
      v.save();
      assert.deepEqual(v.unlistedWraps(), [], "a normal vault has none");

      // Drop the roster entry but leave the wrap: the shape a revoked member
      // would leave behind to keep quiet access.
      const raw = JSON.parse(readFileSync(path, "utf8"));
      const ghostFp = Object.keys(raw.recipients).find((fp) => raw.recipients[fp].name === "ghost")!;
      delete raw.recipients[ghostFp];
      writeFileSync(path, JSON.stringify(raw, null, 2));

      const reopened = Vault.open(path);
      assert.deepEqual(reopened.unlistedWraps(), [ghostFp]);
      assert.ok(!reopened.members().some((m) => m.name === "ghost"), "team ls would have shown them");
      // And they really can still read it — which is why it has to be reported.
      assert.equal(reopened.get(ghost, "default", "K"), "value-here-long-enough");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("the merge path validates too", () => {
  test("a malformed vault landing mid-save is refused, not laundered back out", () => {
    // saveLocked() is the one place that adopts an on-disk vault without going
    // through open(), and it adopts it wholesale — so a malformed file arriving
    // here would replace the in-memory copy and be written straight back.
    const dir = scratch();
    try {
      const me = generateIdentity();
      const path = join(dir, "vault.json");
      const v = Vault.create(path, "merge", { name: "me", pub: me.pub });
      v.set(me, "default", "MINE", "mine-value-long-enough");
      v.save();

      const mine = Vault.open(path);
      mine.set(me, "default", "LATER", "later-value-long-enough");

      // Someone else writes something malformed while we were thinking.
      const raw = JSON.parse(readFileSync(path, "utf8"));
      raw.dek.generation = "lots";
      writeFileSync(path, JSON.stringify(raw, null, 2));

      assert.throws(() => mine.save(), /malformed/i, "a malformed vault was merged into");
      // And it was not rewritten: what is on disk is still what the other
      // writer left, rather than our copy of it.
      assert.equal(JSON.parse(readFileSync(path, "utf8")).dek.generation, "lots");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("link.json arrives over git, so it is untrusted too", () => {
  // `.hush/link.json` is documented as safe to commit, which is the same thing
  // as saying it comes from whoever wrote the repository you cloned.
  const rig = (link: unknown) => {
    const home = mkdtempSync(join(tmpdir(), "hush-link-home-"));
    const proj = mkdtempSync(join(tmpdir(), "hush-link-proj-"));
    mkdirSync(join(proj, ".hush"), { recursive: true });
    writeFileSync(join(proj, ".hush", "link.json"), JSON.stringify(link));
    const saved = process.env.HUSH_HOME;
    process.env.HUSH_HOME = home;
    return {
      home,
      proj,
      done: () => {
        if (saved === undefined) delete process.env.HUSH_HOME;
        else process.env.HUSH_HOME = saved;
        for (const d of [home, proj]) rmSync(d, { recursive: true, force: true });
      },
    };
  };

  test("a relative vault name cannot walk out of ~/.hush/vaults", () => {
    // The name is joined onto ~/.hush/vaults, so traversal reaches anything the
    // user can read — an ssh key, for instance.
    for (const name of ["../../.ssh/id_ed25519", "..", "../vaults", "a/b", "./x", "..\\..\\x"]) {
      const r = rig({ vault: name, env: "default" });
      try {
        assert.throws(
          () => resolveVaultPath(r.proj),
          /not a vault name|do not trust it/,
          `accepted ${JSON.stringify(name)} as a vault name`,
        );
      } finally {
        r.done();
      }
    }
  });

  test("an ordinary vault name still resolves", () => {
    const r = rig({ vault: "personal", env: "default" });
    try {
      const target = join(r.home, "vaults", "personal", "vault.json");
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, "{}");
      assert.equal(resolveVaultPath(r.proj)?.vaultPath, target);
    } finally {
      r.done();
    }
  });

  test("a link pointing at a device or a directory is refused, not read", () => {
    // `{"vault":"/dev/zero"}` in a cloned repo would otherwise make every hush
    // command read for ever.
    for (const target of ["/dev/zero", "/dev/null", "/etc"]) {
      if (!existsSync(target)) continue;
      const r = rig({ vault: target, env: "default" });
      try {
        assert.throws(() => resolveVaultPath(r.proj), /not a vault file|No vault at/, `read ${target}`);
      } finally {
        r.done();
      }
    }
  });

  test("a parse failure never quotes the file it failed on", () => {
    // V8 puts an excerpt in the message: `Unexpected token 'r', "root:x:0:0:…"
    // is not valid JSON`. Combined with a link naming someone else's file, that
    // prints its first bytes to the terminal — and into an agent's context.
    const dir = mkdtempSync(join(tmpdir(), "hush-leak-"));
    try {
      const secretish = join(dir, "vault.json");
      writeFileSync(secretish, "root:x:0:0:SENSITIVE-CONTENT-HERE:/root:/bin/sh\n");
      let message = "";
      try {
        Vault.open(secretish);
      } catch (e) {
        message = (e as Error).message;
      }
      assert.notEqual(message, "", "opening a non-vault did not fail");
      assert.ok(
        !message.includes("SENSITIVE-CONTENT-HERE"),
        `the error quoted the file's contents:\n${message}`,
      );
      assert.ok(!message.includes("root:x:0:0"), `the error quoted the file's contents:\n${message}`);
      assert.match(message, /not valid JSON/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("an absolute link outside ~/.hush is announced rather than followed silently", () => {
    const r = rig({ vault: "/tmp/somewhere-else/vault.json", env: "default" });
    const written: string[] = [];
    const realWrite = process.stderr.write.bind(process.stderr);
    (process.stderr as unknown as { write: (s: string) => boolean }).write = (s: string) => {
      written.push(s);
      return true;
    };
    try {
      try { resolveVaultPath(r.proj); } catch { /* the file does not exist; the notice is the point */ }
      assert.ok(
        written.join("").includes("points outside ~/.hush"),
        `no notice was printed for an absolute link: ${JSON.stringify(written)}`,
      );
    } finally {
      (process.stderr as unknown as { write: typeof realWrite }).write = realWrite;
      r.done();
    }
  });
});

describe("a structural change refuses to merge rather than guessing", () => {
  test("adding a member while someone else writes is refused, not blended", () => {
    // Value edits replay onto the newer copy. Membership and rotation cannot:
    // blending them produces a vault with one branch's data key and the other's
    // recipient list, which is valid JSON that nobody can open.
    const dir = mkdtempSync(join(tmpdir(), "hush-struct-"));
    try {
      const me = generateIdentity();
      const other = generateIdentity();
      const path = join(dir, "vault.json");
      const v = Vault.create(path, "struct", { name: "me", pub: me.pub });
      v.set(me, "default", "SEED", "seed-value-long-enough");
      v.save();

      const mine = Vault.open(path);
      const theirs = Vault.open(path);

      // A structural change, with an identity and a journal — so the refusal
      // cannot be coming from the "no opener" arm.
      mine.addRecipient(me, "colleague", encodePub(other.pub));
      mine.set(me, "default", "ALSO", "also-value-long-enough");

      theirs.set(me, "default", "THEIRS", "theirs-value-long-enough");
      theirs.save();

      assert.throws(() => mine.save(), /cannot be merged automatically|Re-run/);

      // Their write survived intact and ours landed nowhere.
      const fresh = Vault.open(path);
      assert.equal(fresh.get(me, "default", "THEIRS"), "theirs-value-long-enough");
      assert.equal(fresh.has("default", "ALSO"), false, "half of the refused change was written");
      assert.ok(!fresh.members().some((m) => m.name === "colleague"), "a member was added by a refused save");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a failed write leaves no temporary file behind", () => {
    // The temp file holds the whole vault. Leaving one on every failed save
    // litters the repo with copies that are not covered by .gitignore's
    // vault.json entry and are easy to commit by accident.
    const dir = mkdtempSync(join(tmpdir(), "hush-tmpfile-"));
    try {
      const me = generateIdentity();
      const path = join(dir, "vault.json");
      const v = Vault.create(path, "tmp", { name: "me", pub: me.pub });
      v.set(me, "default", "SEED", "seed-value-long-enough");
      v.save();

      // Make the rename fail while the temp file has already been written: a
      // directory at the destination cannot be replaced by a file.
      const reopened = Vault.open(path);
      reopened.set(me, "default", "MORE", "more-value-long-enough");
      rmSync(path);
      mkdirSync(path);
      assert.throws(() => reopened.save());
      rmSync(path, { recursive: true });

      const strays = readdirSync(dir).filter((n) => n.includes(".tmp"));
      assert.deepEqual(strays, [], `a temporary vault copy was left behind: ${strays.join(", ")}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("the private key never appears in an argument list", () => {
  test("hush hands it to `security` on stdin, where the process table cannot see it", {
    skip: platform() === "darwin" ? false : "macOS keychain only",
  }, () => {
    // Arguments are world-readable through ps(1) for the life of the call. A
    // fake `security` on PATH records its own argv, which is the only way to
    // check this without writing to the real keychain.
    const dir = mkdtempSync(join(tmpdir(), "hush-sec-"));
    const saved = { path: process.env.PATH, home: process.env.HUSH_HOME, no: process.env.HUSH_NO_KEYCHAIN };
    try {
      const log = join(dir, "argv.log");
      writeFileSync(
        join(dir, "security"),
        `#!/bin/sh\nprintf '%s\\n' "$@" >> ${log}\ncat > ${join(dir, "stdin.log")}\nexit 0\n`,
        { mode: 0o755 },
      );
      process.env.PATH = dir + ":" + (saved.path ?? "");
      process.env.HUSH_HOME = dir;
      delete process.env.HUSH_NO_KEYCHAIN;

      const id = createIdentity("argvtest", true);
      const secret = encodeSecret({ pub: id.pub!, priv: id.priv! });

      const argv = existsSync(log) ? readFileSync(log, "utf8") : "";
      assert.notEqual(argv, "", "the fake security was never called");
      assert.ok(!argv.includes(secret), "the private key was passed as a command-line argument");
      assert.ok(!argv.includes(secret.slice(0, 24)), "part of the private key was passed as an argument");
      // It really did go somewhere — stdin.
      const viaStdin = readFileSync(join(dir, "stdin.log"), "utf8");
      assert.equal(viaStdin.trim(), secret, "the key did not reach security on stdin");
    } finally {
      for (const [k, v] of [["PATH", saved.path], ["HUSH_HOME", saved.home], ["HUSH_NO_KEYCHAIN", saved.no]] as const) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("biometry: the platform gate", () => {
  test("everywhere but macOS, gating reports itself unavailable rather than trying", () => {
    // Removing this check is invisible on a mac — which is the only machine
    // this is developed on — and turns every Linux install into a swiftc error
    // in the middle of an approval.
    for (const plat of ["linux", "win32", "freebsd", "android"]) {
      const r = ensureHelper(plat);
      assert.equal(r.ok, false, `${plat}: tried to compile a macOS helper`);
      assert.match(r.reason ?? "", /macOS-only/, `${plat}: refused for the wrong reason`);
    }
    // And on macOS it does not refuse for that reason, so the check is not
    // simply refusing everything.
    const saved = process.env.HUSH_BIOMETRY;
    process.env.HUSH_BIOMETRY = "off";
    try {
      assert.match(ensureHelper("darwin").reason ?? "", /HUSH_BIOMETRY=off/);
    } finally {
      if (saved === undefined) delete process.env.HUSH_BIOMETRY;
      else process.env.HUSH_BIOMETRY = saved;
    }
  });
});

describe("a nudge never takes a command with it", () => {
  test("maybeNudge swallows anything the posture check throws", () => {
    // Nudging is decoration: a hint about the security ladder. Whatever goes
    // wrong working out what to suggest, `hush ls` still has to list secrets.
    // The guard is defensive by nature, so the only way to show it works is to
    // make the thing it guards actually throw.
    const dir = mkdtempSync(join(tmpdir(), "hush-nudge-throw-"));
    try {
      const exploding = {
        get data(): never { throw new Error("boom"); },
        members(): never { throw new Error("boom"); },
        envNames(): never { throw new Error("boom"); },
        list(): never { throw new Error("boom"); },
      } as unknown as Vault;

      assert.doesNotThrow(() => maybeNudge(exploding, dir, dir), "a broken posture broke the command");
      assert.doesNotThrow(() => maybeNudge(null, dir, dir));
      assert.doesNotThrow(() => maybeNudge(exploding, null, null));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("named env sets", () => {
  const rig = () => {
    const dir = mkdtempSync(join(tmpdir(), "hush-named-"));
    const owner = generateIdentity();
    const v = Vault.create(join(dir, "v.json"), "named", { name: "me", pub: owner.pub });
    v.set(owner, "default", "STRIPE_SECRET_KEY", "sk_live_value_1234567890");
    v.set(owner, "default", "FAL_KEY", "fal_value_abcdefghij");
    v.save();
    return { dir, path: join(dir, "v.json"), owner, v };
  };

  test("a name becomes a slug you can actually use on the command line", () => {
    for (const [typed, expected] of [
      ["Acme Production", "acme-production"],
      ["  Personal / fal  ", "personal-fal"],
      ["CLIENT client (staging)", "client-client-staging"],
      ["Café Ünïcode", "cafe-unicode"],
      ["prod", "prod"],
      ["a".repeat(80), "a".repeat(48)],
    ] as const) {
      const slug = slugifyEnv(typed);
      assert.equal(slug, expected, `"${typed}" slugged to "${slug}"`);
      // Whatever comes out has to be a name the rest of hush accepts.
      assert.doesNotThrow(() => assertScopeName(slug), `"${slug}" is not a usable scope name`);
    }
    // Names that slug to nothing still produce something usable rather than throwing.
    for (const awkward of ["...", "!!!", "   ", "—"]) {
      const slug = slugifyEnv(awkward);
      assert.doesNotThrow(() => assertScopeName(slug), `"${awkward}" gave an unusable "${slug}"`);
    }
    assert.notEqual(slugifyEnv("..."), slugifyEnv("!!!"), "two different names collided");
  });

  test("a set carries a name, a description and a note about when to use it", () => {
    const { dir, v, owner } = rig();
    try {
      v.describeEnv("default", {
        label: "Acme Production",
        description: "Live Stripe + Convex",
        whenToUse: "deploys only",
      });
      v.save();

      const reopened = Vault.open(join(dir, "v.json"));
      const set = reopened.envSets().find((s) => s.name === "default")!;
      assert.equal(set.label, "Acme Production");
      assert.equal(set.description, "Live Stripe + Convex");
      assert.equal(set.whenToUse, "deploys only");
      assert.deepEqual(set.keys, ["FAL_KEY", "STRIPE_SECRET_KEY"]);

      // Metadata is plaintext beside the ciphertext, so describing needs no key.
      assert.doesNotThrow(() => reopened.describeEnv("default", { description: "changed" }));
      // And every field is optional: clearing one leaves the others.
      reopened.describeEnv("default", { description: "" });
      const after = reopened.envSets().find((s) => s.name === "default")!;
      assert.equal(after.description, undefined);
      assert.equal(after.whenToUse, "deploys only");
      assert.equal(after.label, "Acme Production");
      void owner;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("renaming a set re-seals every value under the new name", () => {
    const { dir, path, owner, v } = rig();
    try {
      v.describeEnv("default", { label: "Old Name" });
      v.save();

      const { moved } = v.renameEnv(owner, "default", "acme-production");
      v.describeEnv("acme-production", { label: "Acme Production" });
      v.save();
      assert.equal(moved, 2);

      const reopened = Vault.open(path);
      assert.equal(reopened.has("default", "STRIPE_SECRET_KEY"), false, "the old name still has the values");
      assert.equal(reopened.get(owner, "acme-production", "STRIPE_SECRET_KEY"), "sk_live_value_1234567890");
      assert.equal(reopened.envLabel("acme-production"), "Acme Production", "the description did not move");

      // Re-sealed, not copied: the name is part of each value's AAD, so a value
      // carried across verbatim would not open under the new name at all.
      const raw = JSON.parse(readFileSync(path, "utf8")) as any;
      assert.ok(raw.envs["acme-production"].STRIPE_SECRET_KEY, "the value is missing");
      assert.equal(raw.envs.default, undefined, "the old set is still in the file");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("renaming onto a name that already exists is refused", () => {
    const { dir, owner, v } = rig();
    try {
      v.ensureEnvExists("taken");
      assert.throws(() => v.renameEnv(owner, "default", "taken"), /already exists/);
      // And nothing moved.
      assert.equal(v.has("default", "STRIPE_SECRET_KEY"), true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a key can be moved between sets, and opens under its new name", () => {
    // The state everybody starts in is one pile under "default"; carving it up
    // is the whole point of naming sets.
    const { dir, path, owner, v } = rig();
    try {
      v.ensureEnvExists("acme-production");
      v.moveSecret(owner, "STRIPE_SECRET_KEY", "default", "acme-production");
      v.save();

      const reopened = Vault.open(path);
      assert.equal(reopened.has("default", "STRIPE_SECRET_KEY"), false, "it is still in the old set");
      assert.equal(
        reopened.get(owner, "acme-production", "STRIPE_SECRET_KEY"),
        "sk_live_value_1234567890",
        "it did not open under its new name",
      );
      // The one left behind is untouched.
      assert.equal(reopened.get(owner, "default", "FAL_KEY"), "fal_value_abcdefghij");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a move that would overwrite something is refused", () => {
    const { dir, owner, v } = rig();
    try {
      v.ensureEnvExists("other");
      v.set(owner, "other", "STRIPE_SECRET_KEY", "a_different_value_here");
      assert.throws(() => v.moveSecret(owner, "STRIPE_SECRET_KEY", "default", "other"), /already has/);
      assert.equal(v.get(owner, "other", "STRIPE_SECRET_KEY"), "a_different_value_here", "it was overwritten");
      assert.equal(v.get(owner, "default", "STRIPE_SECRET_KEY"), "sk_live_value_1234567890", "the source was lost");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a vault written before sets had names still opens", () => {
    // `meta` is optional on purpose: an older vault has none, and it should not
    // need converting to be read.
    const { dir, path, owner } = rig();
    try {
      const raw = JSON.parse(readFileSync(path, "utf8")) as any;
      delete raw.meta;
      writeFileSync(path, JSON.stringify(raw, null, 2));

      const reopened = Vault.open(path);
      assert.equal(reopened.get(owner, "default", "FAL_KEY"), "fal_value_abcdefghij");
      // With nothing said about it, a set is named after itself.
      assert.equal(reopened.envLabel("default"), "default");
      assert.deepEqual(reopened.envMeta("default"), {});
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
