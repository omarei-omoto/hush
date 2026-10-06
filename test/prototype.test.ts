/**
 * Names that are properties of every JavaScript object — `__proto__`,
 * `constructor`, `prototype` — never become set or key names, and a
 * `__proto__` key in a file or message hush did not write is refused before
 * anything copies it. Found by CodeQL's first run (docs/AUDIT.md, fifteenth pass).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { generateIdentity } from "../src/crypto.ts";
import { Vault, assertKeyName, assertScopeName, isValidKeyName } from "../src/vault.ts";
import { parseJson } from "../src/json.ts";
import { parseArgs } from "../src/cli/args.ts";

const RESERVED = ["__proto__", "constructor", "prototype"];

/** Fails the test if anything was written onto the prototype every object shares. */
function assertPrototypeClean(): void {
  assert.deepEqual(Object.keys(Object.prototype), []);
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
}

test("reserved names are refused as key names and as set names", () => {
  for (const name of RESERVED) {
    assert.throws(() => assertKeyName(name), /not a valid variable name/);
    assert.equal(isValidKeyName(name), false);
    assert.throws(() => assertScopeName(name), /not a valid environment/);
    assert.throws(() => assertScopeName(`stripe/${name}`), /not a valid environment/);
  }
  assert.doesNotThrow(() => assertKeyName("CONSTRUCTOR_URL"));
  assert.doesNotThrow(() => assertScopeName("prototype-api"));
});

test("storing a value under a reserved set or key name is refused, and nothing reaches Object.prototype", () => {
  const dir = mkdtempSync(join(tmpdir(), "hush-proto-"));
  try {
    const id = generateIdentity();
    const v = Vault.create(join(dir, "vault.json"), "t", { name: "me", pub: id.pub });
    for (const name of RESERVED) {
      assert.throws(() => v.set(id, name, "polluted", "a-long-enough-value"));
      assert.throws(() => v.set(id, "default", name, "a-long-enough-value"));
    }
    assertPrototypeClean();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a vault file arriving with a reserved name is refused when it is opened", () => {
  const dir = mkdtempSync(join(tmpdir(), "hush-proto-"));
  try {
    const id = generateIdentity();
    const path = join(dir, "vault.json");
    Vault.create(path, "t", { name: "me", pub: id.pub }).save();
    const good = readFileSync(path, "utf8");

    // A "__proto__" key anywhere in the file: refused by the parser.
    writeFileSync(path, good.replace('"envs": {', '"envs": {"__proto__": {"polluted": {}},'));
    assert.throws(() => Vault.open(path), /not valid JSON \(a … key is not allowed\)/);

    // "constructor" as a set name, and as a key name: refused by the shape check.
    const data = JSON.parse(good);
    data.envs.constructor = {};
    writeFileSync(path, JSON.stringify(data));
    assert.throws(() => Vault.open(path), /reserved/);
    data.envs = { default: { prototype: {} } };
    writeFileSync(path, JSON.stringify(data));
    assert.throws(() => Vault.open(path), /reserved/);
    assertPrototypeClean();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("parseJson refuses a __proto__ key at any depth and is JSON.parse otherwise", () => {
  assert.throws(() => parseJson('{"__proto__": {"polluted": true}}'), /__proto__/);
  assert.throws(() => parseJson('{"a": [{"b": {"__proto__": 1}}]}'), /__proto__/);
  assert.deepEqual(parseJson('{"constructor": "a string is fine here", "n": [1, 2]}'), { constructor: "a string is fine here", n: [1, 2] });
  assertPrototypeClean();
});

test("a --__proto__ flag is just a flag", () => {
  const a = parseArgs(["--__proto__", "x", "--__proto__", "y", "--polluted"]);
  assert.deepEqual(a.flags.__proto__, ["x", "y"]);
  assert.equal(a.flags.polluted, true);
  assertPrototypeClean();
});

test("a member fingerprint named after an Object property is refused when the vault is opened (review F18)", () => {
  const dir = mkdtempSync(join(tmpdir(), "hush-proto-"));
  try {
    const id = generateIdentity();
    const path = join(dir, "vault.json");
    Vault.create(path, "t", { name: "me", pub: id.pub }).save();
    const data = JSON.parse(readFileSync(path, "utf8"));
    const [[, me]] = Object.entries(data.recipients);
    for (const fp of ["constructor", "toString", "valueOf", "hasOwnProperty"]) {
      writeFileSync(path, JSON.stringify({ ...data, recipients: { ...data.recipients, [fp]: me } }));
      assert.throws(() => Vault.open(path), /fingerprint is not one hush writes/, fp);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});


test("folder patterns and exposure lists from a vault file meet the rules hush writes them by (review F26)", () => {
  const dir = mkdtempSync(join(tmpdir(), "hush-shape-"));
  try {
    const id = generateIdentity();
    const path = join(dir, "vault.json");
    const v = Vault.create(path, "t", { name: "me", pub: id.pub });
    v.set(id, "default", "K", "a-long-enough-value");
    v.save();
    const good = JSON.parse(readFileSync(path, "utf8"));
    const withMeta = (onlyIn: unknown) => ({ ...good, meta: { default: { onlyIn } } });
    for (const [label, data] of [
      ["an over-long pattern", withMeta(["/" + "**a".repeat(200) + "b"])],
      ["a relative pattern", withMeta(["code/*"])],
      ["a pattern that is not a string", withMeta([{}])],
      ["onlyIn that is not a list", withMeta("/x")],
      ["an exposure list of objects", { ...good, envs: { default: { K: { ...good.envs.default.K, exposed: [{ toString: 1 }] } } } }],
    ] as const) {
      writeFileSync(path, JSON.stringify(data));
      assert.throws(() => Vault.open(path), /malformed/, label);
    }
    writeFileSync(path, JSON.stringify(withMeta(["~/code/*"])));
    assert.doesNotThrow(() => Vault.open(path), "an ordinary pattern was refused");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a save refuses to write a vault it would refuse to open (review F29)", () => {
  const dir = mkdtempSync(join(tmpdir(), "hush-save-shape-"));
  try {
    const id = generateIdentity();
    const path = join(dir, "vault.json");
    const v = Vault.create(path, "t", { name: "me", pub: id.pub });
    v.save();
    const before = readFileSync(path, "utf8");
    const [fp] = Object.keys(v.data.recipients);
    (v.data.recipients[fp] as { name: unknown }).name = 123;
    assert.throws(() => v.save(), /malformed/);
    assert.equal(readFileSync(path, "utf8"), before, "the broken vault was written");
    assert.doesNotThrow(() => Vault.open(path));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an atomic write never goes through a link waiting at a temp name (review F10, F11)", async () => {
  const { writeFileAtomic } = await import("../src/vault-files.ts");
  const { symlinkSync, readdirSync } = await import("node:fs");
  const dir = mkdtempSync(join(tmpdir(), "hush-atomic-"));
  try {
    const target = join(dir, "victim");
    writeFileSync(target, "untouched");
    const path = join(dir, "config.json");
    writeFileSync(path, "old");
    // The names the old writers used: pid-based, so predictable.
    symlinkSync(target, `${path}.${process.pid}.tmp`);
    symlinkSync(target, `${path}.hush-${process.pid}.tmp`);
    writeFileAtomic(path, "new");
    assert.equal(readFileSync(path, "utf8"), "new");
    assert.equal(readFileSync(target, "utf8"), "untouched");
    assert.deepEqual(readdirSync(dir).filter((f) => f.endsWith(".tmp") && !f.includes(String(process.pid) + ".tmp") && !f.includes("hush-")), [], "a temp file was left behind");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("files hush appends to or creates in a repository are never reached through a committed link", async () => {
  const { symlinkSync, existsSync } = await import("node:fs");
  const { audit } = await import("../src/audit.ts");
  const { writeProjectDotfiles } = await import("../src/library.ts");
  const dir = mkdtempSync(join(tmpdir(), "hush-links-"));
  try {
    const hushDir = join(dir, ".hush");
    mkdirSync(hushDir);
    const outside = join(dir, "outside");
    mkdirSync(outside);
    // audit.log: a link to a file elsewhere stays untouched; hush's own log is not written through it.
    const victim = join(outside, "rc");
    writeFileSync(victim, "untouched\n");
    symlinkSync(victim, join(hushDir, "audit.log"));
    audit(hushDir, { actor: "test", action: "probe" });
    assert.equal(readFileSync(victim, "utf8"), "untouched\n", "the audit line went through the link");
    // .gitignore and .gitattributes: a dangling link's target is never created.
    symlinkSync(join(outside, "made-by-ignore"), join(hushDir, ".gitignore"));
    symlinkSync(join(outside, "made-by-attrs"), join(hushDir, ".gitattributes"));
    writeProjectDotfiles(hushDir);
    assert.ok(!existsSync(join(outside, "made-by-ignore")) && !existsSync(join(outside, "made-by-attrs")), "a dangling link's target was created");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
