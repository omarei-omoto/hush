/**
 * Names that are properties of every JavaScript object — `__proto__`,
 * `constructor`, `prototype` — never become set or key names, and a
 * `__proto__` key in a file or message hush did not write is refused before
 * anything copies it. Found by CodeQL's first run (docs/AUDIT.md, fifteenth pass).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

