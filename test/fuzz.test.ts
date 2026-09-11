/**
 * Property-based tests over randomised input.
 *
 * The examples elsewhere check cases someone thought of. These check invariants
 * over inputs nobody chose — which is how the chunk-boundary leak in the
 * redactor would have been caught deliberately, rather than by accident.
 *
 * The PRNG is seeded, so any failure is reproducible from the printed seed.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

import { Redactor } from "../src/redact.ts";
import { parseEnvFile } from "../src/scan.ts";
import { toEnvFile, toShellExports } from "../src/run.ts";
import { Vault } from "../src/vault.ts";
import { generateIdentity } from "../src/crypto.ts";

/**
 * How hard to push. The default keeps `npm test` quick; a deeper sweep is one
 * variable away, and reproducible — HUSH_FUZZ_SCALE multiplies both the number
 * of seeds and the rounds per seed, so `HUSH_FUZZ_SCALE=50 npm test` is the same
 * search, fifty times longer, and any failure still prints the seed that found
 * it. Hard-coding the counts meant "run it harder" was an edit, and an edit that
 * is not committed is a check that only ever happens once.
 */
const SCALE = Math.max(1, Number(process.env.HUSH_FUZZ_SCALE ?? 1) || 1);
const rounds = (base: number): number => base * SCALE;

/** `base` seeds, plus derived ones when the scale is turned up. */
const seeds = (base: number[]): number[] => {
  const out = [...base];
  for (let k = 1; k < SCALE; k++) for (const s of base) out.push((s * 2654435761 + k) >>> 0);
  return out;
};

/** xorshift32 — small, seeded, and good enough to shuffle bytes around. */
function rng(seed: number): () => number {
  let s = seed || 1;
  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >> 17;
    s ^= s << 5;
    s >>>= 0;
    return s / 0x100000000;
  };
}

/** Deliberately nasty: quotes, escapes, whitespace, newlines, multi-byte. */
const ALPHABET =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
  "_-./:@#$%^&*()[]{}|\\\"'`~+= " +
  "\t\n\r" +
  "é\u{1f510}";

const randomString = (r: () => number, len: number): string => {
  const chars = [...ALPHABET];
  let out = "";
  for (let i = 0; i < len; i++) out += chars[Math.floor(r() * chars.length)];
  return out;
};

describe("fuzz: the redactor never emits a secret", () => {
  for (const seed of seeds([1, 7, 42, 1337, 90210])) {
    test(`seed ${seed}: no secret survives any chunking`, () => {
      const r = rng(seed);

      for (let round = 0; round < rounds(60); round++) {
        const count = 1 + Math.floor(r() * 5);
        const secrets: Record<string, string> = {};
        for (let i = 0; i < count; i++) {
          secrets[`KEY_${i}`] = randomString(r, 6 + Math.floor(r() * 40));
        }
        const values = Object.values(secrets);

        // Output with the secrets embedded at random positions.
        let output = "";
        for (let i = 0; i < 12; i++) {
          output += randomString(r, Math.floor(r() * 30));
          if (r() < 0.7) output += values[Math.floor(r() * values.length)];
        }

        // Split into random chunks, some of length one.
        const chunks: string[] = [];
        let pos = 0;
        while (pos < output.length) {
          const size = Math.max(1, Math.floor(r() * 12));
          chunks.push(output.slice(pos, pos + size));
          pos += size;
        }

        const redactor = new Redactor(secrets);
        let emitted = "";
        for (const c of chunks) emitted += redactor.push(c);
        emitted += redactor.flush();

        for (const [name, value] of Object.entries(secrets)) {
          if (value.length < 5) continue; // below the masking threshold, by design
          assert.ok(
            !emitted.includes(value),
            `seed ${seed} round ${round}: leaked ${name} (${JSON.stringify(value.slice(0, 24))})`,
          );
        }
      }
    });
  }

  test("output containing no secret is passed through byte for byte", () => {
    const r = rng(31337);
    const redactor = new Redactor({ A: "zzzzzzzzzzzzzzzz" });
    for (let i = 0; i < rounds(200); i++) {
      const text = randomString(r, 1 + Math.floor(r() * 50)).replace(/z/g, "y");
      const out = redactor.push(text) + redactor.flush();
      assert.equal(out, text, "altered output that contained no secret");
    }
  });
});

describe("fuzz: env files round-trip", () => {
  for (const seed of seeds([3, 11, 808])) {
    test(`seed ${seed}: any value survives export and import`, () => {
      const r = rng(seed);
      for (let i = 0; i < rounds(300); i++) {
        const value = randomString(r, Math.floor(r() * 60));
        const back = parseEnvFile(toEnvFile({ K: value })).K;
        assert.equal(back, value, `value did not survive: ${JSON.stringify(value)}`);
      }
    });
  }

  test("arbitrary junk never crashes the parser", () => {
    const r = rng(5150);
    for (let i = 0; i < rounds(500); i++) {
      assert.doesNotThrow(() => parseEnvFile(randomString(r, Math.floor(r() * 200))));
    }
  });
});

describe("fuzz: the vault survives random operation sequences", () => {
  test("set/get/delete stay consistent with a plain model", () => {
    const r = rng(2024);
    const dir = mkdtempSync(join(tmpdir(), "hush-fuzz-"));
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "v.json"), "fuzz", { name: "a", pub: owner.pub });

    const model = new Map<string, string>();
    const scopes = ["default", "prod", "fal/personal"];
    const keys = ["A_KEY", "B_KEY", "C_KEY", "LONG_NAME_KEY"];

    for (let i = 0; i < rounds(400); i++) {
      const scope = scopes[Math.floor(r() * scopes.length)];
      const key = keys[Math.floor(r() * keys.length)];
      const id = `${scope} ${key}`;
      const roll = r();

      if (roll < 0.6) {
        const value = randomString(r, 1 + Math.floor(r() * 40));
        vault.set(owner, scope, key, value);
        model.set(id, value);
      } else if (roll < 0.8) {
        const had = model.delete(id);
        assert.equal(vault.delete(scope, key), had, "delete disagreed with the model");
      } else {
        assert.equal(vault.has(scope, key), model.has(id), "has() disagreed with the model");
        if (model.has(id)) {
          assert.equal(vault.get(owner, scope, key), model.get(id), "value disagreed with the model");
        }
      }
    }

    // Everything must still be readable across a save and a key rotation.
    vault.save();
    vault.rotate(owner);
    vault.save();
    const reopened = Vault.open(join(dir, "v.json"));
    for (const [id, value] of model) {
      const [scope, key] = id.split(" ");
      assert.equal(reopened.get(owner, scope, key), value, `lost ${scope}/${key} across rotate`);
    }
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("fuzz: a hostile vault file", () => {
  // The vault arrives over git, from whoever opened the pull request. Each case
  // states what should happen, because "it decrypted" is not by itself a
  // finding: a tamper that does not touch your own key wrap has no reason to
  // stop you reading your own secret. Asserting that blanket produced six false
  // alarms the first time, which is its own lesson.
  const scratch = () => mkdtempSync(join(tmpdir(), "hush-hostile-"));
  const owner = generateIdentity();

  const good = (() => {
    const dir = scratch();
    const path = join(dir, "vault.json");
    const v = Vault.create(path, "vf", { name: "me", pub: owner.pub });
    v.set(owner, "default", "GOOD_KEY", "good_value_1234567890");
    v.save();
    const text = readFileSync(path, "utf8");
    rmSync(dir, { recursive: true, force: true });
    return text;
  })();

  const write = (mutate: (v: any) => void): string => {
    const parsed = JSON.parse(good);
    mutate(parsed);
    const dir = scratch();
    const path = join(dir, "vault.json");
    writeFileSync(path, JSON.stringify(parsed, null, 2));
    return path;
  };
  const writeRaw = (text: string): string => {
    const dir = scratch();
    const path = join(dir, "vault.json");
    writeFileSync(path, text);
    return path;
  };

  test("a structurally broken vault is refused, never half-read", () => {
    const refused: [string, string][] = [
      ["empty file", ""],
      ["not json", "this is not json at all"],
      ["json but not an object", "[1,2,3]"],
      ["null", "null"],
      ["git conflict markers", "<<<<<<< HEAD\n" + good + "\n=======\n" + good + "\n>>>>>>> other\n"],
      ["truncated mid-object", good.slice(0, Math.floor(good.length / 2))],
      ["deeply nested envs", '{"scheme":"hush/v1","id":"x","name":"n","createdAt":"","dek":{"generation":1,"wraps":{}},"recipients":{},"envs":' + "[".repeat(2000) + "]".repeat(2000) + "}"],
    ];
    for (const [label, text] of refused) {
      assert.throws(() => Vault.open(writeRaw(text)), `${label} was opened`);
    }
  });

  test("nothing in a hostile vault reaches Object.prototype", () => {
    for (const mutate of [
      (v: any) => { v.envs["__proto__"] = { POLLUTED: { iv: "", ct: "", tag: "", gen: 1, updatedAt: "", updatedBy: "" } }; },
      (v: any) => { v.recipients["__proto__"] = { name: "x", pk: "age1" + "z".repeat(58), role: "member", addedAt: "" }; },
      (v: any) => { v.dek.wraps["__proto__"] = { epk: "", iv: "", ct: "", tag: "" }; },
    ]) {
      try { Vault.open(write(mutate)); } catch { /* refusing is a fine outcome too */ }
      assert.equal(({} as Record<string, unknown>).POLLUTED, undefined, "Object.prototype was polluted");
      assert.equal(({} as Record<string, unknown>).epk, undefined, "Object.prototype was polluted");
    }
  });

  test("a value cannot be moved to a name or an environment it was not sealed for", () => {
    // This is what the AAD is for, and it is the tamper a line-by-line git merge
    // of two vaults would actually produce.
    const renamed = Vault.open(write((v) => {
      v.envs.default.OTHER_KEY = v.envs.default.GOOD_KEY;
      delete v.envs.default.GOOD_KEY;
    }));
    assert.throws(() => renamed.get(owner, "default", "OTHER_KEY"), "a value opened under a name it was not sealed for");

    const copied = Vault.open(write((v) => { v.envs.prod = { GOOD_KEY: v.envs.default.GOOD_KEY }; }));
    assert.throws(() => copied.get(owner, "prod", "GOOD_KEY"), "a value opened in an environment it was not sealed for");
    // The original still opens where it belongs, so this is not just refusing everything.
    assert.equal(copied.get(owner, "default", "GOOD_KEY"), "good_value_1234567890");
  });

  test("flipped ciphertext or a flipped tag fails to open rather than returning rubbish", () => {
    for (const field of ["ct", "tag"] as const) {
      const v = Vault.open(write((raw) => {
        const b = Buffer.from(raw.envs.default.GOOD_KEY[field], "base64");
        b[0] ^= 0xff;
        raw.envs.default.GOOD_KEY[field] = b.toString("base64");
      }));
      assert.throws(() => v.get(owner, "default", "GOOD_KEY"), `a flipped ${field} was accepted`);
    }
  });

  test("a vault nobody can open still lists, so it can be diagnosed", () => {
    // Refusing outright would stop you inspecting the very thing you need to
    // look at. It opens, it lists, and it cannot decrypt.
    const v = Vault.open(write((raw) => { raw.dek.wraps = {}; }));
    assert.deepEqual(v.list("default").map((x) => x.key), ["GOOD_KEY"]);
    assert.throws(() => v.get(owner, "default", "GOOD_KEY"), /not a recipient/);
  });
});

describe("fuzz: a value cannot escape its shell quoting", () => {
  // `hush export --shell` is fed to `eval` by the shell hook, so a value that
  // can break out of its quoting runs as a command on every machine that loads
  // the vault. Examples check the characters someone thought of; this checks
  // whatever the generator produces.
  // Bounded scaling, unlike the in-process fuzzers above. This one spawns a
  // shell per round, so multiplying the seeds *and* the rounds turns a 60x sweep
  // into 3600x the work and the run never finishes. More values per shell is the
  // cheap axis, and the property is per-value, so that is the one to grow.
  for (const seed of seeds([11, 2027, 65537]).slice(0, 3 * Math.min(SCALE, 4))) {
    test(`seed ${seed}: every generated value survives a real shell verbatim`, () => {
      const r = rng(seed);
      const dir = mkdtempSync(join(tmpdir(), "hush-fuzzsh-"));
      try {
        // One script per round, many variables per script: spawning a shell is
        // the expensive part, and the property is per-value either way.
        for (let round = 0; round < 6; round++) {
          const values: Record<string, string> = {};
          for (let i = 0; i < 25 * Math.min(SCALE, 20); i++) {
            // No NUL: a shell cannot carry one in an environment variable at
            // all, so it is out of scope rather than a gap.
            values[`FUZZ_${i}`] = randomString(r, Math.floor(r() * 60)).replace(/ /g, "");
          }
          const canary = join(dir, `executed-${round}`);
          const probe = Object.keys(values)
            .map((k) => `printf '<<%s>>%s<<END>>\\n' ${k} "$${k}"`)
            .join("\n");
          const script = join(dir, `check-${round}.sh`);
          writeFileSync(script, toShellExports(values) + probe + "\n");

          const out = spawnSync("sh", [script], { encoding: "utf8" });
          assert.equal(out.status, 0, `seed ${seed} round ${round}: the script did not run:\n${out.stderr}`);
          assert.ok(!existsSync(canary), `seed ${seed} round ${round}: something executed`);

          for (const [k, v] of Object.entries(values)) {
            const start = out.stdout.indexOf(`<<${k}>>`);
            assert.notEqual(start, -1, `seed ${seed}: ${k} never printed`);
            const from = start + `<<${k}>>`.length;
            const got = out.stdout.slice(from, out.stdout.indexOf("<<END>>", from));
            // A shell drops trailing newlines from "$VAR" in a printf argument,
            // so compare with those removed from both sides.
            assert.equal(
              got.replace(/\n+$/, ""),
              v.replace(/\n+$/, ""),
              `seed ${seed} round ${round}: ${k} did not survive: ${JSON.stringify(v)}`,
            );
          }
        }
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});
