/**
 * Property-based tests for the surfaces added after test/fuzz.test.ts was
 * written: set suggestion, policy merging, set composition order, scope-name
 * round trips, and the project link file. Same shape as test/fuzz.test.ts —
 * a seeded PRNG, HUSH_FUZZ_SCALE, and a printed seed on failure — kept in a
 * separate file so each can be read against the one surface it covers.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";

import { suggestSets, usedSets, composeSets, saveLinks, loadLinks, globalVaultName } from "../src/library.ts";
import { Vault, ValidationError, slugifyEnv, assertScopeName } from "../src/vault.ts";
import { generateIdentity } from "../src/crypto.ts";
import { DEFAULT_POLICY, type Policy } from "../src/mcp.ts";
import { mergePolicies, policyWeakenings, checkScopes } from "../src/policy.ts";

/** Same knob as test/fuzz.test.ts: HUSH_FUZZ_SCALE multiplies seeds and rounds. */
const SCALE = Math.max(1, Number(process.env.HUSH_FUZZ_SCALE ?? 1) || 1);
const rounds = (base: number): number => base * SCALE;
const seeds = (base: number[]): number[] => {
  const out = [...base];
  for (let k = 1; k < SCALE; k++) for (const s of base) out.push((s * 2654435761 + k) >>> 0);
  return out;
};

/** xorshift32, identical to test/fuzz.test.ts's — seeded, reproducible. */
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

const pick = <T>(r: () => number, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)];
const chance = (r: () => number, p: number): boolean => r() < p;

/** A random subset of `xs`, order preserved, no duplicates. */
function randomSubset<T>(r: () => number, xs: readonly T[]): T[] {
  return xs.filter(() => chance(r, 0.5));
}

/** A random list of (possibly repeated) items, e.g. a --use list with dupes. */
function randomList<T>(r: () => number, xs: readonly T[], maxLen: number): T[] {
  const len = Math.floor(r() * (maxLen + 1));
  return Array.from({ length: len }, () => pick(r, xs));
}

/** Deliberately nasty label text: unicode, punctuation, long, leading/trailing junk. */
const LABEL_ALPHABET = "abcXYZ019 -_./:@#$%^&*()[]{}|\\\"'`~+=\t\n" + "é\u{1f510}é́";
const randomLabel = (r: () => number, len: number): string => {
  const chars = [...LABEL_ALPHABET];
  let out = "";
  for (let i = 0; i < len; i++) out += chars[Math.floor(r() * chars.length)];
  return out;
};

const scratch = () => mkdtempSync(join(tmpdir(), "hush-fuzzsurf-"));

/** Same helper as test/sets.test.ts: point HUSH_HOME at a scratch dir. */
function withHome<T>(home: string, fn: () => T): T {
  const saved = process.env.HUSH_HOME;
  process.env.HUSH_HOME = home;
  try {
    return fn();
  } finally {
    if (saved === undefined) delete process.env.HUSH_HOME;
    else process.env.HUSH_HOME = saved;
  }
}

const makeGlobalVault = (home: string, owner: ReturnType<typeof generateIdentity>) => {
  const path = join(home, "vaults", globalVaultName(), "vault.json");
  mkdirSync(dirname(path), { recursive: true });
  return Vault.create(path, "global", { name: "owner", pub: owner.pub });
};

// -------------------------------------------------------------- suggestSets

describe("fuzz: suggestSets", () => {
  const KEYS: string[] = ["K0", "K1", "K2", "K3", "K4"];
  const NAMES: string[] = ["s0", "s1", "s2", "s3", "s4"];

  /** A random library: each set gets a random non-empty subset of KEYS. */
  function randomLibrary(r: () => number): { name: string; keys: string[] }[] {
    return NAMES.filter(() => chance(r, 0.8)).map((name) => ({
      name,
      keys: KEYS.filter(() => chance(r, 0.4)),
    }));
  }

  for (const seed of seeds([1, 2, 3])) {
    test(`seed ${seed}: provider/ambiguous/uncovered partition needed, and are internally consistent`, () => {
      const r = rng(seed);
      for (let round = 0; round < rounds(150); round++) {
        const sets = randomLibrary(r);
        const needed = randomSubset(r, KEYS);
        const result = suggestSets(needed, sets);
        const byName = new Map(sets.map((s) => [s.name, s]));
        const label = `seed ${seed} round ${round} needed=${JSON.stringify(needed)} sets=${JSON.stringify(sets)}`;

        // provider: every key is needed, and the named set really offers it.
        for (const [key, setName] of Object.entries(result.provider)) {
          assert.ok(needed.includes(key), `${label}: provider key ${key} not in needed`);
          const set = byName.get(setName);
          assert.ok(set, `${label}: provider names a set that does not exist: ${setName}`);
          assert.ok(set!.keys.includes(key), `${label}: ${setName} does not actually provide ${key}`);
        }

        // picks: distinct, all real, and each contributes at least one provided key.
        assert.equal(new Set(result.picks).size, result.picks.length, `${label}: duplicate pick`);
        for (const name of result.picks) {
          assert.ok(byName.has(name), `${label}: pick ${name} is not a real set`);
          assert.ok(
            Object.values(result.provider).includes(name),
            `${label}: pick ${name} provides nothing in the end`,
          );
        }

        // ambiguous: keys are needed, not resolved, and genuinely contested.
        for (const { key, options } of result.ambiguous) {
          assert.ok(needed.includes(key), `${label}: ambiguous key ${key} not in needed`);
          assert.ok(!(key in result.provider), `${label}: ${key} is both ambiguous and resolved`);
          assert.ok(new Set(options).size === options.length && options.length >= 2, `${label}: ${key} options not >=2 distinct: ${options}`);
          for (const name of options) {
            const set = byName.get(name);
            assert.ok(set?.keys.includes(key), `${label}: ambiguous option ${name} does not offer ${key}`);
          }
        }

        // uncovered: genuinely provided by no set at all.
        for (const key of result.uncovered) {
          assert.ok(needed.includes(key), `${label}: uncovered key ${key} not in needed`);
          assert.ok(!sets.some((s) => s.keys.includes(key)), `${label}: uncovered key ${key} IS provided by some set`);
        }

        // partition: provider ∪ ambiguous ∪ uncovered === needed, no overlap.
        const providerKeys = Object.keys(result.provider);
        const ambiguousKeys = result.ambiguous.map((a) => a.key);
        const uncoveredKeys = result.uncovered;
        const union = new Set([...providerKeys, ...ambiguousKeys, ...uncoveredKeys]);
        assert.equal(union.size, providerKeys.length + ambiguousKeys.length + uncoveredKeys.length, `${label}: overlap between provider/ambiguous/uncovered`);
        assert.deepEqual([...union].sort(), [...new Set(needed)].sort(), `${label}: partition does not cover needed`);

        // determinism regardless of the order `sets` was given in.
        const shuffled = [...sets];
        for (let i = shuffled.length - 1; i > 0; i--) {
          const j = Math.floor(r() * (i + 1));
          [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }
        assert.deepEqual(suggestSets(needed, shuffled), result, `${label}: order of \`sets\` changed the result`);
      }
    });
  }

  test("empty needed means everything empty, for any library", () => {
    const r = rng(999);
    for (let i = 0; i < rounds(30); i++) {
      const sets = randomLibrary(r);
      assert.deepEqual(suggestSets([], sets), { picks: [], ambiguous: [], uncovered: [], provider: {} });
    }
  });
});

// ------------------------------------------------------------ mergePolicies

describe("fuzz: mergePolicies / policyWeakenings", () => {
  const COMMANDS = ["node", "bash", "npm", "curl", "./script.sh", "git"] as const;
  const ENVS = ["dev", "staging", "prod", "fal/acme"] as const;
  const HOSTS = ["api.stripe.com", "*.example.com", "localhost:3000", "api.github.com"] as const;
  const KEYS = ["API_KEY", "DB_URL", "TOKEN"] as const;
  const ACTIONS = ["run", "add", "reveal", "export"] as const;
  const BIOMETRY_RANK: Record<Policy["biometry"], number> = { off: 0, preferred: 1, required: 2 };
  const SCOPE_RANK: Record<Policy["approvalScope"], number> = { sets: 0, command: 1 };

  function randomPartial(r: () => number): Partial<Policy> {
    const p: Partial<Policy> = {};
    if (chance(r, 0.7)) p.allowCommands = randomSubset(r, COMMANDS);
    if (chance(r, 0.7)) p.denyCommands = randomSubset(r, COMMANDS);
    if (chance(r, 0.7)) p.unsafeAllowCommands = randomSubset(r, COMMANDS);
    if (chance(r, 0.7)) p.allowEnvs = randomSubset(r, ENVS);
    if (chance(r, 0.7)) p.allowHosts = randomSubset(r, HOSTS);
    if (chance(r, 0.7)) p.denyKeys = randomSubset(r, KEYS);
    if (chance(r, 0.7)) p.maxRunMs = Math.floor(r() * 300_000);
    if (chance(r, 0.7)) p.approvalTtlSeconds = Math.floor(r() * 3600);
    if (chance(r, 0.7)) p.approvalTimeoutSeconds = Math.floor(r() * 300);
    if (chance(r, 0.7)) p.requireApproval = randomSubset(r, ACTIONS);
    if (chance(r, 0.7)) p.biometry = pick(r, ["off", "preferred", "required"] as const);
    if (chance(r, 0.7)) p.approvalScope = pick(r, ["sets", "command"] as const);
    return p;
  }

  /** "Weaker than floor", defined per field exactly as the doc comment does. */
  function weakerThanFloor(floor: Partial<Policy>, effective: Policy): string[] {
    const bad: string[] = [];
    for (const field of ["allowCommands", "allowEnvs", "allowHosts"] as const) {
      const fl = floor[field];
      if (fl && fl.length && effective[field].some((x) => !fl.includes(x))) bad.push(field);
    }
    const fu = floor.unsafeAllowCommands ?? [];
    if (effective.unsafeAllowCommands.some((x) => !fu.includes(x))) bad.push("unsafeAllowCommands");
    // denyCommands is the one field where a floor entry is allowed to be
    // missing from the effective list: the floor can name it in its own
    // unsafeAllowCommands (agreed by the repo too) to deliberately exempt it,
    // which is the sanctioned override, not a weakening — see mergePolicies'
    // own comment on unsafeAllowCommands ("the whole point of the floor").
    const flDeny = floor.denyCommands ?? [];
    if (flDeny.some((x) => !effective.denyCommands.includes(x) && !effective.unsafeAllowCommands.includes(x))) {
      bad.push("denyCommands");
    }
    for (const field of ["denyKeys", "requireApproval"] as const) {
      const fl = floor[field] ?? [];
      if (fl.some((x) => !effective[field].includes(x))) bad.push(field);
    }
    for (const field of ["maxRunMs", "approvalTtlSeconds"] as const) {
      const fl = floor[field];
      if (fl !== undefined && effective[field] > fl) bad.push(field);
    }
    if (floor.biometry && BIOMETRY_RANK[effective.biometry] < BIOMETRY_RANK[floor.biometry]) bad.push("biometry");
    if (floor.approvalScope && SCOPE_RANK[effective.approvalScope] < SCOPE_RANK[floor.approvalScope]) bad.push("approvalScope");
    return bad;
  }

  /** Today's plain `{...DEFAULT_POLICY, ...repo}` merge, field by field, per mergePolicies' own doc comment. */
  function oldTwoWayMerge(base: Policy, repo: Partial<Policy>): Omit<Policy, "unsafeAllowCommands"> {
    const uniq = (xs: string[]): string[] => [...new Set(xs)];
    return {
      allowCommands: repo.allowCommands ?? base.allowCommands,
      denyCommands: uniq([...base.denyCommands, ...(repo.denyCommands ?? [])]),
      allowEnvs: repo.allowEnvs ?? base.allowEnvs,
      allowHosts: repo.allowHosts ?? base.allowHosts,
      denyKeys: uniq([...base.denyKeys, ...(repo.denyKeys ?? [])]),
      maxRunMs: repo.maxRunMs ?? base.maxRunMs,
      requireApproval: repo.requireApproval ?? base.requireApproval,
      approvalTtlSeconds: repo.approvalTtlSeconds ?? base.approvalTtlSeconds,
      approvalTimeoutSeconds: repo.approvalTimeoutSeconds ?? base.approvalTimeoutSeconds,
      biometry: repo.biometry ?? base.biometry,
      approvalScope: repo.approvalScope ?? base.approvalScope,
      unmaskKeys: base.unmaskKeys ?? [],
    };
  }

  /** "Asked for something wider than the floor", derived independently, per field. */
  function askedWider(floor: Partial<Policy>, repo: Partial<Policy>): boolean {
    if ((repo.unsafeAllowCommands ?? []).some((c) => !(floor.unsafeAllowCommands ?? []).includes(c))) return true;
    for (const field of ["allowCommands", "allowEnvs", "allowHosts"] as const) {
      const fl = floor[field];
      const rl = repo[field];
      if (fl?.length && rl?.length && rl.some((x) => !fl.includes(x))) return true;
    }
    if (repo.requireApproval && (floor.requireApproval ?? []).some((a) => !repo.requireApproval!.includes(a))) return true;
    if (repo.denyKeys && (floor.denyKeys ?? []).some((k) => !repo.denyKeys!.includes(k))) return true;
    for (const field of ["maxRunMs", "approvalTtlSeconds"] as const) {
      if (floor[field] !== undefined && repo[field] !== undefined && repo[field]! > floor[field]!) return true;
    }
    if (floor.biometry && repo.biometry && BIOMETRY_RANK[repo.biometry] < BIOMETRY_RANK[floor.biometry]) return true;
    if (floor.approvalScope && repo.approvalScope && SCOPE_RANK[repo.approvalScope] < SCOPE_RANK[floor.approvalScope]) return true;
    return false;
  }

  for (const seed of seeds([11, 22, 33])) {
    test(`seed ${seed}: effective policy is never weaker than the floor, and merging is idempotent`, () => {
      const r = rng(seed);
      for (let round = 0; round < rounds(200); round++) {
        const floor = randomPartial(r);
        const repo = randomPartial(r);
        const effective = mergePolicies(DEFAULT_POLICY, floor, repo);
        const label = `seed ${seed} round ${round} floor=${JSON.stringify(floor)} repo=${JSON.stringify(repo)}`;

        assert.deepEqual(weakerThanFloor(floor, effective), [], `${label}: weaker than floor: effective=${JSON.stringify(effective)}`);

        const again = mergePolicies(DEFAULT_POLICY, floor, effective);
        assert.deepEqual(again, effective, `${label}: mergePolicies is not idempotent`);

        const withoutFloor = mergePolicies(DEFAULT_POLICY, {}, repo);
        const old = oldTwoWayMerge(DEFAULT_POLICY, repo);
        for (const field of Object.keys(old) as (keyof typeof old)[]) {
          const got = withoutFloor[field];
          const want = old[field];
          if (Array.isArray(got)) {
            assert.deepEqual([...got].sort(), [...(want as string[])].sort(), `${label}: empty-floor field ${field} diverges from the old two-way merge`);
          } else {
            assert.equal(got, want, `${label}: empty-floor field ${field} diverges from the old two-way merge`);
          }
        }

        assert.equal(policyWeakenings(floor, repo).length > 0, askedWider(floor, repo), `${label}: policyWeakenings emptiness disagrees with an independent "asked wider" check`);
      }
    });
  }
});

// ----------------------------------------------------- usedSets/composeSets

describe("fuzz: usedSets / composeSets order", () => {
  /** Same idiom as library.ts's private lastMentionWins: last occurrence wins, order otherwise preserved. */
  const lastMentionWins = (names: string[]): string[] => [...new Set([...names].reverse())].reverse();

  const CREATABLE: string[] = ["a", "b", "c"]; // sets this round may actually create somewhere
  const LINK_POOL: string[] = [...CREATABLE, "default", "ghost"]; // "ghost" exists nowhere, on purpose

  // Bounded scaling, like test/fuzz.test.ts's shell property: each round does
  // real crypto (an X25519 identity, two Vault.create() calls, several seals)
  // and two temp directories, so this is I/O- and CPU-bound per round rather
  // than per byte generated. Scaling the round count by SCALE^2 the way
  // rounds()+seeds() do together would turn a 45-round sweep into 18,000
  // rounds at HUSH_FUZZ_SCALE=20 — correct, but minutes long for no more
  // coverage of this (small, discrete) state space than a few hundred rounds
  // already gets. More seeds is still the cheap axis.
  for (const seed of seeds([5, 6, 7]).slice(0, 3 * Math.min(SCALE, 4))) {
    test(`seed ${seed}: layers are deduped, ordered by last mention, and secrets follow the same order`, () => {
      const r = rng(seed);
      for (let round = 0; round < 15 + 5 * Math.min(SCALE, 10); round++) {
        const home = scratch();
        try {
          withHome(home, () => {
            const owner = generateIdentity();
            const dir = scratch();
            const hushDir = join(dir, ".hush");
            mkdirSync(hushDir, { recursive: true });

            const hasProject = chance(r, 0.7);
            const project = hasProject ? Vault.create(join(dir, "vault.json"), "proj", { name: "owner", pub: owner.pub }) : null;
            const library = makeGlobalVault(home, owner);

            // Each creatable name lives in exactly one location, so the winning
            // value for the shared key identifies which layer actually won.
            const locations = new Map<string, "project" | "library" | null>();
            for (const name of CREATABLE) {
              const roll = r();
              if (roll < 0.35) locations.set(name, null);
              else if (roll < 0.7 || !hasProject) locations.set(name, "library");
              else locations.set(name, "project");
            }
            for (const [name, where] of locations) {
              if (where === "project") project!.set(owner, name, "SHARED", `project:${name}`);
              else if (where === "library") library.set(owner, name, "SHARED", `library:${name}`);
            }
            // The library's default is the global floor — but only when it
            // holds something; an empty one must add no layer at all.
            const globalHasKeys = chance(r, 0.5);
            if (globalHasKeys) library.set(owner, "default", "GLOBAL_ONLY", "everywhere");
            library.save();

            const links = randomList(r, LINK_POOL, 5);
            saveLinks(hushDir, links);

            // usedSets: "default" floors the list unless named explicitly; last mention wins.
            const expectedUsed = lastMentionWins(links.includes("default") ? links : ["default", ...links]);
            assert.deepEqual(usedSets(hushDir), expectedUsed, `seed ${seed} round ${round}: usedSets order, links=${JSON.stringify(links)}`);

            // A --use name that exists nowhere always throws, regardless of anything else.
            if (chance(r, 0.25)) {
              assert.throws(
                () => composeSets(project, owner, hushDir, ["ghost2"]),
                (e: unknown) => e instanceof ValidationError,
                `seed ${seed} round ${round}: an extra name nowhere should throw`,
              );
              return;
            }

            // `extra` (a --use flag) always throws on a name that exists
            // nowhere (checked in its own branch above), so keep it to names
            // this round actually created — otherwise composeSets throws here
            // instead of exercising the ordering/merge properties below.
            const existingNames = CREATABLE.filter((n) => locations.get(n));
            const extra = existingNames.length ? randomList(r, existingNames, 2) : [];
            const result = composeSets(project, owner, hushDir, extra);
            const label = `seed ${seed} round ${round}: links=${JSON.stringify(links)} extra=${JSON.stringify(extra)} locations=${JSON.stringify([...locations])} hasProject=${hasProject}`;

            // No duplicate layers.
            assert.equal(new Set(result.layers).size, result.layers.length, `${label}: duplicate layer`);

            // Rebuild the expected order/resolution independently and compare.
            const names = lastMentionWins([...expectedUsed, ...extra]);
            const extraSet = new Set(extra);
            const expectedLayers: string[] = [];
            const expectedMissing: string[] = [];
            const expectedSecrets: Record<string, string> = {};
            for (const name of names) {
              if (name === "default") {
                if (globalHasKeys) {
                  expectedLayers.push(`${globalVaultName()}:default`);
                  expectedSecrets.GLOBAL_ONLY = "everywhere";
                }
                if (hasProject) expectedLayers.push("default");
                continue;
              }
              const where = locations.get(name);
              if (hasProject && where === "project") {
                expectedSecrets.SHARED = `project:${name}`;
                expectedLayers.push(name);
              } else if (where === "library") {
                expectedSecrets.SHARED = `library:${name}`;
                expectedLayers.push(`${globalVaultName()}:${name}`);
              } else if (extraSet.has(name)) {
                throw new Error(`test bug: ${name} should have thrown already`);
              } else {
                expectedMissing.push(name);
              }
            }

            assert.deepEqual(result.layers, expectedLayers, `${label}: layers`);
            assert.deepEqual(result.missing, expectedMissing, `${label}: missing`);
            assert.deepEqual(result.secrets, expectedSecrets, `${label}: secrets (last mention should win)`);

            // Every extra name that exists somewhere shows up in layers.
            for (const name of extra) {
              if (locations.get(name)) {
                assert.ok(
                  result.layers.some((l) => l === name || l.endsWith(`:${name}`)),
                  `${label}: extra name ${name} exists but is missing from layers`,
                );
              }
            }

            // A linked name nowhere lands in missing, never thrown on.
            if (links.includes("ghost")) {
              assert.ok(result.missing.includes("ghost"), `${label}: linked-but-nowhere name should be in missing`);
            }
          });
        } finally {
          rmSync(home, { recursive: true, force: true });
        }
      }
    });
  }
});

// --------------------------------------------------- scope-name round trips

describe("fuzz: slugifyEnv / assertScopeName round trips", () => {
  for (const seed of seeds([13, 14])) {
    test(`seed ${seed}: any label slugifies to an accepted, idempotent, colon/slash-free name`, () => {
      const r = rng(seed);
      for (let round = 0; round < rounds(300); round++) {
        const label = randomLabel(r, Math.floor(r() * 60));
        const slug = slugifyEnv(label);
        const tag = `seed ${seed} round ${round} label=${JSON.stringify(label)} slug=${JSON.stringify(slug)}`;

        assert.doesNotThrow(() => assertScopeName(slug), `${tag}: slug rejected by assertScopeName`);
        assert.equal(slugifyEnv(slug), slug, `${tag}: not idempotent`);
        assert.ok(!slug.includes(":"), `${tag}: slug contains ":"`);
        assert.ok(!slug.includes("/"), `${tag}: slug contains "/"`);

        // The same property checkScopes leans on: a policy naming the plain
        // slug must match a layer spelled "<vault>:<slug>", which only works
        // if the slug itself has no ":" to confuse the split.
        const policy = { ...DEFAULT_POLICY, allowEnvs: [slug] };
        const layer = `somevault:${slug}`;
        assert.doesNotThrow(() => checkScopes(policy, [layer]), `${tag}: checkScopes did not recognise its own slug through a library layer`);
      }
    });
  }

  test("a valid scope name round-trips through a real vault's resolveSets exactly as given", () => {
    const r = rng(4242);
    for (let round = 0; round < rounds(20); round++) {
      const dir = scratch();
      try {
        const owner = generateIdentity();
        const vault = Vault.create(join(dir, "vault.json"), "t", { name: "owner", pub: owner.pub });

        // Build distinct valid scope names straight out of the slugifier, so
        // every one of them is guaranteed to pass assertScopeName.
        const count = 2 + Math.floor(r() * 3);
        const names = new Set<string>();
        while (names.size < count) names.add(slugifyEnv(randomLabel(r, 5 + Math.floor(r() * 20))));
        const list = [...names];

        list.forEach((name, i) => vault.set(owner, name, `K${i}`, `v${i}`));
        const resolved = vault.resolveSets(owner, list);

        assert.deepEqual(resolved.layers, list, `round ${round}: resolveSets should hand back exactly the names given`);
        list.forEach((_, i) => {
          assert.equal(resolved.secrets[`K${i}`], `v${i}`, `round ${round}: key from ${list[i]} did not resolve`);
        });
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
  });
});

// -------------------------------------------------------- saveLinks/loadLinks

describe("fuzz: saveLinks / loadLinks", () => {
  const NAMES = ["default", "acme-production", "work-fal", "personal-fal", "gemini-team"] as const;
  const lastMentionWins = (names: string[]): string[] => [...new Set([...names].reverse())].reverse();

  for (const seed of seeds([21, 22])) {
    test(`seed ${seed}: round-trips with duplicates collapsed to the last mention`, () => {
      const r = rng(seed);
      for (let round = 0; round < rounds(80); round++) {
        const dir = scratch();
        try {
          const hushDir = join(dir, ".hush");
          mkdirSync(hushDir, { recursive: true });
          const list = randomList(r, NAMES, 8);
          saveLinks(hushDir, list);
          assert.deepEqual(loadLinks(hushDir), lastMentionWins(list), `seed ${seed} round ${round}: list=${JSON.stringify(list)}`);
        } finally {
          rmSync(dir, { recursive: true, force: true });
        }
      }
    });
  }

  test("a corrupt or non-array envs.json reads as [], for arbitrary junk", () => {
    const r = rng(7777);
    const fixed = [
      "",
      "not json",
      "null",
      "42",
      '"just a string"',
      "[1,2,3]",
      "{}",
      '{"use": "not-an-array"}',
      '{"use": [1, 2, 3]}',
      '{"use": null}',
      "{".repeat(500),
    ];
    const ALPHABET = "abc{}[]\":,0123456789 \n\t";
    for (let i = 0; i < rounds(80); i++) {
      const len = Math.floor(r() * 40);
      let junk = "";
      for (let k = 0; k < len; k++) junk += ALPHABET[Math.floor(r() * ALPHABET.length)];
      fixed.push(junk);
    }

    for (const text of fixed) {
      const dir = scratch();
      try {
        const hushDir = join(dir, ".hush");
        mkdirSync(hushDir, { recursive: true });
        writeFileSync(join(hushDir, "envs.json"), text);
        assert.deepEqual(loadLinks(hushDir), [], `junk did not read as []: ${JSON.stringify(text.slice(0, 60))}`);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
  });
});
