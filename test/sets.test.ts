/**
 * Unify-sets: one storage mechanism, one vocabulary.
 *
 * Before this change a scope was either an "environment" (named in
 * data.meta, listed by envSets()) or a "service account" (a name with a "/"
 * in it, listed by accounts()) — two code paths over the same map. These
 * tests cover the replacement API (sets(), resolveSets(), usedSets(),
 * composeSets()) and, separately, that the old API a vault written before
 * this change relied on still resolves the same secrets today.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { generateIdentity } from "../src/crypto.ts";
import { Vault, ValidationError, findHushDir, locateProject } from "../src/vault.ts";
import {
  usedSets,
  composeSets,
  librarySets,
  saveLinks,
  globalVaultName,
  suggestSets,
  ensureProjectVault,
  writeProjectDotfiles,
  LIBRARY_DEFAULT,
} from "../src/library.ts";
import { setNameFor } from "../src/services.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const scratch = () => mkdtempSync(join(tmpdir(), "hush-sets-"));

/** Point HUSH_HOME at a scratch dir for the duration of `fn`, then restore it. */
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

/**
 * Write .hush/use.json the way a pre-unification vault would have. saveUse()
 * is gone along with every other writer of this file — loadUse() (and, through
 * it, usedSets()) still reads it for compatibility, which is the one thing
 * these tests need to fake.
 */
const writeUseFile = (hushDir: string, use: Record<string, string>): void =>
  writeFileSync(join(hushDir, "use.json"), JSON.stringify(use, null, 2) + "\n");

describe("services: setNameFor", () => {
  test("joins service and account with a slash", () => {
    // The one place the "/" convention lives — CLI/MCP call this rather than
    // building the string themselves.
    assert.equal(setNameFor("fal", "acme"), "fal/acme");
    assert.equal(setNameFor("gemini", "team"), "gemini/team");
  });
});

describe("Vault.sets() / hasSet()", () => {
  const setup = () => {
    const dir = scratch();
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "vault.json"), "t", { name: "owner", pub: owner.pub });
    return { dir, owner, vault };
  };

  test("sets() lists every scope with no isAccount field, slash or not", () => {
    const { owner, vault } = setup();
    vault.set(owner, "fal/acme", "FAL_KEY", "x");
    vault.set(owner, "prod", "DATABASE_URL", "y");

    const sets = vault.sets();
    const names = sets.map((s) => s.name).sort();
    assert.deepEqual(names, ["default", "fal/acme", "prod"]);
    for (const s of sets) assert.ok(!("isAccount" in s), `sets() still carries isAccount for ${s.name}`);
  });

  test("hasSet() reports existence without materialising anything", () => {
    const { owner, vault } = setup();
    vault.set(owner, "fal/acme", "FAL_KEY", "x");
    assert.equal(vault.hasSet("default"), true);
    assert.equal(vault.hasSet("fal/acme"), true);
    assert.equal(vault.hasSet("nope"), false);
  });
});

describe("Vault.resolveSets()", () => {
  const setup = () => {
    const dir = scratch();
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "vault.json"), "t", { name: "owner", pub: owner.pub });
    return { owner, vault };
  };

  // Bites: without ordered merging, this passes whichever way Object.assign
  // happens to run rather than because the later set actually won.
  test("merges named sets in order, later wins per key", () => {
    const { owner, vault } = setup();
    vault.set(owner, "a", "SHARED", "from-a");
    vault.set(owner, "a", "ONLY_A", "a-only");
    vault.set(owner, "b", "SHARED", "from-b");

    const forward = vault.resolveSets(owner, ["a", "b"]);
    assert.deepEqual(forward.secrets, { SHARED: "from-b", ONLY_A: "a-only" });
    assert.deepEqual(forward.layers, ["a", "b"]);

    // Reversed order really does flip the winner, not just the layer list.
    const backward = vault.resolveSets(owner, ["b", "a"]);
    assert.equal(backward.secrets.SHARED, "from-a");
  });

  // Bites: a version that swallowed the lookup miss (e.g. `?? {}` before the
  // check) would materialise nothing instead of throwing, and this test
  // would see an empty object rather than a thrown error.
  test("an unknown name throws, naming it and every set that does exist", () => {
    const { owner, vault } = setup();
    vault.set(owner, "prod", "X", "1");
    assert.throws(
      () => vault.resolveSets(owner, ["nope"]),
      (e: unknown) => {
        assert.ok(e instanceof ValidationError);
        assert.match((e as Error).message, /No set called "nope"/);
        assert.match((e as Error).message, /You have: default, prod\./);
        return true;
      },
    );
  });

  // Bites: a version that special-cased "default" (e.g. always resolving it
  // even if absent from `names`) would pass this by accident.
  test("an empty list resolves to nothing", () => {
    const { owner, vault } = setup();
    assert.deepEqual(vault.resolveSets(owner, []), { secrets: {}, layers: [] });
  });

  test("does not special-case 'default': asking for it when it is not in the list changes nothing", () => {
    const { owner, vault } = setup();
    vault.set(owner, "default", "D", "d-value");
    vault.set(owner, "prod", "P", "p-value");
    // "default" holds a value but is not named, so it must not leak in.
    assert.deepEqual(vault.resolveSets(owner, ["prod"]), { secrets: { P: "p-value" }, layers: ["prod"] });
  });
});

describe("sets with a '/' round-trip through the structural operations", () => {
  test("ensureEnvExists, describeEnv, renameEnv, moveSecret, staleValues, unlistedWraps all work unchanged", () => {
    const dir = scratch();
    const owner = generateIdentity();
    const vault = Vault.create(join(dir, "vault.json"), "t", { name: "owner", pub: owner.pub });

    vault.ensureEnvExists("new/svc");
    assert.equal(vault.hasSet("new/svc"), true);

    vault.set(owner, "fal/acme", "FAL_KEY", "fal-key-value");
    vault.set(owner, "fal/acme", "OTHER", "other-value");
    vault.describeEnv("fal/acme", { label: "Acme Fal", description: "the client's fal account" });

    const described = vault.sets().find((s) => s.name === "fal/acme");
    assert.equal(described?.label, "Acme Fal");
    assert.equal(described?.description, "the client's fal account");

    // unlistedWraps() walks recipients, not env names — a slash-named scope
    // elsewhere in the vault must not confuse it.
    assert.deepEqual(vault.unlistedWraps(), []);

    // Force one entry stale and check staleValues() reports the right env name.
    vault.data.envs["fal/acme"].OTHER.gen = 0;
    assert.deepEqual(vault.staleValues(), [{ env: "fal/acme", key: "OTHER", gen: 0 }]);
    vault.data.envs["fal/acme"].OTHER.gen = vault.data.dek.generation; // restore

    const { moved } = vault.renameEnv(owner, "fal/acme", "fal/acme-2");
    assert.equal(moved, 2);
    assert.equal(vault.hasSet("fal/acme"), false);
    assert.equal(vault.hasSet("fal/acme-2"), true);
    assert.equal(vault.envLabel("fal/acme-2"), "Acme Fal", "metadata did not move with the rename");
    assert.equal(vault.get(owner, "fal/acme-2", "FAL_KEY"), "fal-key-value");

    vault.moveSecret(owner, "OTHER", "fal/acme-2", "fal/elsewhere");
    assert.equal(vault.get(owner, "fal/elsewhere", "OTHER"), "other-value");
    assert.equal(vault.has("fal/acme-2", "OTHER"), false);
    assert.equal(vault.get(owner, "fal/acme-2", "FAL_KEY"), "fal-key-value", "the sibling key should be untouched");
  });
});

describe("library: usedSets()", () => {
  const hushDirScratch = () => {
    const dir = scratch();
    const hushDir = join(dir, ".hush");
    mkdirSync(hushDir, { recursive: true });
    return hushDir;
  };

  // Bites: a version that read use.json before envs.json links, or that put
  // "default" last, would still pass a test that only checked set
  // membership — this checks the actual order.
  test("orders 'default' first, then envs.json links, then use.json compat pairs, last mention wins", () => {
    const hushDir = hushDirScratch();
    saveLinks(hushDir, ["acme-production", "fal/acme"]); // a link that happens to look like a compat name too
    writeUseFile(hushDir, { gemini: "team", fal: "acme" }); // fal/acme names the link above again

    const used = usedSets(hushDir);
    // "default" is the floor; "fal/acme" is not repeated and keeps its *last*
    // position, because later wins and the later mention is the one meant.
    assert.deepEqual(used, ["default", "acme-production", "gemini/team", "fal/acme"]);
  });

  // Bites: a version that always unshifted "default" would put it back at the
  // floor even when the person deliberately moved it.
  test("naming 'default' in envs.json positions it, so it can be made to win", () => {
    const hushDir = hushDirScratch();
    saveLinks(hushDir, ["work-fal", "default"]);
    assert.deepEqual(usedSets(hushDir), ["work-fal", "default"]);
  });

  // Bites: the old saveLinks() sorted the list, which made position — now
  // precedence — impossible to control from either the CLI or the UI.
  test("saveLinks keeps the order it was given; a repeat mention moves the set last", () => {
    const hushDir = hushDirScratch();
    saveLinks(hushDir, ["beta", "alpha", "zeta", "beta"]);
    assert.deepEqual(usedSets(hushDir), ["default", "alpha", "zeta", "beta"]);
  });

  test("with no hushDir, or an empty one, the list is just ['default']", () => {
    assert.deepEqual(usedSets(null), ["default"]);
    assert.deepEqual(usedSets(hushDirScratch()), ["default"]);
  });
});

describe("library: composeSets()", () => {
  const projectSetup = () => {
    const dir = scratch();
    const owner = generateIdentity();
    const project = Vault.create(join(dir, "vault.json"), "proj", { name: "owner", pub: owner.pub });
    const hushDir = join(dir, ".hush");
    mkdirSync(hushDir, { recursive: true });
    return { dir, owner, project, hushDir };
  };

  const makeGlobalVault = (home: string, owner: ReturnType<typeof generateIdentity>) => {
    const path = join(home, "vaults", globalVaultName(), "vault.json");
    mkdirSync(dirname(path), { recursive: true });
    return Vault.create(path, "global", { name: "owner", pub: owner.pub });
  };

  test("a project set wins over a library set of the same name", () => {
    const home = scratch();
    withHome(home, () => {
      const { owner, project, hushDir } = projectSetup();
      const library = makeGlobalVault(home, owner);
      project.set(owner, "shared", "KEY", "from-project");
      library.set(owner, "shared", "KEY", "from-library");
      library.save();
      saveLinks(hushDir, ["shared"]);

      const result = composeSets(project, owner, hushDir);
      assert.equal(result.secrets.KEY, "from-project");
      assert.deepEqual(result.missing, []);
    });
  });

  // Bites: with "default" last in usedSets(), the project's baseline would
  // silently override the set the person just chose to use.
  test("'default' is the floor: a used set wins over it for a shared key", () => {
    const home = scratch();
    withHome(home, () => {
      const { owner, project, hushDir } = projectSetup();
      project.set(owner, "default", "FAL_KEY", "team-placeholder");
      project.set(owner, "work-fal", "FAL_KEY", "the-one-i-chose");
      saveLinks(hushDir, ["work-fal"]);
      const result = composeSets(project, owner, hushDir);
      assert.equal(result.secrets.FAL_KEY, "the-one-i-chose");
      assert.deepEqual(result.layers, ["default", "work-fal"]);
    });
  });

  // Bites: a first-occurrence dedupe would leave "a" where the project put it,
  // so "b" would still win after the person typed --use a.
  test("an extra name the project already uses moves last, so it wins for this run", () => {
    const home = scratch();
    withHome(home, () => {
      const { owner, project, hushDir } = projectSetup();
      project.set(owner, "a", "K", "from-a");
      project.set(owner, "b", "K", "from-b");
      saveLinks(hushDir, ["a", "b"]);
      assert.equal(composeSets(project, owner, hushDir).secrets.K, "from-b");
      const again = composeSets(project, owner, hushDir, ["a"]);
      assert.equal(again.secrets.K, "from-a");
      assert.deepEqual(again.layers, ["default", "b", "a"]);
    });
  });

  // The library is a catalog, not a floor: its default reaches a folder only
  // when that folder asks for it, and then under the project's own default
  // only if listed before it (later wins, like every other set).
  test("the library's default is used only in folders that add it", () => {
    const home = scratch();
    withHome(home, () => {
      const { owner, project, hushDir } = projectSetup();
      const library = makeGlobalVault(home, owner);
      library.set(owner, "default", "SHARED", "from-library");
      library.set(owner, "default", "GLOBAL_ONLY", "everywhere");
      library.save();
      project.set(owner, "default", "SHARED", "from-project");

      const untouched = composeSets(project, owner, hushDir);
      assert.equal(untouched.secrets.GLOBAL_ONLY, undefined, "the library leaked into a folder that never asked");
      assert.deepEqual(untouched.layers, ["default"]);

      saveLinks(hushDir, [LIBRARY_DEFAULT]);
      const opted = composeSets(project, owner, hushDir);
      assert.equal(opted.secrets.GLOBAL_ONLY, "everywhere");
      assert.equal(opted.secrets.SHARED, "from-library", "a set added later wins, as always");
      assert.deepEqual(opted.layers, ["default", `${globalVaultName()}:default`]);
    });
  });

  // Bites: an always-present "global:default" layer would name an empty set
  // in every approval prompt and "using" line.
  test("an empty library default adds no layer", () => {
    const home = scratch();
    withHome(home, () => {
      const { owner, project, hushDir } = projectSetup();
      makeGlobalVault(home, owner).save();
      project.set(owner, "default", "K", "v");
      saveLinks(hushDir, [LIBRARY_DEFAULT]);
      assert.deepEqual(composeSets(project, owner, hushDir).layers, ["default"]);
    });
  });

  test("a library-only set is found through a link", () => {
    const home = scratch();
    withHome(home, () => {
      const { owner, project, hushDir } = projectSetup();
      const library = makeGlobalVault(home, owner);
      library.set(owner, "acme-production", "KEY", "from-library");
      library.save(); // composeSets() reopens the library fresh from disk
      saveLinks(hushDir, ["acme-production"]);

      const result = composeSets(project, owner, hushDir);
      assert.equal(result.secrets.KEY, "from-library");
      assert.ok(result.layers.some((l) => l.endsWith(":acme-production")));
    });
  });

  // Bites: a version that folded `extra` into the same "report, don't throw"
  // bucket as linked names would let a typo'd --use flag pass silently.
  test("a --use (extra) name in neither vault throws, naming what does exist", () => {
    const home = scratch();
    withHome(home, () => {
      const { owner, project, hushDir } = projectSetup();
      project.set(owner, "prod", "K", "v");
      assert.throws(
        () => composeSets(project, owner, hushDir, ["nope"]),
        (e: unknown) => {
          assert.ok(e instanceof ValidationError);
          assert.match((e as Error).message, /No set called "nope"/);
          assert.match((e as Error).message, /prod/);
          return true;
        },
      );
    });
  });

  // Bites: a list that spelled library sets "main:work-fal" would offer a name
  // that --use does not accept.
  test("the unknown-name message lists library sets by the name a person would type", () => {
    const home = scratch();
    withHome(home, () => {
      const { owner, project, hushDir } = projectSetup();
      const library = makeGlobalVault(home, owner);
      library.set(owner, "work-fal", "FAL_KEY", "v");
      library.save();
      assert.throws(
        () => composeSets(project, owner, hushDir, ["nope"]),
        (e: unknown) => {
          const msg = (e as Error).message;
          assert.match(msg, /(^|[^:\w-])work-fal/);
          assert.doesNotMatch(msg, /:work-fal/);
          return true;
        },
      );
    });
  });

  // Bites: a version that threw on any unresolved name (rather than only
  // `extra`) would break every teammate who has not made their own copy of a
  // linked global set yet.
  test("a linked name in neither vault lands in missing, without throwing", () => {
    const home = scratch();
    withHome(home, () => {
      const { owner, project, hushDir } = projectSetup();
      saveLinks(hushDir, ["acme-production"]); // no library at all
      const result = composeSets(project, owner, hushDir);
      assert.deepEqual(result.missing, ["acme-production"]);
    });
  });

  // Bites: a version that reported every unresolved name, "default" included,
  // would spam a fresh project with a "missing: default" warning on its very
  // first run.
  test("a missing 'default' is silent: not an error, not in missing", () => {
    const home = scratch();
    withHome(home, () => {
      const { owner, project, hushDir } = projectSetup();
      // Rename "default" away, so the project genuinely has none.
      project.renameEnv(owner, "default", "renamed");
      const result = composeSets(project, owner, hushDir);
      assert.deepEqual(result.missing, []);
      assert.deepEqual(result.secrets, {});
    });
  });
});

describe("library: use.json compatibility", () => {
  // Bites: a version that dropped the loadUse() fold in usedSets() would
  // resolve only "default" here, missing FAL_KEY entirely — a project set up
  // before sets were unified would silently lose its pinned account.
  test("a vault with a fal/acme scope and a use.json pin still resolves through usedSets()/composeSets()", () => {
    const home = scratch();
    withHome(home, () => {
      const dir = scratch();
      const owner = generateIdentity();
      const vault = Vault.create(join(dir, "vault.json"), "t", { name: "owner", pub: owner.pub });
      vault.set(owner, "default", "SHARED", "shared-value");
      vault.set(owner, "fal/personal", "FAL_KEY", "personal-key");
      vault.set(owner, "fal/acme", "FAL_KEY", "acme-key");

      const hushDir = join(dir, ".hush");
      mkdirSync(hushDir, { recursive: true });
      // The old pin, written directly rather than through saveUse() — which
      // no longer exists — to fake a project set up before sets were unified.
      writeUseFile(hushDir, { fal: "acme" });

      const result = composeSets(vault, owner, hushDir);
      assert.deepEqual(result.secrets, { SHARED: "shared-value", FAL_KEY: "acme-key" });
      assert.deepEqual(result.layers, ["default", "fal/acme"]);
    });
  });

  test("use.json is read for compatibility, but nothing writes it any more", () => {
    // A quick source grep rather than a behavioural assertion — saveUse() was
    // the only writer and it is gone entirely now, so the claim is just that
    // nothing reintroduces one, while loadUse() keeps reading the file.
    const vaultSrc = readFileSync(join(root, "src/vault.ts"), "utf8");
    const librarySrc = readFileSync(join(root, "src/library.ts"), "utf8");
    assert.ok(!/saveUse/.test(vaultSrc), "src/vault.ts still defines or calls saveUse");
    assert.ok(!/saveUse/.test(librarySrc), "src/library.ts still defines or calls saveUse");
    assert.ok(/loadUse\(/.test(librarySrc), "src/library.ts does not read use.json for compatibility");
  });
});

describe("library: librarySets() lists sets with a '/' in the name", () => {
  test("a library set named like a service account is no longer filtered out", () => {
    const home = scratch();
    withHome(home, () => {
      const owner = generateIdentity();
      const path = join(home, "vaults", globalVaultName(), "vault.json");
      mkdirSync(dirname(path), { recursive: true });
      const library = Vault.create(path, "global", { name: "owner", pub: owner.pub });
      library.set(owner, "fal/acme", "FAL_KEY", "x");
      library.save(); // librarySets() reopens the library fresh from disk

      const names = librarySets().map((s) => s.name);
      assert.ok(names.includes("fal/acme"), `fal/acme missing from librarySets(): ${names.join(", ")}`);
    });
  });
});

describe("a project without a vault", () => {
  // Bites: a findHushDir() that only knows vault.json/link.json returns null
  // for a folder that uses library sets, and every command says "no vault".
  test("envs.json alone makes a folder a project; hasVault says whether it has one", () => {
    const dir = scratch();
    const hushDir = join(dir, ".hush");
    mkdirSync(hushDir, { recursive: true });
    saveLinks(hushDir, ["work-fal"]);
    mkdirSync(join(dir, "src", "deep"), { recursive: true });
    assert.equal(findHushDir(join(dir, "src", "deep")), hushDir, "envs.json alone did not mark the project");
    const loc = locateProject(dir)!;
    assert.equal(loc.hushDir, hushDir);
    assert.equal(loc.hasVault, false);

    const owner = generateIdentity();
    Vault.create(join(hushDir, "vault.json"), "p", { name: "owner", pub: owner.pub });
    assert.equal(locateProject(dir)!.hasVault, true);
  });
});

describe("suggestSets()", () => {
  const lib = [
    { name: "acme-production", keys: ["DATABASE_URL", "STRIPE_SECRET_KEY", "FAL_KEY"] },
    { name: "work-fal", keys: ["FAL_KEY"] },
    { name: "personal-fal", keys: ["FAL_KEY"] },
    { name: "gemini-team", keys: ["GEMINI_API_KEY"] },
  ];

  // Bites: a first-match or alphabetical picker takes acme-production for
  // DATABASE_URL and then still lists work-fal/personal-fal for FAL_KEY.
  test("the set covering the most needed keys wins the keys it shares with smaller ones", () => {
    const s = suggestSets(["DATABASE_URL", "FAL_KEY"], lib);
    assert.deepEqual(s.picks, ["acme-production"]);
    // The same with the big set sorting *last*, so alphabetical-first cannot pass by luck.
    const z = suggestSets(["DATABASE_URL", "FAL_KEY"], [
      { name: "aaa-fal", keys: ["FAL_KEY"] },
      { name: "zzz-production", keys: ["DATABASE_URL", "FAL_KEY"] },
    ]);
    assert.deepEqual(z.picks, ["zzz-production"], "coverage must beat name order");
    assert.deepEqual(s.provider, { DATABASE_URL: "acme-production", FAL_KEY: "acme-production" });
    assert.deepEqual(s.ambiguous, []);
    assert.deepEqual(s.uncovered, []);
  });

  // Bites: a picker that breaks ties by name silently chooses personal-fal.
  test("a tie is reported, not guessed: the person picks between equally good sets", () => {
    const s = suggestSets(["FAL_KEY", "GEMINI_API_KEY"], lib.filter((x) => x.name !== "acme-production"));
    assert.deepEqual(s.picks, ["gemini-team"]);
    assert.deepEqual(s.ambiguous, [{ key: "FAL_KEY", options: ["personal-fal", "work-fal"] }]);
    assert.deepEqual(s.uncovered, []);
  });

  test("keys no set provides are reported as uncovered; nothing needed means nothing picked", () => {
    const s = suggestSets(["DATABASE_URL", "NOBODY_HAS_THIS"], lib);
    assert.deepEqual(s.picks, ["acme-production"]);
    assert.deepEqual(s.uncovered, ["NOBODY_HAS_THIS"]);
    assert.deepEqual(suggestSets([], lib), { picks: [], ambiguous: [], uncovered: [], provider: {} });
  });

  // Bites: a picker that stops at the first tie never gets to gemini-team.
  test("after a tie, the remaining keys are still resolved", () => {
    const s = suggestSets(["FAL_KEY", "GEMINI_API_KEY"], lib.filter((x) => x.name !== "acme-production"));
    assert.ok(s.picks.includes("gemini-team"), "the unambiguous key was abandoned after the tie");
  });

  // Regression: found by the suggestSets fuzz property in test/fuzz-surfaces.test.ts.
  // Three sets tied for "most coverage" (one key each, no set sharing a key with
  // another) used to make the picker give up outright: the tie-break loop only
  // ever cleared a key out of `remaining` when *two or more* of the tied sets
  // both offered it, and checked whether *anything had ever been marked
  // ambiguous* to decide whether to keep going. With no shared key anywhere,
  // that check was false on the very first pass, so it `break`-ed immediately
  // and reported all three keys as "uncovered" even though each had an exact,
  // unambiguous provider.
  test("a tie with no actually-contested key resolves every set, not 'uncovered'", () => {
    const s = suggestSets(["A", "B", "C"], [
      { name: "S1", keys: ["A"] },
      { name: "S2", keys: ["B"] },
      { name: "S3", keys: ["C"] },
    ]);
    assert.deepEqual(s.picks.slice().sort(), ["S1", "S2", "S3"]);
    assert.deepEqual(s.provider, { A: "S1", B: "S2", C: "S3" });
    assert.deepEqual(s.ambiguous, []);
    assert.deepEqual(s.uncovered, []);
  });

  // Regression: same root cause, but worse. Once one real ambiguity had already
  // been recorded earlier in the run, the same "anything ever ambiguous?" check
  // stayed true forever, so a later three-way tie with no contested key neither
  // broke nor made progress — `remaining` never shrank and the function spun
  // forever. This is what the fuzzer actually found: a run of `npm test` that
  // never returns. The fixed picker instead tracks whether *this round* found a
  // contested key and, when it did not, takes every tied set at once (their
  // covered keys are disjoint by construction, so there is nothing to decide).
  test("a tie with no contested key after an earlier real one does not hang", () => {
    const s = suggestSets(["X", "A", "B", "C"], [
      { name: "S1", keys: ["X", "A"] },
      { name: "S2", keys: ["X", "B"] },
      { name: "S3", keys: ["C"] },
    ]);
    assert.deepEqual(s.ambiguous, [{ key: "X", options: ["S1", "S2"] }]);
    assert.deepEqual(s.provider, { A: "S1", B: "S2", C: "S3" });
    assert.deepEqual(s.uncovered, []);
  });
});

describe("ensureProjectVault()", () => {
  // Bites: a version that always creates would re-key a vault that exists;
  // one that never writes the dotfiles leaves audit.log committable.
  test("creates a vault with the member as admin once, and the dotfiles git needs", () => {
    const dir = scratch();
    const hushDir = join(dir, ".hush");
    const owner = generateIdentity();
    const first = ensureProjectVault(hushDir, { name: "me", pub: owner.pub }, "proj");
    assert.equal(first.created, true);
    assert.ok(first.vault.canRead(owner), "the member cannot read the vault it was made for");
    assert.ok(readFileSync(join(hushDir, ".gitignore"), "utf8").includes("*.local.json"));
    assert.ok(readFileSync(join(hushDir, ".gitattributes"), "utf8").includes("vault.json -merge"));

    first.vault.set(owner, "default", "K", "v");
    first.vault.save();
    const again = ensureProjectVault(hushDir, { name: "me", pub: owner.pub }, "proj");
    assert.equal(again.created, false);
    assert.ok(again.vault.has("default", "K"), "an existing vault was replaced");
  });

  test("writeProjectDotfiles does not overwrite a .gitignore someone edited", () => {
    const dir = scratch();
    const hushDir = join(dir, ".hush");
    mkdirSync(hushDir, { recursive: true });
    writeFileSync(join(hushDir, ".gitignore"), "custom\n");
    writeProjectDotfiles(hushDir);
    assert.equal(readFileSync(join(hushDir, ".gitignore"), "utf8"), "custom\n");
  });
});
