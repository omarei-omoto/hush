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
import { mkdtempSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { generateIdentity } from "../src/crypto.ts";
import { Vault, loadUse, saveUse, ValidationError } from "../src/vault.ts";
import {
  usedSets,
  composeSets,
  compose,
  librarySets,
  saveLinks,
  globalVaultName,
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

describe("services: setNameFor", () => {
  test("joins service and account with a slash", () => {
    // The one place the "/" convention lives — CLI/MCP call this rather than
    // building the string themselves.
    assert.equal(setNameFor("fal", "acme"), "fal/acme");
    assert.equal(setNameFor("gemini", "team"), "gemini/team");
  });
});

describe("Vault.sets() / envSets() / hasSet()", () => {
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

  test("envSets() is a deprecated alias: same shape as sets(), plus isAccount computed", () => {
    const { owner, vault } = setup();
    vault.set(owner, "fal/acme", "FAL_KEY", "x");
    vault.set(owner, "prod", "DATABASE_URL", "y");

    const sets = vault.sets();
    const envSets = vault.envSets();
    assert.deepEqual(
      envSets.map(({ isAccount: _isAccount, ...rest }) => rest),
      sets,
    );
    const byName = new Map(envSets.map((s) => [s.name, s.isAccount]));
    assert.equal(byName.get("fal/acme"), true);
    assert.equal(byName.get("prod"), false);
    assert.equal(byName.get("default"), false);
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
    saveUse(hushDir, { gemini: "team", fal: "acme" }); // fal/acme names the link above again

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

describe("library: compose() vs composeSets() — migration compatibility", () => {
  // Bites: this is the one the task calls out by name. Build a vault the way
  // code *before* this change would have — accounts() scopes plus a
  // use.json pin — then check the unified reader gets the same secrets as
  // the account-shaped reader did.
  test("a vault with fal/acme scopes and a use.json pin resolves identically both ways", () => {
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
      saveUse(hushDir, { fal: "acme" }); // the old pin, written the old way

      // Old-style caller: resolve the pin into (service, account) choices
      // itself, exactly as chooseAccounts() in cli.ts does, then call compose().
      const oldChoices = Object.entries(loadUse(hushDir)).map(([service, account]) => ({ service, account }));
      const viaCompose = compose(vault, owner, hushDir, "default", oldChoices);

      // New-style caller: composeSets() reads the same use.json through
      // usedSets(), with nothing extra to pass.
      const viaComposeSets = composeSets(vault, owner, hushDir);

      assert.deepEqual(viaComposeSets.secrets, viaCompose.secrets);
      assert.deepEqual(viaCompose.secrets, { SHARED: "shared-value", FAL_KEY: "acme-key" });
    });
  });

  test("use.json is read for compatibility, but nothing in library.ts or vault.ts writes it again", () => {
    // A quick source grep rather than a behavioural assertion — the claim is
    // about what calls saveUse(), which a runtime test of these two files
    // can't observe directly since neither exposes a hook for it. vault.ts
    // *defines* saveUse() (one occurrence of "saveUse("); library.ts must
    // have none at all. `hush use` in cli.ts still calls it for old
    // projects, which is unaffected by this check.
    const vaultSrc = readFileSync(join(root, "src/vault.ts"), "utf8");
    const librarySrc = readFileSync(join(root, "src/library.ts"), "utf8");
    const vaultCalls = [...vaultSrc.matchAll(/saveUse\(/g)].length;
    assert.equal(vaultCalls, 1, "src/vault.ts calls saveUse() somewhere other than defining it");
    assert.ok(!/saveUse\(/.test(librarySrc), "src/library.ts calls saveUse()");
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

      const names = librarySets(null).map((s) => s.name);
      assert.ok(names.includes("fal/acme"), `fal/acme missing from librarySets(): ${names.join(", ")}`);
    });
  });
});
