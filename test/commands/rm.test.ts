/**
 * `hush rm`.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { Vault } from "../../src/vault.ts";
import { join } from "node:path";
import { project } from "../helpers/cli.ts";

describe("hush rm", () => {
  test("rm KEY --from <set> removes the key; rm <set> --yes removes the whole set", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=v", "--to", "work-fal"]).code, 0);
      const removedKey = p.run(["rm", "FAL_KEY", "--from", "work-fal"]);
      assert.equal(removedKey.code, 0, removedKey.out);
      let vault = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.equal(vault.has("work-fal", "FAL_KEY"), false);
      assert.ok(vault.hasSet("work-fal"), "removing the key also removed the set");

      assert.equal(p.run(["add", "OTHER_KEY=v", "--to", "work-fal"]).code, 0);
      const removedSet = p.run(["rm", "work-fal", "--yes"]);
      assert.equal(removedSet.code, 0, removedSet.out);
      vault = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.equal(vault.hasSet("work-fal"), false, "the set survived `rm <set> --yes`");
    } finally {
      p.cleanup();
    }
  });

  test("a name that is both a key and a set refuses and asks for --from", () => {
    const p = project();
    try {
      // "shared" is both a set name and, once this runs, a key inside "other"
      // — a key name cannot contain a "-", which is why this is not "work-fal".
      assert.equal(p.run(["add", "FAL_KEY=v", "--to", "shared"]).code, 0);
      assert.equal(p.run(["add", "shared=v", "--to", "other"]).code, 0);

      const r = p.run(["rm", "shared"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /both a key and a set/);
      assert.match(r.out, /--from/);
    } finally {
      p.cleanup();
    }
  });
});
