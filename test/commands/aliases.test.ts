/**
 * Deprecated aliases keep working, each with a one-line notice.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { Vault } from "../../src/vault.ts";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import { project } from "../helpers/cli.ts";

describe("deprecated aliases keep working, each with a one-line notice", () => {
  test("`hush set` behaves like `hush add KEY=value`", () => {
    const p = project();
    try {
      const r = p.run(["set", "PLAIN_KEY=v"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /`hush set` is deprecated/);
      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.ok(vault.has("default", "PLAIN_KEY"));
    } finally {
      p.cleanup();
    }
  });

  test("`hush accounts` behaves like `hush ls`", () => {
    const p = project();
    try {
      const r = p.run(["accounts"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /`hush accounts` is deprecated/);
      assert.match(r.out, /THIS PROJECT/);
    } finally {
      p.cleanup();
    }
  });

  test("`hush envs` and `hush env` behave like `hush ls`", () => {
    const p = project();
    try {
      for (const args of [["envs"], ["env"]]) {
        const r = p.run(args);
        assert.equal(r.code, 0, r.out);
        assert.match(r.out, /is deprecated/);
        assert.match(r.out, /THIS PROJECT/);
      }
    } finally {
      p.cleanup();
    }
  });

  test("`hush env use` and `hush env drop` behave like `hush use` / `hush use --not`", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=v", "--to", "work-fal"]).code, 0);
      const used = p.run(["env", "use", "work-fal"]);
      assert.equal(used.code, 0, used.out);
      assert.match(used.out, /`hush env use` is deprecated/);
      assert.deepEqual((JSON.parse(readFileSync(join(p.hushDir, "envs.json"), "utf8")) as { use: string[] }).use, ["work-fal"]);

      const dropped = p.run(["env", "drop", "work-fal"]);
      assert.equal(dropped.code, 0, dropped.out);
      assert.match(dropped.out, /`hush env drop` is deprecated/);
      assert.deepEqual((JSON.parse(readFileSync(join(p.hushDir, "envs.json"), "utf8")) as { use: string[] }).use, []);
    } finally {
      p.cleanup();
    }
  });

  test("`--with a:b` aliases to `--use a/b`", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=v", "--to", "fal/acme"]).code, 0);
      const r = p.run(["export", "--names", "--with", "fal:acme"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /--with fal:acme is deprecated/);
      assert.match(r.out, /FAL_KEY/);
    } finally {
      p.cleanup();
    }
  });
});
