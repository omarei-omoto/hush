/**
 * `hush scan`.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { project } from "../helpers/cli.ts";

describe("hush scan reconciles against every used set, not just the literal env", () => {
  test("a key a used library set provides is no longer reported missing", () => {
    const p = project(); // has a vault of its own
    try {
      assert.equal(p.run(["global", "--create"]).code, 0);
      writeFileSync(join(p.root, ".env.fal"), "FAL_KEY=v\n");
      assert.equal(p.run(["add", ".env.fal", "--as", "Work fal", "--library", "--no-use"]).code, 0);
      assert.equal(p.run(["use", "work-fal"]).code, 0);
      writeFileSync(join(p.root, "index.js"), "process.env.FAL_KEY;\n");

      const out = p.run(["scan"]).out;
      assert.match(out, /0 missing/, `FAL_KEY reported missing:\n${out}`);
      assert.ok(!/^\s*FAL_KEY\s/m.test(out.split("Missing:")[1] ?? ""), `FAL_KEY listed under Missing:\n${out}`);
    } finally {
      p.cleanup();
    }
  });
});
