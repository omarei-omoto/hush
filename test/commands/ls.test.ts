/**
 * `hush ls`.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { project } from "../helpers/cli.ts";

describe("hush ls treats every set the same, slash or not", () => {
  // Sets unified environments and service accounts into one vocabulary, so
  // the old split view ("environments" vs "other envs" holding accounts) is
  // gone — a name with a "/" in it is listed exactly like any other set. This
  // replaces the old "account scopes are not listed as environments" test,
  // which asserted the opposite of what the unified model intends.
  test("a slash-named set (an old service account) appears in THIS PROJECT like any other set", () => {
    const p = project();
    p.run(["set", "PROD_KEY", "--env", "prod"], "prod-value\n");
    p.run(["add", "fal", "--account", "personal", "--vars", "FAL_KEY"], "fal-value\n");

    const out = p.run(["ls"]).out;
    assert.match(out, /\(prod\)/, `expected the "prod" set in:\n${out}`);
    assert.match(out, /\(fal\/personal\)/, `expected "fal/personal" listed like any other set:\n${out}`);

    // And `hush ls fal/personal` shows its key names, never values.
    const detail = p.run(["ls", "fal/personal"]).out;
    assert.match(detail, /FAL_KEY/);
    assert.ok(!detail.includes("fal-value"), "a value leaked from `hush ls <set>`");
  });
});

describe("hush ls", () => {
  test("shows both sections with the ● marker for what this project uses", () => {
    const p = project();
    try {
      assert.equal(p.run(["global", "--create"]).code, 0);
      assert.equal(p.run(["add", "FAL_KEY=v", "--to", "work-fal", "--project"]).code, 0);
      assert.equal(p.run(["use", "work-fal"]).code, 0);

      const out = p.run(["ls"]).out;
      assert.match(out, /YOUR LIBRARY/);
      assert.match(out, /THIS PROJECT/);
      assert.match(out, /●[^\n]*work-fal/, `expected work-fal marked used:\n${out}`);
    } finally {
      p.cleanup();
    }
  });

  test("hush ls <set> lists key names and never values", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=a_live_value", "--to", "work-fal"]).code, 0);
      const out = p.run(["ls", "work-fal"]).out;
      assert.match(out, /FAL_KEY/);
      assert.ok(!out.includes("a_live_value"), "a value leaked from `hush ls <set>`");
    } finally {
      p.cleanup();
    }
  });
});
