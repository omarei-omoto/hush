/**
 * `hush level`: the security ladder, as the CLI shows it.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { project } from "../helpers/cli.ts";

describe("hush level", () => {
  test("reports a rung, the checklist, and a concrete next step", () => {
    const p = project();
    const { out } = p.run(["level"]);
    assert.match(out, /rung \d of 5/);
    assert.match(out, /secrets are encrypted at rest/);
    assert.match(out, /Next/);
    p.cleanup();
  });

  test("a stray .env caps you at rung 0 no matter what else passes", () => {
    const p = project();
    writeFileSync(join(p.root, ".env"), "FOO=bar\n");
    assert.match(p.run(["level"]).out, /rung 0 of 5/);
    rmSync(join(p.root, ".env"));
    assert.ok(!/rung 0 of 5/.test(p.run(["level"]).out), "removing the .env did not raise the rung");
    p.cleanup();
  });

  test("--json is machine readable", () => {
    const p = project();
    const parsed = JSON.parse(p.run(["level", "--json"]).out) as { rung: number; checks: unknown[] };
    assert.equal(typeof parsed.rung, "number");
    assert.equal(parsed.checks.length, 7);
    p.cleanup();
  });

  test("high-value key names are surfaced, but never their values", () => {
    const p = project();
    const { out } = p.run(["level"]);
    assert.match(out, /STRIPE_SECRET_KEY/);
    assert.ok(!out.includes("sk_live_cli"), "a value leaked into the ladder output");
    p.cleanup();
  });
});
