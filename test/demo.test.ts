/**
 * The demo repository (D-2, examples/hush-demo, made by scripts/make-demo.mjs)
 * does what its README says, in a copy, from a machine that has never seen it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CLI } from "./helpers/cli.ts";

const demo = join(import.meta.dirname, "..", "examples", "hush-demo");

test("clone, set the published identity, hush run: the output is exactly what the README shows", () => {
  const dir = mkdtempSync(join(tmpdir(), "hush-demo-"));
  const home = mkdtempSync(join(tmpdir(), "hush-demo-home-"));
  cpSync(demo, dir, { recursive: true });
  const env = {
    ...process.env, HUSH_HOME: home, HOME: home, HUSH_NO_KEYCHAIN: "1", HUSH_NO_NUDGE: "1", NO_COLOR: "1",
    HUSH_IDENTITY: readFileSync(join(dir, "DEMO_IDENTITY.txt"), "utf8").trim(),
  };
  const hush = (...args: string[]) => spawnSync(process.execPath, [CLI, ...args], { cwd: dir, env, encoding: "utf8" });
  try {
    const readme = readFileSync(join(dir, "README.md"), "utf8");
    const shown = /```\n(Calling the demo API[\s\S]*?)```/.exec(readme)?.[1];
    assert.ok(shown, "the README no longer shows the output");

    const run = hush("run", "--", process.execPath, "app.js");
    assert.equal(run.status, 0, run.stdout + run.stderr);
    assert.equal(run.stdout, shown, "the demo's output is not what its README promises");
    assert.ok(!run.stdout.includes("demo_live_"), "the key reached the terminal");

    const staging = hush("run", "--use", "staging", "--", process.execPath, "app.js");
    assert.equal(staging.status, 0, staging.stdout + staging.stderr);
    assert.match(staging.stdout, /\[redacted:DEMO_API_KEY\]/);

    const verify = hush("verify");
    assert.equal(verify.status, 0, verify.stdout + verify.stderr);
    assert.match(verify.stdout + verify.stderr, /decryption\s+3 value/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  }
});
