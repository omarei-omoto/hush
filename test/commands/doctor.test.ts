/**
 * `hush doctor`.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { biometryStatus } from "../../src/biometry.ts";
import { spawnSync } from "node:child_process";
import { CLI, project } from "../helpers/cli.ts";

describe("hush doctor reports the whole setup", () => {
  test("it lists every set once, marking the ones this project uses", () => {
    // doctor used to print environments and service accounts as two lists —
    // the same two-vocabulary confusion `hush ls` had. A set is a set.
    const p = project();
    assert.equal(p.run(["add", "PROD_KEY=v", "--to", "prod"]).code, 0);
    assert.equal(p.run(["add", "fal", "--as", "Personal fal", "--no-use"], "v\n").code, 0);

    const out = p.run(["doctor"]).out;
    const line = out.match(/sets\s+(.*)/)?.[1] ?? "";
    assert.match(line, /default ●/, `default is the floor, so it is used: "${line}"`);
    assert.match(line, /prod ●/, `a set made from inside the project is used: "${line}"`);
    assert.match(line, /personal-fal(?! ●)/, `a --no-use set must not be marked: "${line}"`);
    assert.ok(!/environments|service accounts/.test(out), "the old two-list vocabulary is back");
    p.cleanup();
  });

  test("it reports the policy actually in force", () => {
    const p = project();
    assert.match(p.run(["doctor"]).out, /approval required\s+run, add, reveal, request/);
    writeFileSync(join(p.root, ".hush", "policy.json"), JSON.stringify({ requireApproval: [] }));
    assert.match(p.run(["doctor"]).out, /nothing is gated/);
    p.cleanup();
  });

  test("it reports whether a user-level policy floor exists", () => {
    const p = project();
    try {
      assert.match(p.run(["doctor"]).out, /policy floor\s+.*none/);
      writeFileSync(join(p.home, "policy.json"), JSON.stringify({ requireApproval: ["run"] }));
      const out = p.run(["doctor"]).out;
      assert.match(out, /policy floor/);
      assert.ok(!/policy floor\s+.*none/.test(out), "a floor file was present but doctor still reported none");
    } finally {
      p.cleanup();
    }
  });

  test("it flags a repo attempt to weaken the user's floor", () => {
    const p = project();
    try {
      // A floor that never mentions unsafeAllowCommands defaults to allowing
      // none of it — the repo's request below is exactly what the fix (only
      // the user's own file can lower the floor) refuses.
      writeFileSync(join(p.home, "policy.json"), JSON.stringify({ requireApproval: ["run"] }));
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ unsafeAllowCommands: ["node"] }));
      const out = p.run(["doctor"]).out;
      assert.match(out, /unsafeAllowCommands: node — ignored, below your floor/);
    } finally {
      p.cleanup();
    }
  });

  test("biometry is only ticked when it is actually enforced", { skip: biometryStatus().available ? false : "no biometry on this host" }, () => {
    // Must run with biometry genuinely available, or "preferred" and "required"
    // both come out unticked and the test proves nothing.
    const p = project();
    const withBiometry = (policy: Record<string, unknown>) => {
      writeFileSync(join(p.root, ".hush", "policy.json"), JSON.stringify(policy));
      const env: NodeJS.ProcessEnv = { ...process.env, HUSH_HOME: p.home, HUSH_NO_NUDGE: "1", NO_COLOR: "1" };
      delete env.HUSH_BIOMETRY; // let the real check run
      const r = spawnSync(process.execPath, [CLI, "doctor"], {
        cwd: p.root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
      });
      const out = (r.stdout ?? "") + (r.stderr ?? "");
      return out.split("\n").find((l) => l.includes("biometry")) ?? "";
    };

    const preferred = withBiometry({ biometry: "preferred" });
    assert.ok(!preferred.includes("✓"), `ticked a policy that still allows a click: ${preferred}`);
    assert.match(preferred, /a click still works/);

    const required = withBiometry({ biometry: "required" });
    assert.ok(required.includes("✓"), `did not tick an enforced policy: ${required}`);
    p.cleanup();
  });

  test("it shows where you are on the ladder and what is next", () => {
    const p = project();
    const out = p.run(["doctor"]).out;
    assert.match(out, /rung \d of 5/);
    assert.match(out, /next:/);
    assert.match(out, /hush secure/);
    p.cleanup();
  });

  test("it never prints a secret value", () => {
    const p = project();
    const out = p.run(["doctor"]).out;
    assert.ok(!out.includes("sk_live_cli"), "doctor leaked a value");
    p.cleanup();
  });
});

describe("hush doctor in a folder that only uses library sets", () => {
  // Bites: a doctor that opens the vault unconditionally reports
  // "vault readable ✗ ENOENT" and stops before the policy checks.
  test("reports the missing vault as a state, not a failure, and still checks the policy", () => {
    const p = project();
    try {
      rmSync(join(p.hushDir, "vault.json"));
      writeFileSync(join(p.hushDir, "envs.json"), JSON.stringify({ use: [] }));
      const r = p.run(["doctor"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /no vault yet/, r.out);
      assert.match(r.out, /policy floor/, "the checks after the vault were skipped");
      assert.doesNotMatch(r.out, /ENOENT|vault readable/);
    } finally {
      p.cleanup();
    }
  });
});
