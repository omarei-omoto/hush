/**
 * The CLI enforces .hush/policy.json — an agent's shell must not bypass what the MCP server enforces.
 */
import { writePolicies } from "../helpers/policy.ts";
import { test, describe } from "node:test";
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync, symlinkSync, chmodSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";
import { runScope } from "../../src/policy.ts";
import { DEFAULT_POLICY } from "../../src/mcp.ts";
import { requestApproval, clearApprovalCache } from "../../src/approval.ts";
import { tmpdir } from "node:os";
import { CLI, clickingAllow, project } from "../helpers/cli.ts";
import { spawnSync } from "node:child_process";

describe("the CLI enforces .hush/policy.json — an agent's shell must not bypass what the MCP server enforces", () => {
  // The project fixture runs with HUSH_NO_DIALOG=1, so an enforced approval has
  // nothing to show and is refused outright. That is the point of most of these
  // tests — the gate holds with no human present — and it is also why none of
  // them can pop a real macOS dialog on the developer's screen.

  test("reveal denied by biometry: `hush get --yes` still refuses", () => {
    const p = project();
    try {
      writePolicies(p.home, p.root, { requireApproval: ["reveal"], biometry: "required", approvalTimeoutSeconds: 1 });
      const r = p.run(["get", "STRIPE_SECRET_KEY", "--yes"]);
      assert.equal(r.code, 1, r.out);
      assert.ok(!r.out.includes("sk_live_cli"), `a credential leaked past a denied approval:\n${r.out}`);
      assert.match(r.out, /biometry|denied/i);
    } finally {
      p.cleanup();
    }
  });

  // Red team, 2026-09-12: grants.local.json lives inside .hush/, which an
  // agent has ordinary write access to — it is not the user-level floor. It
  // used to be trusted unconditionally as proof a human already approved,
  // for every action including "reveal" and "add". An agent could write its
  // own future-dated entry for the exact scope string it was about to need
  // (every shape is documented in policy.ts and this file's own comments)
  // and skip approval entirely, including a policy that requires biometry.
  // "run" keeps using this cache deliberately (see the tests above) — the
  // fix is that "reveal" (hands back plaintext) and "add" (writes a secret
  // the agent itself supplied, unreviewed) never consult it.
  test("a forged reveal grant on disk is never honoured, even with biometry required", () => {
    const p = project();
    try {
      writePolicies(p.home, p.root, { requireApproval: ["reveal"], biometry: "required", approvalTimeoutSeconds: 1 });
      // Exactly the scope string cmdGet computes for this key and env.
      writeFileSync(
        join(p.hushDir, "grants.local.json"),
        JSON.stringify({ "reveal:default/STRIPE_SECRET_KEY": Date.now() + 3_600_000 }),
      );
      const r = p.run(["get", "STRIPE_SECRET_KEY", "--yes"]);
      assert.equal(r.code, 1, r.out);
      assert.ok(!r.out.includes("sk_live_cli"), `a forged grants.local.json leaked a credential:\n${r.out}`);
    } finally {
      p.cleanup();
    }
  });

  // Bites: with run grants read from disk regardless of biometry, the forged
  // entry below lets the command run with no fingerprint and no prompt.
  test("with biometry required, a forged run grant on disk is never honoured either", () => {
    const p = project();
    try {
      writePolicies(p.home, p.root, { requireApproval: ["run"], biometry: "required", approvalTimeoutSeconds: 1 });
      // Exactly the scope runScope() computes for this command and this project's sets.
      writeFileSync(
        join(p.hushDir, "grants.local.json"),
        JSON.stringify({ "run:npm:default": Date.now() + 3_600_000 }),
      );
      const r = p.run(["run", "--", "npm", "--version"]);
      assert.equal(r.code, 1, `a forged grant stood in for a fingerprint:\n${r.out}`);
    } finally {
      p.cleanup();
    }
  });

  test("a forged add grant on disk is never honoured — an agent cannot pre-approve planting its own secret", () => {
    const p = project();
    try {
      writePolicies(p.home, p.root, { requireApproval: ["add"], biometry: "required", approvalTimeoutSeconds: 1 });
      // Exactly the scope string cmdAddKeyValue computes for this key and set.
      writeFileSync(
        join(p.hushDir, "grants.local.json"),
        JSON.stringify({ "add:default/PLANTED_KEY": Date.now() + 3_600_000 }),
      );
      const r = p.run(["add", "PLANTED_KEY=malicious-value", "--to", "default"]);
      assert.equal(r.code, 1, r.out);

      const meta = JSON.parse(p.run(["ls", "default", "--json"]).out) as { keys: string[] };
      assert.ok(!meta.keys.includes("PLANTED_KEY"), "a forged grants.local.json let an unapproved secret get planted");
    } finally {
      p.cleanup();
    }
  });

  test("export is gated as reveal; --names is not, because it reveals nothing", () => {
    const p = project();
    try {
      writePolicies(p.home, p.root, { requireApproval: ["reveal"], biometry: "required", approvalTimeoutSeconds: 1 });
      const exported = p.run(["export"]);
      assert.equal(exported.code, 1, exported.out);
      assert.ok(!exported.out.includes("sk_live_cli"), `export leaked a value past a denied approval:\n${exported.out}`);

      const names = p.run(["export", "--names"]);
      assert.equal(names.code, 0, names.out);
      assert.match(names.out, /STRIPE_SECRET_KEY/);
    } finally {
      p.cleanup();
    }
  });

  test("allowCommands is a whitelist enforced by the CLI too", () => {
    // "sh" would be refused by the built-in deny floor regardless of
    // allowCommands (it is one of the built-in denyCommands), which would
    // test the wrong mechanism. "git" is not on that floor, so refusing it
    // can only be allowCommands doing its job.
    const p = project();
    try {
      writePolicies(p.home, p.root, { requireApproval: [], allowCommands: ["npm"] });

      const refused = p.run(["run", "--", "git", "--version"]);
      assert.equal(refused.code, 1, refused.out);
      assert.match(refused.out, /allowCommands/);

      const allowed = p.run(["run", "--quiet", "--", "npm", "--version"]);
      assert.equal(allowed.code, 0, allowed.out);
    } finally {
      p.cleanup();
    }
  });

  test("pass-through is refused by allowCommands exactly like `hush run --`", () => {
    // Pass-through (`hush <cmd>` with no `run --`) has to route through the
    // same gate `hush run` does, or it would be a way around a policy an
    // agent's other tools were already refused by.
    const p = project();
    try {
      writePolicies(p.home, p.root, { requireApproval: [], allowCommands: ["npm"] });

      const refused = p.run(["echo", "hi"]);
      assert.equal(refused.code, 1, refused.out);
      assert.match(refused.out, /allowCommands/);
      assert.ok(!refused.out.includes("hi"), "the command ran despite being refused");
    } finally {
      p.cleanup();
    }
  });

  // The deny list is for the agent's MCP tools (see mcp.test.ts). In a
  // terminal it turns into a warning on the approval prompt, the way
  // `op run` asks rather than refuses: an agent shelling out to `hush run`
  // still has to get past a dialog it cannot click.
  test("an interpreter goes to the approval prompt, not a flat refusal", () => {
    const p = project();
    try {
      writePolicies(p.home, p.root, { requireApproval: ["run"], approvalTimeoutSeconds: 1 });
      const gated = p.run(["run", "--", "sh", "-c", "echo RAN"]);
      assert.equal(gated.code, 1, gated.out);
      assert.match(gated.out, /Approval denied/, "not routed through the approval gate");
      assert.doesNotMatch(gated.out, /denied by default/);
      assert.ok(!gated.out.includes("RAN"), "ran without an approval");

      // No approval asked for: the person opted out, and their command runs.
      writePolicies(p.home, p.root, { requireApproval: [] });
      const open = p.run(["run", "--quiet", "--", "sh", "-c", "echo RAN"]);
      assert.equal(open.code, 0, open.out);
      assert.match(open.out, /RAN/);
    } finally {
      p.cleanup();
    }
  });

  test("allowEnvs restricts `hush run` to the environments named", () => {
    const p = project();
    try {
      writePolicies(p.home, p.root, { requireApproval: [], allowEnvs: ["default"] });
      assert.equal(p.run(["set", "K", "--env", "prod"], "secret_value_1234\n").code, 0);

      const r = p.run(["run", "--env", "prod", "--", "npm", "--version"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /Policy forbids/);
    } finally {
      p.cleanup();
    }
  });

  test("run gated by requireApproval times out with nothing spawned", () => {
    const p = project();
    try {
      writePolicies(p.home, p.root, { requireApproval: ["run"], approvalTimeoutSeconds: 1 });
      const r = p.run(["run", "--", "echo", "RAN"]);
      assert.equal(r.code, 1, r.out);
      assert.ok(!r.out.includes("RAN"), `the command ran despite a timed-out approval:\n${r.out}`);
    } finally {
      p.cleanup();
    }
  });

  test("a grant written by an earlier process is not honoured", () => {
    // "Allow 15 min" used to be mirrored into .hush/grants.local.json so the
    // next `hush` process could reuse it. That file sits in the project, which
    // an agent can write, so it was a way to approve yourself. Nothing reads
    // it now — the key below is spelled exactly as the real one would be, and
    // it changes nothing.
    const p = project();
    try {
      writePolicies(p.home, p.root, { requireApproval: ["run"], approvalTimeoutSeconds: 1 });
      const grantsPath = join(p.hushDir, "grants.local.json");

      // Exactly what runScope() computes for a plain, default-env `echo` run
      // under the default approvalScope: "command" — the same key mcp.ts's
      // hush_run builds. Computed rather than typed, so the test cannot drift
      // from the implementation.
      const echoScope = runScope(DEFAULT_POLICY, "echo", ["default"]);
      writeFileSync(grantsPath, JSON.stringify({ [echoScope]: Date.now() + 60_000 }));
      const live = p.run(["run", "--", "echo", "RAN"]);
      assert.equal(live.code, 1, live.out);
      assert.ok(!live.out.includes("RAN"), `a project file pre-authorised a run:\n${live.out}`);
    } finally {
      p.cleanup();
    }
  });

  test("with no policy file at all, the CLI is unchanged — the gate is opt-in, not a default refusal", () => {
    const p = project();
    try {
      assert.ok(!existsSync(join(p.hushDir, "policy.json")), "test fixture drifted: a policy file exists");
      assert.match(p.run(["get", "STRIPE_SECRET_KEY", "--yes"]).out, /sk_live_cli/);
      assert.match(p.run(["run", "--", "echo", "RAN"]).out, /RAN/);
    } finally {
      p.cleanup();
    }
  });

  test("a user-level policy floor alone gates `hush run`, with no repo policy.json at all", () => {
    // The whole point of a floor outside the repo: it must work even for a
    // project that has never opted into .hush/policy.json.
    const p = project();
    try {
      assert.ok(!existsSync(join(p.hushDir, "policy.json")), "test fixture drifted: a repo policy file exists");
      writeFileSync(join(p.home, "policy.json"), JSON.stringify({ requireApproval: ["run"], approvalTimeoutSeconds: 1 }));
      const r = p.run(["run", "--", "echo", "RAN"]);
      assert.equal(r.code, 1, r.out);
      assert.ok(!r.out.includes("RAN"), `the command ran despite no answer to the floor's approval prompt:\n${r.out}`);
    } finally {
      p.cleanup();
    }
  });

  test("a grant file cannot stand in for an approval, whatever scope shape it uses", () => {
    // Both shapes are exercised here: the default "command" scope and the
    // wider "sets" one. Neither is read from disk any more — the scope-shape
    // itself is covered by policy.test.ts's runScope tests.
    for (const approvalScope of ["command", "sets"] as const) {
      const p = project();
      try {
        writePolicies(p.home, p.root, { requireApproval: ["run"], approvalScope, approvalTimeoutSeconds: 1 });
        writeFileSync(
          join(p.hushDir, "grants.local.json"),
          JSON.stringify({
            [runScope({ ...DEFAULT_POLICY, approvalScope }, "npm", ["default"])]: Date.now() + 60_000,
          }),
        );
        const r = p.run(["run", "--", "npm", "--version"]);
        assert.equal(r.code, 1, `approvalScope ${approvalScope}: a grant file pre-authorised a run\n${r.out}`);
      } finally {
        p.cleanup();
      }
    }
  });

  test("a run with requireApproval on and nothing to answer it does not run", () => {
    const p = project();
    try {
      writePolicies(p.home, p.root, { requireApproval: ["run"] });
      const r = p.run(["run", "--", "echo", "RAN"]);
      assert.equal(r.code, 1, r.out);
      assert.ok(!r.out.includes("RAN"), `the command ran without an approval:\n${r.out}`);
    } finally {
      p.cleanup();
    }
  });

  test("an approval writes no grants file at all, in any location", async () => {
    // The file this test used to check the permissions of is gone. It lived in
    // the project, which an agent can write, so "keep it 0600" was the wrong
    // fix: the answer is that there is nothing there to read or steal. A
    // session approval now lasts exactly as long as this process does.
    clearApprovalCache();
    const dir = mkdtempSync(join(tmpdir(), "hush-cli-grants-"));
    try {
      process.env.DISPLAY = ":0";
      process.env.FAKE_EXIT = "1"; // zenity's extra button: "Allow 15 min"
      process.env.FAKE_STDOUT = "Allow 15 min";
      const r = await requestApproval(dir, {
        action: "run", summary: "Run: echo RAN", scope: runScope(DEFAULT_POLICY, "echo", ["default"]),
        ttlSeconds: 900, timeoutMs: 5000,
      }, clickingAllow);
      assert.equal(r.decision, "session", "the fixture dialog did not return a session approval");

      assert.deepEqual(
        readdirSync(dir),
        [],
        "an approval left something behind in the directory it was asked from",
      );
      // And the grant is in memory only, so a second process would ask again.
      clearApprovalCache(); // what a fresh `hush` process sees: nothing
      const restarted = await requestApproval(dir, {
        action: "run", summary: "Run: echo RAN", scope: runScope(DEFAULT_POLICY, "echo", ["default"]),
        ttlSeconds: 900, timeoutMs: 200,
      }, { authenticate: async () => "unavailable" as const, platform: () => "linux" });
      assert.equal(restarted.cached, false, "a grant survived its process");
    } finally {
      delete process.env.DISPLAY;
      delete process.env.FAKE_EXIT;
      delete process.env.FAKE_STDOUT;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // Red team, 2026-09-12: grants.local.json lived inside .hush/, which an
  // agent confined to the project can write to, and writeFileSync/chmodSync
  // follow symlinks by default — so a symlink planted there turned the next
  // legitimate approval into a rewrite of the user's policy floor. The write
  // is gone (see the test above), and this pins that a session approval still
  // touches nothing at that path, symlink or not.
  test("an approval writes nothing where grants.local.json used to be, even as a symlink", async () => {
    clearApprovalCache();
    const dir = mkdtempSync(join(tmpdir(), "hush-cli-symlink-"));
    try {
      const floorPath = join(dir, "floor.json");
      const floorBefore = JSON.stringify({ requireApproval: ["run", "add", "reveal"], denyCommands: ["node", "bash"] });
      writeFileSync(floorPath, floorBefore);

      const grantsPath = join(dir, "grants.local.json");
      symlinkSync(floorPath, grantsPath);

      // The human legitimately approves — this is not the attack, it is the
      // ordinary path a real session grant is written through.
      process.env.DISPLAY = ":0";
      process.env.FAKE_EXIT = "1";
      process.env.FAKE_STDOUT = "Allow 15 min";
      const r = await requestApproval(dir, {
        action: "run", summary: "Run: echo RAN", scope: runScope(DEFAULT_POLICY, "echo", ["default"]),
        ttlSeconds: 900, timeoutMs: 5000,
      }, clickingAllow);
      assert.equal(r.decision, "session");

      assert.equal(readFileSync(floorPath, "utf8"), floorBefore, "a legitimate approval clobbered the user's policy floor through a symlink");
    } finally {
      delete process.env.DISPLAY;
      delete process.env.FAKE_EXIT;
      delete process.env.FAKE_STDOUT;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("a repository cannot switch approvals off (review F4)", () => {
  test("a committed requireApproval: [] still asks; only this machine's choice turns it off", () => {
    const p = project();
    try {
      const script = join(p.root, "show.sh");
      writeFileSync(script, '#!/bin/sh\necho "ran"\n');
      chmodSync(script, 0o755);
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: [], biometry: "off", approvalScope: "sets" }));
      const gated = p.run(["run", "--", "./show.sh"]);
      assert.notEqual(gated.code, 0, `a repository's policy.json switched the approval off:\n${gated.out}`);
      assert.doesNotMatch(gated.out, /^ran$/m);
      writePolicies(p.home, p.root, { requireApproval: [] });
      const mine = p.run(["run", "--", "./show.sh"]);
      assert.equal(mine.code, 0, mine.out);
      assert.match(mine.out, /^ran$/m);
    } finally {
      p.cleanup();
    }
  });
});

describe("HUSH_HOME inside the repository (review F8)", () => {
  test("is refused, so a cloned project cannot hand hush a floor of its own", () => {
    const p = project();
    try {
      spawnSync("git", ["init", "-q"], { cwd: p.root });
      const inside = join(p.root, ".evil-home");
      const refused = spawnSync(process.execPath, [CLI, "ls"], { cwd: p.root, env: { ...p.env, HUSH_HOME: inside }, encoding: "utf8" });
      assert.equal(refused.status, 1, refused.stdout + refused.stderr);
      assert.match(refused.stderr, /HUSH_HOME .* is inside the repository/);
      assert.ok(!existsSync(inside), "hush wrote into a HUSH_HOME inside the repository");
      // Outside the repository it is honoured as ever.
      assert.equal(p.run(["ls"]).code, 0);
    } finally {
      p.cleanup();
    }
  });
});
