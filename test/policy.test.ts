/**
 * The policy checks shared by the CLI and the MCP server. The surface tests
 * prove each surface calls them; this file pins what the checks themselves
 * mean, where that is not obvious from one call site.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { DEFAULT_POLICY } from "../src/mcp.ts";
import { checkScopes, runScope, approvalCoverageLine, mergePolicies, policyWeakenings } from "../src/policy.ts";

describe("checkScopes", () => {
  // Bites: matching only the full layer name makes allowEnvs: ["work-fal"]
  // refuse the very set it names whenever that set lives in the library.
  test("allowEnvs matches a library layer by the set's plain name", () => {
    const policy = { ...DEFAULT_POLICY, allowEnvs: ["default", "work-fal"] };
    assert.doesNotThrow(() => checkScopes(policy, ["default", "main:work-fal"]));
    assert.doesNotThrow(() => checkScopes(policy, ["default", "my:vault:work-fal"]));
    assert.throws(() => checkScopes(policy, ["default", "main:personal-fal"]), /Policy forbids agent access to "main:personal-fal"/);
  });

  test("an empty allowEnvs allows every set", () => {
    assert.doesNotThrow(() => checkScopes({ ...DEFAULT_POLICY, allowEnvs: [] }, ["anything", "lib:whatever"]));
  });
});

describe("runScope", () => {
  // Bites: scoping only by the sets is exactly the bug this function fixes —
  // "Allow 15 min" for one command silently covering every other allowed
  // command sharing those sets.
  test('"command" (the default) names the command\'s basename, not the whole path, plus the sets', () => {
    const policy = { ...DEFAULT_POLICY, approvalScope: "command" as const };
    assert.equal(runScope(policy, "npm", ["default"]), "run:npm:default");
    assert.equal(runScope(policy, "/usr/local/bin/npm", ["default", "work-fal"]), "run:npm:default+work-fal");
  });

  test('"sets" reproduces the pre-existing, command-agnostic shape', () => {
    const policy = { ...DEFAULT_POLICY, approvalScope: "sets" as const };
    assert.equal(runScope(policy, "npm", ["default"]), "run:default");
    assert.equal(runScope(policy, "git", ["default"]), "run:default", "different commands must collide under \"sets\"");
  });
});

describe("approvalCoverageLine", () => {
  test('names the command\'s basename under "command" scope', () => {
    const policy = { ...DEFAULT_POLICY, approvalScope: "command" as const };
    assert.equal(approvalCoverageLine(policy, "/usr/bin/npm", ["default"]), "Allow 15 min covers:  npm with default");
  });

  test('says "any command" under "sets" scope, and lists every set', () => {
    const policy = { ...DEFAULT_POLICY, approvalScope: "sets" as const };
    assert.equal(
      approvalCoverageLine(policy, "npm", ["default", "work-fal"]),
      "Allow 15 min covers:  any command with default, work-fal",
    );
  });
});

describe("mergePolicies", () => {
  const base = DEFAULT_POLICY;

  test("denyCommands is the union of the built-in floor, the user's floor, and the repo file", () => {
    const merged = mergePolicies(base, { denyCommands: ["floorcmd"] }, { denyCommands: ["repocmd"] });
    assert.ok(merged.denyCommands.includes("node"), "the built-in floor was dropped");
    assert.ok(merged.denyCommands.includes("floorcmd"), "the user's floor addition was dropped");
    assert.ok(merged.denyCommands.includes("repocmd"), "the repo's addition was dropped");
  });

  test("unsafeAllowCommands only exempts an entry both the floor and the repo name", () => {
    const both = mergePolicies(base, { unsafeAllowCommands: ["node"] }, { unsafeAllowCommands: ["node", "bash"] });
    assert.deepEqual(both.unsafeAllowCommands, ["node"]);
    assert.ok(!both.denyCommands.includes("node"), "an entry both files agreed on was still denied");
    assert.ok(both.denyCommands.includes("bash"), "an entry the floor did not also list was exempted anyway");

    // The case this whole change exists for: a repo file, on its own, cannot
    // reopen anything — only the user's own floor can lower the floor.
    const repoOnly = mergePolicies(base, {}, { unsafeAllowCommands: ["node"] });
    assert.deepEqual(repoOnly.unsafeAllowCommands, []);
    assert.ok(repoOnly.denyCommands.includes("node"), "a repo-only entry with no floor support was honoured");
  });

  test("allowCommands: a non-empty floor narrows the repo's list to the overlap", () => {
    const narrowed = mergePolicies(base, { allowCommands: ["npm", "git"] }, { allowCommands: ["npm", "curl"] });
    assert.deepEqual(narrowed.allowCommands, ["npm"]);
  });

  test("allowCommands: an empty or absent floor lets the repo's list apply as today", () => {
    assert.deepEqual(mergePolicies(base, {}, { allowCommands: ["npm"] }).allowCommands, ["npm"]);
    assert.deepEqual(mergePolicies(base, { allowCommands: [] }, { allowCommands: ["npm"] }).allowCommands, ["npm"]);
  });

  test("allowEnvs follows the same narrow-only rule as allowCommands", () => {
    const narrowed = mergePolicies(base, { allowEnvs: ["default"] }, { allowEnvs: ["default", "prod"] });
    assert.deepEqual(narrowed.allowEnvs, ["default"]);
  });

  test("denyKeys is a union: the repo can add, never drop, what the floor denies", () => {
    const merged = mergePolicies(base, { denyKeys: ["FLOOR_KEY"] }, { denyKeys: ["REPO_KEY"] });
    assert.deepEqual(merged.denyKeys.sort(), ["FLOOR_KEY", "REPO_KEY"]);
  });

  test("requireApproval is a union: the repo can add actions, never remove one the floor requires", () => {
    const merged = mergePolicies(base, { requireApproval: ["run"] }, { requireApproval: [] });
    assert.deepEqual(merged.requireApproval, ["run"], "the repo dropped an action the floor requires");

    const noFloor = mergePolicies(base, {}, { requireApproval: [] });
    assert.deepEqual(noFloor.requireApproval, [], "an absent floor forced the base defaults back on");
  });

  test("maxRunMs and approvalTtlSeconds take the smaller of the floor and the repo", () => {
    const merged = mergePolicies(base, { maxRunMs: 5000, approvalTtlSeconds: 60 }, { maxRunMs: 9000, approvalTtlSeconds: 30 });
    assert.equal(merged.maxRunMs, 5000);
    assert.equal(merged.approvalTtlSeconds, 30);

    // Neither can be raised past the floor by a repo that just does not ask.
    assert.equal(mergePolicies(base, { maxRunMs: 5000 }, {}).maxRunMs, 5000);
  });

  test("approvalTimeoutSeconds: the repo's value wins even over the floor's", () => {
    const merged = mergePolicies(base, { approvalTimeoutSeconds: 10 }, { approvalTimeoutSeconds: 300 });
    assert.equal(merged.approvalTimeoutSeconds, 300, "a longer wait is not a weakening, so the repo should win");
  });

  test("biometry: the stricter of the floor and the repo wins, either direction", () => {
    assert.equal(mergePolicies(base, { biometry: "required" }, { biometry: "off" }).biometry, "required");
    assert.equal(mergePolicies(base, { biometry: "off" }, { biometry: "required" }).biometry, "required");
  });

  test('approvalScope: "command" is stricter than "sets" and wins either direction', () => {
    assert.equal(mergePolicies(base, { approvalScope: "command" }, { approvalScope: "sets" }).approvalScope, "command");
    assert.equal(mergePolicies(base, { approvalScope: "sets" }, { approvalScope: "command" }).approvalScope, "command");
  });

  test("an absent floor reproduces today's plain repo-over-defaults merge", () => {
    // Every field except unsafeAllowCommands (see its own test above) should
    // come out exactly as the old two-way `{...DEFAULT_POLICY, ...repo}` did.
    const repo = { allowEnvs: ["dev"], requireApproval: [], biometry: "off" as const, maxRunMs: 5000 };
    const merged = mergePolicies(base, {}, repo);
    assert.deepEqual(merged.allowEnvs, ["dev"]);
    assert.deepEqual(merged.requireApproval, []);
    assert.equal(merged.biometry, "off");
    assert.equal(merged.maxRunMs, 5000);
  });
});

describe("policyWeakenings", () => {
  test("names a repo unsafeAllowCommands entry the floor did not also list", () => {
    const lines = policyWeakenings({}, { unsafeAllowCommands: ["node"] });
    assert.match(lines.join("\n"), /unsafeAllowCommands: node.*ignored, below your floor/);
  });

  test("says nothing when the repo asks for no more than the floor allows", () => {
    assert.deepEqual(policyWeakenings({ unsafeAllowCommands: ["node"] }, { unsafeAllowCommands: ["node"] }), []);
    assert.deepEqual(policyWeakenings({}, {}), []);
  });

  test("names an allowCommands entry outside a non-empty floor", () => {
    const lines = policyWeakenings({ allowCommands: ["npm"] }, { allowCommands: ["npm", "curl"] });
    assert.match(lines.join("\n"), /allowCommands: curl — ignored, outside your floor/);
  });

  test("names a requireApproval action the repo tried to drop", () => {
    const lines = policyWeakenings({ requireApproval: ["run"] }, { requireApproval: [] });
    assert.match(lines.join("\n"), /requireApproval: run — ignored, your floor requires it/);
  });

  test("names a biometry downgrade attempt", () => {
    const lines = policyWeakenings({ biometry: "required" }, { biometry: "off" });
    assert.match(lines.join("\n"), /biometry: off — ignored, below your floor of required/);
  });

  test("names an approvalScope downgrade attempt", () => {
    const lines = policyWeakenings({ approvalScope: "command" }, { approvalScope: "sets" });
    assert.match(lines.join("\n"), /approvalScope: sets — ignored, below your floor of command/);
  });
});

describe("approvalCoverageLine names the policy's own TTL", () => {
  // Bites: a hardcoded "15 min" lies as soon as approvalTtlSeconds is changed.
  test("an hour-long TTL says so", () => {
    const line = approvalCoverageLine({ ...DEFAULT_POLICY, approvalTtlSeconds: 3600 }, "npm", ["default"]);
    assert.match(line, /^Allow 1 hr covers:/);
  });
});
