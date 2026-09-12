/**
 * The policy checks shared by the CLI and the MCP server. The surface tests
 * prove each surface calls them; this file pins what the checks themselves
 * mean, where that is not obvious from one call site.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { DEFAULT_POLICY } from "../src/mcp.ts";
import { checkScopes } from "../src/policy.ts";

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
