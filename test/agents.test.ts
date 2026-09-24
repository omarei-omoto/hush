/**
 * Registering hush with a coding agent.
 *
 * The bug these pin: every installer wrote Claude Code's file regardless of
 * which agent was in the room, so a Codex or Cursor user got a tick for a file
 * their agent never reads. There is one of these per agent now, and the merge
 * rules are pure functions so each shape can be checked without a filesystem.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";

import {
  AGENTS,
  mergeMcpJson,
  mergeMcpToml,
  renderMcp,
  skillDescription,
  stripFrontmatter,
} from "../src/agents.ts";

const entry = { command: "node", args: ["/usr/local/lib/hush/cli.ts", "mcp"] };

describe("the agent table", () => {
  test("every agent says where its MCP config lives and in which format", () => {
    const byId = Object.fromEntries(AGENTS.map((g) => [g.id, g]));
    assert.deepEqual(Object.keys(byId).sort(), ["claude-code", "codex", "cursor"]);

    // The paths are the documented ones. A wrong path here is the whole bug.
    assert.equal(
      byId["codex"].mcp.path("/proj", { HOME: "/home/me" }),
      "/home/me/.codex/config.toml",
    );
    assert.equal(byId["codex"].mcp.format, "toml");
    assert.equal(byId["claude-code"].mcp.path("/proj", { HOME: "/home/me" }), "/proj/.mcp.json");
    assert.equal(byId["cursor"].mcp.path("/proj", { HOME: "/home/me" }), "/proj/.cursor/mcp.json");

    // Codex reads skills from ~/.agents/skills and .agents/skills, not .codex/.
    assert.equal(byId["codex"].skill.project("/proj"), "/proj/.agents/skills/hush/SKILL.md");
    assert.equal(byId["codex"].skill.global?.({ HOME: "/home/me" }), "/home/me/.agents/skills/hush/SKILL.md");
    assert.equal(byId["claude-code"].skill.project("/proj"), "/proj/.claude/skills/hush/SKILL.md");
    // Cursor keeps rules in the repo and has no equivalent user-level file.
    assert.equal(byId["cursor"].skill.project("/proj"), "/proj/.cursor/rules/hush.mdc");
    assert.equal(byId["cursor"].skill.global, null);
  });

  test("each agent can say what to paste when hush cannot write the file", () => {
    for (const agent of AGENTS) {
      const line = agent.manual("/usr/local/lib/hush/cli.ts", "/proj");
      assert.ok(line.length > 10, `${agent.id} has no manual instruction`);
      assert.match(line, /hush|cli\.ts/, `${agent.id}'s instruction does not mention the path`);
    }
    assert.match(AGENTS.find((g) => g.id === "codex")!.manual("/x/cli.ts", "/proj"), /codex mcp add hush/);
  });
});

describe("merging into a JSON config (Claude Code, Cursor)", () => {
  test("creates the file when there is none", () => {
    const r = mergeMcpJson(null, "hush", entry);
    assert.ok(r.ok && r.changed);
    assert.deepEqual(JSON.parse(r.text), { mcpServers: { hush: entry } });
  });

  test("keeps every other server the user already had", () => {
    const before = JSON.stringify({ mcpServers: { other: { command: "npx", args: ["x"] } } }, null, 2);
    const r = mergeMcpJson(before, "hush", entry);
    assert.ok(r.ok && r.changed);
    const after = JSON.parse(r.text) as { mcpServers: Record<string, unknown> };
    assert.deepEqual(Object.keys(after.mcpServers).sort(), ["hush", "other"]);
    assert.deepEqual(after.mcpServers.other, { command: "npx", args: ["x"] });
  });

  test("leaves an existing hush entry exactly as it is", () => {
    // It may point at a wrapper the user wrote on purpose. Rewriting it would be
    // worse than saying "already registered".
    const before = JSON.stringify({ mcpServers: { hush: { command: "my-wrapper", args: [] } } });
    const r = mergeMcpJson(before, "hush", entry);
    assert.ok(r.ok && !r.changed);
    assert.equal(r.text, before);
  });

  test("refuses to touch a file it cannot parse", () => {
    const r = mergeMcpJson("{ not json", "hush", entry);
    assert.equal(r.ok, false);
    assert.match((r as { reason: string }).reason, /not valid JSON/);
  });
});

describe("merging into config.toml (Codex)", () => {
  test("appends a table and leaves the rest of the file alone", () => {
    const before = 'model = "gpt-5.6-terra"\n\n[features]\nmemories = true\n';
    const r = renderMcp("toml", before, "hush", entry);
    assert.ok(r.ok && r.changed);
    assert.ok(r.text.startsWith(before), "the existing config was rewritten, not appended to");
    assert.match(r.text, /\n\[mcp_servers\.hush\]\ncommand = "node"\nargs = \["\/usr\/local\/lib\/hush\/cli\.ts", "mcp"\]\n$/);
  });

  test("creates a valid file when there is none", () => {
    const r = mergeMcpToml(null, "hush", entry);
    assert.ok(r.changed);
    assert.equal(r.text, '[mcp_servers.hush]\ncommand = "node"\nargs = ["/usr/local/lib/hush/cli.ts", "mcp"]\n');
  });

  test("does not add a second hush table", () => {
    const before = '[mcp_servers.hush]\ncommand = "node"\nargs = ["/somewhere/else", "mcp"]\n';
    const r = mergeMcpToml(before, "hush", entry);
    assert.equal(r.changed, false);
    assert.equal(r.text, before);
  });

  test("a table with a different name is not mistaken for ours", () => {
    const before = '[mcp_servers.hushy]\ncommand = "other"\nargs = []\n';
    const r = mergeMcpToml(before, "hush", entry);
    assert.ok(r.changed);
    assert.equal((r.text.match(/\[mcp_servers\.hush\]/g) ?? []).length, 1);
  });

  test("no trailing newline in the user's file still yields a parseable result", () => {
    const r = mergeMcpToml('model = "x"', "hush", entry);
    assert.ok(r.changed);
    assert.equal(r.text, 'model = "x"\n\n[mcp_servers.hush]\ncommand = "node"\nargs = ["/usr/local/lib/hush/cli.ts", "mcp"]\n');
  });
});

describe("Cursor wants a rule file, not a skill file", () => {
  const skill = "---\nname: hush\ndescription: Use for any task involving API keys.\n---\n\n# hush\n\nBody text.\n";

  test("the skill's own frontmatter is replaced, not duplicated", () => {
    const rule = AGENTS.find((g) => g.id === "cursor")!.skill.transform!(skill, skillDescription(skill));
    assert.equal((rule.match(/^---$/gm) ?? []).length, 2, "frontmatter fences are wrong");
    assert.match(rule, /^---\ndescription: Use for any task involving API keys\.\nalwaysApply: false\n---\n\n# hush/m);
    assert.match(rule, /Body text\./);
    assert.ok(!rule.includes("name: hush"), "the skill's own frontmatter leaked through");
  });

  test("a file with no frontmatter is passed through", () => {
    assert.equal(stripFrontmatter("# plain\n"), "# plain\n");
  });
});

describe("what counts as registered", () => {
  test("a config file with no hush entry is not a registration", async () => {
    const { mcpRegistrations } = await import("../src/agents.ts");
    const files: Record<string, string> = {
      "/home/me/.codex/config.toml": `model = "o3"\n`,
      "/proj/.mcp.json": JSON.stringify({ mcpServers: { hush: { command: "hush", args: ["mcp"] } } }),
    };
    const found = mcpRegistrations("/proj", { HOME: "/home/me" }, (p) => files[p] ?? null);
    assert.deepEqual(found.map((f) => f.agent.id), ["claude-code"]);
  });
});
