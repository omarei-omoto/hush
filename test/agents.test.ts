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
  mergeMcpVscode,
  mergeMcpZed,
  stripJsonc,
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
    assert.deepEqual(
      Object.keys(byId).sort(),
      ["claude-code", "cline", "codex", "continue", "cursor", "gemini", "vscode", "windsurf", "zed"],
    );

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

describe("the agents added in 0.7 (F-5)", () => {
  const byId = Object.fromEntries(AGENTS.map((g) => [g.id, g]));
  const env = { HOME: "/home/me" };

  test("each reads the file its own documentation names", () => {
    assert.equal(byId["windsurf"].mcp.path("/proj", env), "/home/me/.config/devin/mcp_config.json");
    assert.equal(byId["windsurf"].mcp.path("/proj", { ...env, XDG_CONFIG_HOME: "/xdg" }), "/xdg/devin/mcp_config.json");
    assert.equal(byId["gemini"].mcp.path("/proj", env), "/proj/.gemini/settings.json");
    assert.equal(byId["vscode"].mcp.path("/proj", env), "/proj/.vscode/mcp.json");
    assert.equal(byId["vscode"].mcp.format, "vscode");
    assert.equal(byId["zed"].mcp.path("/proj", env), "/home/me/.config/zed/settings.json");
    assert.equal(byId["zed"].mcp.format, "zed");
    assert.equal(byId["cline"].mcp.path("/proj", env), "/home/me/.cline/mcp.json");
    assert.equal(byId["continue"].mcp.path("/proj", env), "/proj/.continue/mcpServers/hush.json");
  });

  test("skills and rules go where each one looks, with the frontmatter it wants", () => {
    const skill = "---\nname: hush\ndescription: Use for keys.\n---\n\n# hush\n\nBody.\n";
    const d = "Use for keys.";
    assert.equal(byId["gemini"].skill.project("/p"), "/p/.agents/skills/hush/SKILL.md");
    assert.equal(byId["zed"].skill.project("/p"), "/p/.agents/skills/hush/SKILL.md");
    assert.equal(byId["windsurf"].skill.project("/p"), "/p/.windsurf/rules/hush.md");
    assert.match(byId["windsurf"].skill.transform!(skill, d), /^---\ntrigger: model_decision\ndescription: Use for keys\.\n---\n\n# hush/);
    assert.equal(byId["vscode"].skill.project("/p"), "/p/.github/instructions/hush.instructions.md");
    assert.match(byId["vscode"].skill.transform!(skill, d), /^---\ndescription: Use for keys\.\n---\n\n# hush/);
    assert.equal(byId["cline"].skill.project("/p"), "/p/.clinerules/hush.md");
    assert.equal(byId["cline"].skill.transform!(skill, d), "# hush\n\nBody.\n");
    assert.equal(byId["continue"].skill.project("/p"), "/p/.continue/rules/hush.md");
    assert.match(byId["continue"].skill.transform!(skill, d), /^---\nname: hush\ndescription: Use for keys\.\nalwaysApply: false\n---/);
    for (const g of AGENTS) {
      if (!g.skill.transform) continue;
      const out = g.skill.transform(skill, d);
      assert.equal((out.match(/^---$/gm) ?? []).length, out.startsWith("---") ? 2 : 0, `${g.id}: frontmatter fences`);
    }
  });

  test("every agent's manual line names hush", () => {
    for (const id of ["windsurf", "gemini", "vscode", "zed", "cline", "continue"]) {
      assert.match(byId[id].manual({ command: "hush", args: ["mcp"] }, "/proj"), /hush/, id);
    }
    assert.match(byId["gemini"].manual({ command: "hush", args: ["mcp"] }, "/p"), /^gemini mcp add hush hush mcp$/);
  });
});

describe("VS Code's servers shape", () => {
  test("creates, merges, and leaves an existing entry alone", () => {
    const r = mergeMcpVscode(null, "hush", entry);
    assert.ok(r.ok && r.changed);
    assert.deepEqual(JSON.parse(r.text), { servers: { hush: { type: "stdio", ...entry } } });
    const other = JSON.stringify({ servers: { gh: { type: "http", url: "https://x" } }, inputs: [] }, null, 2);
    const m = mergeMcpVscode(other, "hush", entry);
    assert.ok(m.ok && m.changed);
    const doc = JSON.parse(m.text);
    assert.deepEqual(Object.keys(doc.servers).sort(), ["gh", "hush"]);
    assert.deepEqual(doc.inputs, []);
    const again = mergeMcpVscode(m.text, "hush", { command: "x", args: [] });
    assert.ok(again.ok && !again.changed);
  });

  test("a file with comments is not rewritten (its comments would be lost)", () => {
    const r = mergeMcpVscode('{\n  // mine\n  "servers": {}\n}', "hush", entry);
    assert.equal(r.ok, false);
  });
});

describe("Zed's settings file, which has comments", () => {
  const zedDefault = `// Zed settings
//
// For information on how to configure Zed, see the Zed
// documentation: https://zed.dev/docs/configuring-zed
{
  "theme": "One Dark", // keep this
  "ui_font_size": 16,
}
`;

  test("adds context_servers without losing a single comment", () => {
    const r = mergeMcpZed(zedDefault, "hush", entry);
    assert.ok(r.ok && r.changed, JSON.stringify(r));
    for (const c of ["// Zed settings", "// keep this", "// documentation: https://zed.dev/docs/configuring-zed"]) {
      assert.ok(r.text.includes(c), `lost ${c}`);
    }
    const doc = JSON.parse(stripJsonc(r.text));
    assert.deepEqual(doc.context_servers.hush, { ...entry, env: {} });
    assert.equal(doc.theme, "One Dark");
  });

  test("joins an existing context_servers, empty or not, and never adds a second hush", () => {
    const withOther = '{\n  "context_servers": {\n    "gh": { "command": "gh-mcp", "args": [] } // mine\n  }\n}\n';
    const r = mergeMcpZed(withOther, "hush", entry);
    assert.ok(r.ok && r.changed);
    const doc = JSON.parse(stripJsonc(r.text));
    assert.deepEqual(Object.keys(doc.context_servers).sort(), ["gh", "hush"]);
    assert.ok(r.text.includes("// mine"));
    const empty = mergeMcpZed('{ "context_servers": {} }', "hush", entry);
    assert.ok(empty.ok && empty.changed);
    assert.deepEqual(JSON.parse(stripJsonc(empty.text)).context_servers.hush, { ...entry, env: {} });
    const again = mergeMcpZed(r.text, "hush", entry);
    assert.ok(again.ok && !again.changed);
  });

  test("a key named context_servers inside another object is not mistaken for the real one", () => {
    const tricky = '{ "agent": { "context_servers": { } }, "x": 1 }';
    const r = mergeMcpZed(tricky, "hush", entry);
    assert.ok(r.ok && r.changed);
    const doc = JSON.parse(stripJsonc(r.text));
    assert.ok(doc.context_servers?.hush, r.text);
    assert.deepEqual(doc.agent.context_servers, {});
  });

  test("stripJsonc keeps // inside strings and drops trailing commas", () => {
    assert.deepEqual(JSON.parse(stripJsonc('{ "u": "https://x//y", /* c */ "a": [1,2,], }')), { u: "https://x//y", a: [1, 2] });
  });

  test("an unparseable file is left alone", () => {
    assert.equal(mergeMcpZed("{ oops", "hush", entry).ok, false);
  });
});

describe("installing for the new agents, end to end", () => {
  test("Zed's commented settings keep their comments, and one skill file serves Codex, Gemini and Zed", async () => {
    const { spawnSync } = await import("node:child_process");
    const { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join, dirname } = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.ts");
    const home = mkdtempSync(join(tmpdir(), "hush-agents-home-"));
    const root = mkdtempSync(join(tmpdir(), "hush-agents-proj-"));
    mkdirSync(join(home, ".config", "zed"), { recursive: true });
    const settings = join(home, ".config", "zed", "settings.json");
    writeFileSync(settings, '// my zed\n{\n  "theme": "One Dark", // mine\n}\n');
    const run = (args: string[]) =>
      spawnSync(process.execPath, [CLI, ...args], {
        cwd: root,
        env: { ...process.env, HOME: home, HUSH_HOME: join(home, ".hush"), XDG_CONFIG_HOME: "", NO_COLOR: "1", HUSH_NO_NUDGE: "1" },
        encoding: "utf8",
      });
    const mcp = run(["install-mcp", "--for", "zed", "--yes"]);
    assert.equal(mcp.status, 0, mcp.stdout + mcp.stderr);
    const text = readFileSync(settings, "utf8");
    assert.ok(text.includes("// my zed") && text.includes("// mine"), text);
    assert.ok(JSON.parse(stripJsonc(text)).context_servers.hush, text);

    // What doctor and the app read agrees that Zed now has hush.
    const { mcpRegistrations } = await import("../src/agents.ts");
    const found = mcpRegistrations(root, { HOME: home }, (p) => (existsSync(p) ? readFileSync(p, "utf8") : null));
    assert.ok(found.some((f) => f.agent.id === "zed"), JSON.stringify(found.map((f) => f.agent.id)));

    for (const id of ["codex", "gemini", "zed"]) {
      const r = run(["install-skill", "--for", id, "--yes"]);
      assert.equal(r.status, 0, r.stdout + r.stderr);
    }
    assert.ok(existsSync(join(root, ".agents", "skills", "hush", "SKILL.md")));
    for (const d of [home, root]) rmSync(d, { recursive: true, force: true });
  });
});
