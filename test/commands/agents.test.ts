/**
 * Registering agents from a folder that only uses library sets.
 */
import { test, describe } from "node:test";
import { join } from "node:path";
import { writeFileSync, readFileSync, mkdirSync, existsSync, rmSync } from "node:fs";
import assert from "node:assert/strict";
import { project } from "../helpers/cli.ts";

// Setup in a vault-less folder ends with "hush install-mcp when you're ready";
// that promise has to hold without a vault.
describe("agent registration in a folder that only uses library sets", () => {
  // Bites: install-mcp/install-skill on the strict ctx() refuse with the
  // "no vault of its own yet" message instead of writing anything.
  test("install-mcp and install-skill work with envs.json and no vault", () => {
    // HOME is pointed at a scratch directory for every test in this describe:
    // registering an agent writes to files that live in the user's home
    // (`~/.codex/config.toml`, `~/.claude/…`), and a test run must never touch
    // the developer's real ones.
    const p = project();
    try {
      const fakeHome = join(p.home, "home");
      mkdirSync(join(fakeHome, ".claude"), { recursive: true });
      p.env.HOME = fakeHome;
      p.env.PATH = "";
      rmSync(join(p.hushDir, "vault.json"));
      writeFileSync(join(p.hushDir, "envs.json"), JSON.stringify({ use: [] }));
      const mcp = p.run(["install-mcp"]);
      assert.equal(mcp.code, 0, mcp.out);
      assert.ok(existsSync(join(p.root, ".mcp.json")), ".mcp.json was not written");
      const skill = p.run(["install-skill"]);
      assert.equal(skill.code, 0, skill.out);
      assert.ok(existsSync(join(p.root, ".claude", "skills", "hush", "SKILL.md")), "the skill was not written");
    } finally {
      p.cleanup();
    }
  });

  test("a Codex session gets Codex's file, not Claude Code's", () => {
    // The bug this pins: install-mcp wrote `.mcp.json` unconditionally and
    // printed a tick. In a Codex session that file is never read, so a new user
    // was told they were set up while their agent knew nothing about hush.
    const p = project();
    try {
      const fakeHome = join(p.home, "home");
      mkdirSync(join(fakeHome, ".codex"), { recursive: true });
      p.env.HOME = fakeHome;
      p.env.PATH = ""; // nothing on PATH, so detection is the directory alone

      const mcp = p.run(["install-mcp"]);
      assert.equal(mcp.code, 0, mcp.out);
      assert.match(mcp.out, /Codex/);

      const config = readFileSync(join(fakeHome, ".codex", "config.toml"), "utf8");
      assert.match(config, /^\[mcp_servers\.hush\]$/m, "no hush section was written for Codex");
      assert.match(config, /^command = "node"$/m);
      assert.match(config, /^args = \[".*cli\.ts", "mcp"\]$/m);
      assert.ok(
        !existsSync(join(p.root, ".mcp.json")),
        "wrote Claude Code's file for a Codex-only machine — the tick would mean nothing",
      );

      const skill = p.run(["install-skill"]);
      assert.equal(skill.code, 0, skill.out);
      const dest = join(p.root, ".agents", "skills", "hush", "SKILL.md");
      assert.ok(existsSync(dest), `the skill did not go where Codex reads it (${dest})`);
      assert.match(readFileSync(dest, "utf8"), /Never ask the user to paste a credential into the chat/);
    } finally {
      p.cleanup();
    }
  });

  test("neither agent here: it says so and prints the line to paste", () => {
    const p = project();
    try {
      const fakeHome = join(p.home, "home");
      mkdirSync(fakeHome, { recursive: true });
      p.env.HOME = fakeHome;
      p.env.PATH = "";

      const r = p.run(["install-mcp"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /No coding agent detected/);
      assert.match(r.out, /codex mcp add hush -- node/);
      assert.ok(!existsSync(join(p.root, ".mcp.json")), "wrote a file no agent reads");
      assert.ok(!existsSync(join(fakeHome, ".codex", "config.toml")), "wrote a config for an agent that is not here");

      // --for is how someone registers an agent hush could not see.
      const forced = p.run(["install-mcp", "--for", "cursor"]);
      assert.equal(forced.code, 0, forced.out);
      const cursor = JSON.parse(readFileSync(join(p.root, ".cursor", "mcp.json"), "utf8")) as {
        mcpServers: { hush: { command: string; args: string[] } };
      };
      assert.equal(cursor.mcpServers.hush.command, "node");
      assert.deepEqual(cursor.mcpServers.hush.args.slice(1), ["mcp"]);
    } finally {
      p.cleanup();
    }
  });

  test("an entry that is already there is left alone", () => {
    const p = project();
    try {
      const fakeHome = join(p.home, "home");
      mkdirSync(join(fakeHome, ".codex"), { recursive: true });
      const configPath = join(fakeHome, ".codex", "config.toml");
      const mine = `[mcp_servers.hush]\ncommand = "my-own-wrapper"\nargs = []\n`;
      writeFileSync(configPath, mine);
      p.env.HOME = fakeHome;
      p.env.PATH = "";

      const r = p.run(["install-mcp"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /already registered/);
      assert.equal(readFileSync(configPath, "utf8"), mine, "an existing entry was rewritten");
    } finally {
      p.cleanup();
    }
  });
});
