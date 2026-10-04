/**
 * `hush scan --agents`: plaintext credentials in coding agents' own config
 * files, and `--fix`, which moves the ones it can into the library and starts
 * the server through `hush run` instead.
 *
 * Every fixture value here is made up. The CLI tests run against a scratch
 * HOME, so nothing reads or rewrites a real agent's config.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import {
  agentConfigFiles, alreadyWrapped, applyWrap, findSecrets, indentOf, isPlaceholder, looksLikeCredential,
  planWraps, secretName, serviceOf,
} from "../src/agent-configs.ts";
import { bareFolder } from "./helpers/cli.ts";

const GH = "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB";
const ANTHROPIC = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345";

// ------------------------------------------------------------------ detection

test("a provider's key is recognised by its shape, whatever the field is called", () => {
  assert.equal(serviceOf(GH), "github");
  assert.equal(serviceOf(ANTHROPIC), "anthropic");
  assert.equal(serviceOf("sk_" + "live_abcdefghijklmnop1234"), "stripe");
  assert.equal(serviceOf("AKIAABCDEFGHIJKLMNOP"), "aws");
  // `sk-` in the middle of another vendor's key is not an OpenAI key.
  assert.equal(serviceOf("ctx7sk-ea802c3e-0000-0000-0000-000000000000"), null);
});

test("a credential's name is told apart from a setting that shares a word", () => {
  for (const n of ["GITHUB_TOKEN", "apiKey", "x-api-key", "OUTLOOK_CLIENT_SECRET", "DB_PASSWORD", "brave_api_key"]) {
    assert.ok(secretName(n), n);
  }
  for (const n of ["MAX_TOKENS", "LOG_LEVEL", "userID", "PORT"]) assert.ok(!secretName(n), n);
});

test("placeholders, paths, dates and short settings are not credentials", () => {
  for (const v of ["${GITHUB_TOKEN}", "$GITHUB_TOKEN", "<your-key>", "your-api-key-here", "xxxxxxxxxxxx", "{{token}}"]) {
    assert.ok(isPlaceholder(v), v);
  }
  for (const v of ["4096", "oauth", "~/.ssh/id_ed25519", "/etc/key.pem", "2025-09-30T12:00:00.000Z", "https://example.com"]) {
    assert.ok(!looksLikeCredential(v), v);
  }
  assert.ok(looksLikeCredential("quwAb12Cd34Ef56Gh78Ij90Kl"));
});

test("JSON: env values, headers, args and URLs inside each server are found, settings are not", () => {
  const text = JSON.stringify({
    mcpServers: {
      github: { command: "npx", args: ["-y", "gh-mcp"], env: { GITHUB_TOKEN: GH, LOG: "debug", MAX_TOKENS: "4096" } },
      remote: { url: "https://mcp.example.com/mcp?secret=Ab12Cd34Ef56Gh78", headers: { Authorization: `Bearer ${GH}` } },
      cli: { command: "srv", args: ["--api-key", "Zq81Lm02Np93Kr74Ts65"] },
      templated: { command: "npx", env: { API_KEY: "${API_KEY}" } },
    },
  });
  const { findings } = findSecrets(text, "json");
  const got = findings.map((f) => `${f.server}:${f.kind}:${f.name}`).sort();
  assert.deepEqual(got, ["cli:arg:api-key", "github:env:GITHUB_TOKEN", "remote:header:Authorization", "remote:url:url"]);
  const env = findings.find((f) => f.kind === "env")!;
  assert.deepEqual(env.entryPath, ["mcpServers", "github"]);
  assert.equal(env.service, "github");
  // Only a command-started server's env can be moved.
  assert.equal(findings.find((f) => f.kind === "header")!.entryPath, null);
});

test("Claude Code's ~/.claude.json: servers nested under projects are found too", () => {
  const text = JSON.stringify({
    claudeCodeFirstTokenDate: "2025-09-30T12:00:00.000Z",
    projects: { "/Users/x/app": { mcpServers: { unsplash: { command: "npx", env: { UNSPLASH_ACCESS_KEY: "H41abcDEF123ghiJKL456mno" } } } } },
  });
  const { findings } = findSecrets(text, "json");
  assert.deepEqual(findings.map((f) => f.name), ["UNSPLASH_ACCESS_KEY"]);
  assert.deepEqual(findings[0].entryPath, ["projects", "/Users/x/app", "mcpServers", "unsplash"]);
});

test("JSONC with comments is read, TOML env tables and header tables are read", () => {
  const jsonc = `{\n  // my servers\n  "context_servers": { "brave": { "settings": { "brave_api_key": "BSAab12CD34ef56GH78ij" } } },\n}`;
  assert.deepEqual(findSecrets(jsonc, "jsonc").findings.map((f) => `${f.server}:${f.kind}`), ["brave:field"]);

  const toml = [
    "[mcp_servers.github]",
    'command = "npx"',
    "[mcp_servers.github.env]",
    `GITHUB_TOKEN = "${GH}"`,
    "[mcp_servers.context7.env_http_headers]",
    'CONTEXT7_API_KEY = "ctx7sk-ea802c3e-0000-0000-0000-00000000aaaa"',
    "[mcp_servers.other]",
    `env = { OTHER_TOKEN = "Ab12Cd34Ef56Gh78Ij90" }`,
  ].join("\n");
  assert.deepEqual(
    findSecrets(toml, "toml").findings.map((f) => `${f.server}:${f.kind}:${f.name}`),
    ["github:env:GITHUB_TOKEN", "context7:header:CONTEXT7_API_KEY", "other:env:OTHER_TOKEN"],
  );
});

test("a file that is not what its name says is reported unreadable, not guessed at", () => {
  const r = findSecrets("{ not json", "json");
  assert.equal(r.findings.length, 0);
  assert.ok(r.unreadable);
});

// ------------------------------------------------------------------ rewriting

test("applyWrap starts the server through hush and keeps every non-secret setting", () => {
  const doc = { mcpServers: { github: { command: "npx", args: ["-y", "gh-mcp"], env: { GITHUB_TOKEN: GH, LOG: "debug" } } } };
  const [plan] = planWraps(findSecrets(JSON.stringify(doc), "json").findings);
  const launch = { command: "/usr/local/bin/node", args: ["/x/cli.js", "run", "--use", "mcp-github", "--"] };
  assert.deepEqual(applyWrap(doc, plan, launch), { ok: true });
  assert.deepEqual(doc.mcpServers.github, {
    command: "/usr/local/bin/node",
    args: ["/x/cli.js", "run", "--use", "mcp-github", "--", "npx", "-y", "gh-mcp"],
    env: { LOG: "debug" },
  });
  assert.ok(alreadyWrapped(doc.mcpServers.github));
  assert.ok(!JSON.stringify(doc).includes(GH));
});

test("applyWrap refuses an entry that changed after it was read", () => {
  const doc = { mcpServers: { github: { command: "npx", env: { GITHUB_TOKEN: GH } } } };
  const [plan] = planWraps(findSecrets(JSON.stringify(doc), "json").findings);
  doc.mcpServers.github.env.GITHUB_TOKEN = "ghp_somethingelse000000000000000000000000";
  const r = applyWrap(doc, plan, { command: "hush", args: ["run", "--"] });
  assert.equal(r.ok, false);
  assert.equal(doc.mcpServers.github.command, "npx");
});

test("indentOf keeps a file's own indentation", () => {
  assert.equal(indentOf('{\n\t"a": 1\n}'), "\t");
  assert.equal(indentOf('{\n    "a": 1\n}'), 4);
  assert.equal(indentOf("{}"), 2);
});

test("the file list covers user-wide and project files, each path once", () => {
  const files = agentConfigFiles("/proj", { HOME: "/home/me" }, "darwin");
  const paths = files.map((f) => f.path);
  assert.ok(paths.includes("/home/me/Library/Application Support/Claude/claude_desktop_config.json"));
  assert.ok(paths.includes("/home/me/.cursor/mcp.json"));
  assert.ok(paths.includes("/proj/.mcp.json"));
  assert.equal(new Set(paths).size, paths.length);
  // The home folder as the project: still one entry per file.
  const same = agentConfigFiles("/home/me", { HOME: "/home/me" }, "linux").map((f) => f.path);
  assert.equal(new Set(same).size, same.length);
});

// ------------------------------------------------------------------ the command

/** HOME, and XDG_CONFIG_HOME under it, so a CI runner's own XDG settings cannot move the files. */
const agentEnv = (home: string) => ({ HOME: home, XDG_CONFIG_HOME: join(home, ".config") });

function agentHome() {
  const home = mkdtempSync(join(tmpdir(), "hush-agent-home-"));
  const server = join(home, "fake-server.sh");
  writeFileSync(server, '#!/bin/sh\necho "len=${#GITHUB_TOKEN} log=$LOG args=$*"\n');
  chmodSync(server, 0o755);
  // Wherever Claude Desktop keeps it on this platform (~/Library/… on macOS,
  // ~/.config/… on Linux): the same answer hush itself will look for.
  const desktop = agentConfigFiles(home, agentEnv(home)).find((f) => f.agent === "Claude Desktop")!.path;
  mkdirSync(join(desktop, ".."), { recursive: true });
  writeFileSync(desktop, JSON.stringify({
    mcpServers: { github: { command: server, args: ["--stdio"], env: { GITHUB_TOKEN: GH, LOG: "debug" } } },
  }, null, 2) + "\n");
  const cursor = join(home, ".cursor", "mcp.json");
  mkdirSync(join(cursor, ".."), { recursive: true });
  writeFileSync(cursor, `{\n\t"mcpServers": {\n\t\t"github": { "command": "${server}", "env": { "GITHUB_TOKEN": "${GH}" } }\n\t}\n}\n`);
  return { home, desktop, cursor, cleanup: () => rmSync(home, { recursive: true, force: true }) };
}

test("hush scan --agents reports where, never what", { skip: process.platform === "win32" }, () => {
  const h = agentHome();
  const b = bareFolder(agentEnv(h.home));
  try {
    const r = b.run(["scan", "--agents"]);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /Claude Desktop/);
    assert.match(r.out, /GITHUB_TOKEN/);
    assert.match(r.out, /can move/);
    assert.ok(!r.out.includes(GH), "the report printed a value");
    const json = b.run(["scan", "--agents", "--json"]);
    assert.ok(!json.out.includes(GH), "--json printed a value");
    assert.equal(JSON.parse(json.out).findings.length, 2);
  } finally {
    b.cleanup?.();
    h.cleanup();
  }
});

test("hush scan --agents --fix moves the keys, rewrites the files, and the server still gets its key", { skip: process.platform === "win32" }, () => {
  const h = agentHome();
  const b = bareFolder(agentEnv(h.home));
  try {
    const r = b.run(["scan", "--agents", "--fix", "--yes"]);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /moved 2 credential/);

    const desktop = readFileSync(h.desktop, "utf8");
    const cursor = readFileSync(h.cursor, "utf8");
    assert.ok(!desktop.includes(GH) && !cursor.includes(GH), "a value is still in a config file");
    assert.ok(cursor.startsWith('{\n\t"'), "the tab-indented file lost its indentation");

    // Started the way an agent starts it: from /, with only what the file says.
    const entry = JSON.parse(desktop).mcpServers.github;
    assert.deepEqual(entry.env, { LOG: "debug" });
    const started = spawnSync(entry.command, entry.args, { cwd: "/", env: { ...b.env, ...entry.env }, encoding: "utf8" });
    assert.equal(started.status, 0, started.stderr);
    assert.match(started.stdout, new RegExp(`len=${GH.length} log=debug args=--stdio`));

    // Nothing left to report, and a second --fix is a no-op.
    assert.match(b.run(["scan", "--agents"]).out, /no plaintext credentials/);
  } finally {
    b.cleanup?.();
    h.cleanup();
  }
});

test("--fix with no terminal and no --yes changes nothing", { skip: process.platform === "win32" }, () => {
  const h = agentHome();
  const b = bareFolder(agentEnv(h.home));
  try {
    const before = readFileSync(h.desktop, "utf8");
    const r = b.run(["scan", "--agents", "--fix"]);
    assert.notEqual(r.code, 0);
    assert.match(r.out, /--yes/);
    assert.equal(readFileSync(h.desktop, "utf8"), before);
  } finally {
    b.cleanup?.();
    h.cleanup();
  }
});
