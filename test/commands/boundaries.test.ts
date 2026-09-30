/**
 * hush stays out of places it was not asked into.
 */
import { test, describe } from "node:test";
import { join, dirname } from "node:path";
import assert from "node:assert/strict";
import { writeFileSync, readFileSync, mkdirSync, existsSync, symlinkSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { CLI, bareFolder, project } from "../helpers/cli.ts";

describe("hush stays out of places it was not asked into", () => {
  // Bites: ~/.hush and a project's .hush share a name, so the upward walk from
  // any folder under $HOME found it. One `hush use` from the home folder wrote
  // ~/.hush/envs.json and every folder beneath became part of that "project".
  test("~/.hush is never a project, and nothing writes project files into it", () => {
    const p = bareFolder();
    const hushHome = join(p.root, ".hush");
    p.env.HUSH_HOME = hushHome;
    try {
      p.librarySet("work", { WORK_KEY: "work_value_1234" });
      const use = p.run(["use", "work"]);
      assert.equal(use.code, 1, use.out);
      assert.match(use.out, /not a project/);
      assert.ok(!existsSync(join(hushHome, "envs.json")), "wrote envs.json into ~/.hush");

      const init = p.run(["init"]);
      assert.equal(init.code, 1, init.out);
      assert.ok(!existsSync(join(hushHome, "vault.json")), "made a project vault in ~/.hush");

      // A folder left in the old state is not picked up either.
      writeFileSync(join(hushHome, "envs.json"), JSON.stringify({ use: ["work"] }));
      const nested = join(p.root, "code", "app");
      mkdirSync(nested, { recursive: true });
      const r = spawnSync(process.execPath, [CLI, "root"], { cwd: nested, env: p.env, encoding: "utf8" });
      assert.notEqual(r.status, 0, `a folder under $HOME resolved to ~/.hush: ${r.stdout}`);
    } finally {
      p.cleanup();
    }
  });

  // Bites: macOS's /var is a link to /private/var, so HUSH_HOME and the
  // folder the walk reaches can be the same directory spelled two ways.
  test("~/.hush is recognised through a symlinked path too", () => {
    const p = bareFolder();
    const real = join(p.root, "real");
    const link = join(p.root, "link");
    try {
      mkdirSync(join(real, ".hush"), { recursive: true });
      mkdirSync(join(real, "code", "app"), { recursive: true });
      writeFileSync(join(real, ".hush", "envs.json"), JSON.stringify({ use: [] }));
      symlinkSync(real, link);
      p.env.HUSH_HOME = join(link, ".hush");
      const r = spawnSync(process.execPath, [CLI, "root"], { cwd: join(real, "code", "app"), env: p.env, encoding: "utf8" });
      assert.notEqual(r.status, 0, `~/.hush reached through a link was taken for a project: ${r.stdout}`);
    } finally {
      p.cleanup();
    }
  });

  // Bites: the absolute path to one machine's node_modules went into the
  // committed .mcp.json, wrong on every teammate's machine.
  test("install-mcp registers a bare `hush mcp` when PATH's hush is this install", () => {
    const p = project();
    try {
      const fakeHome = join(p.home, "home");
      mkdirSync(join(fakeHome, ".claude"), { recursive: true });
      const bin = join(p.home, "bin");
      mkdirSync(bin);
      symlinkSync(join(dirname(CLI), "..", "bin", "hush.js"), join(bin, "hush"));
      p.env.HOME = fakeHome;
      p.env.PATH = bin;
      const r = p.run(["install-mcp"]);
      assert.equal(r.code, 0, r.out);
      const doc = JSON.parse(readFileSync(join(p.root, ".mcp.json"), "utf8")) as {
        mcpServers: { hush: { command: string; args: string[] } };
      };
      assert.deepEqual(doc.mcpServers.hush, { command: "hush", args: ["mcp"] });
    } finally {
      p.cleanup();
    }
  });

  test("writing a policy says what it does to your own runs", () => {
    const p = project();
    try {
      const fakeHome = join(p.home, "home");
      mkdirSync(fakeHome, { recursive: true });
      p.env.HOME = fakeHome;
      p.env.PATH = "";
      const r = p.run(["install-mcp"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /yours too/);
      // HUSH_NO_DIALOG: nothing here can show a prompt, and it has to say so.
      assert.match(r.out, /every hush run here will be refused/);
    } finally {
      p.cleanup();
    }
  });

  // Bites: the ladder only looked for a project vault, so a folder that uses
  // library sets — the recommended model — was told "your secrets are not encrypted".
  test("a folder that only uses library sets counts as encrypted", () => {
    const p = bareFolder();
    try {
      p.librarySet("work", { WORK_KEY: "work_value_1234" });
      assert.equal(p.run(["use", "work"]).code, 0);
      const r = p.run(["level"]);
      assert.match(r.out, /✓ secrets are encrypted at rest/, r.out);
    } finally {
      p.cleanup();
    }
  });
});
