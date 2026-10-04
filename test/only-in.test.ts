/**
 * "Use this key for MODIO projects only": a set kept for some folders.
 *
 *   hush env describe "FAL MODIO" --only-in "~/code/modio-*"
 *
 * hush itself refuses the set anywhere else — for a person at the terminal
 * and an agent through MCP alike, whether it is asked for by name or was
 * linked into a project before the rule existed — rather than trusting a
 * note the agent may or may not follow.
 */
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir, platform } from "node:os";
import { join } from "node:path";

import { CLI } from "./helpers/cli.ts";
import { Vault, onlyInAllows, assertOnlyInPattern, ValidationError } from "../src/vault.ts";
import { generateIdentity, encodeSecret } from "../src/crypto.ts";

// ------------------------------------------------------------------ matching

describe("which folders a pattern covers", () => {
  const mac = { home: "/Users/me", platform: "darwin" };
  const linux = { home: "/home/me", platform: "linux" };
  const cases: [string[], string, boolean, typeof mac][] = [
    [["~/code/modio-*"], "/Users/me/code/modio-app", true, mac],
    [["~/code/modio-*"], "/Users/me/code/modio-app/packages/api", true, mac],
    [["~/code/modio-*"], "/Users/me/code/other", false, mac],
    [["~/code/modio-*"], "/Users/me/code/x/modio-app", false, mac], // * stays within one folder name
    [["~/code/**/modio"], "/Users/me/code/a/b/modio", true, mac],
    [["~/code/**/modio"], "/Users/me/code/modio", true, mac],
    [["~/code/mod?o"], "/Users/me/code/modio", true, mac],
    [["/srv/modio"], "/srv/modio2", false, linux], // a name is not a prefix of another name
    [["~/code/modio.app"], "/Users/me/code/modioXapp", false, mac], // "." is literal
    [["~/Code/MODIO"], "/Users/me/code/modio", true, mac], // macOS folders ignore case
    [["~/Code/MODIO"], "/home/me/code/modio", false, linux], // Linux's do not
    [["~/code/a", "~/code/b"], "/Users/me/code/b/web", true, mac],
    [["C:\\work\\modio-*"], "C:\\work\\modio-api\\src", true, { home: "C:\\Users\\me", platform: "win32" }],
  ];
  for (const [patterns, place, expected, opts] of cases) {
    test(`${patterns.join(" + ")}  ${expected ? "covers" : "does not cover"}  ${place}`, () => {
      assert.equal(onlyInAllows(patterns, place, opts), expected);
    });
  }

  test("a pattern must be a full path", () => {
    for (const bad of ["code/modio-*", "./modio", "", "  ", "modio", "~code", "/a\u001b[2Jb"]) {
      assert.throws(() => assertOnlyInPattern(bad), ValidationError, `accepted ${JSON.stringify(bad)}`);
    }
    for (const good of ["~", "~/code/modio-*", "/srv/modio", "C:\\work\\modio"]) assertOnlyInPattern(good);
  });
});

// ------------------------------------------------------------------ end to end

/**
 * A machine with a library holding "FAL MODIO", kept for <code>/modio-*, and
 * two projects: <code>/modio-app and <code>/other.
 */
function world() {
  // Real paths from the start: the rule compares real paths (a symlinked
  // folder cannot borrow a key), and macOS's tmpdir is itself a symlink.
  const base = realpathSync(mkdtempSync(join(tmpdir(), "hush-onlyin-")));
  const home = join(base, "home");
  const code = join(base, "code");
  mkdirSync(home);
  const id = generateIdentity();

  const lib = Vault.create(join(home, "vaults", "global", "vault.json"), "global", { name: "me", pub: id.pub, priv: id.priv });
  lib.set(id, "fal-modio", "FAL_KEY", "fal_modio_secret_value");
  lib.set(id, "fal-personal", "FAL_KEY", "fal_personal_secret_value");
  lib.describeEnv("fal-modio", { label: "FAL MODIO", description: "the MODIO team's fal account" });
  lib.save();

  const mkProject = (name: string) => {
    const root = join(code, name);
    mkdirSync(join(root, ".hush"), { recursive: true });
    const v = Vault.create(join(root, ".hush", "vault.json"), name, { name: "me", pub: id.pub, priv: id.priv });
    v.set(id, "default", "APP_NAME", name);
    v.save();
    writeFileSync(join(root, ".hush", "policy.json"), JSON.stringify({ requireApproval: [], biometry: "off" }));
    return root;
  };
  const modio = mkProject("modio-app");
  const other = mkProject("other");

  const env: NodeJS.ProcessEnv = {
    ...process.env, HOME: home, HUSH_HOME: home, HUSH_IDENTITY: encodeSecret(id), HUSH_NO_KEYCHAIN: "1",
    HUSH_BIOMETRY: "off", HUSH_NO_DIALOG: "1", HUSH_NO_NUDGE: "1", NO_COLOR: "1",
  };
  const hush = (cwd: string, ...args: string[]) => {
    const r = spawnSync(process.execPath, [CLI, ...args], { cwd, env, encoding: "utf8" });
    return { out: (r.stdout ?? "") + (r.stderr ?? ""), stdout: r.stdout ?? "", code: r.status };
  };
  const printKey = ["--", process.execPath, "-e", "console.log('FAL_KEY=' + (process.env.FAL_KEY ?? 'unset'))"];
  return { base, home, code, modio, other, env, hush, printKey, cleanup: () => rmSync(base, { recursive: true, force: true }) };
}

describe('hush env describe --only-in: "this key is for MODIO projects only"', () => {
  let w: ReturnType<typeof world>;
  before(() => {
    w = world();
    const set = w.hush(w.modio, "env", "describe", "FAL MODIO", "--only-in", `${w.code}/modio-*`);
    assert.equal(set.code, 0, set.out);
    assert.match(set.out, /only usable in/);
  });
  after(() => w.cleanup());

  test("inside a MODIO project it works as any set does", () => {
    const r = w.hush(w.modio, "run", "--use", "fal-modio", ...w.printKey);
    assert.equal(r.code, 0, r.out);
    assert.match(r.stdout, /FAL_KEY=\[redacted:FAL_KEY\]/);
  });

  test("anywhere else, asking for it by name is refused, and nothing runs", () => {
    const r = w.hush(w.other, "run", "--use", "fal-modio", ...w.printKey);
    assert.notEqual(r.code, 0, r.out);
    assert.match(r.out, /only for .*modio-\*, and this is .*other/);
    assert.doesNotMatch(r.out, /FAL_KEY=/, "the command ran anyway");
    // The other surfaces resolve sets the same way.
    assert.notEqual(w.hush(w.other, "get", "FAL_KEY", "--use", "fal-modio", "--yes").code, 0);
    assert.notEqual(w.hush(w.other, "export", "--use", "fal-modio").code, 0);
  });

  test("it cannot be linked into another project", () => {
    const r = w.hush(w.other, "use", "fal-modio");
    assert.notEqual(r.code, 0, r.out);
    assert.match(r.out, /only for/);
    assert.ok(!readFileSync(join(w.other, ".hush", "envs.json"), { flag: "a+" }).toString().includes("fal-modio"));
  });

  test("linked before the rule existed: skipped and said, and the rest of the run goes ahead", () => {
    writeFileSync(join(w.other, ".hush", "envs.json"), JSON.stringify({ use: ["fal-modio"] }));
    // It was linked by the person back then, so it was confirmed for this
    // project; what skips it now is the folder rule, not the confirmation.
    writeFileSync(join(w.home, "confirmed-links.json"), JSON.stringify({ [realpathSync(w.other)]: ["fal-modio"] }));
    try {
      const r = w.hush(w.other, "run", ...w.printKey);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /skipped FAL MODIO: it is only for/);
      assert.match(r.stdout, /FAL_KEY=unset/);
    } finally {
      rmSync(join(w.other, ".hush", "envs.json"), { force: true });
    }
  });

  test("a symlink named like a MODIO folder does not make another project one", { skip: platform() === "win32" && "symlinks need privileges on Windows" }, () => {
    // Held twice over: finding .hush already resolves the real folder, and
    // placeOf() resolves it again, so removing either alone still passes.
    const alias = join(w.code, "modio-alias");
    symlinkSync(w.other, alias);
    try {
      const r = w.hush(alias, "run", "--use", "fal-modio", ...w.printKey);
      assert.notEqual(r.code, 0, `a symlink into another project was treated as a MODIO project:\n${r.out}`);
      assert.match(r.out, /only for/);
    } finally {
      rmSync(alias, { force: true });
    }
  });

  test("hush ls shows the rule, and says where it does not apply", () => {
    assert.match(w.hush(w.modio, "ls").out, /only in .*modio-\*/);
    const there = w.hush(w.other, "ls").out;
    assert.match(there, /only in .*modio-\*\s+— not usable here/);
  });

  test("an agent is told, and refused the same way", { skip: platform() === "win32" && "a POSIX script stands in for the agent's command" }, async () => {
    // A script, not `node -e`: the MCP policy rightly refuses interpreters.
    const script = join(w.other, "print-key.sh");
    writeFileSync(script, '#!/bin/sh\necho "FAL_KEY=${FAL_KEY:-unset}"\n');
    chmodSync(script, 0o755);
    const replies = await mcp(w, w.other, [
      { jsonrpc: "2.0", id: 0, method: "initialize", params: {} },
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "hush_list_sets", arguments: {} } },
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "hush_run", arguments: { command: "./print-key.sh", sets: ["fal-modio"] } } },
      { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "hush_run", arguments: { command: "./print-key.sh", sets: ["fal-personal"] } } },
    ]);
    const text = (id: number) => (replies.find((r) => r.id === id)?.result?.content?.[0]?.text ?? "") as string;
    assert.match(text(1), /FAL MODIO[\s\S]*NOT usable in this project/);
    assert.equal(replies.find((r) => r.id === 2)?.result?.isError, true, text(2));
    assert.match(text(2), /only for/);
    assert.doesNotMatch(text(2), /fal_modio_secret_value/);
    // The same script, with a set that has no rule, runs: it is the rule that refused, not the setup.
    assert.match(text(3), /FAL_KEY=\[redacted:FAL_KEY\]/, text(3));
  });

  test("--when on its own leaves the description alone; --anywhere lifts the rule", () => {
    const d = w.hush(w.modio, "env", "describe", "FAL MODIO", "--when", "MODIO work only");
    assert.equal(d.code, 0, d.out);
    const lib = JSON.parse(readFileSync(join(w.home, "vaults", "global", "vault.json"), "utf8"));
    assert.equal(lib.meta["fal-modio"].description, "the MODIO team's fal account", "--when wiped the description");
    assert.equal(lib.meta["fal-modio"].label, "FAL MODIO", "--when wiped the label");
    assert.deepEqual(lib.meta["fal-modio"].onlyIn, [`${w.code}/modio-*`], "--when wiped the folder rule");

    assert.equal(w.hush(w.modio, "env", "describe", "FAL MODIO", "--anywhere").code, 0);
    const r = w.hush(w.other, "run", "--use", "fal-modio", ...w.printKey);
    assert.equal(r.code, 0, r.out);
    // Put it back for any test that runs after.
    w.hush(w.modio, "env", "describe", "FAL MODIO", "--only-in", `${w.code}/modio-*`);
  });

  test("an unquoted pattern the shell expanded is caught rather than half-applied", () => {
    const r = w.hush(w.modio, "env", "describe", "FAL MODIO", "--only-in", `${w.code}/modio-app`, `${w.code}/modio-b`);
    assert.notEqual(r.code, 0);
    assert.match(r.out, /Quote a folder pattern/);
  });
});

/** Speak JSON-RPC to `hush mcp` in `cwd`. */
function mcp(w: ReturnType<typeof world>, cwd: string, requests: unknown[]): Promise<{ id?: number; result?: { isError?: boolean; content?: { text: string }[] } }[]> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, "mcp"], { cwd, env: w.env, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.on("exit", () =>
      resolve(
        out
          .split("\n")
          .filter((l) => l.trim())
          .flatMap((l) => {
            try {
              return [JSON.parse(l)];
            } catch {
              return [];
            }
          }),
      ),
    );
    for (const r of requests) child.stdin.write(JSON.stringify(r) + "\n");
    child.stdin.end();
  });
}
