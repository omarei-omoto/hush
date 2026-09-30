/**
 * F-1 through real git: the driver as git runs it, `hush merge` for a clone
 * without the driver, and `hush merge pick` for what is left to choose.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { Vault } from "../src/vault.ts";
import { generateIdentity, encodeSecret } from "../src/crypto.ts";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.ts");
const hasGit = spawnSync("git", ["--version"]).status === 0;

function repo() {
  const home = mkdtempSync(join(tmpdir(), "hush-mg-home-"));
  const root = mkdtempSync(join(tmpdir(), "hush-mg-repo-"));
  const id = generateIdentity();
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home, HUSH_HOME: home, HUSH_IDENTITY: encodeSecret(id), HUSH_NO_KEYCHAIN: "1",
    HUSH_NO_NUDGE: "1", NO_COLOR: "1",
    GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t",
    GIT_CONFIG_NOSYSTEM: "1",
  };
  const g = (...args: string[]) => spawnSync("git", args, { cwd: root, env, encoding: "utf8" });
  const hush = (...args: string[]) => {
    const r = spawnSync(process.execPath, [CLI, ...args], { cwd: root, env, encoding: "utf8" });
    return { out: (r.stdout ?? "") + (r.stderr ?? ""), code: r.status ?? 1 };
  };
  g("init", "-q", "-b", "main");
  mkdirSync(join(root, ".hush"));
  const path = join(root, ".hush", "vault.json");
  const v = Vault.create(path, "mg", { name: "me", pub: id.pub });
  for (const [k, val] of [["KEY_C", "c-base-value"], ["KEEP", "keep-base-value"]]) v.set(id, "default", k, val);
  v.save();
  spawnSync(process.execPath, [CLI, "use", "default"], { cwd: root, env });
  g("add", "-A");
  g("commit", "-qm", "base");
  /** Change the vault on a branch, the way a person would: through hush. */
  const onBranch = (branch: string, fn: (v: Vault) => void, from = "main") => {
    g("checkout", "-q", "-B", branch, from);
    const w = Vault.open(path);
    fn(w);
    w.save();
    g("commit", "-qam", branch);
  };
  const values = () => {
    const w = Vault.open(path);
    return w.materialize(id, "default");
  };
  return { home, root, id, env, g, hush, path, onBranch, values, cleanup: () => { for (const d of [home, root]) rmSync(d, { recursive: true, force: true }); } };
}

describe("F-1: through git", { skip: !hasGit && "git is not installed" }, () => {
  test("with the driver installed, a rotation on one branch and a new key on the other merge cleanly", () => {
    const r = repo();
    const installed = r.hush("merge-driver", "--install");
    assert.equal(installed.code, 0, installed.out);
    assert.match(readFileSync(join(r.root, ".git", "info", "attributes"), "utf8"), /\.hush\/vault\.json merge=hush/);
    // Nothing committed changed: a teammate without the driver keeps -merge.
    assert.match(readFileSync(join(r.root, ".hush", ".gitattributes"), "utf8"), /vault\.json -merge/);

    r.onBranch("theirs", (v) => v.rotate(r.id));
    r.onBranch("ours", (v) => v.set(r.id, "default", "ADDED_HERE", "added-here-value"));
    const merged = r.g("merge", "-q", "theirs", "-m", "merge");
    assert.equal(merged.status, 0, merged.stdout + merged.stderr);
    assert.deepEqual(r.values(), { KEY_C: "c-base-value", KEEP: "keep-base-value", ADDED_HERE: "added-here-value" });
    assert.equal(Vault.open(r.path).data.dek.generation, 2, "the rotation was lost");
    assert.equal(r.hush("verify").code, 0);
    r.cleanup();
  });

  test("a key changed on both branches is left to choose, and pick settles it without a value in sight", () => {
    const r = repo();
    r.hush("merge-driver", "--install");
    r.onBranch("theirs", (v) => v.set(r.id, "default", "KEY_C", "c-theirs-value"));
    r.onBranch("ours", (v) => v.set(r.id, "default", "KEY_C", "c-ours-value"));
    const merged = r.g("merge", "theirs", "-m", "merge");
    assert.notEqual(merged.status, 0, "git reported a clean merge over a real conflict");
    assert.match(merged.stdout + merged.stderr, /default\/KEY_C/);
    assert.doesNotMatch(merged.stdout + merged.stderr, /c-ours-value|c-theirs-value/);
    const record = readFileSync(join(r.root, ".hush", "merge-conflicts.json"), "utf8");
    assert.doesNotMatch(record, /c-ours-value|c-theirs-value/);
    assert.equal(r.values().KEY_C, "c-ours-value", "the file does not hold a working vault with this branch's side");

    assert.match(r.hush("merge", "status").out, /KEY_C/);
    assert.match(r.hush("ls").out, /keys to choose/, "commands do not mention the open choice");
    const picked = r.hush("merge", "pick", "KEY_C", "--theirs");
    assert.equal(picked.code, 0, picked.out);
    assert.equal(r.values().KEY_C, "c-theirs-value");
    assert.ok(!existsSync(join(r.root, ".hush", "merge-conflicts.json")));
    r.cleanup();
  });

  test("without the driver, git stops on the vault and hush merge finishes it", () => {
    const r = repo();
    r.onBranch("theirs", (v) => v.set(r.id, "default", "FROM_THEIRS", "from-theirs-value"));
    r.onBranch("ours", (v) => v.set(r.id, "default", "FROM_OURS", "from-ours-value"));
    const merged = r.g("merge", "theirs", "-m", "merge");
    assert.notEqual(merged.status, 0, "git merged the vault without hush");
    const fixed = r.hush("merge");
    assert.equal(fixed.code, 0, fixed.out);
    assert.deepEqual(
      Object.keys(r.values()).sort(),
      ["FROM_OURS", "FROM_THEIRS", "KEEP", "KEY_C"],
    );
    assert.match(fixed.out, /git add/);
    r.cleanup();
  });

  test("uninstall puts it back, and doctor says which it is", () => {
    const r = repo();
    r.hush("merge-driver", "--install");
    assert.match(r.hush("doctor").out, /✓ merge driver/);
    r.hush("merge-driver", "--uninstall");
    assert.doesNotMatch(readFileSync(join(r.root, ".git", "info", "attributes"), "utf8"), /merge=hush/);
    assert.match(r.hush("doctor").out, /✗ merge driver/);
    r.cleanup();
  });
});
