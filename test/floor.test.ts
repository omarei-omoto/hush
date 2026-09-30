/**
 * S-1: the policy floor exists by default once an agent is near the vault.
 *
 * docs/RED-TEAM.md finding 4: a copy of a committed vault, opened through
 * HUSH_VAULT from a folder with no policy.json of its own, ran with no policy at
 * all when `~/.hush/policy.json` did not exist — `hush get` printed a value with
 * no prompt even though the real project required fingerprint approval. The
 * floor's *existence* is the fix, and nothing used to create one.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, copyFileSync, rmSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { Vault } from "../src/vault.ts";
import { generateIdentity, encodeSecret } from "../src/crypto.ts";
import { ensureFloor } from "../src/policy.ts";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.ts");
const VALUE = "FAKE-VALUE-DO-NOT-USE-5678";

function setup() {
  const home = mkdtempSync(join(tmpdir(), "hush-floor-home-"));
  const root = mkdtempSync(join(tmpdir(), "hush-floor-proj-"));
  const scratch = mkdtempSync(join(tmpdir(), "hush-floor-scratch-"));
  mkdirSync(join(root, ".hush"), { recursive: true });
  const id = generateIdentity();
  const vault = Vault.create(join(root, ".hush", "vault.json"), "floor", { name: "tester", pub: id.pub });
  vault.set(id, "default", "FAKE_API_KEY", VALUE);
  vault.save();
  writeFileSync(join(root, ".hush", "policy.json"), JSON.stringify({ requireApproval: ["reveal"], biometry: "required" }));
  const run = (args: string[], opts: { cwd?: string; env?: NodeJS.ProcessEnv } = {}) => {
    const r = spawnSync(process.execPath, [CLI, ...args], {
      cwd: opts.cwd ?? root,
      env: {
        ...process.env,
        HOME: home,
        HUSH_HOME: home,
        HUSH_IDENTITY: encodeSecret(id),
        HUSH_NO_KEYCHAIN: "1",
        HUSH_BIOMETRY: "off",
        HUSH_NO_DIALOG: "1",
        HUSH_NO_NUDGE: "1",
        NO_COLOR: "1",
        ...opts.env,
      },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 30_000,
    });
    return { out: (r.stdout ?? "") + (r.stderr ?? ""), stdout: r.stdout ?? "", code: r.status ?? 1 };
  };
  /** Red-team finding 4, verbatim: a copy of the vault, reached through HUSH_VAULT. */
  const redirect = () => {
    copyFileSync(join(root, ".hush", "vault.json"), join(scratch, "vault.json"));
    return run(["get", "FAKE_API_KEY", "--yes"], { cwd: scratch, env: { HUSH_VAULT: join(scratch, "vault.json") } });
  };
  return {
    home, root, run, redirect,
    cleanup: () => { for (const d of [home, root, scratch]) rmSync(d, { recursive: true, force: true }); },
  };
}

describe("S-1: the policy floor is created when an agent comes near", () => {
  test("after hush install-mcp, the HUSH_VAULT redirect meets an approval and refuses", () => {
    const s = setup();
    const installed = s.run(["install-mcp", "--for", "claude-code", "--yes"]);
    assert.equal(installed.code, 0, installed.out);
    assert.ok(existsSync(join(s.home, "policy.json")), "install-mcp did not write the floor:\n" + installed.out);
    assert.match(installed.out, /policy floor/);

    const r = s.redirect();
    assert.notEqual(r.code, 0, "the redirect was not refused:\n" + r.out);
    assert.ok(!r.stdout.includes(VALUE), "the value leaked through the redirect");
    s.cleanup();
  });

  test("hush install-skill and hush init --agent write it too, and say so once", () => {
    const s = setup();
    const skill = s.run(["install-skill", "--for", "claude-code", "--yes"]);
    assert.equal(skill.code, 0, skill.out);
    assert.ok(existsSync(join(s.home, "policy.json")), skill.out);
    const again = s.run(["install-skill", "--for", "claude-code", "--yes"]);
    assert.doesNotMatch(again.out, /policy floor/, "an existing floor was announced again");
    s.cleanup();

    const t = setup();
    const fresh = mkdtempSync(join(tmpdir(), "hush-floor-init-"));
    const init = t.run(["init", "demo", "--agent"], { cwd: fresh });
    assert.equal(init.code, 0, init.out);
    assert.ok(existsSync(join(t.home, "policy.json")), init.out);
    rmSync(fresh, { recursive: true, force: true });
    t.cleanup();
  });

  test("hush level fails the floor check only once an agent is registered, and hush secure floor fixes it", () => {
    const s = setup();
    const floorCheck = () =>
      (JSON.parse(s.run(["level", "--json"]).stdout) as { checks: { id: string; pass: boolean }[] }).checks.find(
        (c) => c.id === "floor",
      );
    assert.equal(floorCheck()?.pass, true, "no agent registered, yet the floor check failed");

    // Registered by hand, the way someone who never ran install-mcp would.
    writeFileSync(join(s.root, ".mcp.json"), JSON.stringify({ mcpServers: { hush: { command: "hush", args: ["mcp"] } } }));
    assert.equal(floorCheck()?.pass, false, "an agent is registered and there is no floor, yet the check passed");
    assert.match(s.run(["doctor"]).out, /hush secure floor/);

    const fixed = s.run(["secure", "floor"]);
    assert.equal(fixed.code, 0, fixed.out);
    assert.equal(readFileSync(join(s.home, "policy.json"), "utf8"), "{}\n");
    assert.equal(statSync(join(s.home, "policy.json")).mode & 0o777, 0o600);
    assert.equal(floorCheck()?.pass, true);
    s.cleanup();
  });

  test("ensureFloor never overwrites a floor someone wrote", () => {
    const home = mkdtempSync(join(tmpdir(), "hush-floor-own-"));
    writeFileSync(join(home, "policy.json"), JSON.stringify({ allowCommands: ["npm"] }));
    const r = ensureFloor(home);
    assert.equal(r.created, false);
    assert.deepEqual(JSON.parse(readFileSync(join(home, "policy.json"), "utf8")), { allowCommands: ["npm"] });
    rmSync(home, { recursive: true, force: true });
  });
});
