/**
 * What the CLI tests share: the path to the CLI, a scratch project with a
 * vault and an identity, a bare folder, and a stand-in for clicking Allow.
 */
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdtempSync, mkdirSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { generateIdentity, encodeSecret } from "../../src/crypto.ts";
import { Vault } from "../../src/vault.ts";
import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";

export const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "src", "cli.ts");
/** The stand-in desktop dialog, for the approval paths these tests drive in-process. */
export const ZENITY = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "zenity");
/** The same "human clicks Allow 15 min" the CLI subprocess tests cannot fake. */
export const clickingAllow = {
  authenticate: async () => "unavailable" as const,
  platform: () => "linux",
  resolveDialogProgram: (cmd: "osascript" | "zenity" | "kdialog") => (cmd === "zenity" ? ZENITY : null),
};

/**
 * @param envOverride  Merged over the base env, for the few tests that need to
 * change something about how the CLI is invoked.
 */
export function project(envOverride: NodeJS.ProcessEnv = {}) {
  const home = mkdtempSync(join(tmpdir(), "hush-cli-home-"));
  const root = mkdtempSync(join(tmpdir(), "hush-cli-proj-"));
  mkdirSync(join(root, ".hush"), { recursive: true });
  const id = generateIdentity();
  const vault = Vault.create(join(root, ".hush", "vault.json"), "clitest", { name: "tester", pub: id.pub });
  vault.set(id, "default", "STRIPE_SECRET_KEY", "sk_live_cli");
  vault.save();
  // Typed as the full environment, not the literal object, so a test can point
  // HOME at a scratch directory before running (`run` closes over this object).
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HUSH_HOME: home,
    HUSH_IDENTITY: encodeSecret(id),
    HUSH_BIOMETRY: "off",
    // No desktop: on macOS an enforced approval would otherwise open a real
    // osascript dialog on the developer's screen and hang the run. This is the
    // narrowing switch — it can only make an approval fail, never succeed.
    HUSH_NO_DIALOG: "1",
    HUSH_NO_NUDGE: "1",
    NO_COLOR: "1",
    ...envOverride,
  };
  /**
   * @param input piped to the command — `hush set` reads its value from stdin.
   *
   * `out` is stdout and stderr together, on success as well as on failure.
   * Capturing stderr only when the command failed hid every warning hush prints
   * on a successful run, so a test could assert on a message that was never
   * actually reaching the user's terminal.
   */
  const run = (args: string[], input?: string) => {
    const r = spawnSync(process.execPath, [CLI, ...args], {
      cwd: root,
      env,
      encoding: "utf8",
      input,
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
    return { out: (r.stdout ?? "") + (r.stderr ?? ""), code: r.status ?? 1 };
  };
  return {
    home, root, env, run,
    hushDir: join(root, ".hush"),
    cleanup: () => { for (const d of [home, root]) rmSync(d, { recursive: true, force: true }); },
  };
}

// ===========================================================================
// "In a new folder, if it's run then we need it to work": commands that don't
// need a project vault stop demanding one, and the first run in a folder
// nobody has told hush anything about proposes what to use instead of
// silently doing nothing.
// ===========================================================================

/**
 * A folder hush has never seen: no `.hush` anywhere above it, only a temp
 * HUSH_HOME. `librarySet()` builds a named library set from a *separate*
 * scratch cwd, never `root` — `audit()` in src/vault.ts creates `.hush`
 * unconditionally (even with `--no-use`) the moment any command runs there,
 * so fixture setup done *in* `root` would make a "this folder is untouched"
 * assertion pass by accident even if the code under test were broken.
 */
export function bareFolder(envOverride: NodeJS.ProcessEnv = {}) {
  const home = mkdtempSync(join(tmpdir(), "hush-cli-home-"));
  const root = mkdtempSync(join(tmpdir(), "hush-cli-bare-"));
  let setupDir: string | null = null;
  const id = generateIdentity();
  const env = {
    ...process.env,
    HUSH_HOME: home,
    HUSH_IDENTITY: encodeSecret(id),
    HUSH_BIOMETRY: "off",
    // No desktop: on macOS an enforced approval would otherwise open a real
    // osascript dialog on the developer's screen. This is the narrowing switch
    // — it can only make an approval fail, never succeed.
    HUSH_NO_DIALOG: "1",
    HUSH_NO_NUDGE: "1",
    NO_COLOR: "1",
    ...envOverride,
  };
  const runIn = (cwd: string, args: string[], input?: string) => {
    const r = spawnSync(process.execPath, [CLI, ...args], {
      cwd,
      env,
      encoding: "utf8",
      input,
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
    return { out: (r.stdout ?? "") + (r.stderr ?? ""), code: r.status ?? 1 };
  };
  const run = (args: string[], input?: string) => runIn(root, args, input);
  return {
    home, root, env, run,
    hushDir: join(root, ".hush"),
    /** Named library set with a label equal to its slug, so prompt-text assertions stay simple. */
    librarySet(name: string, values: Record<string, string>): void {
      if (!setupDir) setupDir = mkdtempSync(join(tmpdir(), "hush-cli-libsetup-"));
      if (!existsSync(join(home, "vaults", "global", "vault.json"))) {
        const created = runIn(setupDir, ["global", "--create"]);
        assert.equal(created.code, 0, created.out);
      }
      const pairs = Object.entries(values).map(([k, v]) => `${k}=${v}`);
      const r = runIn(setupDir, ["add", ...pairs, "--to", name, "--library", "--no-use"]);
      assert.equal(r.code, 0, r.out);
    },
    cleanup: () => {
      for (const d of [home, root, ...(setupDir ? [setupDir] : [])]) rmSync(d, { recursive: true, force: true });
    },
  };
}
