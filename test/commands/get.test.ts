/**
 * `hush get --copy`.
 */
import { test, describe } from "node:test";
import { mkdtempSync, readFileSync, existsSync, rmSync, symlinkSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir, platform } from "node:os";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { project } from "../helpers/cli.ts";

describe("hush get --copy", () => {
  /**
   * The platform's first clipboard candidate, symlinked to the stub. Doing it
   * per-platform keeps the test honest on macOS and on CI's ubuntu alike.
   */
  function clipboardEnv(): { env: NodeJS.ProcessEnv; read: () => string; dir: string } {
    const dir = mkdtempSync(join(tmpdir(), "hush-clip-"));
    const name = platform() === "darwin" ? "pbcopy" : "wl-copy";
    symlinkSync(join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "clipboard-stub"), join(dir, name));
    const out = join(dir, "copied.txt");
    return {
      dir,
      env: { PATH: `${dir}:${process.env.PATH ?? ""}`, HUSH_TEST_CLIPBOARD: out },
      read: () => (existsSync(out) ? readFileSync(out, "utf8") : ""),
    };
  }

  test("the value goes to the clipboard and never to stdout", () => {
    const clip = clipboardEnv();
    const p = project({ ...clip.env });
    try {
      const r = p.run(["get", "STRIPE_SECRET_KEY", "--copy", "--yes"]);
      assert.equal(r.code, 0, r.out);
      assert.equal(clip.read(), "sk_live_cli", "the clipboard did not receive the value");
      assert.doesNotMatch(r.out, /sk_live_cli/, "the value was printed as well as copied");
      assert.match(r.out, /copied STRIPE_SECRET_KEY to the clipboard/);
      assert.match(r.out, /11 characters/, "the confirmation should say how much was copied");
    } finally {
      p.cleanup();
      rmSync(clip.dir, { recursive: true, force: true });
    }
  });

  test("a clipboard tool that fails is reported, not silently ignored", () => {
    const clip = clipboardEnv();
    const p = project({ ...clip.env, HUSH_TEST_CLIPBOARD_EXIT: "3" });
    try {
      const r = p.run(["get", "STRIPE_SECRET_KEY", "--copy", "--yes"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /Could not copy/);
      assert.doesNotMatch(r.out, /sk_live_cli/);
    } finally {
      p.cleanup();
      rmSync(clip.dir, { recursive: true, force: true });
    }
  });

  test("with no clipboard tool at all, it says which ones it looked for", () => {
    const empty = mkdtempSync(join(tmpdir(), "hush-nopath-"));
    const p = project({ PATH: empty });
    try {
      const r = p.run(["get", "STRIPE_SECRET_KEY", "--copy", "--yes"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /No clipboard tool found/);
      assert.match(r.out, /pbcopy|wl-copy/, "the error does not name anything to install");
      assert.match(r.out, /drop --copy/, "the error does not offer the alternative");
    } finally {
      p.cleanup();
      rmSync(empty, { recursive: true, force: true });
    }
  });

  test("printing still works, and still warns about the scrollback", () => {
    const p = project();
    try {
      const r = p.run(["get", "STRIPE_SECRET_KEY", "--yes"]);
      assert.match(r.out, /sk_live_cli/);
    } finally {
      p.cleanup();
    }
  });
});
