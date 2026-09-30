/**
 * The single-file binary (F-8, scripts/build-binaries.mjs).
 *
 * The whole suite runs against a binary with `npm run test:binary`
 * (test/helpers/binary-shim.ts). This file checks what only the binary can get
 * wrong: files it has to carry with it, the page it serves, and two defaults of
 * Bun's that would hand a cloned repository control of hush.
 *
 * The binary checks run when HUSH_TEST_BINARY names one; CI builds it first.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { ASSET_FILES } from "../src/assets.ts";
import { PAGE } from "../src/ui-page.ts";
import { VERSION } from "../src/version.ts";
import { generateIdentity, encodeSecret } from "../src/crypto.ts";
import { Vault } from "../src/vault.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const binary = process.env.HUSH_TEST_BINARY;

describe("what the binary embeds", () => {
  test("every asset exists, and ships in the npm package too", () => {
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { files: string[] };
    for (const [name, rel] of Object.entries(ASSET_FILES)) {
      const path = join(root, "src", rel);
      assert.ok(existsSync(path), `asset "${name}" is missing: ${path}`);
      const top = relative(root, path).split(/[\\/]/)[0];
      assert.ok(pkg.files.includes(top), `asset "${name}" is not in package.json "files" (${top})`);
    }
  });
});

describe("the built binary", { skip: !binary && "set HUSH_TEST_BINARY to a built binary (npm run build:binaries)" }, () => {
  const env = (home: string, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv => ({
    PATH: process.env.PATH,
    HOME: home,
    HUSH_HOME: home,
    HUSH_NO_KEYCHAIN: "1",
    HUSH_BIOMETRY: "off",
    HUSH_NO_DIALOG: "1",
    HUSH_NO_NUDGE: "1",
    NO_COLOR: "1",
    ...(process.env.SYSTEMROOT ? { SYSTEMROOT: process.env.SYSTEMROOT } : {}),
    ...extra,
  });

  test("it is this version", () => {
    const r = spawnSync(binary!, ["--version"], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.trim(), VERSION);
  });

  test("it carries JavaScript, not the TypeScript source", () => {
    const bytes = readFileSync(binary!);
    // Type-only syntax that exists in src/ and cannot survive a compile.
    for (const ts of ["export interface Opener {", "export type AssetName = keyof typeof FILES"]) {
      assert.equal(bytes.indexOf(ts), -1, `the binary contains TypeScript source: ${ts}`);
    }
  });

  test("a .env in the working directory is not loaded into hush", () => {
    // Bun's compiled programs load ./.env by default. In hush that would read
    // the very file hush replaces, and let a cloned repository set HUSH_* for
    // anyone who runs hush in it.
    const home = mkdtempSync(join(tmpdir(), "hush-bin-home-"));
    const proj = mkdtempSync(join(tmpdir(), "hush-bin-proj-"));
    mkdirSync(join(proj, ".hush"));
    const id = generateIdentity();
    const v = Vault.create(join(proj, ".hush", "vault.json"), "bin", { name: "tester", pub: id.pub, priv: id.priv });
    v.set(id, "default", "FROM_VAULT", "vault-value");
    v.save();
    writeFileSync(join(proj, ".env"), "PLANTED_BY_DOTENV=leaked\nHUSH_NO_DIALOG=planted\n");
    // node, not sh, so this runs on Windows as well.
    const probe = 'console.log("[" + (process.env.PLANTED_BY_DOTENV ?? "") + "]")';
    const r = spawnSync(binary!, ["run", "--", process.execPath, "-e", probe], {
      cwd: proj,
      env: env(home, { HUSH_IDENTITY: encodeSecret(id) }),
      encoding: "utf8",
    });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /^\[\]$/m, `the binary loaded .env:\n${r.stdout}`);
    rmSync(home, { recursive: true, force: true });
    rmSync(proj, { recursive: true, force: true });
  });

  test("a bunfig.toml in the working directory cannot preload code into hush", () => {
    const dir = mkdtempSync(join(tmpdir(), "hush-bin-bunfig-"));
    const marker = join(dir, "preloaded");
    writeFileSync(join(dir, "evil.ts"), `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "yes");\n`);
    writeFileSync(join(dir, "bunfig.toml"), 'preload = ["./evil.ts"]\n');
    const r = spawnSync(binary!, ["--version"], { cwd: dir, env: env(dir), encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(!existsSync(marker), "bunfig.toml's preload ran inside hush");
    rmSync(dir, { recursive: true, force: true });
  });

  test("hush ui serves exactly the page the source builds", async () => {
    // The page is String.raw templates; a bundler's \u escapes change their
    // value (src/assets.ts builtPage). Byte-for-byte, or it is not the page.
    const home = mkdtempSync(join(tmpdir(), "hush-bin-ui-"));
    const child = spawn(binary!, ["ui", "--no-open", "--port", "0"], {
      cwd: home,
      env: env(home, { HUSH_IDENTITY: encodeSecret(generateIdentity()) }),
    });
    try {
      const url = await new Promise<string>((resolve, reject) => {
        let out = "";
        const timer = setTimeout(() => reject(new Error(`no URL from hush ui:\n${out}`)), 15_000);
        const read = (d: Buffer) => {
          out += d;
          const m = /http:\/\/127\.0\.0\.1:\d+\/#t=[A-Za-z0-9_-]+/.exec(out);
          if (m) {
            clearTimeout(timer);
            resolve(m[0]);
          }
        };
        child.stdout.on("data", read);
        child.stderr.on("data", read);
      });
      const served = await (await fetch(url.split("#")[0])).text();
      assert.ok(!/\\u[0-9a-f]{4}/i.test(served), "the served page contains a literal \\u escape");
      assert.equal(served, PAGE, "the binary serves a different page from the source");
    } finally {
      child.kill();
      rmSync(home, { recursive: true, force: true });
    }
  });
});
