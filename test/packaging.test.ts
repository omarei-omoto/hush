/**
 * Does the thing we publish actually work when someone installs it?
 *
 * Separate from the rest because it is a release check rather than a unit one:
 * it shells out to npm, it takes seconds rather than milliseconds, and — the
 * reason it lives in its own file — `npm pack` runs `tsc` through prepack. Under
 * a mutation-testing harness that turns every mutation into a compile error into
 * a failing test, so every mutant would come back "killed" whatever it did. A
 * check that can only report good news is not a check, and the same mistake has
 * already cost this project five batches of meaningless results.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync, readdirSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

describe("the published package actually runs", () => {
  // Every other test runs hush from this checkout, where Node strips the types
  // in src/ directly. An installed copy cannot: Node refuses to strip types for
  // anything under node_modules, so `npm install hush && hush --version` failed
  // with ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING — the package was
  // completely unusable, and a green suite said nothing about it.
  //
  // This is slow because it is the only honest way to check: pack it, install
  // it, run it.
  const haveNpm = (() => {
    const r = spawnSync("npm", ["--version"], { encoding: "utf8" });
    return !r.error && r.status === 0;
  })();

  test(
    "npm pack -> npm install -> hush works",
    { skip: haveNpm ? false : "npm is not on PATH" },
    () => {
      const packDir = mkdtempSync(join(tmpdir(), "hush-pack-"));
      const installDir = mkdtempSync(join(tmpdir(), "hush-install-"));
      const home = mkdtempSync(join(tmpdir(), "hush-pack-home-"));
      const proj = mkdtempSync(join(tmpdir(), "hush-pack-proj-"));
      try {
        const packed = spawnSync("npm", ["pack", "--pack-destination", packDir], {
          cwd: root, encoding: "utf8",
        });
        assert.equal(packed.status, 0, `npm pack failed:\n${packed.stdout}${packed.stderr}`);
        const tarball = readdirSync(packDir).find((n) => n.endsWith(".tgz"));
        assert.ok(tarball, "npm pack produced no tarball");

        const installed = spawnSync("npm", ["install", join(packDir, tarball), "--no-audit", "--no-fund"], {
          cwd: installDir, encoding: "utf8",
        });
        assert.equal(installed.status, 0, `npm install failed:\n${installed.stdout}${installed.stderr}`);

        const hush = join(installDir, "node_modules", ".bin", "hush");
        assert.ok(existsSync(hush), "the hush bin was not installed");

        const env = {
          ...process.env,
          HUSH_HOME: home,
          HUSH_NO_NUDGE: "1",
          HUSH_NO_KEYCHAIN: "1",
          HUSH_BIOMETRY: "off",
          NO_COLOR: "1",
        };
        const run = (...args: string[]) =>
          spawnSync(hush, args, { cwd: proj, env, encoding: "utf8" });

        const version = run("--version");
        assert.equal(version.status, 0, `hush --version failed:\n${version.stdout}${version.stderr}`);
        const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { version: string; name: string };
        assert.equal(version.stdout.trim(), pkg.version);

        // Not just --version: a real end-to-end path through the crypto, the
        // vault and the child process, from the installed copy.
        assert.equal(run("id", "--create").status, 0);
        assert.equal(run("init", "packtest").status, 0);
        assert.equal(run("set", "PACKED_KEY=packed_value_1234567890").status, 0);

        const ran = run("run", "--quiet", "--", "sh", "-c", 'echo "$PACKED_KEY"');
        assert.equal(ran.status, 0, `hush run failed:\n${ran.stdout}${ran.stderr}`);
        assert.match(ran.stdout, /redacted:PACKED_KEY/, "the installed copy did not inject or redact");
        assert.ok(!ran.stdout.includes("packed_value_1234567890"), "the installed copy leaked a value");

        const verified = run("verify");
        assert.equal(verified.status, 0, `hush verify failed:\n${verified.stdout}${verified.stderr}`);

        // The MCP server is how an agent reaches it, and it is a separate entry
        // point — so it gets its own check rather than being assumed.
        const mcp = spawnSync(hush, ["mcp"], {
          cwd: proj, env, encoding: "utf8",
          input: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize", params: {} }) + "\n",
        });
        assert.match(mcp.stdout, /"serverInfo"/, `the installed MCP server did not answer:\n${mcp.stderr}`);

        // It really is running the built copy: src/ is shipped too, and an
        // installed copy that reached for it would not have got this far.
        // Derived from the package name rather than hardcoded: a scoped name
        // installs to node_modules/@scope/name, and this assertion quietly
        // became about a path that does not exist the moment the name changed.
        assert.ok(
          existsSync(join(installDir, "node_modules", ...pkg.name.split("/"), "dist", "cli.js")),
          "the installed package has no dist/",
        );
      } finally {
        for (const d of [packDir, installDir, home, proj]) rmSync(d, { recursive: true, force: true });
      }
    },
  );

test("package.json is in the form npm will publish", () => {
    // `npm publish` normalises and validates more than `npm pack` does, and a
    // field it does not like is *silently removed* rather than rejected. A
    // leading "./" on the bin path was enough: publish warned "bin[hush] script
    // name was invalid and removed", which would have put a package with no
    // `hush` command on the registry — while every local test passed, because
    // they install from `npm pack`, which does not apply that step.
    //
    // `npm pkg fix` performs exactly that normalisation. If it wants to change
    // anything, publish would too.
    const before = read("package.json");
    const r = spawnSync("npm", ["pkg", "fix"], { cwd: root, encoding: "utf8" });
    const after = read("package.json");
    if (after !== before) writeFileSync(join(root, "package.json"), before);

    assert.equal(r.status, 0, `npm pkg fix failed:\n${r.stdout}${r.stderr}`);
    assert.equal(
      after,
      before,
      "npm would rewrite package.json on publish — run `npm pkg fix` and commit the result",
    );
  });

  test("the bin entry survives into a packed tarball", () => {
    const pkg = JSON.parse(read("package.json")) as { bin: Record<string, string> };
    assert.deepEqual(Object.keys(pkg.bin), ["hush"], "the command is not called hush");
    // The path is relative and has no leading "./", which is what publish strips.
    assert.match(pkg.bin.hush, /^[^./]/, `bin path "${pkg.bin.hush}" starts with . or /`);
    assert.ok(existsSync(join(root, pkg.bin.hush)), `bin points at a missing file: ${pkg.bin.hush}`);
  });

  test("the tarball carries the built javascript, not only the sources", () => {
    const pkg = JSON.parse(read("package.json")) as { files: string[]; scripts: Record<string, string> };
    assert.ok(pkg.files.includes("dist"), "the published files omit dist/ — an installed copy cannot run");
    assert.ok(pkg.scripts.prepack?.includes("build"), "nothing builds dist/ before packing");
    // The shim picks by whether it is running from node_modules, which is the
    // actual thing Node cares about — not by whether dist/ happens to exist.
    // Preferring dist whenever it was there broke the other direction: `npm
    // link` points node_modules back at the checkout, so a stale build would
    // silently shadow every edit to src/ until someone rebuilt.
    const shim = read("bin/hush.js");
    assert.match(shim, /node_modules/, "the bin shim does not distinguish an installed copy from a clone");
    assert.match(shim, /dist/, "the bin shim never looks at dist/");
    assert.match(shim, /src/, "the bin shim cannot run from a clone");
  });
});
