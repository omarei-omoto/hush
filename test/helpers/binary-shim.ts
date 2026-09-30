/**
 * Runs the whole test suite against the single-file binary instead of the
 * TypeScript source (F-8):
 *
 *   node scripts/build-binaries.mjs
 *   HUSH_TEST_BINARY=$PWD/release/hush-darwin-arm64 npm run test:binary
 *
 * Loaded with `--import` into every test process. Wherever a test spawns
 * `node src/cli.ts …` (or bin/hush.js), the spawn becomes `<binary> …`, so every
 * CLI-level assertion in the suite is made about the binary. In-process library
 * tests are unaffected — they test the same source the binary was built from.
 */
import { createRequire, syncBuiltinESMExports } from "node:module";
import { resolve } from "node:path";
import { existsSync } from "node:fs";

const binary = process.env.HUSH_TEST_BINARY;
if (binary) {
  if (!existsSync(binary)) throw new Error(`HUSH_TEST_BINARY does not exist: ${binary}`);
  const entries = new Set(
    [["src", "cli.ts"], ["bin", "hush.js"], ["dist", "cli.js"]].map((p) => resolve(import.meta.dirname, "..", "..", ...p)),
  );
  const isNode = (file: unknown) => file === process.execPath || file === "node";
  const rewrite = (file: unknown, args: unknown): [unknown, unknown] => {
    if (isNode(file) && Array.isArray(args) && typeof args[0] === "string" && entries.has(resolve(args[0]))) {
      return [binary, args.slice(1)];
    }
    return [file, args];
  };
  // The CommonJS exports object is the writable one; syncBuiltinESMExports then
  // carries the change to every `import { spawnSync } from "node:child_process"`.
  const mod = createRequire(import.meta.url)("node:child_process") as Record<string, (...a: unknown[]) => unknown>;
  for (const name of ["spawn", "spawnSync", "execFile", "execFileSync"]) {
    const original = mod[name];
    mod[name] = function (this: unknown, file: unknown, args: unknown, ...rest: unknown[]) {
      const [f, a] = rewrite(file, args);
      return original.call(this, f, a, ...rest);
    };
  }
  syncBuiltinESMExports();
}
