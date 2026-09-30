#!/usr/bin/env node
/**
 * Run before every `npm pack` / `npm publish` (package.json "prepack"): refuse
 * to package a file git does not track.
 *
 * `files` in package.json names whole folders (src, docs, native…), and npm
 * packs whatever is in them on the machine that runs it — including a private
 * working note, a scratch file, or a key someone dropped in docs/ and never
 * committed. Releases are built by CI from a clean checkout, where this can't
 * happen; this is for the day someone runs `npm publish` from a laptop.
 * dist/ is exempt: it is built, never tracked.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

/** Files under the packaged paths that git does not track (dist/ excepted). */
export function untrackedInPackage(dir) {
  const { files } = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  const paths = files.filter((f) => f !== "dist");
  const out = execFileSync("git", ["ls-files", "--others", "-z", "--", ...paths], { cwd: dir, encoding: "utf8" });
  return out.split("\0").filter(Boolean).sort();
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const stray = untrackedInPackage(root);
  if (stray.length) {
    process.stderr.write(
      `refusing to pack: ${stray.length} file(s) under the packaged folders are not tracked by git:\n` +
        stray.map((f) => `  ${f}`).join("\n") +
        "\nCommit them, move them out, or publish from CI (a clean checkout).\n",
    );
    process.exit(1);
  }
}
