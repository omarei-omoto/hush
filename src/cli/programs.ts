/**
 * Finding programs and files the CLI reaches for.
 */
import { existsSync, readFileSync, statSync, accessSync, realpathSync, constants as fsConstants } from "node:fs";
import { join, dirname, extname, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";
import { onPath as whichOnPath } from "../which.ts";

export function readIfExists(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ programs

/**
 * Resolve an executable from PATH ourselves, the way src/age.ts does for
 * `age` — `which` is missing on Windows and from plenty of minimal container
 * images, so shelling out to it would make pass-through and `hush dev` report
 * "not found" on exactly the machines where that is hardest to debug.
 *
 * Duplicated rather than imported: age.ts's copy is private to that module,
 * and the brief for this change asked for a small local one rather than
 * reaching into an unrelated file for it.
 */
export function onPath(name: string): string | null {
  // A path — "./dev.sh", "/opt/bin/x" — is not looked up on PATH, it is checked.
  if (name.includes("/") || name.includes("\\")) {
    try {
      if (statSync(name).isFile()) {
        accessSync(name, fsConstants.X_OK);
        return resolvePath(name);
      }
    } catch { /* not runnable */ }
    return null;
  }
  // PATH itself: the one lookup, shared with the age bridge and the
  // clipboard, which knows Windows' extension order (see which.ts).
  return whichOnPath(name);
}

/** Walk up from `start` looking for `filename`. Used by `hush dev` to find package.json. */
export function findUpward(filename: string, start: string): string | null {
  let dir = resolvePath(start);
  for (;;) {
    const candidate = join(dir, filename);
    if (existsSync(candidate)) return candidate;
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/** Which package manager owns a project, guessed the only reliable way: its lockfile. */
export function packageManagerFor(dir: string): "bun" | "pnpm" | "yarn" | "npm" {
  if (existsSync(join(dir, "bun.lock")) || existsSync(join(dir, "bun.lockb"))) return "bun";
  if (existsSync(join(dir, "pnpm-lock.yaml"))) return "pnpm";
  if (existsSync(join(dir, "yarn.lock"))) return "yarn";
  return "npm";
}

/**
 * How to run this very hush from somewhere else — an agent's config, git's
 * merge driver. A bare `hush` whenever the `hush` on PATH is this install, so
 * a committed file works on a teammate's machine; otherwise `node` and the
 * absolute path to this entry point, which is at least the right program.
 */
export function selfCommand(args: string[]): { command: string; args: string[] } {
  // src/cli.ts from a checkout, dist/cli.js from an install: the entry point
  // one directory up from this file, in this file's own extension.
  const here = fileURLToPath(import.meta.url);
  const cliPath = join(dirname(here), "..", `cli${extname(here)}`);
  const onPathHush = onPath("hush");
  try {
    if (onPathHush && realpathSync(onPathHush) === realpathSync(join(dirname(cliPath), "..", "bin", "hush.js"))) {
      return { command: "hush", args };
    }
  } catch { /* fall through to the absolute path */ }
  return { command: "node", args: [cliPath, ...args] };
}
