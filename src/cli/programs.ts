/**
 * Finding programs and files the CLI reaches for.
 */
import { existsSync, readFileSync, statSync, accessSync, constants as fsConstants } from "node:fs";
import { join, dirname, resolve as resolvePath } from "node:path";

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
  const dirs = (process.env.PATH ?? "").split(process.platform === "win32" ? ";" : ":");
  const extensions = process.platform === "win32" ? (process.env.PATHEXT ?? ".EXE;.CMD;.BAT").split(";") : [""];
  for (const dir of dirs) {
    if (!dir) continue;
    for (const ext of extensions) {
      const candidate = join(dir, name + ext.toLowerCase());
      try {
        if (statSync(candidate).isFile()) {
          accessSync(candidate, fsConstants.X_OK);
          return candidate;
        }
      } catch { /* not this one */ }
    }
  }
  return null;
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
