/**
 * Finding a program on PATH.
 *
 * Two callers need this now — the age bridge and the clipboard — and the pair
 * lived privately in age.ts, where the second caller would have copied it. The
 * rule is the same in both places and is subtle enough to be worth having once.
 */
import { accessSync, statSync, constants } from "node:fs";
import { join } from "node:path";

const { X_OK } = constants;

/**
 * A real program: a regular file with the execute bit.
 *
 * A directory's execute bit means "you may traverse me", so an `accessSync(p,
 * X_OK)` on its own is satisfied by a directory called `age` sitting on PATH —
 * and the failure then surfaces as EACCES from the middle of a decrypt rather
 * than as "age is not installed".
 */
export function isExecutableFile(path: string): boolean {
  try {
    if (!statSync(path).isFile()) return false;
    accessSync(path, X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolve an executable from PATH ourselves.
 *
 * The obvious implementation shells out to `which`, but `which` is not on
 * Windows at all and is missing from plenty of minimal container images — so
 * the age bridge would report "not installed" on exactly the machines where
 * that is hardest to debug. Reading PATH costs no subprocess either.
 */
export function onPath(name: string, pathValue: string = process.env.PATH ?? ""): string | null {
  const dirs = pathValue.split(process.platform === "win32" ? ";" : ":");
  const extensions =
    process.platform === "win32" ? (process.env.PATHEXT ?? ".EXE;.CMD;.BAT").split(";") : [""];

  for (const dir of dirs) {
    if (!dir) continue;
    for (const ext of extensions) {
      const candidate = join(dir, name + ext.toLowerCase());
      if (isExecutableFile(candidate)) return candidate;
    }
  }
  return null;
}
