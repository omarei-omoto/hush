/**
 * The projects hush knows about on this machine: the list the app's sidebar
 * shows, so one window covers every project instead of the one folder `hush
 * ui` was started in.
 *
 * Kept in `~/.hush/projects.json`, paths only. A project is remembered when
 * hush is used in it (any command, or the app), found once by a bounded search
 * of the usual code folders, or added by hand; hiding one only takes it off the
 * list. Nothing here is a permission: what a project may use is still decided
 * by its own .hush/ and the confirmations in ~/.hush.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";
import { hushHome } from "./identity.ts";
import { parseJson } from "./json.ts";
import { writeFileAtomic } from "./vault-files.ts";

export interface KnownProject {
  /** The project's root: the folder holding .hush/, links resolved. */
  root: string;
  /** When hush was last used there (ISO), or when it was found. */
  seen: string;
  hidden?: boolean;
}

interface Registry {
  projects: KnownProject[];
  /** When the one-time search of the usual code folders ran (ISO). */
  searched?: string;
}

const registryPath = (): string => join(hushHome(), "projects.json");

const real = (p: string): string => {
  try {
    return realpathSync(p);
  } catch {
    return resolve(p);
  }
};

/** A folder hush works in: it has .hush/ with a vault or a list of sets. */
export const isProjectRoot = (root: string): boolean =>
  existsSync(join(root, ".hush", "vault.json")) || existsSync(join(root, ".hush", "envs.json"));

function load(): Registry {
  try {
    const j = parseJson(readFileSync(registryPath(), "utf8")) as Registry;
    const projects = Array.isArray(j?.projects)
      ? j.projects.filter((p) => p && typeof p.root === "string" && typeof p.seen === "string")
      : [];
    return { projects, ...(typeof j?.searched === "string" ? { searched: j.searched } : {}) };
  } catch {
    return { projects: [] };
  }
}

function save(r: Registry): void {
  mkdirSync(hushHome(), { recursive: true, mode: 0o700 });
  writeFileAtomic(registryPath(), JSON.stringify(r, null, 2) + "\n");
}

/**
 * Remember that hush was used in `root`. Cheap enough to call on every
 * command: it writes only for a project not on the list yet, one not seen
 * for a day, or one the person had hidden and is now using again.
 */
export function rememberProject(root: string): void {
  try {
    const at = real(root);
    if (at === real(hushHome()) || !isProjectRoot(at)) return;
    const r = load();
    const now = new Date().toISOString();
    const known = r.projects.find((p) => p.root === at);
    if (known) {
      const stale = Date.now() - Date.parse(known.seen) > 86_400_000;
      if (!stale && !known.hidden) return;
      known.seen = now;
      delete known.hidden;
    } else {
      r.projects.push({ root: at, seen: now });
    }
    save(r);
  } catch {
    // The list is a convenience; it must never break the command being run.
  }
}

/** The projects to show: still there, not hidden, most recently used first. */
export function listProjects(): KnownProject[] {
  return load()
    .projects.filter((p) => !p.hidden && isProjectRoot(p.root))
    .sort((a, b) => b.seen.localeCompare(a.seen) || basename(a.root).localeCompare(basename(b.root)));
}

/** Is `root` on the list (hidden ones included)? The app acts only on these. */
export function isKnownProject(root: string): boolean {
  const at = real(root);
  return load().projects.some((p) => p.root === at);
}

/** Add a folder by hand. It must already be a hush project. */
export function addProject(root: string): KnownProject {
  const at = real(root);
  if (!isProjectRoot(at)) throw new Error(`${at} is not a hush project: it has no .hush/vault.json or .hush/envs.json`);
  const r = load();
  const known = r.projects.find((p) => p.root === at);
  if (known) {
    delete known.hidden;
    known.seen = new Date().toISOString();
  } else {
    r.projects.push({ root: at, seen: new Date().toISOString() });
  }
  save(r);
  return r.projects.find((p) => p.root === at)!;
}

/** Take a project off the list. Its files are untouched. */
export function hideProject(root: string): void {
  const at = real(root);
  const r = load();
  const known = r.projects.find((p) => p.root === at);
  if (!known) return;
  known.hidden = true;
  save(r);
}

/** Where people keep code, for the one-time search. Only the ones that exist are read. */
export function searchRoots(home = homedir()): string[] {
  return ["code", "Code", "projects", "Projects", "dev", "Developer", "src", "repos", "work", "git", "GitHub", "Documents/GitHub", "Documents/code", "Desktop", "Downloads"]
    .map((d) => join(home, d))
    .filter((d) => {
      try {
        return statSync(d).isDirectory();
      } catch {
        return false;
      }
    });
}

const SKIP = new Set(["node_modules", ".git", ".hg", ".svn", "Library", "dist", "build", "target", "vendor", ".venv", "venv", ".next", ".cache"]);

/**
 * Find hush projects under `roots`, bounded so it can never take long: a
 * depth limit, a folder budget and a deadline. Names only — nothing inside a
 * project is read beyond whether .hush/ has a vault or a list of sets.
 */
export function findProjects(roots: string[], limits = { depth: 4, folders: 20_000, ms: 2_000 }): string[] {
  const found: string[] = [];
  const deadline = Date.now() + limits.ms;
  let budget = limits.folders;
  const walk = (dir: string, depth: number): void => {
    if (budget-- <= 0 || Date.now() > deadline) return;
    if (isProjectRoot(dir)) {
      found.push(real(dir));
      return; // a project's own subfolders are its own business
    }
    if (depth >= limits.depth) return;
    let entries: string[];
    try {
      entries = readdirSync(dir, { withFileTypes: true })
        .filter((e) => e.isDirectory() && !e.isSymbolicLink() && !SKIP.has(e.name) && !e.name.startsWith("."))
        .map((e) => e.name);
    } catch {
      return;
    }
    for (const name of entries) walk(join(dir, name), depth + 1);
  };
  for (const r of roots) walk(r, 0);
  return [...new Set(found)];
}

/**
 * Run the one-time search, if it has not run yet, and add what it finds.
 * Returns how many projects were added.
 */
export function searchOnce(roots = searchRoots()): number {
  const r = load();
  if (r.searched) return 0;
  const now = new Date().toISOString();
  let added = 0;
  for (const root of findProjects(roots)) {
    if (r.projects.some((p) => p.root === root)) continue;
    r.projects.push({ root, seen: now });
    added++;
  }
  r.searched = now;
  try {
    save(r);
  } catch {
    return 0;
  }
  return added;
}
