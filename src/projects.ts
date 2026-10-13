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
import { setImmediate as nextTick } from "node:timers/promises";
import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";
import { hushHome } from "./identity.ts";
import { parseJson } from "./json.ts";
import { ValidationError, writeFileAtomic } from "./vault-files.ts";
import { type CodebaseDetails, describeCodebase, isCodebase } from "./codebase.ts";

export interface KnownProject {
  /** The project's root: the folder holding .hush/ (or the codebase's top), links resolved. */
  root: string;
  /** When hush was last used there (ISO), or when it was found. */
  seen: string;
  hidden?: boolean;
  /** What the last crawl found out about it (codebase.ts). */
  details?: CodebaseDetails;
}

interface Registry {
  projects: KnownProject[];
  /** When the one-time search of the usual code folders ran (ISO). */
  searched?: string;
  /** The folders the person chose for hush to look in for codebases. */
  roots?: string[];
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
    const roots = Array.isArray(j?.roots) ? j.roots.filter((x) => typeof x === "string") : undefined;
    return { projects, ...(typeof j?.searched === "string" ? { searched: j.searched } : {}), ...(roots ? { roots } : {}) };
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

/** Still worth listing: a hush project, or a codebase that is still there. */
const listable = (root: string): boolean => isProjectRoot(root) || isCodebase(root);
export const isListedRoot = listable;

/**
 * The projects to show: still there, not hidden. Hush projects first, then
 * codebases hush has found but that are not set up yet; within each, the most
 * recently worked on first.
 */
export function listProjects(): (KnownProject & { hush: boolean })[] {
  const when = (p: KnownProject) => p.details?.active ?? p.seen;
  return load()
    .projects.filter((p) => !p.hidden && listable(p.root))
    .map((p) => ({ ...p, hush: isProjectRoot(p.root) }))
    .sort((a, b) => Number(b.hush) - Number(a.hush) || when(b).localeCompare(when(a)) || basename(a.root).localeCompare(basename(b.root)));
}

/** Is `root` on the list (hidden ones included)? The app acts only on these. */
export function isKnownProject(root: string): boolean {
  const at = real(root);
  return load().projects.some((p) => p.root === at);
}

/** Add a folder by hand: a hush project, or any codebase. */
export function addProject(root: string): KnownProject {
  const at = real(root);
  if (!listable(at)) throw new ValidationError(`${at} is not a codebase hush recognises: no .hush, .git or project file (package.json, pyproject.toml, …) in it`);
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

/** The folders to look in: the ones the person chose, else the usual code folders. */
export function crawlRoots(): { roots: string[]; chosen: boolean } {
  const r = load();
  if (r.roots) return { roots: r.roots, chosen: true };
  // A relocated hush home (HUSH_HOME: a test, a second identity) guesses no
  // folders of the real home: only ones chosen for it are looked in.
  return { roots: process.env.HUSH_HOME ? [] : searchRoots(), chosen: false };
}

/** Choose the folders hush looks in for codebases. Each must be a folder that exists. */
export function setCrawlRoots(roots: string[]): string[] {
  const clean = [...new Set(roots.map((d) => d.trim()).filter(Boolean).map((d) => (d === "~" ? homedir() : d.startsWith("~/") ? join(homedir(), d.slice(2)) : d)).map(real))];
  for (const d of clean) {
    let dir = false;
    try {
      dir = statSync(d).isDirectory();
    } catch { /* missing */ }
    if (!dir) throw new ValidationError(`${d} is not a folder`);
  }
  const r = load();
  r.roots = clean;
  save(r);
  return clean;
}

const SKIP = new Set(["node_modules", ".git", ".hg", ".svn", "Library", "dist", "build", "target", "vendor", ".venv", "venv", ".next", ".cache"]);

/**
 * Find hush projects under `roots`, bounded so it can never take long: a
 * depth limit, a folder budget and a deadline. Names only — nothing inside a
 * project is read beyond whether .hush/ has a vault or a list of sets.
 */
export function findProjects(roots: string[], limits: { depth: number; folders: number; ms: number; codebases?: boolean } = { depth: 4, folders: 20_000, ms: 2_000 }): string[] {
  const found: string[] = [];
  const deadline = Date.now() + limits.ms;
  let budget = limits.folders;
  const walk = (dir: string, depth: number): void => {
    if (budget-- <= 0 || Date.now() > deadline) return;
    if (isProjectRoot(dir) || (limits.codebases && isCodebase(dir))) {
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

// -------------------------------------------------------------- the crawl

export interface CrawlStatus {
  running: boolean;
  /** Codebases described so far, and how many were found. */
  done: number;
  total: number;
  /** The one being described now. */
  current?: string;
  /** When the last crawl finished (ISO). */
  finished?: string;
}

let crawl: CrawlStatus = { running: false, done: 0, total: 0 };

export const crawlStatus = (): CrawlStatus => ({ ...crawl });

/**
 * Look through the chosen folders for codebases and describe each one: its
 * stack, when it was last worked on, and which credentials its code reads
 * (names only). Runs in the background, one codebase at a time, yielding in
 * between so the app stays responsive; the list fills in as it goes.
 */
export function startCrawl(): CrawlStatus {
  if (crawl.running) return crawlStatus();
  const { roots } = crawlRoots();
  const found = findProjects(roots, { depth: 4, folders: 40_000, ms: 4_000, codebases: true });
  const r = load();
  const now = new Date().toISOString();
  for (const root of found) if (!r.projects.some((p) => p.root === root)) r.projects.push({ root, seen: now });
  r.searched = now;
  save(r);
  // Every listed project gets described, not only the ones found this time.
  const todo = [...new Set([...found, ...r.projects.filter((p) => !p.hidden).map((p) => p.root)])].filter(listable);
  crawl = { running: true, done: 0, total: todo.length };
  void (async () => {
    for (const root of todo) {
      crawl.current = basename(root);
      await nextTick();
      let details: CodebaseDetails | null = null;
      try {
        details = describeCodebase(root);
      } catch { /* unreadable: listed without details */ }
      if (details) {
        const latest = load();
        const entry = latest.projects.find((p) => p.root === root);
        if (entry) {
          entry.details = details;
          try {
            save(latest);
          } catch { /* the list is a convenience */ }
        }
      }
      crawl.done++;
    }
    crawl = { running: false, done: crawl.done, total: crawl.total, finished: new Date().toISOString() };
  })();
  return crawlStatus();
}

/** The first time the app opens: crawl once, in the background. */
export function crawlOnce(): void {
  if (!load().searched) startCrawl();
}
