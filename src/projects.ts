/**
 * The projects hush knows about on this machine: the list the app's sidebar
 * shows, so one window covers every project instead of the one folder `hush
 * ui` was started in.
 *
 * Kept in `~/.hush/projects.json`, paths only. A project is remembered when
 * hush is used in it (any command, or the app), found by the crawl of the
 * folders hush looks in, or added by hand. Hiding one moves it to the hidden
 * list; removing one forgets it, and the crawl leaves it out from then on.
 * Only the person undoes either (Show, or adding the folder again): using hush
 * there, or a crawl, never does. Neither touches the project's files. Nothing
 * here is a permission: what a project may use is still decided by its own
 * .hush/ and the confirmations in ~/.hush.
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
  /** The project group it is filed under in the app ("omoto", "Clients"): a folder for the list, nothing more. */
  group?: string;
  /** What the last crawl found out about it (codebase.ts). */
  details?: CodebaseDetails;
}

interface Registry {
  projects: KnownProject[];
  /** When the one-time search of the usual code folders ran (ISO). */
  searched?: string;
  /** When the crawl for codebases last ran (ISO): its own mark, so an older search never stands in for it. */
  crawled?: string;
  /** The folders the person chose for hush to look in for codebases. */
  roots?: string[];
  /** Folders the person removed from the list: the crawl does not add them back. */
  ignored?: string[];
  /** Suggestions the person waved away in the app (suggest.ts), by id: not offered again. */
  dismissed?: string[];
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
    const ignored = Array.isArray(j?.ignored) ? j.ignored.filter((x) => typeof x === "string") : undefined;
    const dismissed = Array.isArray(j?.dismissed) ? j.dismissed.filter((x) => typeof x === "string") : undefined;
    for (const p of projects) if (typeof p.group !== "string" || !p.group.trim()) delete p.group;
    return {
      projects,
      ...(typeof j?.searched === "string" ? { searched: j.searched } : {}),
      ...(typeof j?.crawled === "string" ? { crawled: j.crawled } : {}),
      ...(roots ? { roots } : {}),
      ...(ignored?.length ? { ignored } : {}),
      ...(dismissed?.length ? { dismissed } : {}),
    };
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
 * command: it writes only for a project not on the list yet, or one not seen
 * for a day. A project the person hid stays hidden, and one they removed
 * stays off the list.
 */
export function rememberProject(root: string): void {
  try {
    const at = real(root);
    if (at === real(hushHome()) || !isProjectRoot(at)) return;
    const r = load();
    if (r.ignored?.includes(at)) return;
    const now = new Date().toISOString();
    const known = r.projects.find((p) => p.root === at);
    if (known) {
      const stale = Date.now() - Date.parse(known.seen) > 86_400_000;
      if (!stale) return;
      known.seen = now;
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

/** The hidden projects that are still there, so the person can bring them back. */
export function listHidden(): KnownProject[] {
  return load()
    .projects.filter((p) => p.hidden && listable(p.root))
    .sort((a, b) => basename(a.root).localeCompare(basename(b.root)));
}

/** Did the person take `root` off the list (hid or removed it)? */
export function isSetAside(root: string): boolean {
  const at = real(root);
  const r = load();
  return Boolean(r.ignored?.includes(at) || r.projects.find((p) => p.root === at)?.hidden);
}

/** Is `root` on the list (hidden ones included)? The app acts only on these. */
export function isKnownProject(root: string): boolean {
  const at = real(root);
  return load().projects.some((p) => p.root === at);
}

/** Add a folder by hand: a hush project, or any codebase. Undoes a hide or a removal. */
export function addProject(root: string): KnownProject {
  const at = real(root);
  if (!listable(at)) throw new ValidationError(`${at} is not a codebase hush recognises: no .hush, .git or project file (package.json, pyproject.toml, …) in it`);
  const r = load();
  if (r.ignored) r.ignored = r.ignored.filter((x) => x !== at);
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

/** Take a project off the list, onto the hidden one. Its files are untouched. */
export function hideProject(root: string): void {
  const at = real(root);
  const r = load();
  const known = r.projects.find((p) => p.root === at);
  if (known) known.hidden = true;
  else r.projects.push({ root: at, seen: new Date().toISOString(), hidden: true });
  save(r);
}

/** Bring a hidden project back onto the list. */
export function showProject(root: string): void {
  const at = real(root);
  const r = load();
  const known = r.projects.find((p) => p.root === at);
  if (!known?.hidden) return;
  delete known.hidden;
  save(r);
}

/**
 * Forget a project: off the list, and the crawl leaves it out from now on.
 * Its files, .hush/ included, are untouched; adding the folder again brings it back.
 */
export function removeProject(root: string): void {
  const at = real(root);
  const r = load();
  r.projects = r.projects.filter((p) => p.root !== at);
  r.ignored = [...new Set([...(r.ignored ?? []), at])];
  save(r);
}

/** Describe one project again (its stack, branch, the credentials its code reads). */
export function rescanProject(root: string): void {
  const at = real(root);
  const details = describeCodebase(at);
  const r = load();
  const known = r.projects.find((p) => p.root === at);
  if (!known) return;
  known.details = details;
  save(r);
}

// ----------------------------------------------------------- project groups

const groupKey = (label: string): string => label.trim().toLowerCase().replace(/\s+/g, " ");

/** The groups in use, each with how many projects (listed ones) are in it. */
export function projectGroups(): { label: string; count: number }[] {
  const counts = new Map<string, { label: string; count: number }>();
  for (const p of listProjects()) {
    if (!p.group) continue;
    const k = groupKey(p.group);
    const g = counts.get(k) ?? { label: p.group, count: 0 };
    g.count++;
    counts.set(k, g);
  }
  return [...counts.values()].sort((a, b) => a.label.localeCompare(b.label));
}

/**
 * File projects under a group, or out of any (label null or empty). A label
 * that matches a group already there, case and spacing aside, joins it.
 */
export function setProjectGroup(roots: string[], label: string | null): void {
  const clean = (label ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, 60);
  const r = load();
  const existing = clean ? r.projects.find((p) => p.group && groupKey(p.group) === groupKey(clean))?.group : undefined;
  for (const root of roots) {
    const at = real(root);
    const known = r.projects.find((p) => p.root === at);
    if (!known) throw new ValidationError(`hush does not know ${at}`);
    if (clean) known.group = existing ?? clean;
    else delete known.group;
  }
  save(r);
}

/** Rename a group: every project in it moves with it. */
export function renameProjectGroup(label: string, next: string): void {
  const clean = next.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, 60);
  if (!clean) throw new ValidationError("Give the group a name.");
  const r = load();
  const members = r.projects.filter((p) => p.group && groupKey(p.group) === groupKey(label));
  if (!members.length) throw new ValidationError("No such group.");
  const clash = r.projects.find((p) => p.group && groupKey(p.group) === groupKey(clean) && groupKey(p.group) !== groupKey(label));
  for (const p of members) p.group = clash?.group ?? clean;
  save(r);
}

/** Take every project out of a group. The projects stay on the list. */
export function ungroupProjects(label: string): void {
  const r = load();
  for (const p of r.projects) if (p.group && groupKey(p.group) === groupKey(label)) delete p.group;
  save(r);
}

/** Wave a suggestion away for good. */
export function dismissSuggestion(id: string): void {
  if (!id || id.length > 400) throw new ValidationError("no such suggestion");
  const r = load();
  r.dismissed = [...new Set([...(r.dismissed ?? []), id])].slice(-500);
  save(r);
}

export const dismissedSuggestions = (): Set<string> => new Set(load().dismissed ?? []);

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
    if (r.projects.some((p) => p.root === root) || r.ignored?.includes(root)) continue;
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
  for (const root of found) if (!r.projects.some((p) => p.root === root) && !r.ignored?.includes(root)) r.projects.push({ root, seen: now });
  r.searched = now;
  r.crawled = now;
  save(r);
  // Every listed project gets described, not only the ones found this time.
  const todo = [...new Set([...found.filter((f) => !r.ignored?.includes(f)), ...r.projects.filter((p) => !p.hidden).map((p) => p.root)])].filter(listable);
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
  if (!load().crawled) startCrawl();
}
