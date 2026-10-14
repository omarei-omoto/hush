/**
 * Where a key lives, and moving it there: one of your global keys — kept once,
 * part of any project you give it to — or one project's own.
 *
 * Both are in your library under ~/.hush, never in a repository. A set kept
 * for one project carries that project's folder (EnvMeta.project) and the same
 * folder as its only-in rule, so it stays out of your global keys and hush
 * refuses it anywhere else, for you and your agent alike. A project's own
 * vault — committed, shared with its team — is the third place a key can be,
 * and one there can be made global too.
 *
 * A move never takes a key away from the project it is made from: a set or key
 * made global stays part of it, and one kept here is linked here. The other
 * projects that get a set or key about to become one project's own are named
 * first, and only a confirmed move takes it from them.
 *
 * Global sets can be filed into groups — folders, like "AI stack" — which a
 * project can use whole (library.ts, "group:<slug>").
 */
import { basename, join } from "node:path";
import { Vault, ValidationError, slugifyEnv, assertScopeName, assertKeyName } from "./vault.ts";
import type { Opener } from "./crypto.ts";
import {
  confirmLinks,
  confirmedLinks,
  groupLinkName,
  groupSlug,
  keyLinkName,
  libraryGroups,
  linkNameFor,
  loadLinks,
  openGlobal,
  ownerOf,
  placeOf,
  sameFolder,
  saveLinks,
  setsInGroup,
  writeProjectDotfiles,
} from "./library.ts";
import { listHidden, listProjects } from "./projects.ts";

export interface Using {
  root: string;
  name: string;
  /** The entries in its list that give it the set or key. */
  links: string[];
  /** It gets it only through the set's group. */
  viaGroup: boolean;
}

function library(): Vault {
  const g = openGlobal();
  if (!g) throw new ValidationError("You have no library yet: hush global --create, or save a global key in the app.");
  return g;
}

/** Every project hush knows on this machine: listed and hidden alike, each once. */
function knownRoots(): string[] {
  const out: string[] = [];
  for (const p of [...listProjects(), ...listHidden()]) if (!out.some((r) => sameFolder(r, p.root))) out.push(p.root);
  return out;
}

const hushDirOf = (root: string): string => join(root, ".hush");

/** A set name not yet taken in `v`, from the label someone gave it. */
function freeName(v: Vault, label: string): string {
  const base = slugifyEnv(label);
  if (!v.hasSet(base)) return base;
  for (let i = 2; ; i++) {
    const tail = `-${i}`;
    const next = base.slice(0, 48 - tail.length) + tail;
    if (!v.hasSet(next)) return next;
  }
}

/** The links in a list that give a project this library set, or just `key` of it. */
function linksTo(links: string[], set: string, group: string | null, key?: string): string[] {
  const whole = linkNameFor("library", set);
  const keyPrefix = keyLinkName(set, "");
  return links.filter(
    (l) =>
      l === whole ||
      (group !== null && l === group) ||
      (key === undefined ? l.startsWith(keyPrefix) : l === keyLinkName(set, key)),
  );
}

/**
 * The projects, other than `except`, that get a library set — by its name,
 * through its group, or by one of its keys (only `key`, when given).
 */
export function projectsUsing(lib: Vault, set: string, opts: { key?: string; except?: string } = {}): Using[] {
  const group = lib.envMeta(set).group;
  const groupLink = group && !ownerOf(lib, set) ? groupLinkName(group) : null;
  const out: Using[] = [];
  for (const root of knownRoots()) {
    if (opts.except && sameFolder(root, opts.except)) continue;
    const links = linksTo(loadLinks(hushDirOf(root)), set, groupLink, opts.key);
    if (links.length) out.push({ root, name: basename(root), links, viaGroup: links.every((l) => l === groupLink) });
  }
  return out;
}

/** Whether a project already gets every key of a library set without a key link: by name or through its group. */
function getsWholeSet(lib: Vault, links: string[], set: string): boolean {
  const group = lib.envMeta(set).group;
  return links.includes(linkNameFor("library", set)) || Boolean(group && !ownerOf(lib, set) && links.includes(groupLinkName(group)));
}

/** Add `link` to a project's list, unless it is there already. */
function ensureLink(hushDir: string, link: string): void {
  writeProjectDotfiles(hushDir);
  const links = loadLinks(hushDir);
  if (!links.includes(link)) saveLinks(hushDir, [...links, link]);
}

/** The global set to move a key into: one that exists, or a new one by this label. */
function globalTarget(lib: Vault, to?: string, toLabel?: string, group?: string): string {
  if (to) {
    if (!lib.hasSet(to)) throw new ValidationError(`No global set called "${to}".`);
    if (ownerOf(lib, to)) throw new ValidationError(`"${lib.envLabel(to)}" belongs to one project, so it is not a global set.`);
    return to;
  }
  const label = (toLabel ?? "").trim();
  if (!label) throw new ValidationError("Say which global set it goes into, or name a new one.");
  const name = freeName(lib, label);
  lib.ensureEnvExists(name);
  lib.describeEnv(name, { label, ...(group ? { group: groupLabel(lib, group) } : {}) });
  return name;
}

/** The label to file a set under: an existing group's own spelling, when the slug matches one. */
function groupLabel(lib: Vault, label: string): string {
  const slug = groupSlug(label);
  assertScopeName(slug);
  return libraryGroups(lib).find((g) => g.slug === slug)?.label ?? label.trim();
}

// ------------------------------------------------------------- going up

export interface MakeGlobal {
  id: Opener;
  /** The project this is done from. */
  hushDir: string;
  /** "library": a set kept for this project. "project": its own vault, in the repository. */
  where: "library" | "project";
  set: string;
  /** Just this key of the set; it goes into the global set `to`, or a new one called `toLabel`. */
  key?: string;
  to?: string;
  toLabel?: string;
  /** File the set (or the new set) under this group. */
  group?: string;
  /** Yes, take it out of the repository's vault even though teammates read it there. */
  force?: boolean;
}

export type Placed = { done: string } | { confirm: { teammates?: string[]; projects?: Using[] } };

/**
 * One of this project's own sets, or one key of it, made a global key. The
 * project keeps getting it: the set stays in its list, and a key moved into
 * a global set it does not use whole comes back to it as a key link.
 */
export function makeGlobal(o: MakeGlobal): Placed {
  const lib = library();
  const place = placeOf(o.hushDir);
  const name = basename(place);

  if (o.where === "library") {
    if (!lib.hasSet(o.set)) throw new ValidationError(`No set called "${o.set}" in your library.`);
    const owner = ownerOf(lib, o.set);
    if (!owner) throw new ValidationError(`"${lib.envLabel(o.set)}" is already one of your global keys.`);
    if (!sameFolder(owner, place)) throw new ValidationError(`"${lib.envLabel(o.set)}" belongs to ${owner}, not this project.`);

    if (o.key === undefined) {
      const onlyIn = (lib.envMeta(o.set).onlyIn ?? []).filter((p) => !sameFolder(p, owner));
      lib.describeEnv(o.set, { project: "", onlyIn, ...(o.group ? { group: groupLabel(lib, o.group) } : {}) });
      lib.save();
      ensureLink(o.hushDir, linkNameFor("library", o.set));
      return { done: `${lib.envLabel(o.set)} is one of your global keys now, and still part of ${name}` };
    }

    assertKeyName(o.key);
    if (!lib.has(o.set, o.key)) throw new ValidationError(`No ${o.key} in "${lib.envLabel(o.set)}".`);
    const target = globalTarget(lib, o.to, o.toLabel, o.group);
    lib.moveSecret(o.id, o.key, o.set, target);
    const emptied = Object.keys(lib.data.envs[o.set] ?? {}).length === 0;
    if (emptied) lib.removeSet(o.id, o.set);
    lib.save();
    const links = loadLinks(o.hushDir).filter((l) => !(emptied && l === linkNameFor("library", o.set)));
    const keep = getsWholeSet(lib, links, target) ? links : [...links, keyLinkName(target, o.key)];
    writeProjectDotfiles(o.hushDir);
    saveLinks(o.hushDir, keep);
    return { done: `${o.key} is a global key now, in ${lib.envLabel(target)}, and still part of ${name}` };
  }

  // The repository's own vault: shared with whoever else is a member of it.
  const vaultPath = join(o.hushDir, "vault.json");
  const project = Vault.open(vaultPath);
  if (!project.hasSet(o.set)) throw new ValidationError(`No set called "${o.set}" in this project.`);
  const mine = project.meFingerprint(o.id);
  const teammates = project.members().filter((m) => m.fingerprint !== mine).map((m) => m.name);
  if (teammates.length && !o.force) return { confirm: { teammates } };

  const entries = project.list(o.set).filter((e) => o.key === undefined || e.key === o.key);
  if (o.key !== undefined) {
    assertKeyName(o.key);
    if (!entries.length) throw new ValidationError(`No ${o.key} in "${project.envLabel(o.set)}".`);
  }
  if (!entries.length) throw new ValidationError(`"${project.envLabel(o.set)}" has no keys to make global.`);

  let target: string;
  if (o.key === undefined) {
    const meta = project.envMeta(o.set);
    const label = project.envLabel(o.set) === "default" ? `${name} keys` : project.envLabel(o.set);
    target = freeName(lib, label);
    lib.ensureEnvExists(target);
    lib.describeEnv(target, {
      label,
      ...(meta.description ? { description: meta.description } : {}),
      ...(meta.whenToUse ? { whenToUse: meta.whenToUse } : {}),
      ...(o.group ? { group: groupLabel(lib, o.group) } : {}),
    });
  } else {
    target = globalTarget(lib, o.to, o.toLabel, o.group);
  }
  for (const e of entries) {
    if (lib.has(target, e.key)) throw new ValidationError(`"${lib.envLabel(target)}" already has a ${e.key}. Delete one of them first.`);
    lib.set(o.id, target, e.key, project.get(o.id, o.set, e.key), e.note);
  }
  // Into your library first: a failure after this leaves two copies, never none.
  lib.save();
  if (o.key !== undefined || o.set === "default") for (const e of entries) project.delete(o.set, e.key);
  else project.removeSet(o.id, o.set);
  project.save();

  const links = loadLinks(o.hushDir);
  const used = o.set === "default" || links.includes(o.set);
  let next = links;
  if (o.key === undefined) {
    const link = linkNameFor("library", target);
    next = links.includes(o.set) ? links.map((l) => (l === o.set ? link : l)) : used ? [...links, link] : links;
  } else if (used && !getsWholeSet(lib, links, target)) {
    next = [...links, keyLinkName(target, o.key)];
  }
  saveLinks(o.hushDir, next);
  const what = o.key ?? project.envLabel(o.set);
  return { done: `${what} is ${o.key ? "a global key" : "one of your global keys"} now, in ${lib.envLabel(target)}${used ? `, and still part of ${name}` : ""}` };
}

// ----------------------------------------------------------- going down

export interface KeepHere {
  id: Opener;
  hushDir: string;
  /** A global set this project uses. */
  set: string;
  /** Just this key of it. */
  key?: string;
  /** Yes, take it from the other projects named. */
  force?: boolean;
}

/** This project's own set for single keys: the one named after it, made the first time it is needed. */
function ownSetFor(lib: Vault, place: string): string {
  const name = basename(place);
  const existing = lib.envNames().find((n) => {
    const p = ownerOf(lib, n);
    return p && sameFolder(p, place) && lib.envLabel(n) === name;
  });
  if (existing) return existing;
  const set = freeName(lib, name);
  lib.ensureEnvExists(set);
  lib.describeEnv(set, { label: name, project: place, onlyIn: [place] });
  return set;
}

/** Take a set's links (or one key's) out of another project's list. */
function dropFrom(root: string, set: string, key?: string): void {
  const hushDir = hushDirOf(root);
  const links = loadLinks(hushDir);
  const gone = new Set(key === undefined ? linksTo(links, set, null) : [keyLinkName(set, key)]);
  const next = links.filter((l) => !gone.has(l));
  if (next.length !== links.length) saveLinks(hushDir, next);
}

/**
 * A global set, or one key of it, kept for this project only. Any other
 * project that gets it is named first; confirmed, it is taken from them.
 */
export function keepHere(o: KeepHere): Placed {
  const lib = library();
  const place = placeOf(o.hushDir);
  const name = basename(place);
  if (!lib.hasSet(o.set)) throw new ValidationError(`No set called "${o.set}" in your library.`);
  const owner = ownerOf(lib, o.set);
  if (owner) {
    if (sameFolder(owner, place)) return { done: `${o.key ?? lib.envLabel(o.set)} is already only ${name}'s` };
    throw new ValidationError(`"${lib.envLabel(o.set)}" belongs to ${owner}.`);
  }
  if (o.key === undefined && o.set === "default") {
    throw new ValidationError("Your library's catch-all set stays global. Keep its keys here one at a time instead.");
  }
  if (o.key !== undefined) {
    assertKeyName(o.key);
    if (!lib.has(o.set, o.key)) throw new ValidationError(`No ${o.key} in "${lib.envLabel(o.set)}".`);
  }

  const others = projectsUsing(lib, o.set, { key: o.key, except: place });
  if (others.length && !o.force) return { confirm: { projects: others } };

  writeProjectDotfiles(o.hushDir);
  if (o.key === undefined) {
    lib.describeEnv(o.set, { project: place, onlyIn: [place], group: "" });
    lib.save();
    // This project gets the whole set by name now; its key links into it are covered by that.
    const links = loadLinks(o.hushDir);
    const link = linkNameFor("library", o.set);
    const keyPrefix = keyLinkName(o.set, "");
    const firstPick = links.findIndex((l) => l === link || l.startsWith(keyPrefix));
    const kept = links.filter((l) => l !== link && !l.startsWith(keyPrefix));
    const at = firstPick === -1 ? kept.length : links.slice(0, firstPick).filter((l) => l !== link && !l.startsWith(keyPrefix)).length;
    kept.splice(at, 0, link);
    saveLinks(o.hushDir, kept);
    for (const u of others) dropFrom(u.root, o.set);
    return { done: `${lib.envLabel(o.set)} is only ${name}'s now${others.length ? ` — taken from ${others.map((u) => u.name).join(", ")}` : ""}` };
  }

  const own = ownSetFor(lib, place);
  if (lib.has(own, o.key)) throw new ValidationError(`${name}'s own keys already have a ${o.key}. Delete one of them first.`);
  lib.moveSecret(o.id, o.key, o.set, own);
  lib.save();
  const links = loadLinks(o.hushDir).filter((l) => l !== keyLinkName(o.set, o.key!));
  saveLinks(o.hushDir, links.includes(own) ? links : [...links, linkNameFor("library", own)]);
  for (const u of others) dropFrom(u.root, o.set, o.key);
  return { done: `${o.key} is only ${name}'s now${others.length ? ` — taken from ${others.map((u) => u.name).join(", ")}` : ""}` };
}

// ---------------------------------------------------------------- groups

/** File a global set under a group (a new one, or one that exists), or out of any group with null. */
export function fileUnder(set: string, group: string | null): string {
  const lib = library();
  if (!lib.hasSet(set)) throw new ValidationError(`No set called "${set}" in your library.`);
  if (ownerOf(lib, set)) throw new ValidationError(`"${lib.envLabel(set)}" belongs to one project; only global sets go in groups.`);
  const label = group && group.trim() ? groupLabel(lib, group) : "";
  lib.describeEnv(set, { group: label });
  lib.save();
  return label ? `${lib.envLabel(set)} is in ${label}` : `${lib.envLabel(set)} is in no group`;
}

/**
 * Rewrite one link in every known project's list, keeping its position.
 * `into` empty drops it. The new links are confirmed here only where the old
 * one was: a rename is not a reason to trust a list nobody confirmed.
 */
function relink(from: string, into: string[]): void {
  for (const root of knownRoots()) {
    const hushDir = hushDirOf(root);
    const links = loadLinks(hushDir);
    const at = links.indexOf(from);
    if (at === -1) continue;
    const next = [...links.slice(0, at), ...into.filter((l) => !links.includes(l)), ...links.slice(at + 1)];
    const wasConfirmed = confirmedLinks(hushDir).has(from);
    saveLinks(hushDir, next, { confirm: false });
    if (wasConfirmed) confirmLinks(hushDir, into);
  }
}

/** Rename a group. Projects that use it keep using it, under its new name. */
export function renameGroup(slug: string, label: string): string {
  const lib = library();
  const members = setsInGroup(lib, slug);
  if (!members.length) throw new ValidationError("No such group.");
  const next = label.trim();
  if (!next) throw new ValidationError("Give the group a name.");
  assertScopeName(groupSlug(next));
  const clash = libraryGroups(lib).find((g) => g.slug === groupSlug(next) && g.slug !== slug);
  if (clash) throw new ValidationError(`There is a group called "${clash.label}" already.`);
  for (const set of members) lib.describeEnv(set, { group: next });
  lib.save();
  if (groupSlug(next) !== slug) relink(`group:${slug}`, [groupLinkName(next)]);
  return `the group is called ${next} now`;
}

/**
 * Take every set out of a group. A project that used the group keeps every
 * set it was getting, now each by name.
 */
export function ungroup(slug: string): string {
  const lib = library();
  const members = setsInGroup(lib, slug);
  if (!members.length) throw new ValidationError("No such group.");
  const label = libraryGroups(lib).find((g) => g.slug === slug)?.label ?? slug;
  for (const set of members) lib.describeEnv(set, { group: "" });
  lib.save();
  relink(`group:${slug}`, members.map((s) => linkNameFor("library", s)));
  return `${label} is gone; its ${members.length} set(s) are still yours`;
}

// ------------------------------------------------------------- tidying up

/**
 * Global sets exactly one known project uses whole — by name, not through a
 * group or by single keys — and no other project touches: likely that
 * project's own, made global by an import before keys could belong to one
 * project. Offered, never moved on their own.
 */
export function soleUsers(): { set: string; label: string; keys: number; root: string; name: string }[] {
  const lib = openGlobal();
  if (!lib) return [];
  const lists = knownRoots().map((root) => ({ root, links: loadLinks(hushDirOf(root)) }));
  const out: ReturnType<typeof soleUsers> = [];
  for (const set of lib.envNames()) {
    if (set === "default" || ownerOf(lib, set)) continue;
    const group = lib.envMeta(set).group;
    const groupLink = group ? groupLinkName(group) : null;
    const users = lists
      .map((p) => ({ ...p, hit: linksTo(p.links, set, groupLink) }))
      .filter((p) => p.hit.length);
    if (users.length !== 1) continue;
    if (!users[0].hit.every((l) => l === linkNameFor("library", set))) continue;
    out.push({
      set,
      label: lib.envLabel(set),
      keys: Object.keys(lib.data.envs[set] ?? {}).length,
      root: users[0].root,
      name: basename(users[0].root),
    });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name) || a.label.localeCompare(b.label));
}

/** Keep each chosen set for the one project using it (soleUsers). */
export function tidy(id: Opener, picks: { set: string; root: string }[]): string[] {
  const offered = soleUsers();
  const done: string[] = [];
  for (const p of picks) {
    const ok = offered.find((x) => x.set === p.set && sameFolder(x.root, p.root));
    if (!ok) throw new ValidationError(`"${p.set}" is not used by ${p.root} alone any more. Look again.`);
    const r = keepHere({ id, hushDir: hushDirOf(ok.root), set: ok.set });
    if ("done" in r) done.push(r.done);
  }
  return done;
}

