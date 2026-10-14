/**
 * What the app suggests doing next, each with the one click that does it:
 *
 *   - give         a project's code reads a key one of your global sets has
 *   - same-value   the same key and value kept as several projects' own: keep one global copy
 *   - plaintext    a .env with values sits in a project's folder: import it
 *   - only-one     a global set exactly one project uses: keep it there
 *   - replace      a global key someone removed could still use, or past its rotation age
 *   - repush       a key was sent to a host (push.ts), and has a newer value here
 *   - group        projects sharing a parent folder or a git owner: group them
 *
 * Worked out on this machine from names and metadata — the one exception is
 * same-value, which compares values inside your library, here, and sends
 * nothing but the key's name to the page. A suggestion waved away (by id) is
 * not offered again.
 */
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { homedir } from "node:os";
import { Vault } from "./vault.ts";
import type { Opener } from "./crypto.ts";
import { allowedAt, librarySets, ownerOf, suggestSets, type LibrarySet } from "./library.ts";
import { soleUsers } from "./placement.ts";
import { crawlRoots, dismissedSuggestions } from "./projects.ts";
import { keyAges, describeAge } from "./freshness.ts";
import type { HubProject } from "./ui-state.ts";
import { isStale, pushesFor } from "./push.ts";
import { hostById } from "./hosts.ts";

export interface Suggestion {
  id: string;
  kind: "give" | "same-value" | "plaintext" | "only-one" | "replace" | "repush" | "group";
  /** The projects it is about. */
  roots: string[];
  /** One sentence; names in it are in `names`, so the page can set them apart. */
  text: string;
  names: string[];
  /** The button. */
  label: string;
  /** What the page does on the click: an endpoint and its body, or a dialog to open. */
  act: Record<string, unknown>;
}

const sid = (...parts: string[]): string => createHash("sha256").update(parts.join("\u0000")).digest("hex").slice(0, 16);
const listed = (names: string[]): string => (names.length <= 2 ? names.join(" and ") : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`);

/** A global set worth giving whole: small, or every key of it is one the code reads. */
const wholeSetFits = (set: LibrarySet, reads: Set<string>): boolean => set.keys.length <= 3 || set.keys.every((k) => reads.has(k));

export function suggestions(o: {
  projects: HubProject[];
  library: Vault | null;
  id: Opener;
  /** The rotation ages that apply (a policy's rotateAfterDays), if any. */
  policy?: Parameters<typeof keyAges>[1];
}): Suggestion[] {
  const out: Suggestion[] = [];
  const all = librarySets();
  const global = all.filter((s) => !s.project);
  const byRoot = new Map(o.projects.map((p) => [p.root, p]));

  // give: a key the code reads, that a global set this project may use already has.
  for (const p of o.projects) {
    if (p.state === "codebase" || !p.inGlobal.length) continue;
    const usable = global.filter((s) => !s.onlyIn || allowedAt(s.onlyIn, p.root));
    const plan = suggestSets(p.inGlobal, usable.map((s) => ({ name: s.name, keys: s.keys })));
    const reads = new Set(p.credentials);
    for (const name of plan.picks) {
      const set = usable.find((s) => s.name === name)!;
      const keys = Object.entries(plan.provider).filter(([, s]) => s === name).map(([k]) => k).sort();
      if (!keys.length) continue;
      const whole = wholeSetFits(set, reads);
      out.push({
        id: sid("give", p.root, name, ...keys),
        kind: "give",
        roots: [p.root],
        text: `${p.name} reads ${listed(keys)}, and your global ${set.label} has ${keys.length === 1 ? "it" : "them"}.`,
        names: [p.name, ...keys, set.label],
        label: whole ? `Give ${p.name} ${set.label}` : keys.length === 1 ? "Give it" : "Give them",
        act: {
          assign: { project: p.root, items: whole ? [{ kind: "set", set: name }] : keys.map((key) => ({ kind: "key", set: name, key })) },
        },
      });
    }
  }

  // same-value: one key, one value, kept as several projects' own (and maybe a global copy).
  if (o.library) {
    const lib = o.library;
    const holders = new Map<string, string[]>();
    for (const s of all) for (const k of s.keys) holders.set(k, [...(holders.get(k) ?? []), s.name]);
    for (const [key, sets] of holders) {
      if (sets.length < 2 || !sets.some((n) => ownerOf(lib, n))) continue;
      const byValue = new Map<string, string[]>();
      for (const set of sets) {
        let value: string;
        try {
          value = lib.get(o.id, set, key);
        } catch {
          continue;
        }
        const h = createHash("sha256").update(value).digest("hex");
        byValue.set(h, [...(byValue.get(h) ?? []), set]);
      }
      for (const same of byValue.values()) {
        const own = same.filter((n) => ownerOf(lib, n));
        const shared = same.find((n) => !ownerOf(lib, n));
        if (!own.length || (own.length < 2 && !shared)) continue;
        const projects = [...new Set(own.map((n) => basename(ownerOf(lib, n)!)))];
        const sharedLabel = shared ? lib.envLabel(shared) : "";
        out.push({
          id: sid("same-value", key, ...same.sort()),
          kind: "same-value",
          roots: own.map((n) => ownerOf(lib, n)!),
          text: shared
            ? `${listed(projects)} ${projects.length === 1 ? "keeps its" : "keep their"} own copy of ${key}, the same as your global ${sharedLabel}.`
            : `${key} is the same in ${listed(projects)}'s own keys.`,
          names: [key, ...projects, ...(shared ? [sharedLabel] : [])],
          label: shared ? "Use the global one" : "Make it one global key",
          act: { share: { key, sets: own, ...(shared ? { to: shared } : { toLabel: key }) } },
        });
      }
    }
  }

  // plaintext: a .env with values in the folder.
  for (const p of o.projects) {
    if (!p.plaintextEnv) continue;
    out.push({
      id: sid("plaintext", p.root),
      kind: "plaintext",
      roots: [p.root],
      text: `${p.name} has a .env with its values in plain text. Import them as its own keys, then delete the file.`,
      names: [p.name, ".env"],
      label: "Import it",
      act: { importEnv: { project: p.root } },
    });
  }

  // only-one: a global set exactly one project uses whole.
  for (const t of soleUsers()) {
    if (!byRoot.has(t.root)) continue;
    out.push({
      id: sid("only-one", t.set, t.root),
      kind: "only-one",
      roots: [t.root],
      text: `Only ${t.name} uses your global ${t.label}. It is most likely ${t.name}'s own.`,
      names: [t.name, t.label],
      label: `Keep it for ${t.name}`,
      act: { tidy: { set: t.set, root: t.root } },
    });
  }

  // replace: a global key someone removed could still use, or past its rotation age.
  if (o.library) {
    for (const a of keyAges(o.library, o.policy ?? null)) {
      if (ownerOf(o.library, a.set) && !byRoot.has(ownerOf(o.library, a.set)!)) continue;
      if (!a.exposed.length && !a.overdue) continue;
      const label = o.library.envLabel(a.set);
      out.push({
        id: sid("replace", a.set, a.key, a.updatedAt),
        kind: "replace",
        roots: [],
        text: a.exposed.length
          ? `${a.key} in ${label} could still be used by ${listed(a.exposed)}, who no longer has access. Replace it at the provider, then here.`
          : `${a.key} in ${label} is ${describeAge(a.days)} old, past the ${a.limit} days it is meant to last.`,
        names: [a.key, label],
        label: "Replace…",
        act: { replace: { where: "library", set: a.set, key: a.key } },
      });
    }
  }

  // repush: sent to a host, then replaced here — the host still has the old value.
  for (const p of o.projects) {
    const sent = pushesFor(p.root);
    if (!sent.length) continue;
    let project: Vault | null = null;
    try {
      const f = join(p.root, ".hush", "vault.json");
      project = existsSync(f) ? Vault.open(f) : null;
    } catch { /* unreadable here: nothing to compare */ }
    for (const r of sent) {
      if (isStale(r, project, o.library) !== true || !r.source) continue;
      const host = hostById(r.host);
      if (!host) continue;
      const where = `${host.label}${r.target ? ` · ${r.target}` : ""}${r.env ? ` (${r.env})` : ""}`;
      out.push({
        id: sid("repush", p.root, r.key, r.host, r.target ?? "", r.env ?? "", r.source.updatedAt),
        kind: "repush",
        roots: [p.root],
        text: `${r.key} changed after it was sent to ${where}, which still has the old value.`,
        names: [r.key, where],
        label: "Send the new value",
        act: { repush: { project: p.root, key: r.key, to: r.host, where: r.source.where, set: r.source.set, ...(r.target ? { target: r.target } : {}), ...(r.env ? { env: r.env } : {}), ...(r.name ? { as: r.name } : {}) } },
      });
    }
  }

  // group: projects sharing a parent folder, then a git owner, not grouped yet.
  const loose = o.projects.filter((p) => !p.group);
  const tops = new Set([homedir(), ...crawlRoots().roots]);
  const byParent = new Map<string, HubProject[]>();
  for (const p of loose) {
    const parent = dirname(p.root);
    if (tops.has(parent) || parent === dirname(parent)) continue;
    byParent.set(parent, [...(byParent.get(parent) ?? []), p]);
  }
  const offered = new Set<string>();
  for (const [parent, ps] of byParent) {
    if (ps.length < 2) continue;
    const label = basename(parent);
    for (const p of ps) offered.add(p.root);
    out.push({
      id: sid("group", "parent", parent),
      kind: "group",
      roots: ps.map((p) => p.root),
      text: `${ps.length} projects are in ${parent.replace(homedir(), "~")}: ${listed(ps.map((p) => p.name))}.`,
      names: ps.map((p) => p.name),
      label: `Group them as “${label}”`,
      act: { group: { roots: ps.map((p) => p.root), label } },
    });
  }
  const byOwner = new Map<string, HubProject[]>();
  for (const p of loose) if (p.owner && !offered.has(p.root)) byOwner.set(p.owner, [...(byOwner.get(p.owner) ?? []), p]);
  for (const [owner, ps] of byOwner) {
    if (ps.length < 2) continue;
    const label = owner.split("/").pop()!;
    out.push({
      id: sid("group", "owner", owner),
      kind: "group",
      roots: ps.map((p) => p.root),
      text: `${ps.length} projects are on ${owner}: ${listed(ps.map((p) => p.name))}.`,
      names: ps.map((p) => p.name),
      label: `Group them as “${label}”`,
      act: { group: { roots: ps.map((p) => p.root), label } },
    });
  }

  const gone = dismissedSuggestions();
  return out.filter((x) => !gone.has(x.id));
}
