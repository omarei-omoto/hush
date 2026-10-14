/**
 * The app's intelligence: project groups (projects.ts), what it suggests and
 * the one click behind each suggestion (suggest.ts), and keeping one global
 * copy of a key several projects keep as their own (placement.ts).
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { generateIdentity } from "../src/crypto.ts";
import { Vault } from "../src/vault.ts";
import { composeSets, globalVaultName, librarySets, loadLinks, openGlobal, saveLinks } from "../src/library.ts";
import { keepHere, shareOneCopy } from "../src/placement.ts";
import { dismissSuggestion, listProjects, projectGroups, rememberProject, renameProjectGroup, setProjectGroup, ungroupProjects } from "../src/projects.ts";
import { ownerOf } from "../src/codebase.ts";
import { suggestions } from "../src/suggest.ts";
import type { HubProject } from "../src/ui-state.ts";

const scratch = (p: string) => realpathSync(mkdtempSync(join(tmpdir(), p)));

function world(sets: Record<string, Record<string, string>>) {
  const home = scratch("hush-sug-home-");
  const code = scratch("hush-sug-code-");
  const saved = process.env.HUSH_HOME;
  process.env.HUSH_HOME = home;
  const me = generateIdentity();
  const path = join(home, "vaults", globalVaultName(), "vault.json");
  mkdirSync(dirname(path), { recursive: true });
  const lib = Vault.create(path, "global", { name: "me", pub: me.pub, priv: me.priv });
  for (const [set, keys] of Object.entries(sets)) for (const [k, v] of Object.entries(keys)) lib.set(me, set, k, v);
  lib.save();
  const project = (rel: string, links: string[] = []) => {
    const root = join(code, rel);
    const hushDir = join(root, ".hush");
    mkdirSync(hushDir, { recursive: true });
    writeFileSync(join(hushDir, "envs.json"), JSON.stringify({ use: [] }));
    if (links.length) saveLinks(hushDir, links);
    rememberProject(root);
    return { root, hushDir };
  };
  const hub = (root: string, over: Partial<HubProject> = {}): HubProject => ({
    root,
    name: root.split("/").pop()!,
    state: "links-only",
    keys: 0,
    fromGlobal: 0,
    started: false,
    stack: [],
    credentials: [],
    lacking: [],
    inGlobal: [],
    plaintextEnv: false,
    ...over,
  });
  const done = () => {
    if (saved === undefined) delete process.env.HUSH_HOME;
    else process.env.HUSH_HOME = saved;
    rmSync(home, { recursive: true, force: true });
    rmSync(code, { recursive: true, force: true });
  };
  return { me, project, hub, done, code };
}

describe("project groups", () => {
  test("filing, joining a group however it is typed, renaming and ungrouping", () => {
    const w = world({});
    try {
      const a = w.project("a");
      const b = w.project("b");
      setProjectGroup([a.root], "Clients");
      setProjectGroup([b.root], "  clients ");
      assert.deepEqual(projectGroups(), [{ label: "Clients", count: 2 }], "a second spelling made a second group");
      renameProjectGroup("clients", "Client work");
      assert.deepEqual(listProjects().map((p) => p.group), ["Client work", "Client work"]);
      ungroupProjects("Client work");
      assert.deepEqual(projectGroups(), []);
      assert.equal(listProjects().length, 2, "ungrouping took projects off the list");
      assert.throws(() => setProjectGroup([join(w.code, "unknown")], "x"), /does not know/);
    } finally {
      w.done();
    }
  });

  test("the git owner of a codebase, from either remote shape, and never a credential", () => {
    const cfg = (url: string) => `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${url}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n`;
    assert.equal(ownerOf(cfg("git@github.com:omoto/web.git")), "github.com/omoto");
    assert.equal(ownerOf(cfg("https://user:token@github.com/omoto/web")), "github.com/omoto");
    assert.equal(ownerOf(cfg("file:///srv/repos/web.git")), undefined);
    assert.equal(ownerOf("[core]\n\tbare = false\n"), undefined);
  });
});

describe("suggestions", () => {
  test("a key the code reads that a global set has: give it, whole when the set is small", () => {
    const w = world({ stripe: { STRIPE_KEY: "st-1", STRIPE_PUB: "pk-1" } });
    try {
      const web = w.project("web");
      const s = suggestions({ projects: [w.hub(web.root, { credentials: ["STRIPE_KEY"], lacking: ["STRIPE_KEY"], inGlobal: ["STRIPE_KEY"] })], library: openGlobal(), id: w.me });
      const give = s.find((x) => x.kind === "give")!;
      assert.ok(give, JSON.stringify(s));
      assert.deepEqual(give.act, { assign: { project: web.root, items: [{ kind: "set", set: "stripe" }] } });
      assert.match(give.text, /web reads STRIPE_KEY/);
    } finally {
      w.done();
    }
  });

  test("the same value kept as several projects' own: one global copy, and every project keeps getting it", () => {
    const w = world({ web: { OPENAI_API_KEY: "sk-same", WEB_ONLY: "w" }, api: { OPENAI_API_KEY: "sk-same" }, other: { OPENAI_API_KEY: "sk-different" } });
    try {
      const web = w.project("web", ["web"]);
      const api = w.project("api", ["api"]);
      const other = w.project("other", ["other"]);
      keepHere({ id: w.me, hushDir: web.hushDir, set: "web" });
      keepHere({ id: w.me, hushDir: api.hushDir, set: "api" });
      keepHere({ id: w.me, hushDir: other.hushDir, set: "other" });
      const s = suggestions({ projects: [w.hub(web.root), w.hub(api.root), w.hub(other.root)], library: openGlobal(), id: w.me });
      const same = s.filter((x) => x.kind === "same-value");
      assert.equal(same.length, 1, "a different value was counted as the same: " + JSON.stringify(same));
      assert.deepEqual((same[0].act.share as { sets: string[] }).sets.sort(), ["api", "web"]);
      assert.ok(!JSON.stringify(s).includes("sk-same"), "a value reached a suggestion");

      shareOneCopy({ id: w.me, ...(same[0].act.share as { key: string; sets: string[]; toLabel: string }) });
      const lib = openGlobal()!;
      assert.ok(!lib.hasSet("api"), "the emptied project set was left behind");
      assert.ok(!lib.has("web", "OPENAI_API_KEY"));
      assert.equal(librarySets().find((x) => x.name === "openai-api-key")!.project, undefined);
      assert.equal(composeSets(null, w.me, web.hushDir).secrets.OPENAI_API_KEY, "sk-same");
      assert.equal(composeSets(null, w.me, web.hushDir).secrets.WEB_ONLY, "w");
      assert.equal(composeSets(null, w.me, api.hushDir).secrets.OPENAI_API_KEY, "sk-same");
      assert.deepEqual(loadLinks(api.hushDir), ["openai-api-key#OPENAI_API_KEY"]);
      assert.equal(composeSets(null, w.me, other.hushDir).secrets.OPENAI_API_KEY, "sk-different", "a different value was touched");
    } finally {
      w.done();
    }
  });

  test("a project's own copy of a global key: use the global one", () => {
    const w = world({ openai: { OPENAI_API_KEY: "sk-1" }, web: { OPENAI_API_KEY: "sk-1" } });
    try {
      const web = w.project("web", ["web"]);
      keepHere({ id: w.me, hushDir: web.hushDir, set: "web" });
      const s = suggestions({ projects: [w.hub(web.root)], library: openGlobal(), id: w.me });
      const same = s.find((x) => x.kind === "same-value")!;
      assert.equal(same.label, "Use the global one");
      shareOneCopy({ id: w.me, ...(same.act.share as { key: string; sets: string[]; to: string }) });
      assert.deepEqual(loadLinks(web.hushDir), ["openai#OPENAI_API_KEY"]);
      assert.equal(composeSets(null, w.me, web.hushDir).secrets.OPENAI_API_KEY, "sk-1");
    } finally {
      w.done();
    }
  });

  test("projects in one folder are offered as a group; a dismissed suggestion stays gone", () => {
    const w = world({});
    try {
      const a = w.project("clients/acme");
      const b = w.project("clients/globex");
      const c = w.project("solo");
      const projects = [w.hub(a.root), w.hub(b.root), w.hub(c.root)];
      const group = suggestions({ projects, library: null, id: w.me }).find((x) => x.kind === "group")!;
      assert.ok(group);
      assert.deepEqual(group.act, { group: { roots: [a.root, b.root], label: "clients" } });
      dismissSuggestion(group.id);
      assert.ok(!suggestions({ projects, library: null, id: w.me }).some((x) => x.id === group.id));
      // Grouped already: nothing to suggest.
      setProjectGroup([a.root, b.root], "Clients");
      const grouped = projects.map((p) => (p.root === c.root ? p : { ...p, group: "Clients" }));
      assert.ok(!suggestions({ projects: grouped, library: null, id: w.me }).some((x) => x.kind === "group"));
    } finally {
      w.done();
    }
  });

  test("a plaintext .env and a global set one project uses are suggested", () => {
    const w = world({ "web-env": { A: "1" } });
    try {
      const web = w.project("web", ["web-env"]);
      const s = suggestions({ projects: [w.hub(web.root, { plaintextEnv: true })], library: openGlobal(), id: w.me });
      assert.deepEqual(s.find((x) => x.kind === "plaintext")!.act, { importEnv: { project: web.root } });
      assert.deepEqual(s.find((x) => x.kind === "only-one")!.act, { tidy: { set: "web-env", root: web.root } });
    } finally {
      w.done();
    }
  });
});
