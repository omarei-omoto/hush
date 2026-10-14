/**
 * Where a key lives (placement.ts): one of your global keys, or one project's
 * own; groups of global sets a project can use whole; and moving between the
 * two without a project losing what it had.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { generateIdentity } from "../src/crypto.ts";
import { Vault, assertVaultShape, type VaultFile } from "../src/vault.ts";
import { composeSets, confirmedLinks, globalVaultName, librarySets, loadLinks, openGlobal, saveLinks, setsInGroup } from "../src/library.ts";
import { fileUnder, keepHere, makeGlobal, projectsUsing, renameGroup, soleUsers, tidy, ungroup } from "../src/placement.ts";
import { rememberProject } from "../src/projects.ts";

const scratch = (p: string) => realpathSync(mkdtempSync(join(tmpdir(), p)));

/** A home with a library holding `sets`, and a code folder to make projects in. */
function world(sets: Record<string, Record<string, string>>) {
  const home = scratch("hush-place-home-");
  const code = scratch("hush-place-code-");
  const saved = process.env.HUSH_HOME;
  process.env.HUSH_HOME = home;
  const me = generateIdentity();
  const path = join(home, "vaults", globalVaultName(), "vault.json");
  mkdirSync(dirname(path), { recursive: true });
  const lib = Vault.create(path, "global", { name: "me", pub: me.pub, priv: me.priv });
  for (const [set, keys] of Object.entries(sets)) for (const [k, v] of Object.entries(keys)) lib.set(me, set, k, v);
  lib.save();
  /** A project hush knows, using `links`. */
  const project = (name: string, links: string[] = []) => {
    const root = join(code, name);
    const hushDir = join(root, ".hush");
    mkdirSync(hushDir, { recursive: true });
    writeFileSync(join(hushDir, "envs.json"), JSON.stringify({ use: [] }));
    if (links.length) saveLinks(hushDir, links);
    rememberProject(root);
    return { root, hushDir };
  };
  const done = () => {
    if (saved === undefined) delete process.env.HUSH_HOME;
    else process.env.HUSH_HOME = saved;
    rmSync(home, { recursive: true, force: true });
    rmSync(code, { recursive: true, force: true });
  };
  return { me, project, done, home };
}

const run = (me: ReturnType<typeof generateIdentity>, hushDir: string) => composeSets(null, me, hushDir);

describe("groups of global sets", () => {
  test("a project given a group gets every set in it — including one filed there later", () => {
    const w = world({ fal: { FAL_KEY: "fal-1" }, openai: { OPENAI_API_KEY: "sk-1" }, stripe: { STRIPE_KEY: "st-1" } });
    try {
      fileUnder("fal", "AI stack");
      fileUnder("openai", "ai stack"); // the same group, however it is typed
      const lib = openGlobal()!;
      assert.equal(lib.envMeta("openai").group, "AI stack", "a second spelling made a second group");
      const p = w.project("web", ["group:ai-stack"]);
      assert.deepEqual(run(w.me, p.hushDir).secrets, { FAL_KEY: "fal-1", OPENAI_API_KEY: "sk-1" });
      fileUnder("stripe", "AI stack");
      assert.equal(run(w.me, p.hushDir).secrets.STRIPE_KEY, "st-1", "a set filed later did not reach the project");
      fileUnder("stripe", null);
      assert.equal(run(w.me, p.hushDir).secrets.STRIPE_KEY, undefined, "a set taken out still reached it");
    } finally {
      w.done();
    }
  });

  test("a group a committed list names, but nobody confirmed here, is skipped", () => {
    const w = world({ fal: { FAL_KEY: "fal-1" } });
    try {
      fileUnder("fal", "AI stack");
      const p = w.project("cloned");
      // What a clone carries: the list, but no confirmation on this machine.
      writeFileSync(join(p.hushDir, "envs.json"), JSON.stringify({ use: ["group:ai-stack"] }));
      const r = run(w.me, p.hushDir);
      assert.deepEqual(r.secrets, {});
      assert.deepEqual(r.unconfirmed, ["group:ai-stack"]);
    } finally {
      w.done();
    }
  });

  test("renaming a group keeps every project on it; ungrouping leaves each set it had", () => {
    const w = world({ fal: { FAL_KEY: "fal-1" }, openai: { OPENAI_API_KEY: "sk-1" } });
    try {
      fileUnder("fal", "AI stack");
      fileUnder("openai", "AI stack");
      const p = w.project("web", ["group:ai-stack"]);
      renameGroup("ai-stack", "Gen AI");
      assert.deepEqual(loadLinks(p.hushDir), ["group:gen-ai"]);
      assert.ok(confirmedLinks(p.hushDir).has("group:gen-ai"), "the renamed group was not confirmed where the old one was");
      assert.equal(Object.keys(run(w.me, p.hushDir).secrets).length, 2);
      ungroup("gen-ai");
      assert.deepEqual(setsInGroup(openGlobal(), "gen-ai"), []);
      assert.deepEqual(loadLinks(p.hushDir).sort(), ["fal", "openai"]);
      assert.deepEqual(run(w.me, p.hushDir).secrets, { FAL_KEY: "fal-1", OPENAI_API_KEY: "sk-1" }, "ungrouping took keys from the project");
    } finally {
      w.done();
    }
  });

  test("a rename does not confirm a group nobody confirmed", () => {
    const w = world({ fal: { FAL_KEY: "fal-1" } });
    try {
      fileUnder("fal", "AI stack");
      const p = w.project("cloned");
      writeFileSync(join(p.hushDir, "envs.json"), JSON.stringify({ use: ["group:ai-stack"] }));
      renameGroup("ai-stack", "Gen AI");
      assert.deepEqual(loadLinks(p.hushDir), ["group:gen-ai"]);
      assert.ok(!confirmedLinks(p.hushDir).has("group:gen-ai"));
      assert.deepEqual(run(w.me, p.hushDir).secrets, {});
    } finally {
      w.done();
    }
  });
});

describe("keeping a global set or key for one project", () => {
  test("a set kept here leaves your global keys, still reaches this project, and is refused anywhere else", () => {
    const w = world({ stripe: { STRIPE_KEY: "st-1" } });
    try {
      const web = w.project("web", ["stripe"]);
      const r = keepHere({ id: w.me, hushDir: web.hushDir, set: "stripe" });
      assert.ok("done" in r, JSON.stringify(r));
      const s = librarySets().find((x) => x.name === "stripe")!;
      assert.equal(s.project, web.root);
      assert.deepEqual(s.onlyIn, [web.root]);
      assert.equal(run(w.me, web.hushDir).secrets.STRIPE_KEY, "st-1");
      // Another project naming it is refused when it links it, and skipped when it runs.
      const api = w.project("api");
      assert.throws(() => saveLinks(api.hushDir, ["stripe"]), /only for/);
      writeFileSync(join(api.hushDir, "envs.json"), JSON.stringify({ use: ["stripe"] }));
      const other = composeSets(null, w.me, api.hushDir);
      assert.equal(other.secrets.STRIPE_KEY, undefined);
    } finally {
      w.done();
    }
  });

  test("other projects using it are named first, and only a confirmed move takes it from them", () => {
    const w = world({ stripe: { STRIPE_KEY: "st-1", STRIPE_PUB: "pk-1" } });
    try {
      const web = w.project("web", ["stripe"]);
      const api = w.project("api", ["stripe"]);
      const asked = keepHere({ id: w.me, hushDir: web.hushDir, set: "stripe" });
      assert.ok("confirm" in asked);
      assert.deepEqual(asked.confirm.projects!.map((u) => u.root), [api.root]);
      assert.equal(librarySets().find((x) => x.name === "stripe")!.project, undefined, "asking changed something");
      assert.equal(run(w.me, api.hushDir).secrets.STRIPE_KEY, "st-1");

      const done = keepHere({ id: w.me, hushDir: web.hushDir, set: "stripe", force: true });
      assert.ok("done" in done);
      assert.deepEqual(loadLinks(api.hushDir), [], "the other project still lists it");
      assert.equal(run(w.me, web.hushDir).secrets.STRIPE_KEY, "st-1");
    } finally {
      w.done();
    }
  });

  test("one key kept here moves into the project's own set; projects using the rest of the set keep the rest", () => {
    const w = world({ stripe: { STRIPE_KEY: "st-1", STRIPE_PUB: "pk-1" } });
    try {
      const web = w.project("web", ["stripe#STRIPE_KEY"]);
      const api = w.project("api", ["stripe"]);
      const r = keepHere({ id: w.me, hushDir: web.hushDir, set: "stripe", key: "STRIPE_KEY", force: true });
      assert.ok("done" in r);
      const own = librarySets().find((x) => x.project === web.root)!;
      assert.equal(own.label, "web", "the project's own set is not named after it");
      assert.deepEqual(own.keys, ["STRIPE_KEY"]);
      assert.deepEqual(loadLinks(web.hushDir), [own.name], "the key link was not replaced by the project's own set");
      assert.deepEqual(run(w.me, web.hushDir).secrets, { STRIPE_KEY: "st-1" });
      assert.deepEqual(run(w.me, api.hushDir).secrets, { STRIPE_PUB: "pk-1" });
    } finally {
      w.done();
    }
  });

  test("a project that has it only through its group is named, as using it through the group", () => {
    const w = world({ fal: { FAL_KEY: "fal-1" } });
    try {
      fileUnder("fal", "AI stack");
      const web = w.project("web", ["fal"]);
      const api = w.project("api", ["group:ai-stack"]);
      const asked = keepHere({ id: w.me, hushDir: web.hushDir, set: "fal" });
      assert.ok("confirm" in asked);
      assert.deepEqual(asked.confirm.projects!.map((u) => [u.root, u.viaGroup]), [[api.root, true]]);
      keepHere({ id: w.me, hushDir: web.hushDir, set: "fal", force: true });
      assert.deepEqual(setsInGroup(openGlobal(), "ai-stack"), [], "a set kept for one project stayed in a group");
      assert.equal(run(w.me, api.hushDir).secrets.FAL_KEY, undefined);
      assert.deepEqual(projectsUsing(openGlobal()!, "fal", { except: web.root }), []);
    } finally {
      w.done();
    }
  });

  test("the library's catch-all stays global", () => {
    const w = world({ default: { LOOSE: "x" } });
    try {
      const web = w.project("web", ["library:default"]);
      assert.throws(() => keepHere({ id: w.me, hushDir: web.hushDir, set: "default" }), /catch-all/);
    } finally {
      w.done();
    }
  });
});

describe("making a project's own keys global", () => {
  test("a set kept here, made global, is one of your global keys and still part of the project", () => {
    const w = world({ stripe: { STRIPE_KEY: "st-1" } });
    try {
      const web = w.project("web", ["stripe"]);
      keepHere({ id: w.me, hushDir: web.hushDir, set: "stripe" });
      const r = makeGlobal({ id: w.me, hushDir: web.hushDir, where: "library", set: "stripe", group: "Payments" });
      assert.ok("done" in r);
      const s = librarySets().find((x) => x.name === "stripe")!;
      assert.equal(s.project, undefined);
      assert.equal(s.onlyIn, undefined, "the project's folder rule outlived it");
      assert.equal(s.group, "Payments");
      assert.deepEqual(loadLinks(web.hushDir), ["stripe"]);
      // Usable anywhere again.
      const api = w.project("api", ["stripe"]);
      assert.equal(run(w.me, api.hushDir).secrets.STRIPE_KEY, "st-1");
    } finally {
      w.done();
    }
  });

  test("one key made global goes into the set you pick and comes back to the project as one key", () => {
    const w = world({ stripe: { STRIPE_KEY: "st-1" } });
    try {
      const web = w.project("web", ["stripe"]);
      keepHere({ id: w.me, hushDir: web.hushDir, set: "stripe" });
      const r = makeGlobal({ id: w.me, hushDir: web.hushDir, where: "library", set: "stripe", key: "STRIPE_KEY", toLabel: "Stripe live" });
      assert.ok("done" in r);
      const lib = openGlobal()!;
      assert.ok(!lib.hasSet("stripe"), "the emptied project set was left behind");
      assert.deepEqual(loadLinks(web.hushDir), ["stripe-live#STRIPE_KEY"]);
      assert.deepEqual(run(w.me, web.hushDir).secrets, { STRIPE_KEY: "st-1" });
      assert.equal(librarySets().find((x) => x.name === "stripe-live")!.project, undefined);
    } finally {
      w.done();
    }
  });

  test("a set in the repository's vault moves into your library, and its teammates are named first", () => {
    const w = world({});
    try {
      const web = w.project("web");
      const vault = Vault.create(join(web.hushDir, "vault.json"), "web", { name: "me", pub: w.me.pub, priv: w.me.priv });
      vault.set(w.me, "convex", "CONVEX_URL", "https://c.example", "prod");
      vault.save();
      saveLinks(web.hushDir, ["convex"]);
      const r = makeGlobal({ id: w.me, hushDir: web.hushDir, where: "project", set: "convex" });
      assert.ok("done" in r, JSON.stringify(r));
      assert.ok(!Vault.open(join(web.hushDir, "vault.json")).hasSet("convex"), "it stayed in the repository");
      assert.equal(openGlobal()!.get(w.me, "convex", "CONVEX_URL"), "https://c.example");
      assert.equal(openGlobal()!.list("convex")[0].note, "prod", "the tag was lost");
      assert.deepEqual(loadLinks(web.hushDir), ["convex"]);
      assert.equal(run(w.me, web.hushDir).secrets.CONVEX_URL, "https://c.example");

      // A vault someone else also reads: asked, and unchanged until confirmed.
      const mate = generateIdentity();
      const v2 = Vault.open(join(web.hushDir, "vault.json"));
      v2.set(w.me, "default", "SHARED", "s-1");
      v2.addRecipient(w.me, "sam", `hush_pk_${mate.pub.toString("base64url")}`);
      v2.save();
      const asked = makeGlobal({ id: w.me, hushDir: web.hushDir, where: "project", set: "default", key: "SHARED", toLabel: "Shared" });
      assert.ok("confirm" in asked);
      assert.deepEqual(asked.confirm.teammates, ["sam"]);
      assert.ok(Vault.open(join(web.hushDir, "vault.json")).has("default", "SHARED"));
    } finally {
      w.done();
    }
  });
});

describe("tidying up", () => {
  test("global sets only one project uses whole are offered, and kept there when chosen", () => {
    const w = world({ "web-env": { A: "1" }, shared: { B: "2" }, picked: { C: "3" } });
    try {
      const web = w.project("web", ["web-env", "shared", "picked#C"]);
      w.project("api", ["shared"]);
      const offers = soleUsers();
      assert.deepEqual(offers.map((o) => [o.set, o.root]), [["web-env", web.root]], "a shared set, or one taken key by key, was offered");
      tidy(w.me, [{ set: "web-env", root: web.root }]);
      assert.equal(librarySets().find((x) => x.name === "web-env")!.project, web.root);
      assert.deepEqual(soleUsers(), []);
      assert.throws(() => tidy(w.me, [{ set: "shared", root: web.root }]), /not used by/);
    } finally {
      w.done();
    }
  });
});

describe("the vault file", () => {
  test("a group and a project are checked like everything else in a set's description", () => {
    const w = world({ fal: { FAL_KEY: "x" } });
    try {
      const path = join(w.home, "vaults", globalVaultName(), "vault.json");
      const data = JSON.parse(readFileSync(path, "utf8")) as VaultFile;
      data.meta = { fal: { group: "x".repeat(81) } };
      assert.throws(() => assertVaultShape(data, path), /group/);
      data.meta = { fal: { project: "relative/folder" } };
      assert.throws(() => assertVaultShape(data, path), /project folder/);
      data.meta = { fal: { group: "AI stack", project: "/Users/me/code/web" } };
      assert.doesNotThrow(() => assertVaultShape(data, path));
    } finally {
      w.done();
    }
  });
});
