/**
 * The app as a hub of every project: the project list (projects.ts), giving a
 * project one global key (a key link, "set#KEY", in library.ts), and which
 * of the variables a project's code reads are worth a warning.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { generateIdentity } from "../src/crypto.ts";
import { Vault } from "../src/vault.ts";
import { composeSets, globalVaultName, keyLinkName, loadLinks, parseKeyLink, saveLinks } from "../src/library.ts";
import { addProject, findProjects, hideProject, isKnownProject, listProjects, rememberProject, searchOnce } from "../src/projects.ts";
import { looksLikeSecret } from "../src/ui-state.ts";

const scratch = (p: string) => realpathSync(mkdtempSync(join(tmpdir(), p)));

function withHome<T>(home: string, fn: () => T): T {
  const saved = process.env.HUSH_HOME;
  process.env.HUSH_HOME = home;
  try {
    return fn();
  } finally {
    if (saved === undefined) delete process.env.HUSH_HOME;
    else process.env.HUSH_HOME = saved;
  }
}

/** A folder hush works in: .hush/envs.json is enough. */
function makeProject(parent: string, name: string): string {
  const root = join(parent, name);
  mkdirSync(join(root, ".hush"), { recursive: true });
  writeFileSync(join(root, ".hush", "envs.json"), JSON.stringify({ use: [] }));
  return root;
}

describe("the project list", () => {
  test("remembers projects hush is used in, hides and re-adds them, and ignores folders that are not projects", () => {
    const home = scratch("hush-hub-home-");
    const code = scratch("hush-hub-code-");
    withHome(home, () => {
      const a = makeProject(code, "api");
      const b = makeProject(code, "web");
      rememberProject(a);
      rememberProject(b);
      rememberProject(join(code, "not-a-project"));
      assert.deepEqual(listProjects().map((p) => p.root).sort(), [a, b]);
      hideProject(a);
      assert.deepEqual(listProjects().map((p) => p.root), [b]);
      assert.ok(isKnownProject(a), "a hidden project is still one the app may act on once re-added");
      rememberProject(a);
      assert.ok(listProjects().some((p) => p.root === a), "using a hidden project again brings it back");
      assert.throws(() => addProject(join(code, "plain-folder")), /not a hush project/);
    });
    rmSync(home, { recursive: true, force: true });
    rmSync(code, { recursive: true, force: true });
  });

  test("the one-time search finds projects under the usual folders, skips node_modules, and runs once", () => {
    const home = scratch("hush-hub-home-");
    const code = scratch("hush-hub-code-");
    withHome(home, () => {
      const deep = makeProject(join(code, "clients", "acme"), "site");
      makeProject(join(code, "app", "node_modules"), "pkg");
      const found = findProjects([code]);
      assert.deepEqual(found, [deep]);
      assert.equal(searchOnce([code]), 1);
      assert.equal(searchOnce([code]), 0, "the search ran twice");
      assert.ok(listProjects().some((p) => p.root === deep));
    });
    rmSync(home, { recursive: true, force: true });
    rmSync(code, { recursive: true, force: true });
  });
});

describe("one global key in a project (a key link)", () => {
  const setup = (home: string) => {
    const owner = generateIdentity();
    const path = join(home, "vaults", globalVaultName(), "vault.json");
    mkdirSync(dirname(path), { recursive: true });
    const library = Vault.create(path, "global", { name: "owner", pub: owner.pub });
    library.set(owner, "openai", "OPENAI_API_KEY", "sk-the-one-dragged");
    library.set(owner, "openai", "OPENAI_ORG", "org-not-dragged");
    library.save();
    const dir = scratch("hush-hub-proj-");
    const hushDir = join(dir, ".hush");
    mkdirSync(hushDir, { recursive: true });
    return { owner, dir, hushDir };
  };

  test("the project gets exactly that key, not the rest of its set", () => {
    const home = scratch("hush-hub-home-");
    withHome(home, () => {
      const { owner, hushDir } = setup(home);
      saveLinks(hushDir, [keyLinkName("openai", "OPENAI_API_KEY")]);
      assert.deepEqual(loadLinks(hushDir), ["openai#OPENAI_API_KEY"]);
      const r = composeSets(null, owner, hushDir);
      assert.deepEqual(r.secrets, { OPENAI_API_KEY: "sk-the-one-dragged" });
      assert.deepEqual(r.missing, []);
    });
  });

  test("a key link a project's committed list names, but nobody confirmed here, is skipped", () => {
    const home = scratch("hush-hub-home-");
    withHome(home, () => {
      const { owner, hushDir } = setup(home);
      // Written into the repository's list by someone else, not linked here.
      writeFileSync(join(hushDir, "envs.json"), JSON.stringify({ use: ["openai#OPENAI_API_KEY"] }));
      const r = composeSets(null, owner, hushDir);
      assert.deepEqual(r.secrets, {});
      assert.deepEqual(r.unconfirmed, ["openai#OPENAI_API_KEY"]);
    });
  });

  test("a key the set does not have is reported missing, and a malformed key name is refused", () => {
    const home = scratch("hush-hub-home-");
    withHome(home, () => {
      const { owner, hushDir } = setup(home);
      saveLinks(hushDir, ["openai#NOPE"]);
      assert.deepEqual(composeSets(null, owner, hushDir).missing, ["openai#NOPE"]);
      assert.throws(() => saveLinks(hushDir, ["openai#not a key"]), /not a valid variable name/);
      assert.throws(() => saveLinks(hushDir, ["../x#KEY"]), /not a valid environment/);
    });
  });

  test("parseKeyLink reads only set#KEY", () => {
    assert.deepEqual(parseKeyLink("openai#OPENAI_API_KEY"), { set: "openai", key: "OPENAI_API_KEY" });
    assert.deepEqual(parseKeyLink("library:default#K"), { set: "library:default", key: "K" });
    for (const plain of ["openai", "#K", "openai#", "library:default"]) assert.equal(parseKeyLink(plain), null, plain);
  });
});

test("only variables that look like credentials (or that hush already holds) are worth a warning", () => {
  for (const name of ["OPENAI_API_KEY", "STRIPE_SECRET_KEY", "GITHUB_TOKEN", "DATABASE_URL", "REDIS_URL", "SUPABASE_SERVICE_ROLE_KEY", "SENTRY_DSN", "JWT_SECRET", "DB_PASSWORD"]) {
    assert.ok(looksLikeSecret(name), name);
  }
  for (const name of ["NODE_ENV", "PORT", "HOST", "CI", "HOME", "PATH", "DEBUG", "LOG_LEVEL", "NEXT_PUBLIC_SITE_URL", "npm_package_version", "VERCEL_URL", "TZ"]) {
    assert.ok(!looksLikeSecret(name), name);
  }
});

test("hush use --confirm offers a single key a cloned project's list names, and hush scan counts it", async () => {
  const { spawnSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.ts");
  const base = scratch("hush-hub-cli-");
  const home = join(base, "home");
  const proj = join(base, "proj");
  const elsewhere = join(base, "elsewhere");
  for (const d of [home, join(proj, ".hush"), elsewhere]) mkdirSync(d, { recursive: true });
  writeFileSync(join(proj, "app.js"), "process.env.OPENAI_API_KEY;\n");
  const env = { ...process.env, HOME: home, HUSH_HOME: home, HUSH_NO_KEYCHAIN: "1", HUSH_NO_NUDGE: "1", HUSH_BIOMETRY: "off", HUSH_NO_DIALOG: "1", NO_COLOR: "1" };
  delete (env as NodeJS.ProcessEnv).HUSH_IDENTITY;
  const hush = (args: string[], input?: string, cwd = proj) => {
    const r = spawnSync(process.execPath, [CLI, ...args], { cwd, env, encoding: "utf8", input, stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"] });
    return { code: r.status ?? 1, out: (r.stdout ?? "") + (r.stderr ?? "") };
  };
  try {
    assert.equal(hush(["id", "--create"], undefined, elsewhere).code, 0);
    assert.equal(hush(["global", "--create"], undefined, elsewhere).code, 0);
    assert.equal(hush(["add", "openai", "--as", "my-openai", "--library"], "sk-proj-Example7Tz2Lp9Wx4Mn6Kb3Vc8Hd5\n", elsewhere).code, 0);
    writeFileSync(join(proj, ".hush", "envs.json"), JSON.stringify({ use: ["my-openai#OPENAI_API_KEY"] }));
    const confirm = hush(["use", "--confirm"]);
    assert.doesNotMatch(confirm.out, /Nothing to confirm/, "a key link the list names was not offered");
    assert.match(confirm.out, /Nothing was confirmed/, "it did not ask about the key link");
    assert.deepEqual(JSON.parse(hush(["scan", "--json"]).out).satisfied, ["OPENAI_API_KEY"], "scan did not count the key link");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
