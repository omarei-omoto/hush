/**
 * The app as a hub of every project: the project list (projects.ts), giving a
 * project one global key (a key link, "set#KEY", in library.ts), and which
 * of the variables a project's code reads are worth a warning.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { generateIdentity } from "../src/crypto.ts";
import { Vault } from "../src/vault.ts";
import { composeSets, globalVaultName, keyLinkName, loadLinks, parseKeyLink, saveLinks } from "../src/library.ts";
import { addProject, findProjects, hideProject, isKnownProject, isSetAside, listHidden, listProjects, rememberProject, removeProject, searchOnce, showProject } from "../src/projects.ts";
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
      assert.deepEqual(listHidden().map((p) => p.root), [a]);
      assert.ok(isKnownProject(a), "a hidden project is still one the app may act on");
      rememberProject(a);
      assert.deepEqual(listProjects().map((p) => p.root), [b], "using hush in a hidden project brought it back without being asked");
      showProject(a);
      assert.deepEqual(listProjects().map((p) => p.root).sort(), [a, b]);
      assert.deepEqual(listHidden(), []);
      assert.throws(() => addProject(join(code, "plain-folder")), /not a codebase hush recognises/);
    });
    rmSync(home, { recursive: true, force: true });
    rmSync(code, { recursive: true, force: true });
  });

  test("a removed project stays off the list until it is added again, and its files are untouched", () => {
    const home = scratch("hush-hub-home-");
    const code = scratch("hush-hub-code-");
    withHome(home, () => {
      const a = makeProject(code, "api");
      const site = join(code, "site");
      mkdirSync(site);
      writeFileSync(join(site, "package.json"), "{}");
      rememberProject(a);
      addProject(site);
      removeProject(a);
      removeProject(site);
      assert.deepEqual(listProjects(), []);
      assert.deepEqual(listHidden(), [], "a removed project is not merely hidden");
      assert.ok(isSetAside(a) && !isKnownProject(a));
      // Nothing automatic brings it back: using hush there, or a search of its folder.
      rememberProject(a);
      assert.equal(searchOnce([code]), 0);
      assert.deepEqual(findProjects([code], { depth: 4, folders: 100, ms: 1000, codebases: true }).sort(), [a, site].sort(), "the search itself still sees them");
      assert.deepEqual(listProjects(), []);
      assert.ok(existsSync(join(a, ".hush", "envs.json")) && existsSync(join(site, "package.json")), "a file was touched");
      // Adding it by hand does.
      addProject(a);
      assert.deepEqual(listProjects().map((p) => p.root), [a]);
      assert.ok(!isSetAside(a));
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

describe("codebases, found and described", () => {
  test("describeCodebase reads the stack, branch, the credentials the code reads, and a plaintext .env — never a value", async () => {
    const { describeCodebase, isCodebase } = await import("../src/codebase.ts");
    const root = scratch("hush-cb-");
    try {
      writeFileSync(join(root, "package.json"), JSON.stringify({ dependencies: { next: "15", react: "19" }, devDependencies: { typescript: "5" } }));
      mkdirSync(join(root, ".git"));
      writeFileSync(join(root, ".git", "HEAD"), "ref: refs/heads/feature/hub\n");
      mkdirSync(join(root, "app"));
      writeFileSync(join(root, "app", "page.tsx"), "process.env.OPENAI_API_KEY; process.env.STRIPE_SECRET_KEY; process.env.NODE_ENV; process.env.PORT;\n");
      writeFileSync(join(root, ".env"), "OPENAI_API_KEY=sk-a-real-looking-value-0123456789\n");
      assert.ok(isCodebase(root));
      const d = describeCodebase(root);
      assert.deepEqual(d.stack, ["Next.js", "TypeScript"]);
      assert.equal(d.branch, "feature/hub");
      assert.ok(d.active, "no last-activity time from git's files");
      assert.deepEqual(d.credentials, ["OPENAI_API_KEY", "STRIPE_SECRET_KEY"]);
      assert.equal(d.plaintextEnv, true);
      assert.ok(!JSON.stringify(d).includes("sk-a-real-looking"), "a value was read into the details");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("a Swift package is a codebase, and what its code reads is found", async () => {
    const { describeCodebase, isCodebase } = await import("../src/codebase.ts");
    const root = scratch("hush-cb-swift-");
    try {
      writeFileSync(join(root, "Package.swift"), "// swift-tools-version:5.9\nimport PackageDescription\n");
      mkdirSync(join(root, "Sources", "App"), { recursive: true });
      writeFileSync(join(root, "Sources", "App", "main.swift"), 'let key = ProcessInfo.processInfo.environment["OPENAI_API_KEY"]\n');
      assert.ok(isCodebase(root), "a Swift package was not taken for a codebase");
      const d = describeCodebase(root);
      assert.deepEqual(d.stack, ["Swift"]);
      assert.deepEqual(d.credentials, ["OPENAI_API_KEY"]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("the crawl finds plain codebases as well as hush projects, and only in the folders chosen", async () => {
    const { setCrawlRoots, crawlRoots } = await import("../src/projects.ts");
    const home = scratch("hush-hub-home-");
    const code = scratch("hush-hub-code-");
    withHome(home, () => {
      const hushProject = makeProject(code, "api");
      const plain = join(code, "clients", "landing");
      mkdirSync(plain, { recursive: true });
      writeFileSync(join(plain, "package.json"), "{}");
      mkdirSync(join(code, "notes"));
      assert.deepEqual(crawlRoots(), { roots: [], chosen: false }, "a relocated hush home guessed folders of the real one");
      assert.deepEqual(findProjects([code], { depth: 4, folders: 1000, ms: 1000, codebases: true }).sort(), [hushProject, plain].sort());
      assert.deepEqual(findProjects([code]), [hushProject], "without codebases, only hush projects");
      assert.deepEqual(setCrawlRoots([code]), [code]);
      assert.deepEqual(crawlRoots(), { roots: [code], chosen: true });
      assert.throws(() => setCrawlRoots([join(code, "missing")]), /not a folder/);
    });
    rmSync(home, { recursive: true, force: true });
    rmSync(code, { recursive: true, force: true });
  });
});

test("the first crawl for codebases runs even where the older one-time search already ran", async () => {
  const { crawlOnce, crawlStatus } = await import("../src/projects.ts");
  const home = scratch("hush-hub-home-");
  const code = scratch("hush-hub-code-");
  const saved = process.env.HUSH_HOME;
  // Set by hand rather than with withHome: the crawl finishes in the
  // background, and every write it makes must land in this home.
  process.env.HUSH_HOME = home;
  try {
    const plain = join(code, "site");
    mkdirSync(plain);
    writeFileSync(join(plain, "package.json"), "{}");
    // What the first version of the hub left behind: searched, never crawled.
    writeFileSync(join(home, "projects.json"), JSON.stringify({ projects: [], searched: "2026-10-01T00:00:00.000Z", roots: [code] }));
    crawlOnce();
    assert.ok(listProjects().some((p) => p.root === plain), "the crawl did not run");
    for (let i = 0; i < 100 && crawlStatus().running; i++) await new Promise((r) => setTimeout(r, 20));
    assert.ok(!crawlStatus().running, "the crawl did not finish");
  } finally {
    if (saved === undefined) delete process.env.HUSH_HOME;
    else process.env.HUSH_HOME = saved;
    rmSync(home, { recursive: true, force: true });
    rmSync(code, { recursive: true, force: true });
  }
});

describe("choosing a folder with the system's picker", () => {
  test("each desktop's picker is asked for a folder, starting where hush already looks", async () => {
    const { folderPickerArgs, powershellFolderScript } = await import("../src/dialogs.ts");
    const mac = folderPickerArgs("osascript", 'Pick "one"', "/Users/me/code");
    assert.equal(mac[0], "-e");
    assert.match(mac[1], /^on run argv\n\tactivate\n/, "the picker would open behind the browser");
    assert.match(mac[1], /choose folder with prompt \(item 1 of argv\) default location \(POSIX file \(item 2 of argv\)\)/);
    assert.doesNotMatch(mac[1], /NSOpenPanel/, "a custom open panel from osascript drops clicks in its sidebar");
    assert.match(mac[1], /if n is -128 then error/, "a cancel would reopen the dialog");
    assert.deepEqual(mac.slice(2), ['Pick "one"', "/Users/me/code"], "the prompt and folder were not passed as arguments");
    assert.ok(!mac[1].includes("Pick"), "the prompt was quoted into the script");
    assert.deepEqual(folderPickerArgs("zenity", "p", "/home/me"), ["--file-selection", "--directory", "--title", "p", "--filename", "/home/me/"]);
    assert.deepEqual(folderPickerArgs("kdialog", "p", "/home/me"), ["--title", "p", "--getexistingdirectory", "/home/me"]);
    const win = powershellFolderScript("a 'quoted' prompt", "C:\\Users\\me\\Ünïcode");
    assert.ok(!win.includes("quoted") && !win.includes("Ünïcode"), "the prompt or folder was quoted into the script instead of carried as data");
    assert.match(win, /OpenStandardOutput\(\)/, "the path would go through the console's code page, garbling a name outside ASCII");
    assert.match(win, /UTF8Encoding \$false/, "the path would start with a byte-order mark");
    assert.match(win, /SetOptions\(options \| 0x20/, "the Explorer-style picker is not in folder mode");
    assert.match(win, /catch \{\s*\$d = New-Object Windows\.Forms\.FolderBrowserDialog/, "no picker where Add-Type is not allowed");
    assert.match(win, /^'@$/m, "the C# shim's here-string is not closed at the start of a line");
  });

  test("the macOS picker's AppleScript compiles", { skip: process.platform !== "darwin" }, async () => {
    const { folderPickerArgs } = await import("../src/dialogs.ts");
    const { spawnSync } = await import("node:child_process");
    const dir = scratch("hush-osacompile-");
    try {
      writeFileSync(join(dir, "choose.applescript"), folderPickerArgs("osascript", "p", "/")[1]);
      const r = spawnSync("/usr/bin/osacompile", ["-o", join(dir, "choose.scpt"), join(dir, "choose.applescript")], { encoding: "utf8" });
      assert.equal(r.status, 0, r.stderr);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a picked path is tidied the same way on every system", async () => {
    const { pickedPath } = await import("../src/dialogs.ts");
    const cases: [string, string | null][] = [
      ["/Users/me/code/\n", "/Users/me/code"],
      ["/", "/"],
      ["/home/me/Ünïcode 文件\n", "/home/me/Ünïcode 文件"],
      ["\uFEFFC:\\Users\\me\\code", "C:\\Users\\me\\code"],
      ["C:\\Users\\me\\code\\", "C:\\Users\\me\\code"],
      ["C:\\", "C:\\"],
      ["D:", "D:\\"],
      ["\\\\server\\share\\proj\\", "\\\\server\\share\\proj"],
      ["", null],
      ["\n", null],
    ];
    for (const [out, want] of cases) assert.equal(pickedPath(out), want, JSON.stringify(out));
  });

  test("the folder picked comes back without its trailing slash; a cancel, or no desktop, is null", { skip: process.platform === "win32" }, async () => {
    const { chooseFolder } = await import("../src/dialogs.ts");
    const { chmodSync } = await import("node:fs");
    const dir = scratch("hush-pick-");
    try {
      let n = 0;
      const picker = (script: string) => {
        const path = join(dir, `picker-${n++}`);
        writeFileSync(path, "#!/bin/sh\n" + script + "\n");
        chmodSync(path, 0o755);
        return { env: {}, platform: () => "darwin", resolveProgram: () => path };
      };
      assert.equal(await chooseFolder("p", "/", picker("echo /Users/me/code/")), "/Users/me/code");
      assert.equal(await chooseFolder("p", "/", picker("echo /")), "/");
      // osascript's own exit for "User canceled." (-128) is non-zero.
      assert.equal(await chooseFolder("p", "/", picker("echo 'execution error: User canceled. (-128)' >&2; exit 1")), null);
      assert.equal(await chooseFolder("p", "/", { env: { HUSH_NO_DIALOG: "1" }, platform: () => "darwin", resolveProgram: () => "/bin/false" }), null);
      // One picker at a time: a second ask while one is open shares its answer.
      const slow = picker("sleep 0.3; echo /Users/me/one/");
      const [a, b] = await Promise.all([chooseFolder("p", "/", slow), chooseFolder("p", "/", picker("echo /Users/me/two/"))]);
      assert.deepEqual([a, b], ["/Users/me/one", "/Users/me/one"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
