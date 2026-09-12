/**
 * Drift checks between code and everything that describes it.
 *
 * Documentation rots silently: a tool gets removed and stays in the README, a
 * default changes and the example does not, a config field stops being read and
 * nobody notices. This pass found all three, plus two endpoints with no tests
 * at all — none of which any behavioural test would ever have caught.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, mkdtempSync, rmSync, readdirSync } from "node:fs";
import { tmpdir , platform } from "node:os";
import { execFileSync, spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

const mcp = read("src/mcp.ts");
const cli = read("src/cli.ts");
const ui = read("src/ui.ts");
const skill = read("skills/hush/SKILL.md");
const readme = read("README.md");
const security = read("SECURITY.md");

/**
 * Commands that exist only as pre-unification aliases or internals, and are
 * never advertised in `hush help --all` under their own name — they forward
 * (with a deprecation notice) to a command that IS advertised: `set`/`import`
 * to `add`, `accounts`/`envs` to `ls`, and the plain synonyms `list`/`remove`/
 * `exec`/`account`.
 */
const ALIASES = new Set(["list", "remove", "exec", "account", "set", "import", "accounts", "envs"]);

const mcpTools = [...new Set([...mcp.matchAll(/name: "(hush_[a-z_]+)"/g)].map((m) => m[1]))];
const cliCommands = [
  ...new Set(
    [
      ...cli
        .slice(cli.indexOf("const COMMANDS: Record"), cli.indexOf("async function main"))
        .matchAll(/^\s+"?([a-z-]+)"?:\s*cmd/gm),
    ].map((m) => m[1]),
  ),
];

describe("docs describe the code that exists", () => {
  test("every MCP tool is documented in the skill and the README", () => {
    assert.ok(mcpTools.length >= 6, `only found ${mcpTools.length} tools`);
    for (const tool of mcpTools) {
      assert.ok(skill.includes(tool), `the skill never mentions ${tool}`);
      assert.ok(readme.includes(tool), `the README never mentions ${tool}`);
    }
  });

  test("the docs do not describe tools that were removed", () => {
    for (const [label, doc] of [["skill", skill], ["README", readme]] as const) {
      for (const m of doc.matchAll(/`(hush_[a-z_]+)`/g)) {
        // "There is no hush_get_secret" is a deliberate statement of absence.
        if (new RegExp("no `?" + m[1]).test(doc)) continue;
        assert.ok(mcpTools.includes(m[1]), `${label} documents ${m[1]}, which no longer exists`);
      }
    }
  });

  test("every command appears in hush help --all, and help invents none", () => {
    // `hush help` alone is now eight lines by design (see the test below) — the
    // exhaustive listing this check needs moved to `--all`.
    const help = execFileSync(process.execPath, [join(root, "src/cli.ts"), "help", "--all"], {
      encoding: "utf8",
      env: { ...process.env, NO_COLOR: "1" },
    });
    for (const c of cliCommands) {
      if (ALIASES.has(c)) continue;
      assert.ok(help.includes("hush " + c), `command "${c}" is missing from hush help --all`);
    }
    const builtins = new Set(["help", "mcp", "ui", "version"]);
    for (const m of help.matchAll(/^\s+hush ([a-z-]+)/gm)) {
      assert.ok(
        cliCommands.includes(m[1]) || builtins.has(m[1]),
        `help --all advertises "hush ${m[1]}", which does not exist`,
      );
    }
  });

  test("hush help (no --all) lists exactly the eight daily commands", () => {
    // The whole point of this change: 35 commands on one screen become eight,
    // with everything else one flag away.
    const help = execFileSync(process.execPath, [join(root, "src/cli.ts"), "help"], {
      encoding: "utf8",
      env: { ...process.env, NO_COLOR: "1" },
    });
    const shown = [...help.matchAll(/^\s+hush ([a-z-]+)/gm)].map((m) => m[1]);
    // "help" itself comes from the closing "hush help --all" line, not one of
    // the eight daily commands the screen exists to surface.
    assert.deepEqual(
      shown.filter((c) => c !== "help"),
      ["add", "use", "run", "dev", "ls", "rm", "ui", "team"],
    );
    assert.match(help, /hush help --all/, "the short screen does not point at --all");
  });

  test("commands shown in README code blocks exist, or are pass-through examples", () => {
    const fenced = (readme.match(/```[a-z]*\n[\s\S]*?```/g) ?? []).join("\n");
    const builtins = new Set(["help", "mcp", "ui", "version"]);
    // `hush npm run dev` is the feature, not a typo: anything after hush that
    // is not a hush command runs with secrets injected. These are the programs
    // the README uses to show that, and none of them may ever become a hush
    // command — the day one does, pass-through for it silently stops.
    const passThrough = new Set(["npm", "bun", "python"]);
    for (const p of passThrough) assert.ok(!cliCommands.includes(p), `"${p}" is now a hush command; pick another pass-through example`);
    for (const m of fenced.matchAll(/^\s*(?:\$ )?hush ([a-z-]+)/gm)) {
      assert.ok(
        cliCommands.includes(m[1]) || builtins.has(m[1]) || passThrough.has(m[1]),
        `README shows "hush ${m[1]}", which does not exist`,
      );
    }
    assert.match(readme, /anything after hush/i, "the README never explains pass-through");
  });

  test("internal doc links resolve", () => {
    for (const [name, doc] of [
      ["README.md", readme],
      ["SECURITY.md", security],
      ["docs/BIOMETRY.md", read("docs/BIOMETRY.md")],
    ] as const) {
      for (const m of doc.matchAll(/\]\((\.\/[^)#]+|docs\/[^)#]+)\)/g)) {
        const target = m[1].replace(/^\.\//, "");
        assert.ok(existsSync(join(root, target)), `${name} links to missing ${target}`);
      }
    }
  });
});

describe("configuration has no dead knobs", () => {
  test("nothing is exported that nothing uses", () => {
    // `findExampleFile` sat in scan.ts, exported, referenced by nothing — the
    // same shape as the `gen` field that was written on every value and read by
    // nobody. Dead code reads as a feature: someone extends it, or trusts that
    // it is doing something.
    //
    // If an export is deliberately part of the public API rather than used
    // internally, a test counts as a use — which is the right bar for anything
    // other people are meant to call.
    const srcFiles = readdirSync(join(root, "src")).filter((f) => f.endsWith(".ts"));
    const everything =
      srcFiles.map((f) => read("src/" + f)).join("\n") +
      readdirSync(join(root, "test"))
        .filter((f) => f.endsWith(".ts"))
        .map((f) => read("test/" + f))
        .join("\n");

    const dead: string[] = [];
    for (const f of srcFiles) {
      const text = read("src/" + f);
      const names = [
        ...text.matchAll(/^export (?:async )?function (\w+)|^export (?:const|class|interface|type) (\w+)/gm),
      ].map((m) => m[1] ?? m[2]);
      for (const name of names) {
        const uses = [...everything.matchAll(new RegExp("\\b" + name + "\\b", "g"))].length;
        const declarations = [
          ...everything.matchAll(
            new RegExp("^export (?:async )?(?:function|const|class|interface|type) " + name + "\\b", "gm"),
          ),
        ].length;
        if (uses <= declarations) dead.push(`src/${f}: ${name}`);
      }
    }
    assert.deepEqual(dead, [], `exported and used nowhere:\n  ${dead.join("\n  ")}`);
  });

  test("every policy field is read somewhere", () => {
    const iface = mcp.slice(mcp.indexOf("export interface Policy {"), mcp.indexOf("const DEFAULT_POLICY"));
    const fields = [...new Set([...iface.matchAll(/^\s{2}([a-zA-Z]+):/gm)].map((m) => m[1]))];
    assert.ok(fields.length >= 6, `only found ${fields.length} policy fields`);

    // policy.ts holds checkCommand/checkEnv/checkScopes, which is where
    // allowCommands and allowEnvs are actually read now that mcp.ts and cli.ts
    // both call them rather than each keeping their own copy.
    const consumers = ["mcp.ts", "cli.ts", "ui.ts", "secure.ts", "posture.ts", "approval.ts", "policy.ts"]
      .map((f) => read("src/" + f))
      .join("\n");
    for (const field of fields) {
      const reads = [...consumers.matchAll(new RegExp(`\\.${field}\\b`, "g"))].length;
      assert.ok(reads > 0, `policy field "${field}" is declared and defaulted but never read`);
    }
  });

  test("every policy field is documented", () => {
    const iface = mcp.slice(mcp.indexOf("export interface Policy {"), mcp.indexOf("const DEFAULT_POLICY"));
    const fields = [...new Set([...iface.matchAll(/^\s{2}([a-zA-Z]+):/gm)].map((m) => m[1]))];
    // a loophole for the check in general.
    for (const field of fields) {
      assert.ok(
        readme.includes(field) || security.includes(field),
        `policy field "${field}" is documented nowhere a user would look`,
      );
    }
  });
});

describe("surfaces have coverage", () => {
  test("every UI endpoint is exercised by a test", () => {
    const endpoints = [...new Set([...ui.matchAll(/case "(\/api\/[a-z]+)"/g)].map((m) => m[1]))];
    const uiTest = read("test/ui.test.ts");
    assert.ok(endpoints.length >= 5, `only found ${endpoints.length} endpoints`);
    for (const e of endpoints) {
      assert.ok(uiTest.includes(e), `UI endpoint ${e} has no test`);
    }
  });

  test("every MCP tool is exercised by a test", () => {
    const mcpTest = read("test/mcp.test.ts");
    const anyTest = mcpTest + read("test/hush.test.ts");
    for (const tool of mcpTools) {
      assert.ok(anyTest.includes(tool), `MCP tool ${tool} has no test`);
    }
  });
});

describe("packaging ships what the CLI reaches for", () => {
  test("runtime assets are published and test fixtures are not", () => {
    const pkg = JSON.parse(read("package.json")) as { files: string[]; dependencies?: object };
    assert.ok(pkg.files.includes("native"), "omits native/ — hush biometry compiles from it");
    assert.ok(pkg.files.includes("skills"), "omits skills/ — hush install-skill copies from it");
    assert.ok(pkg.files.includes("src"), "omits src/");
    assert.ok(pkg.files.includes("bin"), "omits bin/");
    assert.ok(!pkg.files.includes("test"), "ships the test fixtures");
    assert.equal(Object.keys(pkg.dependencies ?? {}).length, 0, "gained a runtime dependency");
    assert.ok(existsSync(join(root, "bin/hush.js")), "the bin shim is missing");
  });
});

describe("facts are stated once", () => {
  test("the version has a single source", () => {
    // It used to be typed into src/cli.ts, src/mcp.ts and package.json, with
    // nothing keeping them together — so `hush --version` and the version the
    // MCP server reports to a client could disagree with what was published.
    const declarations = ["src/cli.ts", "src/mcp.ts", "src/version.ts", "src/ui.ts"]
      .filter((f) => /const VERSION\s*=\s*"/.test(read(f)));
    assert.deepEqual(declarations, ["src/version.ts"], "the version is declared in more than one file");

    const pkg = JSON.parse(read("package.json")) as { version: string };
    const declared = read("src/version.ts").match(/VERSION = "([^"]+)"/)![1];
    assert.equal(declared, pkg.version, "src/version.ts and package.json disagree");
  });

  test("the CLI and the MCP server report the same version", () => {
    const cliOut = execFileSync(process.execPath, [join(root, "src/cli.ts"), "--version"], {
      encoding: "utf8",
      env: { ...process.env, NO_COLOR: "1" },
    }).trim();
    const pkg = JSON.parse(read("package.json")) as { version: string };
    assert.equal(cliOut, pkg.version);
    // The MCP server reads the same constant.
    assert.match(read("src/mcp.ts"), /serverInfo: \{ name: "hush", version: VERSION \}/);
  });

  test("cli.ts and mcp.ts build a run: approval scope only through runScope()", () => {
    // Both surfaces used to build `run:${layers.join("+")}` by hand, in two
    // places that had to be kept in sync by eye. runScope() is now the only
    // place that shape is decided (see policy.ts), so a grant one surface
    // hands out is honoured by the other for exactly the same reason.
    for (const [name, src] of [["cli.ts", cli], ["mcp.ts", mcp]] as const) {
      assert.doesNotMatch(src, /scope:\s*`run:/, `${name} builds a run: scope by hand instead of calling runScope()`);
      assert.match(src, /\brunScope\(/, `${name} never calls runScope()`);
    }
  });

  test("the default policy is not retyped anywhere", () => {
    // A hand-written copy in `hush install-mcp` is how `allowReveal` kept being
    // written into every new project after it had stopped meaning anything.
    const literals = ["src/cli.ts", "src/secure.ts"].filter((f) =>
      /requireApproval:\s*\[\s*"run"/.test(read(f)),
    );
    assert.deepEqual(literals, [], `the default policy is retyped in ${literals.join(", ")}`);
    assert.match(read("src/mcp.ts"), /export const DEFAULT_POLICY/, "the defaults are not exported");
  });

  test("a generated policy.json carries only tunable knobs, not the built-in floor", () => {
    // Checked by generating one, not by matching the shape of the source: an
    // assertion about how the code is written goes stale the moment it is
    // refactored, while still passing or failing for the wrong reason.
    // This file is ESM; require() is not available here.
    const home = mkdtempSync(join(tmpdir(), "hush-tpl-home-"));
    const proj = mkdtempSync(join(tmpdir(), "hush-tpl-proj-"));
    const env = { ...process.env, HUSH_HOME: home, HUSH_NO_NUDGE: "1", HUSH_NO_KEYCHAIN: "1", NO_COLOR: "1" };
    const run = (...args: string[]) =>
      execFileSync(process.execPath, [join(root, "src/cli.ts"), ...args], {
        cwd: proj, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
      });

    try {
      run("init", "tpl");
      run("install-mcp");
      const path = join(proj, ".hush", "policy.json");
      assert.ok(existsSync(path), "install-mcp wrote no policy");
      const written = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown> & { denyCommands: string[] };

      assert.deepEqual(written.denyCommands, [], "wrote the built-in floor into the project");
      assert.ok(!("allowReveal" in written), "wrote a setting that does nothing");
      // The knobs a person would actually turn are present.
      for (const knob of ["requireApproval", "biometry", "allowEnvs", "unsafeAllowCommands", "maxRunMs"]) {
        assert.ok(knob in written, `the template omits "${knob}"`);
      }
    } finally {
      for (const d of [home, proj]) rmSync(d, { recursive: true, force: true });
    }
  });
});

describe("examples in the docs are real", () => {
  test("every github link points at the repository package.json names", () => {
    // The owner was guessed from a local username once and was wrong, which put
    // a dead URL into the README badges, the issue templates, the code of
    // conduct and the security policy all at once. package.json is the one
    // place that says who owns this; everything else has to agree with it.
    const pkg = JSON.parse(read("package.json")) as {
      name: string;
      repository: { url: string };
      bugs: { url: string };
      homepage: string;
    };
    const slug = pkg.repository.url.match(/github\.com\/([^/]+\/[^/.]+)/)?.[1];
    assert.ok(slug, `package.json repository.url is not a github URL: ${pkg.repository.url}`);
    assert.ok(pkg.bugs.url.includes(slug!), "bugs.url points somewhere else");
    assert.ok(pkg.homepage.includes(slug!), "homepage points somewhere else");

    const docs = [
      "README.md",
      "CONTRIBUTING.md",
      "SECURITY.md",
      "CODE_OF_CONDUCT.md",
      ".github/ISSUE_TEMPLATE/bug.yml",
      ".github/ISSUE_TEMPLATE/config.yml",
    ];
    const repoName = slug!.split("/")[1];
    for (const doc of docs) {
      for (const m of read(doc).matchAll(/github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)((?:\/[A-Za-z0-9_./-]*)?)/g)) {
        const [, path, rest] = m;
        const repo = path.replace(/\.git$/, "");
        // Ours by either test: it names this repository, or it points at
        // somewhere we would only ever send people for our own — issues,
        // advisories, CI. Deliberately not /blob or /tree: linking into someone
        // else's source is normal, and the README does it for the age plugin
        // spec. An allowlist of other people's repositories would just go stale.
        const looksLikeOurs =
          repo.endsWith("/" + repoName) ||
          /^\/(issues|pulls|actions|discussions|security)\b/.test(rest);
        if (!looksLikeOurs) continue;
        assert.equal(repo, slug, `${doc} links to ${repo}, not ${slug}`);
      }
    }

    // The npm scope is deliberately *not* checked against the repository owner.
    // They are separate namespaces owned by separate accounts — here the repo is
    // omarei-omoto/hush and the package is @omarei/hush — and asserting they
    // match encoded an assumption that simply is not true of npm and GitHub.
    //
    // What does have to hold is that the docs tell people to install the package
    // that actually exists, which is what caught the README recommending the
    // unrelated `hush` package somebody else owns.
    for (const doc of ["README.md", "CONTRIBUTING.md"]) {
      for (const m of read(doc).matchAll(/npm install(?: -g)? (@[a-z0-9-]+\/[a-z0-9-]+)/g)) {
        assert.equal(m[1], pkg.name, `${doc} tells people to install ${m[1]}`);
      }
      // Badges and registry links name it too, and a badge for a package that
      // does not exist renders as a permanent "invalid".
      for (const m of read(doc).matchAll(/npmjs\.com\/package\/(@[a-z0-9-]+\/[a-z0-9-]+)/g)) {
        assert.equal(m[1], pkg.name, `${doc} links to ${m[1]} on npm`);
      }
      for (const m of read(doc).matchAll(/shields\.io\/(?:npm|node)\/v\/(@[a-z0-9-]+\/[a-z0-9-]+)/g)) {
        assert.equal(m[1], pkg.name, `${doc} has a badge for ${m[1]}`);
      }
    }
  });

  test("no document says the same thing twice", () => {
    // A patch script whose replacement string contained a backtick terminated
    // its own template literal and spliced the whole of SECURITY.md into the
    // middle of itself — every heading twice, the second copy authoritative and
    // the first stale. It reads as plausible prose for as long as nobody
    // scrolls, which is exactly the kind of rot these checks exist for.
    for (const doc of ["README.md", "SECURITY.md", "RESEARCH.md", "docs/BIOMETRY.md"]) {
      const headings = [...read(doc).matchAll(/^(#{1,3}) (.+)$/gm)].map((m) => m[0]);
      const seen = new Set<string>();
      for (const h of headings) {
        assert.ok(!seen.has(h), `${doc} contains the heading ${JSON.stringify(h)} more than once`);
        seen.add(h);
      }
    }
  });

  test("no source file declares the same top-level symbol twice", () => {
    // The same accident hit src/run.ts, which ended up containing two complete
    // copies of itself. TypeScript caught that one; a file with no type errors
    // to trip over would not have been caught at all.
    for (const f of readdirSync(join(root, "src")).filter((n) => n.endsWith(".ts"))) {
      const src = read("src/" + f);
      const declared = [...src.matchAll(/^export (?:async )?function (\w+)|^export (?:const|class|interface|type) (\w+)/gm)]
        .map((m) => m[1] ?? m[2]);
      const seen = new Set<string>();
      for (const name of declared) {
        assert.ok(!seen.has(name), `src/${f} declares ${name} more than once`);
        seen.add(name);
      }
    }
  });

  test("in-page links point at headings that exist", () => {
    // A table of contents is the first thing a reader clicks and the first thing
    // to rot when sections are renamed or reordered.
    const slug = (h: string) =>
      h.toLowerCase().replace(/[^\w\s-]/g, "").trim().replace(/\s+/g, "-");

    for (const doc of ["README.md", "SECURITY.md", "CONTRIBUTING.md"]) {
      const text = read(doc);
      // GitHub disambiguates repeated headings with -1, -2, …
      const seen: Record<string, number> = {};
      const available = new Set<string>();
      for (const m of text.matchAll(/^#{1,6} (.+)$/gm)) {
        const s = slug(m[1]);
        seen[s] = (seen[s] ?? 0) + 1;
        available.add(seen[s] > 1 ? `${s}-${seen[s] - 1}` : s);
      }
      for (const m of text.matchAll(/\]\(#([a-z0-9-]+)\)/g)) {
        assert.ok(available.has(m[1]), `${doc} links to #${m[1]}, which is not a heading in it`);
      }
    }
  });

  test("no real key material is used as an example", () => {
    // A public key is not a secret, but pasting a live one from the author's
    // machine into the docs is still publishing their identity — and the secret
    // key encoding begins with the public key, so the two share a prefix and it
    // reads as if a private key had leaked. Examples are generated, not copied.
    // Both places a key can live. Reading only the file made this a no-op on
    // exactly the machine it matters on — a developer who followed the ladder
    // and moved their key into the keychain, which is the recommended setup.
    const home = process.env.HUSH_HOME || join(process.env.HOME ?? "", ".hush");
    const identityFile = join(home, "identity");
    let mine = "";
    if (existsSync(identityFile)) mine = readFileSync(identityFile, "utf8").trim();
    if (!mine && platform() === "darwin") {
      const r = spawnSync(
        "security",
        ["find-generic-password", "-s", "hush-identity", "-a", "default", "-w"],
        { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
      );
      if (r.status === 0) mine = (r.stdout ?? "").trim();
    }
    if (!mine) return; // no identity on this machine to compare against

    const body = mine.replace(/^hush_sk_/, "").slice(0, 16);
    for (const doc of readdirSync(root).filter((f) => f.endsWith(".md"))) {
      assert.ok(!read(doc).includes(body), `${doc} contains this machine's key material`);
    }
  });

  test("every json block parses", () => {
    // A hand-edited example with a trailing comma is not a typo in prose: it is
    // a config file someone will copy, and it will not load. This caught one the
    // moment it was written.
    for (const doc of ["README.md", "SECURITY.md", "docs/BIOMETRY.md"]) {
      const text = read(doc);
      const blocks = [...text.matchAll(/```json\n([\s\S]*?)```/g)].map((m) => m[1]);
      for (const [i, body] of blocks.entries()) {
        // Elisions are how an example stays readable; skip those deliberately.
        if (/^\s*(\.\.\.|…)\s*$/m.test(body) || body.includes("…")) continue;
        assert.doesNotThrow(
          () => JSON.parse(body),
          `${doc}: json block ${i + 1} does not parse:\n${body.slice(0, 200)}`,
        );
      }
    }
  });
});

describe("the tests themselves cannot pass vacuously", () => {
  const testFiles = readdirSync(join(root, "test"))
    .filter((n) => n.endsWith(".test.ts"))
    .map((n) => ["test/" + n, read("test/" + n)] as const);

  test("no helper turns an arbitrary exception into a command result", () => {
    // `execFileSync` throws both when the command exits non-zero and when it
    // was never run at all — a typo, a missing import, a bad path. A catch that
    // converts either into `{ code: 1 }` makes "the command failed" and "the
    // test is broken" indistinguishable, and a test asserting a non-zero exit
    // then passes without the CLI ever starting. That is exactly what happened
    // here. `spawnSync` reports the status instead of throwing, so there is
    // nothing to swallow; where a catch is genuinely needed, it must re-throw.
    for (const [name, src] of testFiles) {
      for (const m of src.matchAll(/\btry\s*\{/g)) {
        const start = m.index!;
        const catchAt = src.indexOf("} catch", start);
        if (catchAt === -1) continue;
        const body = src.slice(start, catchAt);
        if (!/\bexecFileSync\s*\(/.test(body)) continue;

        // Everything up to the end of the catch clause.
        const braceAt = src.indexOf("{", catchAt + "} catch".length);
        let depth = 0;
        let end = braceAt;
        for (let i = braceAt; i < src.length; i++) {
          if (src[i] === "{") depth++;
          else if (src[i] === "}" && --depth === 0) { end = i; break; }
        }
        const handler = src.slice(braceAt, end + 1);
        assert.ok(
          /\bthrow\b/.test(handler),
          `${name}: an execFileSync failure is swallowed into a value near "${body.trim().slice(0, 60)}…" — ` +
            `use spawnSync, or re-throw with the captured output`,
        );
      }
    }
  });

  test("every test file actually asserts something", () => {
    for (const [name, src] of testFiles) {
      const tests = [...src.matchAll(/\btest\(/g)].length;
      const asserts = [...src.matchAll(/\bassert[.(]/g)].length;
      assert.ok(tests > 0, `${name} defines no tests`);
      assert.ok(asserts >= tests, `${name} has ${tests} tests but only ${asserts} assertions`);
    }
  });
});

describe("prose does not state facts that drift", () => {
  test("no document claims how many tests there are", () => {
    // The README said "268 tests" long after there were 396. A count is a fact
    // stated in two places — the prose and the suite — with nothing keeping
    // them together, and the suite prints its own total anyway.
    //
    // docs/AUDIT.md is exempt: it is a record of what was true during a
    // particular pass, not a claim about the present.
    for (const doc of ["README.md", "SECURITY.md", "CONTRIBUTING.md", "docs/BIOMETRY.md"]) {
      const claim = read(doc).match(/\b\d+\s+tests?\b/i);
      assert.equal(claim, null, `${doc} claims a test count: ${claim?.[0]}`);
    }
  });

  test("no comment claims a line count", () => {
    // src/age.ts said "~120 lines" while the file had grown to 245. A number
    // like that is a fact stated in two places — the prose and the file — with
    // nothing keeping them together, and it is never worth the precision.

    for (const f of readdirSync(join(root, "src")).filter((n) => n.endsWith(".ts"))) {
      const src = read("src/" + f);
      const claim = src.match(/(?:about|roughly|~)\s*(?:\d+|forty|fifty|sixty|hundred)[\s-]*lines/i);
      assert.equal(claim, null, `src/${f} claims a line count: ${claim?.[0]}`);
    }
    for (const doc of ["README.md", "SECURITY.md", "docs/BIOMETRY.md"]) {
      const claim = read(doc).match(/(?:about|roughly|~)\s*\d+\s*lines/i);
      assert.equal(claim, null, `${doc} claims a line count: ${claim?.[0]}`);
    }
  });

});
