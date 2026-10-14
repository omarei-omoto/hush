/**
 * The docs site: scripts/build-docs.mjs turns the README and docs/ into the
 * Starlight site's content (website/), and scripts/check-site.mjs checks the
 * built site before it is deployed.
 *
 * What matters most: nothing git would not commit is ever published — the
 * site is built from a working tree that may hold private notes — and every
 * link between pages lands on a page. The home page's live app
 * (scripts/build-demo.mjs) is the real page on made-up keys, and holds no
 * value and no path from the machine that built it.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runInNewContext } from "node:vm";

import { REPO, buildContent, convert, pageSources, slugOf } from "../scripts/build-docs.mjs";
import { checkSite } from "../scripts/check-site.mjs";
import { DEMO_REFUSAL, buildDemo, demoPage } from "../scripts/build-demo.mjs";

/** A throwaway git repository shaped like hush's docs. */
function repo() {
  const dir = mkdtempSync(join(tmpdir(), "hush-docs-"));
  const git = (...args: string[]) => execFileSync("git", args, { cwd: dir, stdio: "ignore" });
  git("init", "-q");
  mkdirSync(join(dir, "docs", "guide"), { recursive: true });
  writeFileSync(join(dir, "README.md"), "# hush\n\nSee [sets](docs/guide/sets.md#sets), [the relay](docs/RELAY.md) and [a test](test/x.test.ts).\n");
  writeFileSync(join(dir, "docs", "guide", "README.md"), "# The guide\n\n- **Using it** — [Sets](sets.md) · [SECURITY.md](../../SECURITY.md)\n");
  writeFileSync(join(dir, "docs", "guide", "sets.md"), "# Sets\n\nBack to [the README](../../README.md).\n");
  writeFileSync(join(dir, "docs", "RELAY.md"), "# Relay\n");
  writeFileSync(join(dir, "SECURITY.md"), "# Security policy\n");
  writeFileSync(join(dir, "docs", "PRIVATE-PLAN.md"), "# Unfixed vulnerability notes\n");
  writeFileSync(join(dir, ".git", "info", "exclude"), "docs/PRIVATE-PLAN.md\n");
  writeFileSync(join(dir, ".gitignore"), "docs/ignored.md\n");
  writeFileSync(join(dir, "docs", "ignored.md"), "# ignored\n");
  git("add", "README.md", "SECURITY.md", "docs/guide", ".gitignore");
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const allText = (dir: string) =>
  (readdirSync(dir, { recursive: true }) as string[])
    .filter((f) => /\.(md|json)$/.test(f))
    .map((f) => readFileSync(join(dir, f), "utf8"))
    .join("\n");

describe("the site's content", () => {
  test("only what git would commit is published: an excluded or ignored note never is", () => {
    const r = repo();
    const site = join(r.dir, "website");
    try {
      assert.deepEqual(pageSources(r.dir), ["README.md", "SECURITY.md", "docs/RELAY.md", "docs/guide/README.md", "docs/guide/sets.md"]);
      buildContent(site, { dir: r.dir });
      const text = allText(site);
      assert.ok(!text.includes("Unfixed vulnerability"), "the private note's text reached the site");
      assert.ok(!text.includes("ignored"), "an ignored file reached the site");
    } finally {
      r.cleanup();
    }
  });

  test("short addresses: the README is /overview/ (the home page is the site's own), the guide is /guide/", () => {
    assert.equal(slugOf("README.md"), "overview");
    assert.equal(slugOf("docs/guide/README.md"), "guide");
    assert.equal(slugOf("docs/guide/sets.md"), "guide/sets");
    assert.equal(slugOf("docs/RED-TEAM.md"), "red-team");
    assert.equal(slugOf("CODE_OF_CONDUCT.md"), "code-of-conduct");
  });

  test("links between files become links between pages; anything else goes to GitHub", () => {
    const r = repo();
    const site = join(r.dir, "website");
    try {
      buildContent(site, { dir: r.dir, branch: "beta" });
      const docs = join(site, "src", "content", "docs");
      const home = readFileSync(join(docs, "overview.md"), "utf8");
      assert.match(home, /^---\ntitle: "Overview"\n/);
      assert.match(home, /\]\(\/guide\/sets\/#sets\)/);
      assert.match(home, /\]\(\/relay\/\)/);
      assert.ok(home.includes(`](${REPO}/blob/beta/test/x.test.ts)`), home);
      assert.match(readFileSync(join(docs, "guide", "sets.md"), "utf8"), /\]\(\/overview\/\)/);
      // The sidebar comes from the guide index; a label that is a file name shows the page's title.
      const sidebar = JSON.parse(readFileSync(join(site, "src", "sidebar.json"), "utf8"));
      assert.deepEqual(sidebar[0], {
        label: "Using it",
        items: [
          { label: "Overview", slug: "overview" },
          { label: "The guide", slug: "guide" },
          { label: "Sets", slug: "guide/sets" },
          { label: "Security policy", slug: "security" },
        ],
      });
      assert.equal(readFileSync(join(site, "public", "CNAME"), "utf8"), "tryhush.dev\n");
      // Where to report a vulnerability, for anyone who looks on the site (RFC 9116).
      const txt = readFileSync(join(site, "public", ".well-known", "security.txt"), "utf8");
      assert.match(txt, /^Contact: https:\/\/github\.com\/omarei-omoto\/hush\/security\/advisories\/new$/m);
      assert.match(txt, /^Expires: \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/m);
      assert.match(txt, /^Policy: https:\/\/tryhush\.dev\/security\/$/m);
    } finally {
      r.cleanup();
    }
  });

  test("the first heading is the title; alerts become asides; code is never rewritten", () => {
    const md = [
      "# The `hush` guide",
      "",
      "> [!WARNING]",
      "> Read [this](sets.md) first.",
      "",
      "```md",
      "[a link in code](sets.md)",
      "> [!NOTE]",
      "```",
      "",
      "and `[inline](sets.md)` too, but [this](sets.md) changes.",
    ].join("\n");
    const { title, body } = convert(md, "docs/guide/x.md", { published: new Set(["docs/guide/sets.md"]) });
    assert.equal(title, "The hush guide");
    assert.match(body, /^---\ntitle: "The hush guide"\neditUrl: ".*\/edit\/main\/docs\/guide\/x\.md"\n---\n/);
    assert.ok(!body.includes("# The"), "the heading is still in the body");
    assert.match(body, /:::caution\[Warning\]\nRead \[this\]\(\/guide\/sets\/\) first\.\n:::/);
    assert.ok(body.includes("```md\n[a link in code](sets.md)\n> [!NOTE]\n```"), body);
    assert.ok(body.includes("`[inline](sets.md)` too, but [this](/guide/sets/) changes."), body);
  });
});

describe("the real docs", () => {
  test("every page builds, every link between pages lands on one, and the private plan is not among them", () => {
    const root = join(import.meta.dirname, "..");
    const site = mkdtempSync(join(tmpdir(), "hush-site-"));
    try {
      const written = buildContent(site, { dir: root });
      const slugs = new Set(written.map((w) => w.slug));
      for (const must of ["overview", "guide", "guide/sets", "guide/setting-up", "relay", "tailnet", "security"]) assert.ok(slugs.has(must), `/${must} was not built`);
      assert.ok(!written.some((w) => /PLAN-1\.0/.test(w.src)), "a private plan was published");
      let links = 0;
      for (const w of written) {
        const body = readFileSync(join(site, "src", "content", "docs", w.file), "utf8");
        for (const [, url] of body.matchAll(/\]\((\/[^)\s#]*)/g)) {
          const slug = url.replace(/^\/|\/$/g, "");
          if (url.startsWith("/assets/")) assert.ok(existsSync(join(site, "public", url)), `${w.src} shows ${url}, which was not copied`);
          else assert.ok(slugs.has(slug), `${w.src} links to ${url}, which is not a page`);
          links++;
        }
      }
      assert.ok(links > 100, `only ${links} links between pages — is the check still matching?`);
      // Every table ends before the prose after it, or the prose becomes a row.
      for (const src of pageSources(root)) {
        const lines = readFileSync(join(root, src), "utf8").split("\n");
        let fence = false;
        lines.forEach((line, i) => {
          if (/^\s*(```|~~~)/.test(line)) fence = !fence;
          if (!fence && i && /^\s*\|.*\|\s*$/.test(lines[i - 1]) && line.trim() && !line.trim().startsWith("|")) {
            assert.fail(`${src}:${i + 1}: a table runs straight into "${line.slice(0, 40)}" — add a blank line`);
          }
        });
      }
    } finally {
      rmSync(site, { recursive: true, force: true });
    }
  });
});

describe("checking the built site", () => {
  test("a link to a page that was not built, a missing anchor, or a script from elsewhere is a problem", () => {
    const dist = mkdtempSync(join(tmpdir(), "hush-dist-"));
    try {
      mkdirSync(join(dist, "guide", "sets"), { recursive: true });
      writeFileSync(join(dist, "guide", "sets", "index.html"), '<h2 id="sets">Sets</h2><a href="#_top">top</a>');
      mkdirSync(join(dist, "_astro"));
      writeFileSync(join(dist, "_astro", "a.js"), "");
      writeFileSync(
        join(dist, "index.html"),
        '<a href="/guide/sets/#sets">ok</a><a href="/guide/sets/#nope">bad anchor</a><a href="/gone/">gone</a>' +
          '<script src="/_astro/a.js"></script><script src="https://cdn.example/x.js"></script>',
      );
      const { problems } = checkSite(dist);
      assert.equal(problems.length, 3, problems.join("\n"));
      assert.ok(problems.some((p) => p.includes("#nope")));
      assert.ok(problems.some((p) => p.includes("/gone/")));
      assert.ok(problems.some((p) => p.includes("cdn.example")));
    } finally {
      rmSync(dist, { recursive: true, force: true });
    }
  });
});

describe("the live app on the home page", () => {
  /** The demo's data and script, run as a browser would run them, against a stand-in window. */
  function load(html: string, opts: { parentTheme?: string } = {}) {
    const data = /<script type="application\/json" id="hush-demo">([\s\S]*?)<\/script>/.exec(html)![1];
    const script = /<\/script><script>([\s\S]*?)<\/script>/.exec(html)![1];
    const root = { dataset: {} as Record<string, string> };
    const stored = new Map([["hush-keys", "open"], ["hush-project", "/somewhere"]]);
    const window: Record<string, unknown> = { fetch: async () => new Response("{}") };
    window.parent = opts.parentTheme ? { document: { documentElement: { dataset: { theme: opts.parentTheme } } } } : window;
    Object.assign(window, {
      window,
      document: { documentElement: root, getElementById: () => ({ textContent: data }) },
      matchMedia: () => ({ matches: false, addEventListener() {} }),
      localStorage: { removeItem: (k: string) => stored.delete(k) },
      location: { href: "https://tryhush.dev/demo/index.html" },
      MutationObserver: class { observe() {} },
      Response,
      URL,
      JSON,
      Date,
    });
    runInNewContext(script, window);
    const fetch = window.fetch as (url: string, init?: RequestInit) => Promise<Response>;
    return { fetch, theme: root.dataset.theme, stored };
  }

  test("it answers the page's reads from what was recorded, and every change with a notice", async () => {
    const page = '<!doctype html><html><head><meta charset="utf-8"><style>:root{--bg:#fff}@media (prefers-color-scheme:dark){:root{--bg:#111;}}</style></head><body></body></html>';
    const at = new Date(Date.now() - 3_600_000).toISOString();
    const html = demoPage(page, { "GET /api/hub ": { projects: [] }, "GET /api/state /p": { seen: at }, "POST /api/audit /p": { entries: [] } }, at);
    // After the charset, which a browser only looks for in the first kilobyte.
    assert.ok(html.startsWith('<!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex">'), html.slice(0, 120));
    assert.ok(!html.includes("@media (prefers-color-scheme:dark)"), "the dark palette still follows only the system");
    assert.match(html, /:root\[data-theme=dark\]\{--bg:#111;\}/);

    const { fetch, theme, stored } = load(html, { parentTheme: "light" });
    assert.equal(theme, "light", "the app did not take the site's theme");
    assert.equal(stored.size, 0, "a choice from an earlier visit was kept");
    const json = async (r: Promise<Response>) => {
      const res = await r;
      return { status: res.status, body: (await res.json()) as Record<string, string> };
    };
    assert.deepEqual(await json(fetch("/api/hub")), { status: 200, body: { projects: [] } });
    // A project's own answer, and the folder the app started in for one it never asked about.
    const state = await json(fetch("/api/state", { headers: { "x-hush-project": "/p" } }));
    assert.ok(Date.now() - Date.parse(state.body.seen) < 60_000, "a recorded time was not moved up to now");
    assert.deepEqual((await json(fetch("/api/audit", { method: "POST", headers: { "x-hush-project": "/p" }, body: "{}" }))).body, { entries: [] });
    assert.deepEqual(await json(fetch("/api/hub", { headers: { "x-hush-project": "/elsewhere" } })), { status: 200, body: { projects: [] } });
    // Anything that would change something: the notice, never a pretend success.
    for (const [path, body] of [["/api/secret", '{"key":"A"}'], ["/api/audit", '{"x":1}'], ["/api/reveal", '{"key":"A"}']]) {
      assert.deepEqual(await json(fetch(path, { method: "POST", headers: { "x-hush-project": "/p" }, body })), { status: 409, body: { error: DEMO_REFUSAL } });
    }
  });

  test(
    "built from the real app on made-up keys: every view it reads, no value, no path from this machine",
    { skip: process.platform === "win32" ? "the site is built on Linux" : false },
    async () => {
      const dir = mkdtempSync(join(tmpdir(), "hush-demo-out-"));
      try {
        const out = join(dir, "index.html");
        const { answers } = await buildDemo(out);
        const keys = Object.keys(answers);
        for (const read of ["GET /api/hub ", "GET /api/state ", "POST /api/suggestions ", "POST /api/push-hosts ", "POST /api/audit "]) {
          assert.ok(keys.includes(read), `${read.trim()} was not recorded`);
        }
        assert.equal(keys.filter((k) => k.startsWith("GET /api/state /Users/alex/code/")).length, 5, keys.join("\n"));
        // What the window is there to show: the app's suggestions, each kind of them.
        const kinds = (answers["POST /api/suggestions "] as { suggestions: { kind: string }[] }).suggestions.map((s) => s.kind).sort();
        for (const kind of ["give", "group", "plaintext", "repush"]) assert.ok(kinds.includes(kind), `no "${kind}" suggestion: ${kinds}`);
        // A Mac set up the way hush start leaves one, wherever this was built.
        assert.equal((answers["GET /api/hub "] as { platform: string }).platform, "darwin");
        assert.equal((answers["GET /api/state "] as { posture: { rung: number } }).posture.rung, 3);
        const html = readFileSync(out, "utf8");
        assert.ok(!html.includes(tmpdir()) && !html.includes(process.cwd()), "a path from this machine is in the demo");
        assert.ok(!/not-a-real|not_a_real/.test(html), "a whole value reached the demo");
        assert.ok(html.includes("<title>hush</title>"), "this is not the app's page");
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
  );
});
