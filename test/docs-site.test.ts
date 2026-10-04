/**
 * The docs site: scripts/build-docs.mjs turns the README and docs/ into the
 * Starlight site's content (website/), and scripts/check-site.mjs checks the
 * built site before it is deployed.
 *
 * What matters most: nothing git would not commit is ever published — the
 * site is built from a working tree that may hold private notes — and every
 * link between pages lands on a page.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { REPO, buildContent, convert, pageSources, slugOf } from "../scripts/build-docs.mjs";
import { checkSite } from "../scripts/check-site.mjs";

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

  test("short addresses: the README is the home page, the guide is /guide/", () => {
    assert.equal(slugOf("README.md"), "");
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
      const home = readFileSync(join(docs, "index.md"), "utf8");
      assert.match(home, /\]\(\/guide\/sets\/#sets\)/);
      assert.match(home, /\]\(\/relay\/\)/);
      assert.ok(home.includes(`](${REPO}/blob/beta/test/x.test.ts)`), home);
      assert.match(readFileSync(join(docs, "guide", "sets.md"), "utf8"), /\]\(\/\)/);
      // The sidebar comes from the guide index; a label that is a file name shows the page's title.
      const sidebar = JSON.parse(readFileSync(join(site, "src", "sidebar.json"), "utf8"));
      assert.deepEqual(sidebar[0], {
        label: "Using it",
        items: [
          { label: "The guide", slug: "guide" },
          { label: "Sets", slug: "guide/sets" },
          { label: "Security policy", slug: "security" },
        ],
      });
      assert.equal(readFileSync(join(site, "public", "CNAME"), "utf8"), "tryhush.dev\n");
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
      for (const must of ["", "guide", "guide/sets", "guide/setting-up", "relay", "tailnet", "security"]) assert.ok(slugs.has(must), `/${must} was not built`);
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
