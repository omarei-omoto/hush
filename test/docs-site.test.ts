/**
 * The docs site (D-2): scripts/markdown.mjs renders hush's Markdown, and
 * scripts/build-docs.mjs turns the README and the guide into pages.
 *
 * What matters most is at the bottom: every link on the built site goes
 * somewhere, and nothing git would not commit is ever published — the site is
 * built from a working tree that may hold private notes.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, posix } from "node:path";

import { render, slugify } from "../scripts/markdown.mjs";
import { buildSite, outputPath, pageSources } from "../scripts/build-docs.mjs";

describe("the Markdown renderer", () => {
  test("headings get GitHub's anchors, repeated ones numbered", () => {
    const html = render("# Sets\n\n## Removing someone\n\n## Removing someone\n\n### `hush team` & friends!");
    assert.match(html, /<h1 id="sets">/);
    assert.match(html, /<h2 id="removing-someone">/);
    assert.match(html, /<h2 id="removing-someone-1">/);
    assert.match(html, /<h3 id="hush-team--friends">/);
    assert.equal(slugify("What hush does not do"), "what-hush-does-not-do");
  });

  test("code is escaped, never interpreted — in blocks and inline", () => {
    const html = render("```html\n<script>alert(1)</script>\n**not bold**\n```\n\nand `<b>` too");
    assert.ok(!html.includes("<script>"), html);
    assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.match(html, /\*\*not bold\*\*/);
    assert.match(html, /<code>&lt;b&gt;<\/code>/);
    assert.match(html, /class="language-html"/);
  });

  test("an HTML comment is dropped, even across lines", () => {
    const html = render("before\n\n<!-- a note\nfor editors -->\n\nafter");
    assert.equal(html, "<p>before</p>\n<p>after</p>");
  });

  test("raw HTML outside the README's header tags is text", () => {
    const html = render('<script>steal()</script>\n\ntext <iframe src="x"></iframe>\n\n<p align="center">kept</p>');
    assert.ok(!/<script|<iframe/i.test(html), html);
    assert.match(html, /<p align="center">kept<\/p>/);
  });

  test("tables, with pipes inside code left alone", () => {
    const html = render("| A | B |\n|---|:-:|\n| `a|b` | **x** |\n| 2 |");
    assert.match(html, /<th>A<\/th><th style="text-align:center">B<\/th>/);
    assert.match(html, /<td><code>a\|b<\/code><\/td><td style="text-align:center"><strong>x<\/strong><\/td>/);
    assert.match(html, /<tr><td>2<\/td><td style="text-align:center"><\/td><\/tr>/);
  });

  test("nested lists, and code inside a list item", () => {
    const tight = render("- one\n  - inner\n- two\n\n1. first\n2. second");
    assert.match(tight, /<li>one\n?<ul>\n<li>inner<\/li>\n<\/ul><\/li>/);
    assert.match(tight, /<li>two<\/li>/);
    assert.match(tight, /<ol>\n<li>first<\/li>\n<li>second<\/li>\n<\/ol>/);
    // A blank line inside an item makes the list loose, as it does on GitHub.
    const loose = render("- run it:\n\n  ```bash\n  hush run\n  ```\n- done");
    assert.match(loose, /<li><p>run it:<\/p>\n<pre><code class="language-bash">hush run<\/code><\/pre><\/li>/);
  });

  test("GitHub alerts and plain quotes", () => {
    const html = render("> [!IMPORTANT]\n> **Status: early.**\n\n> just a quote");
    assert.match(html, /<div class="alert alert-important"><p class="alert-title">Important<\/p><p><strong>Status: early\.<\/strong><\/p><\/div>/);
    assert.match(html, /<blockquote><p>just a quote<\/p><\/blockquote>/);
  });

  test("inline forms, and snake_case left alone", () => {
    const html = render("A [link with `code`](x.md#y), *em*, _em_, ~~gone~~, <https://a.example>, HUSH_NO_DIALOG and file_name_here.");
    assert.match(html, /<a href="x\.md#y">link with <code>code<\/code><\/a>/);
    assert.match(html, /<em>em<\/em>, <em>em<\/em>, <del>gone<\/del>/);
    assert.match(html, /<a href="https:\/\/a\.example">/);
    assert.match(html, /HUSH_NO_DIALOG and file_name_here/);
  });

  test("links go through the rewriter", () => {
    const html = render("[a](../x.md) ![i](p.png)", { link: (h) => `<${h}>` });
    assert.match(html, /href="&lt;\.\.\/x\.md&gt;"/);
    assert.match(html, /src="&lt;p\.png&gt;"/);
  });
});

/** A throwaway git repository shaped like hush's docs. */
function repo() {
  const dir = mkdtempSync(join(tmpdir(), "hush-docs-"));
  const git = (...args: string[]) => execFileSync("git", args, { cwd: dir, stdio: "ignore" });
  git("init", "-q");
  mkdirSync(join(dir, "docs", "guide"), { recursive: true });
  writeFileSync(join(dir, "README.md"), "# hush\n\nSee [sets](docs/guide/sets.md#sets), [the relay](docs/RELAY.md) and [a test](test/x.test.ts).\n");
  writeFileSync(join(dir, "docs", "guide", "README.md"), "# The guide\n\n- **Using it** — [Sets](sets.md)\n");
  writeFileSync(join(dir, "docs", "guide", "sets.md"), "# Sets\n\nBack to [the README](../../README.md).\n");
  writeFileSync(join(dir, "docs", "RELAY.md"), "# Relay\n");
  writeFileSync(join(dir, "docs", "PRIVATE-PLAN.md"), "# Unfixed vulnerability notes\n");
  writeFileSync(join(dir, ".git", "info", "exclude"), "docs/PRIVATE-PLAN.md\n");
  writeFileSync(join(dir, ".gitignore"), "docs/ignored.md\n");
  writeFileSync(join(dir, "docs", "ignored.md"), "# ignored\n");
  git("add", "README.md", "docs/guide", ".gitignore");
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

describe("building the site", () => {
  test("only what git would commit is published: an excluded or ignored note never is", () => {
    const r = repo();
    const out = join(r.dir, "site");
    try {
      const sources = pageSources(r.dir);
      assert.deepEqual(sources, ["README.md", "docs/RELAY.md", "docs/guide/README.md", "docs/guide/sets.md"]);
      buildSite(out, r.dir);
      assert.ok(!existsSync(join(out, "docs", "PRIVATE-PLAN.html")), "an excluded file was published");
      assert.ok(!existsSync(join(out, "docs", "ignored.html")), "an ignored file was published");
      const all = (readdirSync(out, { recursive: true }) as string[])
        .filter((f) => f.endsWith(".html"))
        .map((f) => readFileSync(join(out, f), "utf8"))
        .join("\n");
      assert.ok(!all.includes("Unfixed vulnerability"), "the private note's text reached the site");
    } finally {
      r.cleanup();
    }
  });

  test("links between pages become links between .html files; anything else goes to GitHub", () => {
    const r = repo();
    const out = join(r.dir, "site");
    try {
      buildSite(out, r.dir);
      const index = readFileSync(join(out, "index.html"), "utf8");
      assert.match(index, /href="docs\/guide\/sets\.html#sets"/);
      assert.match(index, /href="docs\/RELAY\.html"/);
      assert.match(index, /href="https:\/\/github\.com\/omarei-omoto\/hush\/blob\/main\/test\/x\.test\.ts"/);
      const sets = readFileSync(join(out, "docs", "guide", "sets.html"), "utf8");
      assert.match(sets, /href="\.\.\/\.\.\/index\.html"/);
      assert.ok(existsSync(join(out, ".nojekyll")));
      assert.equal(outputPath("docs/guide/README.md"), "docs/guide/index.html");
    } finally {
      r.cleanup();
    }
  });

  test("the real site: every page present, every internal link and anchor resolves, and no script anywhere", () => {
    const root = join(import.meta.dirname, "..");
    const out = mkdtempSync(join(tmpdir(), "hush-site-"));
    try {
      const pages = buildSite(out, root);
      for (const must of ["index.html", "docs/guide/index.html", "docs/guide/sets.html", "docs/RELAY.html", "SECURITY.html"]) {
        assert.ok(pages.includes(must), `${must} was not built`);
      }
      assert.ok(!pages.some((p) => /PLAN-1\.0/.test(p)), "a private plan was published");
      let links = 0;
      for (const page of pages) {
        const html = readFileSync(join(out, page), "utf8");
        assert.ok(!/<script/i.test(html), `${page} contains a script`);
        for (const [, src] of html.matchAll(/<img[^>]* src="([^"]+)"/g)) {
          if (/^[a-z]+:/i.test(src)) continue;
          assert.ok(existsSync(join(out, posix.normalize(posix.join(posix.dirname(page), src)))), `${page} shows ${src}, which was not copied`);
        }
        for (const [, href] of html.matchAll(/href="([^"]+)"/g)) {
          if (/^[a-z]+:/i.test(href)) continue;
          const [path, frag] = href.split("#");
          const target = path ? posix.normalize(posix.join(posix.dirname(page), path)) : page;
          assert.ok(existsSync(join(out, target)), `${page} links to ${href}, which was not built`);
          if (frag) {
            const ids = new Set([...readFileSync(join(out, target), "utf8").matchAll(/ id="([^"]+)"/g)].map((m) => m[1]));
            assert.ok(ids.has(frag), `${page} links to ${href}, which has no such anchor`);
          }
          links++;
        }
      }
      assert.ok(links > 500, `only ${links} internal links — is the check still matching?`);
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  });
});

