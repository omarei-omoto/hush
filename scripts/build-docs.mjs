#!/usr/bin/env node
/**
 * The docs site (D-2): the README and the guide as static HTML for GitHub
 * Pages. No dependencies; the Markdown renderer is scripts/markdown.mjs.
 *
 *   node scripts/build-docs.mjs [--out site]
 *
 * Each page keeps its path — README.md is index.html, docs/guide/sets.md is
 * docs/guide/sets.html — so a relative link between two .md files works on
 * GitHub and, with .md swapped for .html, on the site. A link to anything that
 * is not a page (a test file, the LICENSE) goes to the file on GitHub.
 *
 * Only files git would commit are published: tracked ones, and new ones that
 * are not ignored. An ignored or excluded file never reaches the site. That is
 * how a private working note stays private even when it sits in docs/.
 */
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { fileURLToPath } from "node:url";
import { render, inline } from "./markdown.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const REPO = "https://github.com/omarei-omoto/hush";
/**
 * Where the site lives, for canonical links and, on a custom domain, the
 * CNAME file GitHub Pages reads. `--site <url>` overrides it.
 */
const argValue = (flag) => {
  const i = process.argv.indexOf(flag);
  return i === -1 ? undefined : process.argv[i + 1];
};
const SITE = (argValue("--site") ?? "https://tryhush.dev/").replace(/\/?$/, "/");
/**
 * The branch the pages are read from, so "edit this page" opens a page that
 * exists: the beta branch has pages main does not have yet.
 */
const BRANCH = argValue("--branch") ?? process.env.GITHUB_REF_NAME ?? (() => {
  try {
    return execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], { cwd: root, encoding: "utf8" }).trim() || "main";
  } catch {
    return "main";
  }
})();
const ROOT_PAGES = ["README.md", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md", "RELEASING.md", "RESEARCH.md", "CODE_OF_CONDUCT.md"];

/** The Markdown files that become pages: what git would commit, under docs/, plus the root documents. */
export function pageSources(dir = root) {
  const files = execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], { cwd: dir, encoding: "utf8" })
    .split("\0")
    .filter(Boolean);
  return files
    .filter((f) => (ROOT_PAGES.includes(f) || (f.startsWith("docs/") && f.endsWith(".md"))) && existsSync(join(dir, f)))
    .sort();
}

export const outputPath = (src) => src.replace(/(^|\/)README\.md$/, "$1index.html").replace(/\.md$/, ".html");

/** The sidebar: the guide index's groups (docs/guide/README.md), then the project's own documents. */
function navigation(dir) {
  const groups = [];
  const index = readFileSync(join(dir, "docs/guide/README.md"), "utf8");
  for (const m of index.matchAll(/^- \*\*(.+?)\*\* — (.+)$/gm)) {
    const links = [...m[2].matchAll(/\[([^\]]+)\]\(([^)]+)\)/g)].map(([, label, href]) => ({
      label,
      src: posix.normalize(posix.join("docs/guide", href.split("#")[0])),
    }));
    groups.push({ title: m[1], links });
  }
  groups.push({
    title: "Project",
    links: [
      { label: "Security", src: "SECURITY.md" },
      { label: "Contributing", src: "CONTRIBUTING.md" },
      { label: "Architecture", src: "docs/ARCHITECTURE.md" },
      { label: "Changelog", src: "CHANGELOG.md" },
    ],
  });
  return groups;
}

const titleOf = (md, src) => (/^#\s+(.+)$/m.exec(md)?.[1] ?? src).replace(/<[^>]+>/g, "").replace(/[`*]/g, "").trim();

export function buildSite(out, dir = root) {
  const sources = pageSources(dir);
  const published = new Set(sources);
  const nav = navigation(dir);
  // The logo, from assets/ (one source for the README, the app and this site).
  // A tree without the logo files (a test fixture, a fork) gets the word.
  const asset = (f) => (existsSync(join(dir, "assets", f)) ? readFileSync(join(dir, "assets", f), "utf8").trim() : null);
  const logo = asset("logo.svg")?.replace(/ role="img" aria-label="hush"/, ' aria-hidden="true"') ?? "hush";
  const markSvg = asset("logo-mark.svg")
    ?.replace('<path fill="currentColor"', '<rect x="-18.86" y="-47.43" width="194.86" height="194.86" rx="40" fill="#111"/><path fill="#F2F1ED"');
  const icon = markSvg ? "data:image/svg+xml," + encodeURIComponent(markSvg) : "data:,";
  rmSync(out, { recursive: true, force: true });
  const written = [];

  for (const src of sources) {
    const md = readFileSync(join(dir, src), "utf8");
    const here = posix.dirname(src);
    const rel = (target) => posix.relative(here, target) || posix.basename(target);
    const link = (href) => {
      if (/^[a-z]+:/i.test(href) || href.startsWith("//") || href.startsWith("#")) return href;
      const [path, frag] = href.split("#");
      const target = posix.normalize(posix.join(here, path));
      const hash = frag ? `#${frag}` : "";
      if (published.has(target)) return rel(outputPath(target)) + hash;
      if (published.has(posix.join(target, "README.md"))) return rel(outputPath(posix.join(target, "README.md"))) + hash;
      // Not a page: the file (or folder) on GitHub.
      const kind = /\.[a-z0-9]+$/i.test(target) ? "blob" : "tree";
      return `${REPO}/${kind}/main/${target}${hash}`;
    };
    const body = render(md, { link });
    const outFile = outputPath(src);
    const depth = outFile.split("/").length - 1;
    const up = depth ? "../".repeat(depth) : "";
    const navHtml = nav
      .map(
        (g) =>
          `<p class="nav-group">${inline(g.title)}</p><ul>` +
          g.links
            .filter((l) => published.has(l.src))
            .map((l) => `<li${l.src === src ? ' class="here"' : ""}><a href="${up}${outputPath(l.src)}">${inline(l.label)}</a></li>`)
            .join("") +
          `</ul>`,
      )
      .join("\n");
    const title = src === "README.md" ? "hush — secrets your AI agent can use but never read" : `${titleOf(md, src)} · hush`;
    const html = page({ title, body, nav: navHtml, up, edit: `${REPO}/blob/${BRANCH}/${src}`, canonical: SITE + outFile.replace(/index\.html$/, ""), logo, icon });
    mkdirSync(join(out, posix.dirname(outFile)), { recursive: true });
    writeFileSync(join(out, outFile), html);
    written.push(outFile);
  }
  // Images the pages use (the README's demo GIF, the logos), at the same
  // relative path they have in the repository.
  if (existsSync(join(dir, "assets"))) cpSync(join(dir, "assets"), join(out, "assets"), { recursive: true });
  // GitHub Pages runs Jekyll unless told not to; the files are already HTML.
  writeFileSync(join(out, ".nojekyll"), "");
  return written;
}

const CSS = `
:root{--bg:#F2F1ED;--fg:#111111;--muted:#77756E;--line:#DEDCD5;--soft:#FFFFFF;--link:#111111;--code:#E8E6E0;--accent:#2F6B47;
--note:#3B3A36;--tip:#2F6B47;--important:#111111;--warning:#8C5A0E;--caution:#A5321F}
@media (prefers-color-scheme:dark){:root{--bg:#111111;--fg:#F2F1ED;--muted:#8F8C84;--line:#2B2A26;--soft:#1A1A18;--link:#F2F1ED;--code:#242320;--accent:#7FC59A;
--note:#D2D0C9;--tip:#7FC59A;--important:#F2F1ED;--warning:#E3B062;--caution:#EE8A77}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
a{color:var(--link);text-decoration:underline;text-decoration-color:var(--line);text-underline-offset:3px}a:hover{text-decoration-color:currentColor}
nav a,header a{text-decoration:none}
header{display:flex;align-items:center;gap:12px;padding:12px 24px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg);z-index:2}
header .brand{display:flex;color:var(--fg)}header .brand svg{height:20px;width:auto}header .tag{color:var(--muted);font-size:14px}
header .gh{margin-left:auto;font-size:14px}
.wrap{display:flex;max-width:1200px;margin:0 auto}
nav{width:260px;flex:none;padding:20px 16px 40px 24px;border-right:1px solid var(--line);position:sticky;top:53px;align-self:flex-start;max-height:calc(100vh - 53px);overflow:auto;font-size:14px}
nav ul{list-style:none;margin:0 0 12px;padding:0}nav li a{display:block;padding:3px 8px;border-radius:6px;color:var(--fg)}
nav li.here a{background:var(--soft);font-weight:600}nav .nav-group{margin:14px 0 4px 8px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
main{min-width:0;flex:1;padding:24px 40px 80px}
main h1,main h2,main h3{line-height:1.25;margin:1.6em 0 .6em;position:relative}main h1{font-size:2em;margin-top:.4em}main h2{font-size:1.5em;padding-bottom:.3em;border-bottom:1px solid var(--line)}
.anchor{position:absolute;left:-1em;opacity:0;color:var(--muted)}h1:hover .anchor,h2:hover .anchor,h3:hover .anchor{opacity:1}
code{font:85% ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);padding:.15em .35em;border-radius:6px}
pre{background:var(--soft);border:1px solid var(--line);border-radius:8px;padding:14px 16px;overflow:auto;line-height:1.45}pre code{background:none;padding:0;font-size:85%}
.table{overflow:auto}table{border-collapse:collapse;margin:1em 0}th,td{border:1px solid var(--line);padding:6px 12px;vertical-align:top}th{background:var(--soft)}
blockquote{margin:1em 0;padding:0 1em;color:var(--muted);border-left:4px solid var(--line)}
.alert{margin:1em 0;padding:8px 16px;border-left:4px solid var(--note);border-radius:4px;background:var(--soft)}.alert-title{font-weight:600;margin:.4em 0}
.alert-note{border-color:var(--note)}.alert-tip{border-color:var(--tip)}.alert-important{border-color:var(--important)}.alert-warning{border-color:var(--warning)}.alert-caution{border-color:var(--caution)}
img{max-width:100%}hr{border:0;border-top:1px solid var(--line);margin:2em 0}
footer{margin-top:48px;padding-top:16px;border-top:1px solid var(--line);font-size:14px;color:var(--muted)}
details.menu{display:none}
@media (max-width:860px){nav{display:none}.wrap{display:block}main{padding:16px 16px 60px}
details.menu{display:block;border-bottom:1px solid var(--line);padding:8px 16px}details.menu nav{display:block;position:static;width:auto;border:0;padding:8px 0;max-height:none}
header .tag{display:none}.anchor{display:none}}
`;

function page({ title, body, nav, up, edit, canonical, logo, icon }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title.replace(/</g, "&lt;")}</title>
<meta name="description" content="hush — envelope-encrypted team secrets your AI agent can use but never read.">
<link rel="canonical" href="${canonical}">
<link rel="icon" href="${icon}">
<style>${CSS}</style>
</head>
<body>
<header><a class="brand" href="${up}index.html" aria-label="hush">${logo}</a><span class="tag">secrets your AI agent can use but never read</span><a class="gh" href="${REPO}">GitHub</a></header>
<details class="menu"><summary>Menu</summary><nav>${nav}</nav></details>
<div class="wrap">
<nav aria-label="Documentation">${nav}</nav>
<main>
${body}
<footer><a href="${edit}">Edit this page on GitHub</a> · MIT licensed</footer>
</main>
</div>
</body>
</html>
`;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const i = process.argv.indexOf("--out");
  const out = i === -1 ? join(root, "site") : process.argv[i + 1];
  const written = buildSite(out);
  // A custom domain needs a CNAME file at the root of what GitHub Pages serves.
  const host = new URL(SITE).host;
  if (!host.endsWith(".github.io")) writeFileSync(join(out, "CNAME"), host + "\n");
  process.stdout.write(`${written.length} pages → ${out} (${SITE}, edit links on ${BRANCH})\n`);
}
