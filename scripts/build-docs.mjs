#!/usr/bin/env node
/**
 * The docs site at tryhush.dev: the README and docs/ as a Starlight site
 * (website/). This script writes what Starlight builds from; Starlight does
 * the rest — search, a copy button on every code block, the sidebar, dark mode.
 *
 *   node scripts/build-docs.mjs [--site https://tryhush.dev/] [--branch beta]
 *   cd website && npm run build      # this, then astro build, then the link check
 *
 * The Markdown stays where it is and reads the same on GitHub. Each file
 * becomes a page at a short address — docs/guide/sets.md is /guide/sets/,
 * SECURITY.md is /security/ — its first heading becomes the page title, links
 * between files become links between pages, GitHub's [!NOTE] alerts become
 * Starlight asides, and a link to anything that is not a page (a test file,
 * the LICENSE) goes to the file on GitHub. Code is never touched.
 *
 * Only files git would commit are published: tracked ones, and new ones that
 * are not ignored. An ignored or excluded file never reaches the site. That is
 * how a private working note stays private even when it sits in docs/.
 *
 * Everything written here is generated and ignored by git (website/.gitignore).
 */
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
export const REPO = "https://github.com/omarei-omoto/hush";
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

/**
 * A page's address, without slashes: README.md is "" (the home page),
 * docs/guide/README.md is "guide", docs/guide/sets.md is "guide/sets", and
 * docs/RED-TEAM.md and CODE_OF_CONDUCT.md are "red-team" and "code-of-conduct".
 */
export function slugOf(src) {
  if (src === "README.md") return "";
  const kebab = (s) => s.toLowerCase().replace(/_/g, "-");
  if (src.startsWith("docs/guide/")) {
    const name = src.slice("docs/guide/".length, -".md".length);
    return name === "README" ? "guide" : `guide/${kebab(name)}`;
  }
  return kebab(posix.basename(src, ".md"));
}

export const urlOf = (slug) => (slug ? `/${slug}/` : "/");
const fileOf = (slug) => (slug === "" ? "index.md" : slug === "guide" ? "guide/index.md" : `${slug}.md`);

/** A heading's text without its Markdown: what a title or a sidebar label shows. */
const plain = (s) =>
  s
    .replace(/<[^>]+>/g, "")
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/[`*_]/g, "")
    .trim();

const FENCE = /^\s*(`{3,}|~{3,})/;

/** Calls `fn` on each run of lines outside fenced code, so code is never rewritten. */
function outsideCode(lines, fn) {
  const out = [];
  let prose = [];
  let fence = null;
  const flush = () => {
    if (prose.length) out.push(...fn(prose));
    prose = [];
  };
  for (const line of lines) {
    const m = FENCE.exec(line);
    if (fence) {
      out.push(line);
      if (m && m[1][0] === fence[0] && m[1].length >= fence.length && line.trim() === m[1]) fence = null;
    } else if (m) {
      flush();
      out.push(line);
      fence = m[1];
    } else prose.push(line);
  }
  flush();
  return out;
}

/** GitHub's alerts as Starlight asides, which have no direct equivalent of IMPORTANT. */
const ASIDES = { NOTE: ["note", "Note"], TIP: ["tip", "Tip"], IMPORTANT: ["note", "Important"], WARNING: ["caution", "Warning"], CAUTION: ["danger", "Caution"] };

function asides(lines) {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = /^> \[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*$/.exec(lines[i]);
    if (!m) {
      out.push(lines[i]);
      continue;
    }
    const [type, label] = ASIDES[m[1]];
    out.push(`:::${type}[${label}]`);
    while (i + 1 < lines.length && lines[i + 1].startsWith(">")) out.push(lines[++i].replace(/^> ?/, ""));
    out.push(":::");
  }
  return out;
}

/** Rewrites link targets in prose: Markdown links and images, and href/src in raw HTML — never inside `code`. */
function rewriteLinks(lines, link) {
  const rewrite = (text) =>
    text
      .replace(/\]\(\s*(<[^>]*>|[^)\s]+)(\s+"[^"]*")?\s*\)/g, (_, href, title = "") => {
        const bare = href.startsWith("<") ? href.slice(1, -1) : href;
        return `](${link(bare)}${title})`;
      })
      .replace(/\b(href|src)="([^"]*)"/g, (_, attr, href) => `${attr}="${link(href)}"`);
  return lines.map((line) => {
    let out = "";
    let last = 0;
    for (const m of line.matchAll(/(`+)[\s\S]*?[^`]\1(?!`)/g)) {
      out += rewrite(line.slice(last, m.index)) + m[0];
      last = m.index + m[0].length;
    }
    return out + rewrite(line.slice(last));
  });
}

/** The home page's top: the README's header (banner, tagline, badges) is GitHub's; the site has a hero instead. */
const HOME = {
  title: "Secrets your AI agent can use but never read",
  hero: {
    title: "Secrets your AI agent can use but never read",
    tagline: "Envelope-encrypted team secrets that live in your repo. No server, no account, no shared password.",
    actions: [
      { text: "Get started", link: "/guide/setting-up/", icon: "right-arrow" },
      { text: "Read the guide", link: "/guide/", variant: "minimal" },
      { text: "GitHub", link: REPO, icon: "github", variant: "minimal" },
    ],
  },
};

/**
 * One page's Markdown as Starlight content: frontmatter, then the body with
 * its first heading lifted into the title and every link pointed at the site.
 */
export function convert(md, src, { published, branch = "main", dir = root }) {
  const here = posix.dirname(src);
  const link = (href) => {
    if (!href || /^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith("//") || href.startsWith("#") || href.startsWith("/")) return href;
    const at = href.indexOf("#");
    const path = at === -1 ? href : href.slice(0, at);
    const hash = at === -1 ? "" : href.slice(at);
    const target = posix.normalize(posix.join(here, path));
    if (published.has(target)) return urlOf(slugOf(target)) + hash;
    if (published.has(posix.join(target, "README.md"))) return urlOf(slugOf(posix.join(target, "README.md"))) + hash;
    if (target.startsWith("assets/") && existsSync(join(dir, target))) return `/${target}${hash}`;
    // Not a page: the file (or folder) on GitHub, on the branch the site is built from.
    const kind = /\.[a-z0-9]+$/i.test(target) ? "blob" : "tree";
    return `${REPO}/${kind}/${branch}/${target === "." ? "" : target}${hash}`;
  };

  let lines = md.replace(/\r\n/g, "\n").split("\n");
  // The title: the first top-level heading outside code.
  let title = null;
  let fence = null;
  for (let i = 0; i < lines.length; i++) {
    const m = FENCE.exec(lines[i]);
    if (m) fence = fence ? null : m[1];
    if (fence || m) continue;
    const h = /^#\s+(.+?)\s*#*\s*$/.exec(lines[i]);
    if (h) {
      title = plain(h[1]);
      lines.splice(i, lines[i + 1]?.trim() === "" ? 2 : 1);
      break;
    }
  }
  const home = src === "README.md";
  if (home) {
    // Drop the GitHub header: leading HTML blocks, badge lines and blank lines.
    let i = 0;
    while (i < lines.length && (lines[i].trim() === "" || /^\s*<|^\[!\[/.test(lines[i]))) i++;
    lines = lines.slice(i);
  }
  lines = outsideCode(lines, (prose) => rewriteLinks(asides(prose), link));

  const front = home
    ? { ...HOME, template: "splash", editUrl: `${REPO}/edit/${branch}/${src}` }
    : { title: title ?? posix.basename(src, ".md"), editUrl: `${REPO}/edit/${branch}/${src}` };
  return { title: front.title, body: `---\n${yaml(front)}---\n\n${lines.join("\n").trim()}\n` };
}

/** Enough YAML for the frontmatter above: strings are JSON-quoted, which YAML reads as-is. */
function yaml(value, indent = "") {
  let out = "";
  for (const [k, v] of Object.entries(value)) {
    if (Array.isArray(v)) {
      out += `${indent}${k}:\n`;
      // Each item's first line starts "  - "; the rest line up under it.
      for (const item of v) out += `${indent}  - ` + yaml(item, `${indent}    `).slice(indent.length + 4);
    } else if (v && typeof v === "object") out += `${indent}${k}:\n${yaml(v, `${indent}  `)}`;
    else out += `${indent}${k}: ${JSON.stringify(v)}\n`;
  }
  return out;
}

/** The sidebar: the guide index's groups (docs/guide/README.md), then the project's own documents. */
export function sidebar(published, titles, dir = root) {
  const item = (src, label) => ({ label: /\.md$/.test(label) ? titles.get(src) ?? label : label, slug: slugOf(src) });
  const groups = [];
  const index = readFileSync(join(dir, "docs/guide/README.md"), "utf8");
  for (const m of index.matchAll(/^- \*\*(.+?)\*\* — (.+)$/gm)) {
    const items = [...m[2].matchAll(/\[([^\]]+)\]\(([^)]+)\)/g)]
      .map(([, label, href]) => [posix.normalize(posix.join("docs/guide", href.split("#")[0])), plain(label)])
      .filter(([src]) => published.has(src))
      .map(([src, label]) => item(src, label));
    if (items.length) groups.push({ label: m[1], items });
  }
  const project = ["CONTRIBUTING.md", "CHANGELOG.md", "RELEASING.md", "CODE_OF_CONDUCT.md"].filter((s) => published.has(s));
  if (project.length) groups.push({ label: "Project", collapsed: true, items: project.map((s) => item(s, titles.get(s) ?? s)) });
  // The guide's own index opens the first group.
  groups[0]?.items.unshift({ label: "The guide", slug: "guide" });
  return groups;
}

/**
 * Writes the site's content into a Starlight project: the pages, the
 * sidebar, the images the pages show, the favicon and the logos.
 */
export function buildContent(site, { dir = root, branch = "main", siteUrl = "https://tryhush.dev/", now = Date.now() } = {}) {
  const sources = pageSources(dir);
  const published = new Set(sources);
  const content = join(site, "src", "content", "docs");
  const pub = join(site, "public");
  rmSync(content, { recursive: true, force: true });
  rmSync(pub, { recursive: true, force: true });
  mkdirSync(pub, { recursive: true });

  const seen = new Map();
  const titles = new Map();
  const written = [];
  for (const src of sources) {
    const slug = slugOf(src);
    if (seen.has(slug)) throw new Error(`${seen.get(slug)} and ${src} would both be ${urlOf(slug)}`);
    seen.set(slug, src);
    const { title, body } = convert(readFileSync(join(dir, src), "utf8"), src, { published, branch, dir });
    titles.set(src, title);
    const file = join(content, fileOf(slug));
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, body);
    written.push({ src, slug, file: fileOf(slug) });
  }
  writeFileSync(join(site, "src", "sidebar.json"), JSON.stringify(sidebar(published, titles, dir), null, 2) + "\n");

  // Images the pages show (the demo GIF, the logos), at /assets/.
  if (existsSync(join(dir, "assets"))) cpSync(join(dir, "assets"), join(pub, "assets"), { recursive: true });
  const asset = (f) => (existsSync(join(dir, "assets", f)) ? readFileSync(join(dir, "assets", f), "utf8").trim() : null);
  const mark = asset("logo-mark.svg");
  if (mark) {
    writeFileSync(
      join(pub, "favicon.svg"),
      mark.replace('<path fill="currentColor"', '<rect x="-18.86" y="-47.43" width="194.86" height="194.86" rx="40" fill="#111"/><path fill="#F2F1ED"') + "\n",
    );
  }
  mkdirSync(join(site, "src", "assets"), { recursive: true });
  for (const f of ["logo-light.svg", "logo-dark.svg"]) if (asset(f)) cpSync(join(dir, "assets", f), join(site, "src", "assets", f));
  // security.txt (RFC 9116): where to report a vulnerability, for anyone who
  // looks for it on the site rather than in the repository. Expires a year
  // from each build, so a site that is still deployed is never stale.
  mkdirSync(join(pub, ".well-known"), { recursive: true });
  const expires = new Date(now + 365 * 86400e3).toISOString().replace(/\.\d+Z$/, "Z");
  writeFileSync(
    join(pub, ".well-known", "security.txt"),
    [
      `Contact: ${REPO}/security/advisories/new`,
      `Expires: ${expires}`,
      `Policy: ${siteUrl}security/`,
      `Canonical: ${siteUrl}.well-known/security.txt`,
      "Preferred-Languages: en",
      "",
    ].join("\n"),
  );
  // A custom domain needs a CNAME file at the root of what GitHub Pages serves.
  const host = new URL(siteUrl).host;
  if (!host.endsWith(".github.io")) writeFileSync(join(pub, "CNAME"), host + "\n");
  return written;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const arg = (flag) => {
    const i = process.argv.indexOf(flag);
    return i === -1 ? undefined : process.argv[i + 1];
  };
  const siteUrl = (arg("--site") ?? "https://tryhush.dev/").replace(/\/?$/, "/");
  // The branch the pages are read from, so "Edit page" opens a page that
  // exists: the beta branch has pages main does not have yet.
  const branch =
    arg("--branch") ??
    process.env.GITHUB_REF_NAME ??
    (() => {
      try {
        return execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], { cwd: root, encoding: "utf8" }).trim() || "main";
      } catch {
        return "main";
      }
    })();
  const site = join(root, "website");
  const written = buildContent(site, { branch, siteUrl });
  process.stdout.write(`${written.length} pages → website/src/content/docs (${siteUrl}, edit links on ${branch})\n`);
}
