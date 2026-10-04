#!/usr/bin/env node
/**
 * Checks the built docs site (website/dist) before it is deployed:
 *
 *   - every link and image within the site lands on a file that was built,
 *     and every #anchor on an id that page has;
 *   - every script is the site's own: nothing is loaded from another host.
 *
 *   node scripts/check-site.mjs website/dist
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, posix, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

export function checkSite(dist) {
  const problems = [];
  const pages = readdirSync(dist, { recursive: true })
    .map((f) => String(f).split(sep).join("/"))
    .filter((f) => f.endsWith(".html"));
  const ids = new Map();
  const idsOf = (file) => {
    if (!ids.has(file)) ids.set(file, new Set([...readFileSync(join(dist, file), "utf8").matchAll(/\sid="([^"]+)"/g)].map((m) => m[1])));
    return ids.get(file);
  };
  // A URL path to the file that serves it: /guide/sets/ is guide/sets/index.html.
  const fileFor = (path) => {
    const p = decodeURI(path).replace(/^\//, "");
    if (p === "" || p.endsWith("/")) return p + "index.html";
    if (existsSync(join(dist, p)) && statSync(join(dist, p)).isDirectory()) return p + "/index.html";
    return p;
  };
  let links = 0;
  for (const page of pages) {
    const html = readFileSync(join(dist, page), "utf8");
    for (const [, src] of html.matchAll(/<script[^>]*\ssrc="([^"]+)"/g)) {
      if (/^(https?:)?\/\//i.test(src)) problems.push(`${page}: loads a script from ${src}`);
    }
    for (const [, attr, url] of html.matchAll(/\s(href|src)="([^"]*)"/g)) {
      if (!url || /^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith("//")) continue;
      const at = url.indexOf("#");
      const path = (at === -1 ? url : url.slice(0, at)).split("?")[0];
      const frag = at === -1 ? "" : decodeURIComponent(url.slice(at + 1));
      const target = path === "" ? page : path.startsWith("/") ? fileFor(path) : fileFor("/" + posix.join(posix.dirname(page), path) + (path.endsWith("/") ? "/" : ""));
      if (!existsSync(join(dist, target))) {
        problems.push(`${page}: ${attr} ${url} — nothing was built there`);
        continue;
      }
      // "#_top" is Starlight's "back to the top"; the browser handles it.
      if (frag && frag !== "_top" && target.endsWith(".html") && !idsOf(target).has(frag)) problems.push(`${page}: ${url} — no such anchor`);
      links++;
    }
  }
  return { pages: pages.length, links, problems };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const dist = process.argv[2] ?? "website/dist";
  const { pages, links, problems } = checkSite(dist);
  for (const p of problems) process.stderr.write(p + "\n");
  process.stdout.write(`${pages} pages, ${links} links checked in ${relative(process.cwd(), dist) || "."}: ${problems.length ? `${problems.length} problem(s)` : "all good"}\n`);
  process.exit(problems.length ? 1 : 0);
}
