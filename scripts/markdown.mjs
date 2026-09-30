/**
 * Markdown to HTML for the docs site (scripts/build-docs.mjs), with no
 * dependencies, like the rest of hush. It covers what hush's own docs use —
 * GitHub-flavoured headings, fenced code, tables, nested lists, blockquotes
 * and GitHub's [!NOTE]-style alerts, a few HTML blocks, and the usual inline
 * forms — and nothing more. test/docs-site.test.ts pins each one.
 *
 * Everything is escaped unless it is one of the HTML blocks the README uses
 * for its header (p, picture, source, img, details, summary, br, kbd): a
 * <script> in a doc comes out as text.
 */

const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** GitHub's heading anchor: lowercase, punctuation dropped, spaces to hyphens. */
export const slugify = (text) =>
  text
    .replace(/<[^>]+>/g, "")
    .replace(/`/g, "")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}_\s-]/gu, "")
    .trim()
    .replace(/\s/g, "-");

const HTML_BLOCK = /^\s*<\/?(p|picture|source|img|details|summary|div|br|h[1-6])\b[^>]*>/i;
const INLINE_TAGS = /^<\/?(br|kbd|sup|sub|b|i|em|strong|code)\s*\/?>/i;
const ALERTS = { NOTE: "Note", TIP: "Tip", IMPORTANT: "Important", WARNING: "Warning", CAUTION: "Caution" };

// ------------------------------------------------------------------ inline

export function inline(text, opts = {}) {
  const link = opts.link ?? ((href) => href);
  let out = "";
  let i = 0;
  const rest = () => text.slice(i);
  while (i < text.length) {
    const r = rest();
    let m;
    if ((m = /^(`+)([\s\S]*?[^`])\1(?!`)/.exec(r))) {
      out += `<code>${esc(m[2].trim() === "" ? m[2] : m[2].replace(/^ (.*) $/s, "$1"))}</code>`;
      i += m[0].length;
    } else if (r[0] === "\\" && /^\\[\\`*_{}\[\]()#+\-.!|<>~]/.test(r)) {
      out += esc(r[1]);
      i += 2;
    } else if ((m = /^!\[([^\]]*)\]\(([^)\s]+)(?:\s+"([^"]*)")?\)/.exec(r))) {
      out += `<img src="${esc(link(m[2]))}" alt="${esc(m[1])}"${m[3] ? ` title="${esc(m[3])}"` : ""}>`;
      i += m[0].length;
    } else if ((m = matchLink(r))) {
      out += `<a href="${esc(link(m.href))}">${inline(m.label, opts)}</a>`;
      i += m.length;
    } else if ((m = /^<(https?:\/\/[^>\s]+)>/.exec(r))) {
      out += `<a href="${esc(m[1])}">${esc(m[1])}</a>`;
      i += m[0].length;
    } else if ((m = INLINE_TAGS.exec(r))) {
      out += m[0].toLowerCase().replace(/\s+/g, "");
      i += m[0].length;
    } else if ((m = /^(\*\*|__)(?=\S)([\s\S]*?\S)\1/.exec(r)) && (m[1] === "**" || boundary(text, i, m[0].length))) {
      out += `<strong>${inline(m[2], opts)}</strong>`;
      i += m[0].length;
    } else if ((m = /^~~(?=\S)([\s\S]*?\S)~~/.exec(r))) {
      out += `<del>${inline(m[1], opts)}</del>`;
      i += m[0].length;
    } else if ((m = /^([*_])(?=\S)([\s\S]*?[^\s*_])\1(?![*_])/.exec(r)) && (m[1] === "*" || boundary(text, i, m[0].length))) {
      out += `<em>${inline(m[2], opts)}</em>`;
      i += m[0].length;
    } else {
      out += esc(r[0]);
      i += 1;
    }
  }
  return out;
}

/** `_` emphasis only at word boundaries, so snake_case_names stay as they are. */
function boundary(text, start, len) {
  const before = text[start - 1] ?? " ";
  const after = text[start + len] ?? " ";
  return !/[\p{L}\p{N}]/u.test(before) && !/[\p{L}\p{N}]/u.test(after);
}

/** [label](href) with brackets balanced inside the label. */
function matchLink(r) {
  if (r[0] !== "[") return null;
  let depth = 0;
  let j = 0;
  for (; j < r.length; j++) {
    if (r[j] === "`") {
      const close = r.indexOf("`", j + 1);
      if (close > 0) j = close;
      continue;
    }
    if (r[j] === "[") depth++;
    else if (r[j] === "]" && --depth === 0) break;
  }
  if (depth !== 0 || r[j + 1] !== "(") return null;
  const m = /^\(([^)\s]+)(?:\s+"[^"]*")?\)/.exec(r.slice(j + 1));
  if (!m) return null;
  return { label: r.slice(1, j), href: m[1], length: j + 1 + m[0].length };
}

// ------------------------------------------------------------------ blocks

const isBlank = (l) => /^\s*$/.test(l);
const LIST_ITEM = /^(\s*)([-*+]|\d{1,9}[.)])(\s+)(.*)$/;
const FENCE = /^(\s*)(`{3,}|~{3,})\s*([\w+-]*)/;

/**
 * Render a document. `opts.link(href)` rewrites link targets; `opts.ids`
 * collects heading ids (deduplicated the way GitHub does it).
 */
export function render(md, opts = {}) {
  const ids = opts.ids ?? new Map();
  return blocks(md.replace(/\r\n?/g, "\n").split("\n"), { ...opts, ids });
}

function blocks(lines, opts) {
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (isBlank(line)) {
      i++;
      continue;
    }
    let m;
    // fenced code
    if ((m = FENCE.exec(line))) {
      const [, indent, fence, lang] = m;
      const body = [];
      i++;
      while (i < lines.length && !new RegExp(`^\\s*${fence[0]}{${fence.length},}\\s*$`).test(lines[i])) {
        body.push(lines[i].startsWith(indent) ? lines[i].slice(indent.length) : lines[i].trimStart());
        i++;
      }
      i++;
      out.push(`<pre><code${lang ? ` class="language-${esc(lang)}"` : ""}>${esc(body.join("\n"))}</code></pre>`);
      continue;
    }
    // heading
    if ((m = /^(#{1,6})\s+(.*?)\s*#*\s*$/.exec(line))) {
      const level = m[1].length;
      const base = slugify(m[2]);
      const n = opts.ids.get(base) ?? 0;
      opts.ids.set(base, n + 1);
      const id = n ? `${base}-${n}` : base;
      out.push(`<h${level} id="${esc(id)}"><a class="anchor" href="#${esc(id)}" aria-hidden="true">#</a>${inline(m[2], opts)}</h${level}>`);
      i++;
      continue;
    }
    // rule
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) {
      out.push("<hr>");
      i++;
      continue;
    }
    // An HTML comment is a note to editors, not part of the page.
    if (/^\s*<!--/.test(line)) {
      while (i < lines.length && !lines[i].includes("-->")) i++;
      i++;
      continue;
    }
    // HTML block: passed through to the next blank line
    if (HTML_BLOCK.test(line)) {
      const body = [];
      while (i < lines.length && !isBlank(lines[i])) body.push(lines[i++]);
      out.push(body.join("\n"));
      continue;
    }
    // blockquote, and GitHub alerts
    if (/^\s*>/.test(line)) {
      const body = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) body.push(lines[i++].replace(/^\s*> ?/, ""));
      const alert = /^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*$/.exec(body[0] ?? "");
      if (alert) {
        out.push(
          `<div class="alert alert-${alert[1].toLowerCase()}"><p class="alert-title">${ALERTS[alert[1]]}</p>${blocks(body.slice(1), opts)}</div>`,
        );
      } else out.push(`<blockquote>${blocks(body, opts)}</blockquote>`);
      continue;
    }
    // table
    if (line.includes("|") && i + 1 < lines.length && /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/.test(lines[i + 1])) {
      const head = cells(line);
      const align = cells(lines[i + 1]).map((c) => (/^:-+:$/.test(c) ? "center" : /-+:$/.test(c) ? "right" : /^:-+/.test(c) ? "left" : ""));
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].includes("|") && !isBlank(lines[i])) rows.push(cells(lines[i++]));
      const td = (tag, c, k) => `<${tag}${align[k] ? ` style="text-align:${align[k]}"` : ""}>${inline(c, opts)}</${tag}>`;
      out.push(
        `<div class="table"><table><thead><tr>${head.map((c, k) => td("th", c, k)).join("")}</tr></thead><tbody>` +
          rows.map((r) => `<tr>${head.map((_, k) => td("td", r[k] ?? "", k)).join("")}</tr>`).join("") +
          `</tbody></table></div>`,
      );
      continue;
    }
    // list
    if ((m = LIST_ITEM.exec(line))) {
      const [html, next] = list(lines, i, opts);
      out.push(html);
      i = next;
      continue;
    }
    // paragraph
    const para = [];
    while (
      i < lines.length &&
      !isBlank(lines[i]) &&
      !FENCE.test(lines[i]) &&
      !/^#{1,6}\s/.test(lines[i]) &&
      !/^\s*>/.test(lines[i]) &&
      !(para.length && LIST_ITEM.test(lines[i]) && !/^\s{4,}/.test(lines[i])) &&
      !(para.length && HTML_BLOCK.test(lines[i]))
    ) {
      para.push(lines[i++].trim());
    }
    out.push(`<p>${inline(para.join("\n"), opts).replace(/ {2,}\n/g, "<br>\n")}</p>`);
  }
  return out.join("\n");
}

function cells(line) {
  let s = line.trim();
  if (s.startsWith("|")) s = s.slice(1);
  if (s.endsWith("|") && !s.endsWith("\\|")) s = s.slice(0, -1);
  const out = [];
  let cur = "";
  let code = false;
  for (let k = 0; k < s.length; k++) {
    const ch = s[k];
    if (ch === "`") code = !code;
    if (ch === "\\" && s[k + 1] === "|") {
      cur += "|";
      k++;
      continue;
    }
    if (ch === "|" && !code) {
      out.push(cur.trim());
      cur = "";
    } else cur += ch;
  }
  out.push(cur.trim());
  return out;
}

function list(lines, start, opts) {
  const first = LIST_ITEM.exec(lines[start]);
  const baseIndent = first[1].length;
  const ordered = /\d/.test(first[2]);
  const startNum = ordered ? parseInt(first[2], 10) : 1;
  const items = [];
  let loose = false;
  let i = start;
  while (i < lines.length) {
    const m = LIST_ITEM.exec(lines[i]);
    if (!m || m[1].length !== baseIndent || /\d/.test(m[2]) !== ordered) break;
    const contentIndent = m[1].length + m[2].length + m[3].length;
    const body = [m[4]];
    i++;
    let sawBlank = false;
    while (i < lines.length) {
      const l = lines[i];
      if (isBlank(l)) {
        sawBlank = true;
        body.push("");
        i++;
        continue;
      }
      const indent = l.length - l.trimStart().length;
      const sibling = LIST_ITEM.exec(l);
      if (sibling && sibling[1].length <= baseIndent) break;
      if (indent >= Math.min(contentIndent, baseIndent + 2)) {
        body.push(l.slice(Math.min(indent, contentIndent)));
        i++;
        continue;
      }
      if (sawBlank) break;
      body.push(l.trim()); // lazy continuation
      i++;
    }
    while (body.length && body[body.length - 1] === "") body.pop();
    if (body.includes("")) loose = true;
    items.push(body);
    // A blank line *between two items of this list* makes it loose; one after
    // the list's last item is just the end of the list.
    const next = i < lines.length ? LIST_ITEM.exec(lines[i]) : null;
    if (next && next[1].length === baseIndent && /\d/.test(next[2]) === ordered && isBlank(lines[i - 1])) loose = true;
  }
  const tag = ordered ? "ol" : "ul";
  const html = items
    .map((body) => {
      const task = /^\[([ xX])\]\s+/.exec(body[0]);
      if (task) body = [body[0].slice(task[0].length), ...body.slice(1)];
      let inner = blocks(body, opts);
      if (!loose) inner = inner.replace(/^<p>([\s\S]*?)<\/p>/, "$1");
      const box = task ? `<input type="checkbox" disabled${task[1] !== " " ? " checked" : ""}> ` : "";
      return `<li>${box}${inner}</li>`;
    })
    .join("\n");
  return [`<${tag}${ordered && startNum !== 1 ? ` start="${startNum}"` : ""}>\n${html}\n</${tag}>`, i];
}
