/**
 * Writing hush's grants into a tailnet policy file, without touching anything
 * else in it.
 *
 * The policy file is HuJSON — JSON with comments and trailing commas — and
 * people keep notes in theirs. So it is never parsed and re-serialised: a
 * small scanner finds where the top-level object and its `grants` array sit,
 * and a grant is inserted, or removed, as text at those positions. Every
 * other byte stays as it was.
 *
 * Each grant hush writes carries its id inside the capability value
 * (`"grant": "hush-3f9a…"`), so it can be found again even if the comment
 * above it is edited away, and `revoke` removes exactly those and nothing else.
 */
import { randomBytes } from "node:crypto";
import { stripJsonc } from "./agents.ts";
import { HUSH_CAP } from "./broker.ts";

interface Span {
  start: number;
  end: number;
}

/** A just-enough HuJSON scanner: values with their positions, comments and trailing commas allowed. */
class Scanner {
  pos = 0;
  private readonly t: string;
  constructor(t: string) {
    this.t = t;
  }

  ws(): void {
    for (;;) {
      const c = this.t[this.pos];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") this.pos++;
      else if (c === "/" && this.t[this.pos + 1] === "/") {
        while (this.pos < this.t.length && this.t[this.pos] !== "\n") this.pos++;
      } else if (c === "/" && this.t[this.pos + 1] === "*") {
        const end = this.t.indexOf("*/", this.pos + 2);
        if (end === -1) throw new Error("unterminated comment in the policy file");
        this.pos = end + 2;
      } else return;
    }
  }

  string(): string {
    const start = this.pos;
    if (this.t[this.pos] !== '"') throw new Error(`expected a string at ${start}`);
    this.pos++;
    while (this.pos < this.t.length && this.t[this.pos] !== '"') this.pos += this.t[this.pos] === "\\" ? 2 : 1;
    if (this.pos >= this.t.length) throw new Error("unterminated string in the policy file");
    this.pos++;
    return JSON.parse(this.t.slice(start, this.pos)) as string;
  }

  value(): Span {
    this.ws();
    const start = this.pos;
    const c = this.t[this.pos];
    if (c === "{") this.object();
    else if (c === "[") this.array();
    else if (c === '"') this.string();
    else {
      const m = /^(-?\d[\d.eE+-]*|true|false|null)/.exec(this.t.slice(this.pos, this.pos + 64));
      if (!m) throw new Error(`unexpected "${c ?? "end of file"}" at ${this.pos} in the policy file`);
      this.pos += m[0].length;
    }
    return { start, end: this.pos };
  }

  object(): { key: string; value: Span }[] {
    const out: { key: string; value: Span }[] = [];
    this.pos++; // {
    for (;;) {
      this.ws();
      if (this.t[this.pos] === "}") {
        this.pos++;
        return out;
      }
      const key = this.string();
      this.ws();
      if (this.t[this.pos] !== ":") throw new Error(`expected ":" after "${key}" in the policy file`);
      this.pos++;
      out.push({ key, value: this.value() });
      this.ws();
      if (this.t[this.pos] === ",") this.pos++;
      else if (this.t[this.pos] !== "}") throw new Error(`expected "," or "}" at ${this.pos} in the policy file`);
    }
  }

  array(): Span[] {
    const out: Span[] = [];
    this.pos++; // [
    for (;;) {
      this.ws();
      if (this.t[this.pos] === "]") {
        this.pos++;
        return out;
      }
      out.push(this.value());
      this.ws();
      if (this.t[this.pos] === ",") this.pos++;
      else if (this.t[this.pos] !== "]") throw new Error(`expected "," or "]" at ${this.pos} in the policy file`);
    }
  }
}

interface Layout {
  /** Position of the top-level `{`. */
  open: number;
  grants: { open: number; close: number; elements: Span[] } | null;
}

function layout(text: string): Layout {
  const s = new Scanner(text);
  s.ws();
  if (text[s.pos] !== "{") throw new Error("the policy file is not an object");
  const open = s.pos;
  const keys = s.object();
  s.ws();
  if (s.pos !== text.length) throw new Error("unexpected text after the policy file's closing brace");
  const g = keys.find((k) => k.key === "grants");
  if (!g) return { open, grants: null };
  if (text[g.value.start] !== "[") throw new Error('"grants" in the policy file is not a list');
  const inner = new Scanner(text);
  inner.pos = g.value.start;
  const elements = inner.array();
  return { open, grants: { open: g.value.start, close: g.value.end - 1, elements } };
}

// ------------------------------------------------------------------ grants

export interface HushGrant {
  id: string;
  src: string[];
  dst: string[];
  port: number;
  sets: string[];
}

/** Who may appear in `src`: a login, a group, a tag, or an autogroup. */
export function validPrincipal(p: string): boolean {
  return /^[^\s@",]+@[^\s@",]+$/.test(p) || /^(group|tag|autogroup):[a-z0-9][a-z0-9._-]*$/i.test(p);
}

/** Where the broker is: its tailnet IP, a tag, or a host alias from the policy's "hosts". */
export function validDestination(d: string): boolean {
  const ip = /^100\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(d);
  // Tailscale's own range, 100.64.0.0/10: any other address is not a tailnet device.
  if (ip) return Number(ip[1]) >= 64 && Number(ip[1]) <= 127 && Number(ip[2]) <= 255 && Number(ip[3]) <= 255;
  // A host alias is a name, so it starts with a letter: "8.8.8.8" is not one.
  return /^tag:[a-z0-9][a-z0-9._-]*$/i.test(d) || /^[a-z][a-z0-9_-]*$/i.test(d);
}

export function newGrantId(): string {
  return `hush-${randomBytes(4).toString("hex")}`;
}

/**
 * The grant itself: the connection to the broker's port (`ip`), and the hush
 * capability naming the sets (`app`). Both, because a capability alone does
 * not open the port on a tailnet that does not already allow it.
 */
export function grantObject(g: HushGrant): Record<string, unknown> {
  return {
    src: g.src,
    dst: g.dst,
    ip: [`tcp:${g.port}`],
    app: { [HUSH_CAP]: [{ sets: g.sets, grant: g.id }] },
  };
}

function render(g: HushGrant, indent: string): string {
  // One short line per field: a grant is read in the admin console and in a
  // diff, and JSON.stringify's one-item-per-line arrays made both noisy.
  const o = grantObject(g);
  const j = (v: unknown) => JSON.stringify(v).replace(/,"/g, ', "').replace(/":/g, '": ');
  return [
    `${indent}// hush: ${g.src.join(", ")} may use ${g.sets.join(", ")} on the broker (${g.id})`,
    `${indent}{`,
    `${indent}\t"src": ${j(o.src)},`,
    `${indent}\t"dst": ${j(o.dst)},`,
    `${indent}\t"ip":  ${j(o.ip)},`,
    `${indent}\t"app": ${j(o.app)},`,
    `${indent}},`,
  ].join("\n");
}

/** A grant as a person pastes it into the admin console, when hush cannot write it. */
export function grantSnippet(g: HushGrant): string {
  return render(g, "");
}

/** The grants hush wrote, read back from a policy file. */
export function hushGrants(text: string): (HushGrant & Span)[] {
  const l = layout(text);
  if (!l.grants) return [];
  const out: (HushGrant & Span)[] = [];
  for (const el of l.grants.elements) {
    let g: { src?: unknown; dst?: unknown; ip?: unknown; app?: Record<string, unknown> };
    try {
      g = JSON.parse(stripJsonc(text.slice(el.start, el.end)));
    } catch {
      continue;
    }
    const caps = g?.app?.[HUSH_CAP];
    if (!Array.isArray(caps)) continue;
    const mine = caps.find((c) => c && typeof (c as { grant?: unknown }).grant === "string" && /^hush-[0-9a-f]{8}$/.test((c as { grant: string }).grant));
    if (!mine) continue;
    const port = Array.isArray(g.ip) ? Number(String(g.ip[0] ?? "").replace(/^tcp:/, "")) : 0;
    out.push({
      id: (mine as { grant: string }).grant,
      src: Array.isArray(g.src) ? g.src.map(String) : [],
      dst: Array.isArray(g.dst) ? g.dst.map(String) : [],
      port: Number.isInteger(port) ? port : 0,
      sets: Array.isArray((mine as { sets?: unknown }).sets) ? ((mine as { sets: unknown[] }).sets).map(String) : [],
      start: el.start,
      end: el.end,
    });
  }
  return out;
}

/** Make sure an edit left a file that still reads as a policy, and says what was expected. */
function checked(text: string, expect: (grants: HushGrant[]) => boolean): string {
  try {
    JSON.parse(stripJsonc(text));
  } catch (e) {
    throw new Error(`hush would have left the policy file unreadable (${(e as Error).message}), so nothing was changed`);
  }
  if (!expect(hushGrants(text))) throw new Error("hush could not place its grant in the policy file, so nothing was changed");
  return text;
}

/** Insert one grant, at the top of `grants` (made if missing). Everything else is left byte for byte. */
export function insertGrant(text: string, g: HushGrant): string {
  const l = layout(text);
  if (l.grants) {
    const at = l.grants.open + 1;
    const out = `${text.slice(0, at)}\n${render(g, "\t\t")}${text.slice(at)}`;
    return checked(out, (gs) => gs.some((x) => x.id === g.id));
  }
  const at = l.open + 1;
  const out = `${text.slice(0, at)}\n\t"grants": [\n${render(g, "\t\t")}\n\t],${text.slice(at)}`;
  return checked(out, (gs) => gs.some((x) => x.id === g.id));
}

/** Remove one grant hush wrote, with its comment line and its comma. */
export function removeGrant(text: string, id: string): string {
  const target = hushGrants(text).find((g) => g.id === id);
  if (!target) throw new Error(`no grant ${id} in the policy file`);
  let start = target.start;
  let end = target.end;
  // Its trailing comma, if any.
  const after = /^[ \t]*,/.exec(text.slice(end));
  if (after) end += after[0].length;
  // Back to the start of its line, and over the "// hush:" line above it.
  const lineStart = text.lastIndexOf("\n", start - 1) + 1;
  if (/^[ \t]*$/.test(text.slice(lineStart, start))) start = lineStart;
  const prev = text.lastIndexOf("\n", start - 2) + 1;
  if (start > 0 && /^[ \t]*\/\/ hush: /.test(text.slice(prev, start))) start = prev;
  // The newline that ended the removed block.
  if (text[end] === "\n") end++;
  const out = text.slice(0, start) + text.slice(end);
  return checked(out, (gs) => !gs.some((x) => x.id === id));
}

/** The lines that changed, with a little context, for a person to read before applying. */
export function lineDiff(before: string, after: string, context = 2): string {
  const a = before.split("\n");
  const b = after.split("\n");
  let head = 0;
  while (head < a.length && head < b.length && a[head] === b[head]) head++;
  let tail = 0;
  while (tail < a.length - head && tail < b.length - head && a[a.length - 1 - tail] === b[b.length - 1 - tail]) tail++;
  const out: string[] = [];
  for (let i = Math.max(0, head - context); i < head; i++) out.push(`  ${a[i]}`);
  for (let i = head; i < a.length - tail; i++) out.push(`- ${a[i]}`);
  for (let i = head; i < b.length - tail; i++) out.push(`+ ${b[i]}`);
  for (let i = a.length - tail; i < Math.min(a.length, a.length - tail + context); i++) out.push(`  ${a[i]}`);
  return out.join("\n");
}
