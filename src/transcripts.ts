/**
 * Your secrets, word for word, in coding agents' saved conversations.
 *
 * Agents keep every session on disk — Claude Code under ~/.claude/projects,
 * Codex under ~/.codex/sessions, opencode in a SQLite file — and those files
 * hold whatever passed through the conversation: a key pasted into the chat, a
 * `cat .env`, a tool result that printed a token. This finds them. It only
 * reads: nothing here edits or deletes a conversation.
 *
 * Two searches share one pass over each file:
 *
 * - **Exact values** — hush's own values, and the plaintext ones in agents'
 *   config files. A rolling hash over 8-byte windows is checked against a bit
 *   filter of the values' first 8 bytes; only a filter hit is compared in
 *   full. A regex alternation of a few hundred random strings ran at 50 MB/s;
 *   this runs at several hundred, per core.
 * - **Key-shaped strings** — provider prefixes (`ghp_`, `sk-ant-`, `AKIA…`)
 *   for keys hush has never seen.
 *
 * Files are read in chunks with an overlap, so a value split across two reads
 * is still found, and counted once.
 */
import { closeSync, openSync, readdirSync, readSync, statSync } from "node:fs";
import { join, extname } from "node:path";
import { platform as osPlatform } from "node:os";
import { KEY_PREFIXES, KEY_SOURCE, boundedLeft, serviceOf } from "./agent-configs.ts";
import { CATALOG } from "./services.ts";

// ------------------------------------------------------------------ where

export interface TranscriptSource {
  agent: string;
  /** A folder (searched recursively) or a single file. */
  path: string;
  /** Inside a folder, only files whose name passes this. */
  include?: (name: string) => boolean;
  /** Folder names not to descend into. */
  skipDirs?: string[];
}

const home = (env: NodeJS.ProcessEnv): string => env.HOME ?? env.USERPROFILE ?? "~";
const appData = (env: NodeJS.ProcessEnv, plat: string, name: string): string =>
  plat === "darwin"
    ? join(home(env), "Library", "Application Support", name)
    : plat === "win32"
      ? join(env.APPDATA ?? join(home(env), "AppData", "Roaming"), name)
      : join(env.XDG_CONFIG_HOME || join(home(env), ".config"), name);

const TEXTISH = new Set([".jsonl", ".json", ".md", ".txt", ".log", ".sh", ".zsh", ".bash", ""]);
const textish = (name: string): boolean => TEXTISH.has(extname(name).toLowerCase());

/** Where each agent keeps its conversations. Read-only; a missing path is skipped. */
export function transcriptSources(env: NodeJS.ProcessEnv, plat: string = osPlatform()): TranscriptSource[] {
  const h = home(env);
  const share = env.XDG_DATA_HOME || join(h, ".local", "share");
  const code = appData(env, plat, "Code");
  return [
    { agent: "Claude Code", path: join(h, ".claude", "projects"), include: textish },
    { agent: "Claude Code", path: join(h, ".claude", "history.jsonl") },
    { agent: "Claude Code", path: join(h, ".claude", "shell-snapshots"), include: textish },
    { agent: "Codex", path: join(h, ".codex", "sessions"), include: textish },
    { agent: "Codex", path: join(h, ".codex", "history.jsonl") },
    { agent: "Gemini CLI", path: join(h, ".gemini", "tmp"), include: textish },
    // SQLite keeps text uncompressed in its pages, so a byte search reads it.
    { agent: "opencode", path: join(share, "opencode"), include: (n) => textish(n) || /\.db(-wal)?$/.test(n), skipDirs: ["snapshot", "bin", "repos"] },
    { agent: "Continue", path: join(h, ".continue", "sessions"), include: textish },
    { agent: "Cline", path: join(code, "User", "globalStorage", "saoudrizwan.claude-dev", "tasks"), include: textish },
    { agent: "Cursor", path: join(appData(env, plat, "Cursor"), "User"), include: (n) => n === "state.vscdb", skipDirs: ["History", "logs"] },
  ];
}

export interface TranscriptFile {
  agent: string;
  path: string;
  size: number;
  mtimeMs: number;
}

/** Every file the sources name, newest first. `since` drops files not modified after it. */
export function listTranscripts(sources: TranscriptSource[], since = 0): TranscriptFile[] {
  const out: TranscriptFile[] = [];
  const seen = new Set<string>();
  const add = (agent: string, path: string) => {
    if (seen.has(path)) return;
    try {
      const st = statSync(path);
      if (!st.isFile() || st.mtimeMs < since || st.size === 0) return;
      seen.add(path);
      out.push({ agent, path, size: st.size, mtimeMs: st.mtimeMs });
    } catch { /* gone or unreadable */ }
  };
  const walk = (src: TranscriptSource, dir: string, depth: number) => {
    if (depth > 12) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = join(dir, e.name);
      if (e.isDirectory()) {
        if (!src.skipDirs?.includes(e.name)) walk(src, p, depth + 1);
      } else if (e.isFile() && (!src.include || src.include(e.name))) add(src.agent, p);
    }
  };
  for (const src of sources) {
    let st;
    try {
      st = statSync(src.path);
    } catch {
      continue;
    }
    if (st.isDirectory()) walk(src, src.path, 0);
    else add(src.agent, src.path);
  }
  return out.sort((a, b) => b.mtimeMs - a.mtimeMs);
}

// ------------------------------------------------------------------ what

/** Below this a value matches too much ordinary text to mean anything. */
export const MIN_NEEDLE = 8;

/**
 * The byte strings to look for, for one value: as written, and as it appears
 * inside a JSON string (once and twice escaped — a tool result holding JSON,
 * saved inside a JSON line). Transcripts are JSON, so a value with a quote,
 * a backslash or a newline in it is never on disk the way it was typed.
 */
export function variants(value: string): string[] {
  const once = JSON.stringify(value).slice(1, -1);
  const twice = JSON.stringify(once).slice(1, -1);
  return [...new Set([value, once, twice])];
}

/**
 * Made-up keys in docs and tests: an alphabet or counting run, or a value
 * built from very few characters. A real key is none of these.
 */
export function looksMadeUp(token: string): boolean {
  const body = token.replace(/^[A-Za-z]+[-_]/, "");
  if (/abcdefg|bcdefgh|0123456|1234567|xxxxx|XXXXX|00000|aaaaa/i.test(body)) return true;
  return new Set(body).size < 10;
}

/** A person's name for the provider a key-shaped string belongs to. */
export function tokenService(token: string): string {
  const id = serviceOf(token);
  if (!id) return "unknown";
  return CATALOG[id]?.label ?? (id === "private key" ? "Private key" : id === "gitlab" ? "GitLab" : id);
}

// ------------------------------------------------------------------ how

const W = MIN_NEEDLE;
/**
 * The window hash is taken at every STEP-th byte, not every byte. Each value
 * registers its first STEP windows (offsets 0..STEP-1), so an occurrence
 * anywhere is seen at exactly one sampled position — found once, counted
 * once. That needs a value at least W + STEP - 1 bytes long; shorter ones
 * (rare: a credential is longer than ten characters) are searched for directly.
 */
const STEP = 4;
const SAMPLED_MIN = W + STEP - 1;
const FILTER_BITS = 1 << 22;
const FILTER_MASK = FILTER_BITS - 1;

function windowHash(b: Uint8Array, at: number): number {
  let h = 0;
  for (let i = 0; i < W; i++) h = (Math.imul(h, 31) + b[at + i]) | 0;
  return h;
}

export interface FileHits {
  /** Needle index → occurrences. */
  needles: Map<number, number>;
  /** Key-shaped string → occurrences, made-up ones left out. */
  tokens: Map<string, number>;
}

export class Matcher {
  private readonly filter = new Uint8Array(FILTER_BITS >> 3);
  /** Window hash → [needle index, offset of that window in the needle]. */
  private readonly byHash = new Map<number, [number, number][]>();
  /** Needles too short to sample, searched for with indexOf. */
  private readonly short: number[] = [];
  private readonly maxLen: number;
  private readonly needles: Buffer[];
  /** Any key prefix, so the full formats are only tried where one starts. */
  private readonly prefix = new RegExp(KEY_PREFIXES.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"), "g");
  private readonly key = new RegExp(KEY_SOURCE, "y");

  constructor(needles: Buffer[]) {
    this.needles = needles;
    needles.forEach((n, i) => {
      if (n.length < W) throw new Error(`a needle shorter than ${W} bytes`);
      if (n.length < SAMPLED_MIN) {
        this.short.push(i);
        return;
      }
      for (let off = 0; off < STEP; off++) {
        const h = windowHash(n, off);
        const k = h & FILTER_MASK;
        this.filter[k >> 3] |= 1 << (k & 7);
        const list = this.byHash.get(h);
        if (list) list.push([i, off]);
        else this.byHash.set(h, [[i, off]]);
      }
    });
    // Key-shaped strings are well under 300 bytes; the overlap must cover both.
    this.maxLen = Math.max(300, ...needles.map((n) => n.length));
  }

  /**
   * Scan one file, or the byte range [start, end) of it, in chunks. A range
   * starts reading `overlap` bytes early, so a value straddling its start is
   * found — and counted here only if it ends inside the range, which is the
   * same rule chunks use, so splitting a file never counts anything twice.
   */
  scanFile(path: string, chunkSize = 8 << 20, start = 0, end = Number.POSITIVE_INFINITY): FileHits {
    const hits: FileHits = { needles: new Map(), tokens: new Map() };
    const overlap = this.maxLen - 1;
    const buf = Buffer.alloc(chunkSize + overlap);
    let fd: number;
    let size: number;
    try {
      fd = openSync(path, "r");
      size = statSync(path).size;
    } catch {
      return hits;
    }
    try {
      const stop = Math.min(end, size);
      let pos = Math.max(0, start - overlap);
      // The first read carries the lead-in before `start` as already-seen bytes.
      let fresh = start - pos;
      let carry = 0;
      // A key-shaped string ending exactly where a range begins was left for
      // this range by the one before it.
      let deferred = start > 0;
      while (pos < stop) {
        const n = readSync(fd, buf, carry, Math.min(chunkSize, stop - pos), pos);
        if (n <= 0) break;
        pos += n;
        const len = carry + n;
        deferred = this.scanBuffer(buf, len, fresh, hits, pos >= size, deferred);
        // Keep the tail: a value straddling the boundary is completed next time.
        const keep = Math.min(overlap, len);
        buf.copy(buf, 0, len - keep, len);
        carry = keep;
        fresh = keep;
      }
    } finally {
      closeSync(fd);
    }
    return hits;
  }

  /**
   * Scan `len` bytes of `buf`. `fresh` is where the bytes not seen in the
   * previous chunk begin: a match that ends at or before it was counted then,
   * so only matches ending after it count now. A key-shaped string that runs
   * to the end of a chunk might continue into the next, so it is left for the
   * next chunk (`final` false) — which then also accepts one ending exactly
   * at `fresh` (`deferred`). Returns whether it deferred one.
   */
  scanBuffer(buf: Buffer, len: number, fresh: number, hits: FileHits, final = true, deferred = false): boolean {
    const needles = this.needles;
    const count = (idx: number, start: number) => {
      const n = needles[idx];
      const end = start + n.length;
      if (start < 0 || end > len || end <= fresh) return;
      if (buf.compare(n, 0, n.length, start, end) === 0) hits.needles.set(idx, (hits.needles.get(idx) ?? 0) + 1);
    };
    if (this.byHash.size) {
      const filter = this.filter;
      for (let p = 0; p + W <= len; p += STEP) {
        let h = 0;
        for (let i = 0; i < W; i++) h = (Math.imul(h, 31) + buf[p + i]) | 0;
        const k = h & FILTER_MASK;
        if ((filter[k >> 3] & (1 << (k & 7))) === 0) continue;
        const list = this.byHash.get(h);
        if (list) for (const [idx, off] of list) count(idx, p - off);
      }
    }
    for (const idx of this.short) {
      for (let at = buf.indexOf(needles[idx], 0); at !== -1 && at < len; at = buf.indexOf(needles[idx], at + 1)) count(idx, at);
    }

    const text = buf.toString("latin1", 0, len);
    const prefix = this.prefix;
    const key = this.key;
    prefix.lastIndex = 0;
    let deferNext = false;
    let lastEnd = -1;
    let m: RegExpExecArray | null;
    while ((m = prefix.exec(text))) {
      if (m.index < lastEnd) continue;
      key.lastIndex = m.index;
      const k = key.exec(text);
      if (!k) continue;
      const end = k.index + k[0].length;
      prefix.lastIndex = end;
      lastEnd = end;
      if (end < fresh || (end === fresh && !deferred)) continue;
      // A key that runs to the end of the chunk might continue into the next.
      if (end === len && !final) {
        deferNext = true;
        continue;
      }
      if (!boundedLeft(text, k.index) || looksMadeUp(k[0])) continue;
      hits.tokens.set(k[0], (hits.tokens.get(k[0]) ?? 0) + 1);
    }
    return deferNext;
  }
}

// ------------------------------------------------------------------ in parallel

/**
 * Scan every file, across `threads` worker threads. A worker that cannot start
 * (the single-file binary has no separate worker file to load) is not an
 * error: whatever it would have scanned is scanned here instead.
 */
/** Files larger than this are split, so one huge session does not keep a single thread busy. */
export const SEGMENT_BYTES = 256 << 20;

interface WorkItem {
  path: string;
  start: number;
  end: number;
}

function mergeHits(into: FileHits, from: FileHits): void {
  for (const [k, n] of from.needles) into.needles.set(k, (into.needles.get(k) ?? 0) + n);
  for (const [k, n] of from.tokens) into.tokens.set(k, (into.tokens.get(k) ?? 0) + n);
}

export async function scanTranscripts(
  files: TranscriptFile[],
  needles: Buffer[],
  opts: { threads: number; onProgress?: (bytesDone: number) => void; segmentBytes?: number },
): Promise<Map<string, FileHits>> {
  const segment = opts.segmentBytes ?? SEGMENT_BYTES;
  const results = new Map<string, FileHits>();
  const queue: WorkItem[] = [];
  for (const f of [...files].sort((a, b) => b.size - a.size)) {
    for (let start = 0; start < f.size; start += segment) queue.push({ path: f.path, start, end: Math.min(f.size, start + segment) });
  }
  let done = 0;
  const finished = (item: WorkItem, hits: FileHits) => {
    const have = results.get(item.path);
    if (have) mergeHits(have, hits);
    else results.set(item.path, hits);
    done += item.end - item.start;
    opts.onProgress?.(done);
  };

  const inProcess = () => {
    const m = new Matcher(needles);
    for (let it = queue.shift(); it !== undefined; it = queue.shift()) finished(it, m.scanFile(it.path, undefined, it.start, it.end));
  };
  if (opts.threads <= 1 || queue.length < 2) {
    inProcess();
    return results;
  }

  const { Worker } = await import("node:worker_threads");
  const { fileURLToPath } = await import("node:url");
  const here = fileURLToPath(import.meta.url);
  const workerUrl = new URL(`./transcript-worker${extname(here)}`, import.meta.url);
  const shared = needles.map((n) => new Uint8Array(n));

  /**
   * One worker, fed from the shared queue. A worker that cannot start (the
   * single-file binary has no separate worker file to load) or that dies hands
   * its item back, and the main thread finishes whatever is left.
   */
  const one = () =>
    new Promise<void>((resolve) => {
      let current: WorkItem | undefined;
      let w: InstanceType<typeof Worker>;
      try {
        w = new Worker(workerUrl, { workerData: { needles: shared } });
      } catch {
        return resolve();
      }
      const next = () => {
        current = queue.shift();
        w.postMessage(current ?? null);
        if (current === undefined) resolve();
      };
      w.on("message", (msg: { ready?: true; needles?: [number, number][]; tokens?: [string, number][] }) => {
        if (current && msg.needles) {
          finished(current, { needles: new Map(msg.needles), tokens: new Map(msg.tokens) });
          current = undefined;
        }
        next();
      });
      w.on("error", () => {
        if (current !== undefined) queue.unshift(current);
        current = undefined;
        resolve();
      });
      w.on("exit", () => resolve());
    });

  await Promise.all(Array.from({ length: Math.min(opts.threads, queue.length) }, one));
  inProcess();
  return results;
}
