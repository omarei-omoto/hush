/**
 * The local audit log: `.hush/audit.log`, one JSON object per line.
 *
 * Never committed — it records what *you* did on this machine — and never a
 * value, only names, counts and decisions.
 *
 * **Chained (S-3).** Each line carries `prev`, the SHA-256 of the line before
 * it, and the first line of a file carries a random `salt` with `prev` =
 * SHA-256("hush/audit/start|" + salt). Changing, removing, inserting or
 * reordering a line breaks the chain at the next line, and `hush audit verify`
 * names where.
 *
 * What this does not do, said plainly in SECURITY.md too: anything running as
 * you can rewrite the whole file and recompute every hash, or cut lines off
 * the end. The chain makes an edit *visible*, not impossible. A log nobody on
 * the machine can rewrite has to live somewhere else.
 */
import {
  existsSync, mkdirSync, statSync, renameSync, openSync, readSync, closeSync, writeSync,
  readFileSync, unlinkSync,
} from "node:fs";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { openNoFollow } from "./platform.ts";

/** Rotate at this size so a long-lived machine cannot fill the disk. */
const AUDIT_MAX_BYTES = 2 * 1024 * 1024;

/**
 * Generations kept besides the live file: audit.log.1 (newest) to .5. One
 * used to be the whole history, so anything able to write enough lines — a
 * tailnet peer, through the broker — could push every earlier line off the
 * end, and the fresh file looked like an ordinary start.
 */
const AUDIT_GENERATIONS = 5;

/**
 * Longest string an audit field keeps, and most items in a list. Values come
 * from callers that include remote peers (a tool name, a caller's label), so
 * one line must not be able to stand for megabytes.
 */
const FIELD_MAX_CHARS = 300;
const FIELD_MAX_ITEMS = 64;

const capField = (v: unknown): unknown =>
  typeof v === "string"
    ? v.length > FIELD_MAX_CHARS ? v.slice(0, FIELD_MAX_CHARS) + "\u2026" : v
    : Array.isArray(v)
      ? v.slice(0, FIELD_MAX_ITEMS).map(capField)
      : v;

const START = "hush/audit/start|";

export const lineHash = (line: string): string => createHash("sha256").update(line, "utf8").digest("hex");

export const auditPath = (hushDir: string): string => join(hushDir, "audit.log");

/** The last complete line of a file, read from the end rather than whole. */
function lastLine(path: string): string | null {
  let fd: number | undefined;
  try {
    fd = openSync(path, "r");
    const size = statSync(path).size;
    if (!size) return null;
    // A line is a few hundred bytes; 64 KiB covers any real one with room.
    const len = Math.min(size, 64 * 1024);
    const buf = Buffer.alloc(len);
    readSync(fd, buf, 0, len, size - len);
    const text = buf.toString("utf8").replace(/\n+$/, "");
    const i = text.lastIndexOf("\n");
    return i === -1 ? (len === size ? text : null) : text.slice(i + 1);
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

const sleep = (ms: number): void => {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
};

/**
 * Two hush processes appending at once would both read the same last line and
 * fork the chain, which `verify` would then report as tampering. A short lock
 * keeps appends in order; a writer that cannot get it in a second appends
 * anyway, marked `unchained`, because auditing must never block a command.
 */
function withAppendLock<T>(path: string, fn: (locked: boolean) => T): T {
  const lock = `${path}.lock`;
  const deadline = Date.now() + 1000;
  let fd: number | undefined;
  for (;;) {
    try {
      fd = openSync(lock, "wx");
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") return fn(false);
      try {
        // A lock older than ten seconds belongs to a process that died.
        if (Date.now() - statSync(lock).mtimeMs > 10_000) unlinkSync(lock);
      } catch { /* gone already */ }
      if (Date.now() > deadline) return fn(false);
      sleep(10);
    }
  }
  try {
    return fn(true);
  } finally {
    try { closeSync(fd); } catch { /* closed */ }
    try { unlinkSync(lock); } catch { /* best effort */ }
  }
}

export function audit(hushDir: string, event: Record<string, unknown>): void {
  try {
    mkdirSync(hushDir, { recursive: true });
    const path = auditPath(hushDir);
    withAppendLock(path, (locked) => {
      // On rotation the new file's first line names the last line of the one
      // it replaced (`follows`), so verify can tell a rotation it can follow
      // from history that was pushed out of reach.
      let follows: string | undefined;
      if (existsSync(path) && statSync(path).size > AUDIT_MAX_BYTES) {
        const last = lastLine(path);
        if (last !== null) follows = lineHash(last);
        try { unlinkSync(`${path}.${AUDIT_GENERATIONS}`); } catch { /* not there yet */ }
        for (let g = AUDIT_GENERATIONS - 1; g >= 1; g--) {
          if (existsSync(`${path}.${g}`)) renameSync(`${path}.${g}`, `${path}.${g + 1}`);
        }
        renameSync(path, `${path}.1`);
      }
      // Fields hush controls go last, so an event can never supply its own.
      const { prev: _p, salt: _s, unchained: _u, follows: _f, ...raw } = event;
      const body = Object.fromEntries(Object.entries(raw).map(([k, v]) => [k, capField(v)]));
      const entry: Record<string, unknown> = { at: new Date().toISOString(), ...body, ...(follows ? { follows } : {}) };
      if (!locked) {
        entry.unchained = true;
      } else {
        const before = existsSync(path) ? lastLine(path) : null;
        if (before === null) {
          const salt = randomBytes(16).toString("hex");
          entry.salt = salt;
          entry.prev = lineHash(START + salt);
        } else {
          entry.prev = lineHash(before);
        }
      }
      // Not through a link: audit.log is gitignored, but a repository can
      // still commit one, and the log would then be appended to wherever it points.
      const fd = openNoFollow(path, "append");
      try {
        writeSync(fd, JSON.stringify(entry) + "\n");
      } finally {
        closeSync(fd);
      }
    });
  } catch {
    /* auditing must never break the command */
  }
}

export interface ChainReport {
  file: string;
  lines: number;
  /** Lines written before the log was chained (by hush 0.6 or older). */
  legacy: number;
  /** Written while another hush held the lock; not part of the chain. */
  unchained: number[];
  /** 1-based line numbers where the chain does not hold, with why. */
  breaks: { line: number; why: string }[];
  /**
   * This file began by rotating away an older one that is no longer here: the
   * history before it is gone (aged out, or pushed out by a flood of lines).
   */
  earlierGone?: boolean;
}

/**
 * Walk one file's chain. Every `prev` must be the hash of the line above it;
 * the first chained line of a file must either start the file with a salt or
 * follow on from an older, unchained line.
 */
export function verifyChain(file: string): ChainReport {
  const report: ChainReport = { file, lines: 0, legacy: 0, unchained: [], breaks: [] };
  if (!existsSync(file)) return report;
  const lines = readFileSync(file, "utf8").split("\n");
  if (lines.at(-1) === "") lines.pop();
  report.lines = lines.length;

  let chained = false;
  let previous: string | null = null;
  lines.forEach((line, i) => {
    const n = i + 1;
    let entry: Record<string, unknown> | null = null;
    try {
      entry = JSON.parse(line) as Record<string, unknown>;
    } catch {
      report.breaks.push({ line: n, why: "not a log entry (the line was edited)" });
    }
    if (entry) {
      if (entry.unchained === true) {
        report.unchained.push(n);
      } else if (typeof entry.prev !== "string") {
        if (chained) report.breaks.push({ line: n, why: "no link to the line above (a line was inserted)" });
        else report.legacy++;
      } else if (typeof entry.salt === "string") {
        if (i !== 0 && chained) report.breaks.push({ line: n, why: "a second start in the middle of the log" });
        if (entry.prev !== lineHash(START + entry.salt)) report.breaks.push({ line: n, why: "its start was altered" });
        chained = true;
      } else if (previous === null) {
        report.breaks.push({ line: n, why: "the lines before it were removed" });
        chained = true;
      } else {
        if (entry.prev !== lineHash(previous)) {
          report.breaks.push({ line: n, why: "the line above it was changed, removed or moved" });
        }
        chained = true;
      }
    }
    previous = line;
  });
  return report;
}

/**
 * Every generation still here, oldest first, each checked on its own and
 * against the one before it: a file that began by rotating another away must
 * follow on from that file's last line.
 */
export function verifyAudit(hushDir: string): ChainReport[] {
  const path = auditPath(hushDir);
  const files = [...Array.from({ length: AUDIT_GENERATIONS }, (_, i) => `${path}.${AUDIT_GENERATIONS - i}`), path].filter((f) => existsSync(f));
  return files.map((file, i) => {
    const report = verifyChain(file);
    const first = readFileSync(file, "utf8").split("\n")[0];
    let follows: unknown;
    try {
      follows = (JSON.parse(first) as Record<string, unknown>).follows;
    } catch {
      return report;
    }
    if (typeof follows !== "string") return report;
    const before = i > 0 ? lastLine(files[i - 1]) : null;
    if (before === null) report.earlierGone = true;
    else if (lineHash(before) !== follows) report.breaks.unshift({ line: 1, why: "it does not follow on from the end of the older file" });
    return report;
  });
}

/** Fields that exist for the chain, not for a person reading the log. */
export function withoutChain(entry: Record<string, unknown>): Record<string, unknown> {
  const { prev: _p, salt: _s, unchained: _u, follows: _f, ...rest } = entry;
  return rest;
}
