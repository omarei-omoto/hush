/**
 * `hush scan --transcripts`: your secrets, word for word, in agents' saved
 * conversations. Read-only — these tests also pin that it never changes a file.
 * Every value here is made up.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import {
  Matcher, listTranscripts, looksMadeUp, scanTranscripts, tokenService, transcriptSources, variants,
  type TranscriptFile,
} from "../src/transcripts.ts";
import { parseSince } from "../src/commands/scan-transcripts.ts";
import { bareFolder } from "./helpers/cli.ts";

const KEY = "ghp_Qw8eR2tY6uI0oP4aS1dF5gH9jK3lZ7xC2vB6";

function file(text: string): TranscriptFile {
  const dir = mkdtempSync(join(tmpdir(), "hush-tr-"));
  const path = join(dir, "s.jsonl");
  writeFileSync(path, text);
  return { agent: "test", path, size: statSync(path).size, mtimeMs: Date.now() };
}

/** Random filler with no long alphanumeric runs, so it can never look like a key. */
const filler = (n: number) => randomBytes(n).toString("base64").replace(/[A-Za-z0-9+/]{6,}/g, (m) => m.slice(0, 5) + ".");

test("every occurrence is counted exactly once, whatever the chunk size, ranges and thread count", async () => {
  const values = ["Val0" + randomBytes(9).toString("base64url"), "short9chr", "Ab3$xY9!q"]; // two take the short path
  const parts: string[] = [];
  const want = [0, 0, 0];
  let keys = 0;
  for (let j = 0; j < 400; j++) {
    parts.push(filler(Math.floor(Math.random() * 120)));
    const r = Math.random();
    if (r < 0.3) {
      const i = Math.floor(Math.random() * values.length);
      parts.push(values[i]);
      want[i]++;
    } else if (r < 0.4) {
      parts.push(` ${KEY} `);
      keys++;
    }
  }
  const f = file(parts.join(""));
  const needles = values.map((v) => Buffer.from(v));
  for (const chunk of [64, 1000, 1 << 20]) {
    const h = new Matcher(needles).scanFile(f.path, chunk);
    assert.deepEqual(values.map((_, i) => h.needles.get(i) ?? 0), want, `chunk ${chunk}`);
    assert.equal(h.tokens.get(KEY) ?? 0, keys, `chunk ${chunk}`);
  }
  for (const threads of [1, 3]) {
    const h = (await scanTranscripts([f], needles, { threads, segmentBytes: 777 })).get(f.path)!;
    assert.deepEqual(values.map((_, i) => h.needles.get(i) ?? 0), want, `threads ${threads}`);
    assert.equal(h.tokens.get(KEY) ?? 0, keys, `threads ${threads}`);
  }
});

test("a value is found as written and inside a JSON string, escaped once or twice", () => {
  const v = 'pa"ss\\word-Xy7Qz9';
  assert.deepEqual(variants(v), [v, 'pa\\"ss\\\\word-Xy7Qz9', 'pa\\\\\\"ss\\\\\\\\word-Xy7Qz9']);
  const f = file(JSON.stringify({ out: JSON.stringify({ secret: v }) }) + "\n");
  const needles = variants(v).map((x) => Buffer.from(x));
  const h = new Matcher(needles).scanFile(f.path);
  assert.ok([...h.needles.values()].reduce((a, b) => a + b, 0) >= 1);
});

test("key-shaped strings: bounded on both sides, real formats only, made-up ones ignored", () => {
  const text = [
    `"GITHUB_TOKEN=${KEY}"`, // found
    `\\n${KEY}\\n`, // after a JSON-escaped line break: found
    `ctx7sk-ea802c3e-0000-0000-0000-000000000000`, // not an OpenAI key
    `sk-${"A".repeat(2000)}`, // a blob, not a key
    `ghp_abcdefghijklmnopqrstuvwxyz0123456789`, // made up
  ].join(" ");
  const h = new Matcher([]).scanFile(file(text).path);
  assert.deepEqual([...h.tokens], [[KEY, 2]]);
  assert.equal(tokenService(KEY), "GitHub");
  assert.ok(looksMadeUp("sk_" + "live_xxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(!looksMadeUp(KEY));
});

test("sources: each agent's folder, only text and database files, snapshots skipped", () => {
  const home = mkdtempSync(join(tmpdir(), "hush-tr-home-"));
  try {
    const put = (rel: string) => {
      mkdirSync(join(home, rel, ".."), { recursive: true });
      writeFileSync(join(home, rel), "x");
    };
    put(".claude/projects/-Users-me-app/a.jsonl");
    put(".claude/projects/-Users-me-app/image.png");
    put(".codex/sessions/2026/10/02/rollout.jsonl");
    put(".local/share/opencode/opencode.db");
    put(".local/share/opencode/snapshot/objects/ab");
    const found = listTranscripts(transcriptSources({ HOME: home }, "darwin")).map((f) => f.path.slice(home.length + 1)).sort();
    assert.deepEqual(found, [".claude/projects/-Users-me-app/a.jsonl", ".codex/sessions/2026/10/02/rollout.jsonl", ".local/share/opencode/opencode.db"]);
    assert.equal(listTranscripts(transcriptSources({ HOME: home }, "darwin"), Date.now() + 60_000).length, 0, "--since in the future finds nothing");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("--since takes 30d, 12h, 2w and dates", () => {
  const now = Date.parse("2026-10-02T00:00:00Z");
  assert.equal(parseSince("1d", now), now - 86400e3);
  assert.equal(parseSince("12h", now), now - 12 * 3600e3);
  assert.equal(parseSince("2w", now), now - 14 * 86400e3);
  assert.equal(parseSince("2026-09-01", now), Date.parse("2026-09-01"));
});

function hashTree(dir: string): string {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else out.push(`${p}:${readFileSync(p).toString("base64")}`);
    }
  };
  walk(dir);
  return out.sort().join("\n");
}

test("hush scan --transcripts names what leaked and where, prints no value, and changes no file", { skip: process.platform === "win32" }, () => {
  const home = mkdtempSync(join(tmpdir(), "hush-tr-cli-home-"));
  const b = bareFolder({ HOME: home });
  try {
    const stripe = "sk_" + "live_Rq7Tz2Lp9Wx4Mn6Kb3Vc8Hd5";
    const figma = "Fg83Kd92Lq01Mz74Np56Xw";
    b.librarySet("stripe-live", { STRIPE_SECRET_KEY: stripe });
    mkdirSync(join(home, ".cursor"), { recursive: true });
    writeFileSync(join(home, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { figma: { command: "npx", env: { FIGMA_API_KEY: figma } } } }));
    mkdirSync(join(home, ".claude", "projects", "-Users-me-app"), { recursive: true });
    writeFileSync(join(home, ".claude", "projects", "-Users-me-app", "s1.jsonl"), JSON.stringify({ content: `my key is ${stripe}` }) + "\n");
    mkdirSync(join(home, ".codex", "sessions", "2026", "10", "02"), { recursive: true });
    writeFileSync(join(home, ".codex", "sessions", "2026", "10", "02", "r.jsonl"), JSON.stringify({ output: `FIGMA_API_KEY=${figma}\nGITHUB_TOKEN=${KEY}` }) + "\n");

    const before = hashTree(home);
    const r = b.run(["scan", "--transcripts", "--verbose"]);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /STRIPE_SECRET_KEY/);
    assert.match(r.out, /FIGMA_API_KEY/);
    assert.match(r.out, /GitHub/);
    assert.match(r.out, /s1\.jsonl/);
    for (const v of [stripe, figma, KEY]) assert.ok(!r.out.includes(v), "a value was printed");
    assert.match(r.out, /Nothing was changed/);

    const j = JSON.parse(b.run(["scan", "--transcripts", "--json"]).out);
    assert.equal(j.found.length, 2);
    assert.equal(j.keyShaped.length, 1);
    assert.ok(!JSON.stringify(j).includes(stripe) && !JSON.stringify(j).includes(KEY));

    assert.equal(hashTree(home), before, "a file under HOME changed");
  } finally {
    b.cleanup?.();
    rmSync(home, { recursive: true, force: true });
  }
});
