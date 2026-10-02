/**
 * A scan runs wherever someone is standing, and that is not always a project.
 * `hush ui` opened from the home folder walked all of it and the page stayed
 * blank for minutes; these pin the limits that stop that.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scanTree, scanRepo, SCAN_LIMITS } from "../src/scan.ts";

function tree(files: number): string {
  const root = mkdtempSync(join(tmpdir(), "hush-scan-limits-"));
  for (let d = 0; d < 10; d++) {
    const dir = join(root, `pkg${d}`);
    mkdirSync(dir);
    for (let f = 0; f < files / 10; f++) writeFileSync(join(dir, `f${f}.js`), `process.env.KEY_${d}_${f}\n`);
  }
  return root;
}

test("a tree inside the limits is scanned whole, and says so", () => {
  const root = tree(50);
  try {
    const r = scanTree(root);
    assert.equal(r.truncated, false);
    assert.equal(r.usages.length, 50);
    assert.deepEqual(scanRepo(root).map((u) => u.name), r.usages.map((u) => u.name));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("past the entry limit the walk stops and reports a partial result", () => {
  const root = tree(200);
  try {
    const r = scanTree(root, { maxEntries: 40, deadlineMs: 60_000 });
    assert.equal(r.truncated, true);
    assert.ok(r.usages.length < 200, `expected a partial list, got ${r.usages.length}`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("past the deadline the walk stops too, rather than finishing late", () => {
  const root = tree(600);
  try {
    const r = scanTree(root, { maxEntries: 1_000_000, deadlineMs: -1 });
    assert.equal(r.truncated, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the default limits are finite: nothing scans forever by default", () => {
  assert.ok(Number.isFinite(SCAN_LIMITS.maxEntries) && SCAN_LIMITS.maxEntries > 0);
  assert.ok(Number.isFinite(SCAN_LIMITS.deadlineMs) && SCAN_LIMITS.deadlineMs > 0);
});
