/**
 * S-3: the audit log is a hash chain, and `hush audit verify` names the line
 * where it breaks. Not tamper-proof — anything running as the user can rewrite
 * the whole file — but an edit, a removal or a reorder is no longer silent.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { audit, verifyChain, verifyAudit, lineHash } from "../src/audit.ts";
import { Vault } from "../src/vault.ts";
import { generateIdentity, encodeSecret } from "../src/crypto.ts";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.ts");

function logWith(n: number): { dir: string; file: string; lines: () => string[]; write: (l: string[]) => void } {
  const dir = mkdtempSync(join(tmpdir(), "hush-audit-"));
  for (let i = 0; i < n; i++) audit(dir, { actor: "test", action: "step", i });
  const file = join(dir, "audit.log");
  return {
    dir,
    file,
    lines: () => readFileSync(file, "utf8").split("\n").filter(Boolean),
    write: (l) => writeFileSync(file, l.join("\n") + "\n"),
  };
}

describe("S-3: the audit log is a hash chain", () => {
  test("an untouched log verifies, starts with a salt, and each line links to the one above", () => {
    const log = logWith(5);
    const lines = log.lines();
    const first = JSON.parse(lines[0]);
    assert.match(first.salt, /^[0-9a-f]{32}$/);
    for (let i = 1; i < lines.length; i++) assert.equal(JSON.parse(lines[i]).prev, lineHash(lines[i - 1]));
    const r = verifyChain(log.file);
    assert.deepEqual(r.breaks, []);
    assert.equal(r.lines, 5);
    assert.equal(statSync(log.file).mode & 0o777, 0o600);
    rmSync(log.dir, { recursive: true, force: true });
  });

  test("editing, deleting, reordering or inserting a line is each named by line number", () => {
    const cases: [string, (l: string[]) => string[], number][] = [
      ["edit", (l) => { l[2] = l[2].replace('"i":2', '"i":9'); return l; }, 4],
      ["delete", (l) => { l.splice(2, 1); return l; }, 3],
      ["reorder", (l) => { [l[1], l[2]] = [l[2], l[1]]; return l; }, 2],
      ["insert", (l) => { l.splice(3, 0, JSON.stringify({ at: "x", actor: "cli", action: "reveal", key: "K" })); return l; }, 4],
      ["drop the start", (l) => l.slice(1), 1],
    ];
    for (const [label, mutate, firstBad] of cases) {
      const log = logWith(5);
      log.write(mutate(log.lines()));
      const r = verifyChain(log.file);
      assert.ok(r.breaks.length > 0, `${label} went unnoticed`);
      assert.equal(r.breaks[0].line, firstBad, `${label}: first break at ${r.breaks[0].line}: ${r.breaks[0].why}`);
      rmSync(log.dir, { recursive: true, force: true });
    }
  });

  test("an event cannot supply its own prev, salt or unchained flag", () => {
    const dir = mkdtempSync(join(tmpdir(), "hush-audit-"));
    audit(dir, { actor: "test", action: "a" });
    audit(dir, { actor: "test", action: "b", prev: "0".repeat(64), salt: "evil", unchained: true });
    assert.deepEqual(verifyChain(join(dir, "audit.log")).breaks, []);
    const second = JSON.parse(readFileSync(join(dir, "audit.log"), "utf8").split("\n")[1]);
    assert.notEqual(second.prev, "0".repeat(64));
    assert.equal(second.salt, undefined);
    rmSync(dir, { recursive: true, force: true });
  });

  test("a log written before chaining continues cleanly, and its old lines are counted, not blamed", () => {
    const dir = mkdtempSync(join(tmpdir(), "hush-audit-"));
    writeFileSync(join(dir, "audit.log"), ['{"at":"2026-01-01","action":"old1"}', '{"at":"2026-01-02","action":"old2"}'].join("\n") + "\n");
    audit(dir, { actor: "test", action: "new1" });
    audit(dir, { actor: "test", action: "new2" });
    const r = verifyChain(join(dir, "audit.log"));
    assert.deepEqual(r.breaks, []);
    assert.equal(r.legacy, 2);
    rmSync(dir, { recursive: true, force: true });
  });

  test("a writer that cannot get the lock appends anyway, marked unchained, and the chain still holds", () => {
    const dir = mkdtempSync(join(tmpdir(), "hush-audit-"));
    audit(dir, { actor: "test", action: "one" });
    writeFileSync(join(dir, "audit.log.lock"), "held");
    audit(dir, { actor: "test", action: "two" });
    rmSync(join(dir, "audit.log.lock"));
    audit(dir, { actor: "test", action: "three" });
    const r = verifyChain(join(dir, "audit.log"));
    assert.deepEqual(r.unchained, [2]);
    // "three" links to "two", the line above it, so nothing is broken.
    assert.deepEqual(r.breaks, []);
    rmSync(dir, { recursive: true, force: true });
  });

  /** About 5 KB a line: sixteen fields at the 300-character cap. */
  const fill = (dir: string, lines: number) => {
    const pads = Object.fromEntries(Array.from({ length: 16 }, (_, i) => [`pad${i}`, "x".repeat(300)]));
    for (let i = 0; i < lines; i++) audit(dir, { actor: "test", action: "fill", ...pads });
  };

  test("rotation starts a new chain, and both files verify", () => {
    const dir = mkdtempSync(join(tmpdir(), "hush-audit-"));
    fill(dir, 450);
    const reports = verifyAudit(dir);
    assert.equal(reports.length, 2, "the log did not rotate");
    for (const r of reports) assert.deepEqual(r.breaks, [], `${r.file}: ${JSON.stringify(r.breaks[0])}`);
    rmSync(dir, { recursive: true, force: true });
  });

  test("a field is capped, generations are kept, each follows the last, and history pushed away is said (review F5)", () => {
    const dir = mkdtempSync(join(tmpdir(), "hush-audit-"));
    try {
      audit(dir, { actor: "broker", action: "call", tool: "t".repeat(1_000_000) });
      const first = JSON.parse(readFileSync(join(dir, "audit.log"), "utf8").split("\n")[0]);
      assert.ok(first.tool.length <= 301, `a ${first.tool.length}-character field was written whole`);

      fill(dir, 1300); // three rotations
      const reports = verifyAudit(dir);
      assert.equal(reports.length, 4, "older generations were not kept");
      for (const r of reports) assert.deepEqual(r.breaks, [], `${r.file}: ${JSON.stringify(r.breaks[0])}`);
      assert.ok(!reports.some((r) => r.earlierGone), "nothing was removed, yet history is reported gone");

      // Deleting the oldest generation is said, not passed over as a fresh start.
      rmSync(reports[0].file);
      assert.equal(verifyAudit(dir)[0].earlierGone, true);
      // And a generation edited in the middle no longer lines up with the next.
      const middle = verifyAudit(dir)[1].file;
      writeFileSync(middle, readFileSync(middle, "utf8").replace(/\n[^\n]*\n$/, "\n"));
      assert.ok(verifyAudit(dir)[2].breaks.some((b) => /follow on/.test(b.why)), "a cut generation went unnoticed");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("hush audit verify exits non-zero on a break and names it; hush audit shows no chain fields", () => {
    const home = mkdtempSync(join(tmpdir(), "hush-audit-home-"));
    const root = mkdtempSync(join(tmpdir(), "hush-audit-proj-"));
    mkdirSync(join(root, ".hush"));
    const id = generateIdentity();
    const v = Vault.create(join(root, ".hush", "vault.json"), "a", { name: "me", pub: id.pub });
    v.set(id, "default", "K", "value-long-enough");
    v.save();
    const run = (args: string[]) => {
      const r = spawnSync(process.execPath, [CLI, ...args], {
        cwd: root,
        env: { ...process.env, HOME: home, HUSH_HOME: home, HUSH_IDENTITY: encodeSecret(id), HUSH_NO_KEYCHAIN: "1", HUSH_NO_NUDGE: "1", NO_COLOR: "1" },
        encoding: "utf8",
      });
      return { out: (r.stdout ?? "") + (r.stderr ?? ""), code: r.status ?? 1 };
    };
    for (let i = 0; i < 3; i++) run(["run", "--", "true"]);
    const ok = run(["audit", "verify"]);
    assert.equal(ok.code, 0, ok.out);
    assert.match(ok.out, /each following from the one above/);

    const shown = run(["audit"]);
    assert.match(shown.out, /run/);
    assert.doesNotMatch(shown.out, /prev=|salt=/);

    const file = join(root, ".hush", "audit.log");
    const lines = readFileSync(file, "utf8").split("\n").filter(Boolean);
    lines.splice(1, 1);
    writeFileSync(file, lines.join("\n") + "\n");
    const bad = run(["audit", "verify"]);
    assert.equal(bad.code, 1, bad.out);
    assert.match(bad.out, /line 2/);
    for (const d of [home, root]) rmSync(d, { recursive: true, force: true });
  });
});
