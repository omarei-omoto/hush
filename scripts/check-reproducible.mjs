#!/usr/bin/env node
/**
 * The published dist/ has to be a function of the source and nothing else.
 *
 * Builds the package twice, into two fresh directories, and fails on any byte
 * that differs. If a build ever picks up a timestamp, an absolute path or the
 * order a directory happened to be listed in, this is where it shows — before
 * a release, rather than when someone tries to check a tarball against the
 * commit it claims to come from.
 *
 * Run: npm run build:check
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, dirname } from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const tsc = join(root, "node_modules", "typescript", "bin", "tsc");

function build() {
  const out = mkdtempSync(join(tmpdir(), "hush-repro-"));
  const r = spawnSync(process.execPath, [tsc, "-p", "tsconfig.build.json", "--outDir", out], { cwd: root, encoding: "utf8" });
  if (r.status !== 0) {
    process.stderr.write(r.stdout + r.stderr);
    process.exit(1);
  }
  return out;
}

function files(dir) {
  const list = [];
  const walk = (d) => {
    for (const name of readdirSync(d).sort()) {
      const p = join(d, name);
      if (statSync(p).isDirectory()) walk(p);
      else list.push(relative(dir, p));
    }
  };
  walk(dir);
  return list;
}

const a = build();
const b = build();
const fa = files(a);
const fb = files(b);
const problems = [];
if (fa.join("\n") !== fb.join("\n")) problems.push("the two builds produced different sets of files");
const digest = createHash("sha256");
for (const f of fa) {
  const x = readFileSync(join(a, f));
  const y = fb.includes(f) ? readFileSync(join(b, f)) : null;
  if (!y || !x.equals(y)) problems.push(`differs: ${f}`);
  digest.update(f + "\0").update(x);
}
// Built from a different directory each time, so an absolute path would differ too.
for (const f of fa) {
  if (readFileSync(join(a, f), "utf8").includes(a)) problems.push(`carries its build directory: ${f}`);
}
rmSync(a, { recursive: true, force: true });
rmSync(b, { recursive: true, force: true });
if (problems.length) {
  process.stderr.write(problems.slice(0, 20).join("\n") + "\n");
  process.exit(1);
}
process.stdout.write(`reproducible: ${fa.length} files, sha256 ${digest.digest("hex")}\n`);
