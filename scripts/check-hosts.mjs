#!/usr/bin/env node
/**
 * Re-check every host in src/hosts.ts against real CLIs, before a release or
 * whenever a host's CLI ships: its help must still say what the proof relies
 * on, and its version must still meet the minimum.
 *
 *   node scripts/check-hosts.mjs              the CLIs installed on this machine
 *   node scripts/check-hosts.mjs --latest     also the newest npm releases (npx; downloads them)
 *   node scripts/check-hosts.mjs --write      save what each printed as test/fixtures/hosts/<id>.help.txt
 *
 * Help only: nothing here signs in, and no value is ever sent.
 */
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const { HOSTS, normalHelp, versionAtLeast } = await import(join(root, "src", "hosts.ts"));
const { findCli } = await import(join(root, "src", "push.ts"));

const latest = process.argv.includes("--latest");
const write = process.argv.includes("--write");
/** The npm package each CLI is published as, for --latest. */
const NPM = { wrangler: "wrangler", vercel: "vercel", convex: "convex", firebase: "firebase-tools", sst: "sst", railway: "@railway/cli" };
const env = { ...process.env, NO_COLOR: "1", CI: "1", DO_NOT_TRACK: "1", VERCEL_TELEMETRY_DISABLED: "1", WRANGLER_SEND_METRICS: "false" };
const run = (cmd, args) => {
  const r = spawnSync(cmd, args, { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 300_000 });
  return (r.stdout ?? "") + (r.stderr ?? "");
};

let bad = 0;
const check = (label, h, out, versionOut) => {
  const text = normalHelp(out);
  const missing = h.proof.mustSay.filter((s) => !text.includes(normalHelp(s)));
  const v = h.proof.minVersion ? versionAtLeast(versionOut ?? "", h.proof.minVersion.min) : true;
  const ok = !missing.length && v === true;
  if (!ok) bad++;
  console.log(`${ok ? "ok  " : "FAIL"} ${h.id.padEnd(17)} ${label}${missing.length ? `  missing: ${JSON.stringify(missing)}` : ""}${v === true ? "" : `  version: ${(/(\d+\.\d+\.\d+)/.exec(versionOut ?? "") ?? ["?"])[0]} < ${h.proof.minVersion.min}`}`);
  if (ok && write) writeFileSync(join(root, "test", "fixtures", "hosts", `${h.id}.help.txt`), out);
};

for (const h of HOSTS) {
  const bin = findCli(h, process.cwd());
  if (bin) check(bin, h, run(bin, h.proof.help), h.proof.minVersion ? run(bin, h.proof.minVersion.args) : undefined);
  else console.log(`--   ${h.id.padEnd(17)} ${h.bin} not installed here`);
  if (latest && NPM[h.bin]) {
    const pkg = `${NPM[h.bin]}@latest`;
    check(`npx ${pkg}`, h, run("npx", ["-y", pkg, ...h.proof.help]), h.proof.minVersion ? run("npx", ["-y", pkg, ...h.proof.minVersion.args]) : undefined);
  }
}
if (bad) {
  console.log(`\n${bad} check(s) failed: a CLI changed, or is older than hush has checked. Re-read its source before changing hosts.ts.`);
  process.exitCode = 1;
}
