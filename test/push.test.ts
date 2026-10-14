/**
 * `hush push` end to end, against stand-in CLIs that answer --help with the
 * real CLI's help (test/fixtures/hosts) and record exactly what they were run
 * with: argv, stdin, and whether the value was anywhere in their environment.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { project } from "./helpers/cli.ts";

const FIXTURES = join(import.meta.dirname, "fixtures", "hosts");
const posix = process.platform !== "win32";

/**
 * A stand-in CLI: `--version` prints `version`; the help arguments print the
 * fixture; anything else reads stdin and appends {argv, stdin, valueInEnv} to
 * `log`, prints `say` (which may echo the value, to test masking), and exits `code`.
 */
function fakeCli(dir: string, name: string, o: { help: string; helpArgs: string[]; version?: string; log: string; value: string; code?: number; existsArgs?: string[] }) {
  const helpText = readFileSync(join(FIXTURES, o.help), "utf8");
  const script = `#!${process.execPath}
const fs = require("fs");
const argv = process.argv.slice(2);
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
if (argv[0] === "--version" || argv[0] === "version") { console.log(${JSON.stringify(o.version ?? "1.0.0")}); process.exit(0); }
if (same(argv, ${JSON.stringify(o.helpArgs)})) { process.stdout.write(${JSON.stringify(helpText)}); process.exit(0); }
if (${JSON.stringify(o.existsArgs ?? null)} && same(argv, ${JSON.stringify(o.existsArgs ?? [])})) { console.log("THE_CURRENT_VALUE_IS " + ${JSON.stringify(o.value)}); process.exit(0); }
let stdin = "";
try { stdin = fs.readFileSync(0, "utf8"); } catch {}
const valueInEnv = Object.values(process.env).some((v) => v === ${JSON.stringify(o.value)});
fs.appendFileSync(${JSON.stringify(o.log)}, JSON.stringify({ argv, stdin, valueInEnv }) + "\\n");
console.log("Uploaded. (debug: " + stdin + ")");
process.exit(${o.code ?? 0});
`;
  const path = join(dir, name);
  writeFileSync(path, script);
  chmodSync(path, 0o755);
}

const calls = (log: string) => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);

describe("hush push", { skip: !posix && "stand-in CLIs are POSIX scripts" }, () => {
  test("sends the value on stdin only, to the Worker the config names, masks it in the output, and remembers where it went", () => {
    const bin = mkdtempSync(join(tmpdir(), "hush-fakecli-"));
    const log = join(bin, "calls.jsonl");
    const p = project({ PATH: `${bin}:${process.env.PATH}`, STRIPE_COPY: "sk_live_cli" });
    try {
      fakeCli(bin, "wrangler", { help: "cloudflare.help.txt", helpArgs: ["secret", "put", "--help"], version: "4.151.0", log, value: "sk_live_cli" });
      writeFileSync(join(p.root, "wrangler.jsonc"), '{ "name": "linkdaisy" }\n');
      const r = p.run(["push", "STRIPE_SECRET_KEY", "--to", "cloudflare"]);
      assert.equal(r.code, 0, r.out);
      const [call] = calls(log);
      assert.deepEqual(call.argv, ["secret", "put", "STRIPE_SECRET_KEY", "--name", "linkdaisy"]);
      assert.equal(call.stdin, "sk_live_cli", "the value did not arrive exactly");
      assert.equal(call.valueInEnv, false, "the value was in the CLI's environment too");
      assert.ok(!r.out.includes("sk_live_cli"), `the value was printed:\n${r.out}`);
      assert.match(r.out, /\[redacted:STRIPE_SECRET_KEY\]/);
      assert.match(r.out, /Worker linkdaisy, from this project's own config/);

      const listed = p.run(["push", "--list"]);
      assert.match(listed.out, /STRIPE_SECRET_KEY → Cloudflare Workers Worker linkdaisy/);
      const pushes = JSON.parse(readFileSync(join(p.home, "pushes.json"), "utf8"));
      const rec = Object.values(pushes.projects as Record<string, { key: string; host: string; target: string; source: { where: string; set: string } }[]>)[0][0];
      assert.equal(rec.host, "cloudflare");
      assert.equal(rec.target, "linkdaisy");
      assert.deepEqual([rec.source.where, rec.source.set], ["project", "default"]);
      assert.ok(!readFileSync(join(p.home, "pushes.json"), "utf8").includes("sk_live_cli"), "the record holds the value");

      // Replaced: --list says so, and --again sends the new value to the same place.
      assert.equal(p.run(["set", "STRIPE_SECRET_KEY"], "sk_live_rotated\n").code, 0);
      assert.match(p.run(["push", "--list"]).out, /changed since/);
      fakeCli(bin, "wrangler", { help: "cloudflare.help.txt", helpArgs: ["secret", "put", "--help"], version: "4.151.0", log, value: "sk_live_rotated" });
      const again = p.run(["push", "--again"]);
      assert.equal(again.code, 0, again.out);
      assert.equal(calls(log)[1].stdin, "sk_live_rotated");
      assert.doesNotMatch(p.run(["push", "--list"]).out, /changed since/);
    } finally {
      p.cleanup();
      rmSync(bin, { recursive: true, force: true });
    }
  });

  test("an old CLI is refused before anything is sent, with the update to make", () => {
    const bin = mkdtempSync(join(tmpdir(), "hush-fakecli-"));
    const log = join(bin, "calls.jsonl");
    const p = project({ PATH: `${bin}:${process.env.PATH}` });
    try {
      fakeCli(bin, "railway", { help: "railway-4.16.1.help.txt", helpArgs: ["variable", "set", "--help"], log, value: "sk_live_cli" });
      const r = p.run(["push", "STRIPE_SECRET_KEY", "--to", "railway"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /does not say “--stdin”/);
      assert.match(r.out, /Update railway/);
      assert.deepEqual(calls(log), [], "the old CLI was run with the value");

      fakeCli(bin, "wrangler", { help: "cloudflare.help.txt", helpArgs: ["secret", "put", "--help"], version: "2.20.0", log, value: "sk_live_cli" });
      const old = p.run(["push", "STRIPE_SECRET_KEY", "--to", "cloudflare", "--target", "w"]);
      assert.equal(old.code, 1);
      assert.match(old.out, /wrangler is 2\.20\.0; hush has checked Cloudflare Workers from 3\.0\.0 on/);
      assert.deepEqual(calls(log), []);
    } finally {
      p.cleanup();
      rmSync(bin, { recursive: true, force: true });
    }
  });

  test("a value the CLI would change is refused, and nothing runs", () => {
    const bin = mkdtempSync(join(tmpdir(), "hush-fakecli-"));
    const log = join(bin, "calls.jsonl");
    const p = project({ PATH: `${bin}:${process.env.PATH}` });
    try {
      fakeCli(bin, "wrangler", { help: "cloudflare.help.txt", helpArgs: ["secret", "put", "--help"], version: "4.151.0", log, value: "x" });
      assert.equal(p.run(["set", "PEM_KEY"], "-----BEGIN-----\nabc\n-----END-----\n\n").code, 0);
      const r = p.run(["push", "PEM_KEY", "--to", "cloudflare", "--target", "w"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /cannot be sent to Cloudflare Workers exactly: it starts or ends with whitespace/);
      assert.deepEqual(calls(log), []);
      // --dry-run shows the command, sends nothing.
      const dry = p.run(["push", "STRIPE_SECRET_KEY", "--to", "cloudflare", "--target", "w", "--dry-run"]);
      assert.match(dry.out, /would run: wrangler secret put STRIPE_SECRET_KEY --name w/);
      assert.deepEqual(calls(log), []);
    } finally {
      p.cleanup();
      rmSync(bin, { recursive: true, force: true });
    }
  });

  test("GitLab: asks whether it is there, then updates rather than creates — and never shows what the probe printed", () => {
    const bin = mkdtempSync(join(tmpdir(), "hush-fakecli-"));
    const log = join(bin, "calls.jsonl");
    const p = project({ PATH: `${bin}:${process.env.PATH}` });
    try {
      fakeCli(bin, "glab", { help: "gitlab.help.txt", helpArgs: ["variable", "set", "--help"], log, value: "sk_live_cli", existsArgs: ["variable", "get", "STRIPE_SECRET_KEY"] });
      const r = p.run(["push", "STRIPE_SECRET_KEY", "--to", "gitlab"]);
      assert.equal(r.code, 0, r.out);
      assert.deepEqual(calls(log)[0].argv, ["variable", "update", "STRIPE_SECRET_KEY"]);
      assert.equal(calls(log)[0].stdin, "sk_live_cli");
      assert.ok(!r.out.includes("THE_CURRENT_VALUE_IS"), "the probe's output was shown");
    } finally {
      p.cleanup();
      rmSync(bin, { recursive: true, force: true });
    }
  });

  test("a failed push is reported and not remembered", () => {
    const bin = mkdtempSync(join(tmpdir(), "hush-fakecli-"));
    const log = join(bin, "calls.jsonl");
    const p = project({ PATH: `${bin}:${process.env.PATH}` });
    try {
      fakeCli(bin, "gh", { help: "github.help.txt", helpArgs: ["secret", "set", "--help"], log, value: "sk_live_cli", code: 1 });
      const r = p.run(["push", "STRIPE_SECRET_KEY", "--to", "github", "--env", "production"]);
      assert.equal(r.code, 1);
      assert.match(r.out, /did not succeed/);
      assert.deepEqual(calls(log)[0].argv, ["secret", "set", "STRIPE_SECRET_KEY", "--env", "production"]);
      assert.ok(!existsSync(join(p.home, "pushes.json")) || !readFileSync(join(p.home, "pushes.json"), "utf8").includes("STRIPE_SECRET_KEY"));
    } finally {
      p.cleanup();
      rmSync(bin, { recursive: true, force: true });
    }
  });

  test("a CLI that is not installed, and a host hush does not drive, are named", () => {
    const p = project({ PATH: "/usr/bin:/bin" });
    try {
      const missing = p.run(["push", "STRIPE_SECRET_KEY", "--to", "fastly", "--target", "store123"]);
      assert.match(missing.out, /The Fastly Secret Store CLI \(fastly\) is not installed here/);
      const netlify = p.run(["push", "STRIPE_SECRET_KEY", "--to", "netlify"]);
      assert.match(netlify.out, /hush cannot send to "netlify"/);
      assert.match(p.run(["push", "--hosts"]).out, /Netlify, Render, Heroku/);
    } finally {
      p.cleanup();
    }
  });
});

describe("hush run --stdin", { skip: !posix && "POSIX shell" }, () => {
  test("that one value goes to the command's standard input, exactly, and nowhere on its command line", () => {
    const p = project();
    try {
      const out = join(p.root, "got.txt");
      const r = p.run(["run", "--stdin", "STRIPE_SECRET_KEY", "--", process.execPath, "-e", `require("fs").writeFileSync(${JSON.stringify(out)}, require("fs").readFileSync(0))`]);
      assert.equal(r.code, 0, r.out);
      assert.equal(readFileSync(out, "utf8"), "sk_live_cli");
      const bad = p.run(["run", "--stdin", "NOPE", "--", "true"]);
      assert.equal(bad.code, 1);
      assert.match(bad.out, /does not get NOPE/);
      mkdirSync(join(p.root, "x"), { recursive: true });
    } finally {
      p.cleanup();
    }
  });
});
