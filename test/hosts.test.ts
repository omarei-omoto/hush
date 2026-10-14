/**
 * The hosts a key can be sent to (hosts.ts), held to what makes a push exact:
 *
 *   - every proof matches the help the real CLI prints (fixtures captured from
 *     the CLIs themselves, versions in test/fixtures/hosts/VERSIONS.txt);
 *   - each CLI's way of reading stdin, ported here from its source, gives back
 *     exactly the value for every value its host accepts — fuzzed;
 *   - no command line ever holds the value.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import { HOSTS, hostById, normalHelp, versionAtLeast, detectHosts, type Host } from "../src/hosts.ts";
import { planPush } from "../src/push.ts";

const FIXTURES = join(import.meta.dirname, "fixtures", "hosts");
const help = (name: string) => normalHelp(readFileSync(join(FIXTURES, name), "utf8"));

// ------------------------------------------------- the CLIs' own readers
// Each is the stdin handling of that CLI, ported line for line from the file
// named beside it. `wire` is what hush writes; the result is what the host stores.

/** flyctl internal/command/secrets/parser.go parseSecrets — the import format. */
function flyParse(wire: string): Record<string, string> {
  const secrets: Record<string, string> = {};
  let multi = false;
  let key = "";
  let val = "";
  // bufio.ScanLines: split at \n, drop one \r before it, no token after a final \n.
  const lines = wire.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  for (let line of lines.map((l) => (l.endsWith("\r") ? l.slice(0, -1) : l))) {
    if (!multi) {
      if (line.startsWith("#") || line.trim() === "") continue;
      const at = line.indexOf("=");
      if (at < 0) throw new Error("not NAME=VALUE");
      const k = line.slice(0, at).trim();
      let value = line.slice(at + 1).replace(/^ +/, "");
      const hash = value.indexOf("#");
      if (hash >= 0) {
        const l = value.slice(0, hash);
        if ((l.match(/"/g) ?? []).length % 2 === 0) value = l.replace(/ +$/, "");
      }
      if (value.startsWith('"""') && value.endsWith('"""') && value.length >= 6) secrets[k] = value.slice(3, -3);
      else if (value.startsWith('"""')) {
        multi = true;
        key = k;
        val = value.slice(3) + "\n";
      } else {
        if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
        else if (value.startsWith("'") && value.endsWith("'")) value = value.slice(1, -1);
        secrets[k] = value;
      }
    } else if (line.endsWith('"""')) {
      secrets[key] = val + line.slice(0, -3);
      multi = false;
      val = "";
    } else val += line + "\n";
    void line;
  }
  return secrets;
}

const READERS: Record<string, (wire: string, name: string) => string> = {
  // packages/wrangler/src/utils/std.ts: trimTrailingWhitespace = str.trimEnd()
  cloudflare: (w) => w.trimEnd(),
  "cloudflare-pages": (w) => w.trimEnd(),
  // packages/cli/src/util/env/validate-env.ts normalizeStdinEnvValue (one chunk: see the size rule)
  vercel: (w) => {
    const without = w.endsWith("\r\n") ? w.slice(0, -2) : w.endsWith("\n") ? w.slice(0, -1) : null;
    if (without === null || without.includes("\n") || without.includes("\r")) return w;
    return without;
  },
  // npm-packages/convex/src/cli/lib/utils/stdin.ts: data.replace(/\n$/, "")
  convex: (w) => w.replace(/\n$/, ""),
  fly: (w, name) => flyParse(w)[name],
  // src/commands/variable.rs read_value_from_stdin: trim_end_matches('\n').trim_end_matches('\r')
  railway: (w) => w.replace(/\n+$/, "").replace(/\r+$/, ""),
  // src/utils.ts readSecretValue: readFileSync(0, "utf-8")
  firebase: (w) => w,
  // pkg/cmd/secret/set/set.go: bytes.TrimRight(body, "\r\n")
  github: (w) => w.replace(/[\r\n]+$/, ""),
  // variableutils/value.go GetValue: strings.TrimSpace
  gitlab: (w) => w.trim(),
  // console_io.ReadFromFileOrStdin(binary=True)
  gcloud: (w) => w,
  // pkg/koyeb/secrets.go getSecretValue: lines until the first empty one, joined with \n
  koyeb: (w) => {
    const out: string[] = [];
    const lines = w.split("\n");
    if (lines[lines.length - 1] === "") lines.pop();
    for (const raw of lines) {
      const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
      if (!line.length) break;
      out.push(line);
    }
    return out.join("\n");
  },
  // pkg/commands/secretstoreentry/create.go: buf.ReadFrom(in)
  fastly: (w) => w,
  // --raw: "do not trim trailing newlines from the value"
  pulumi: (w) => w,
  // cmd/sst/secret.go: not a terminal, every ReadString('\n') kept
  sst: (w) => w,
};

/** Values with every awkward shape a real secret has: PEM, JSON, padding, unicode, quotes, #, =. */
function sampleValues(n: number): string[] {
  const fixed = [
    "sk_live_51HxAbCdEfGhIjKlMnOp",
    "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nAbCd==\n-----END PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n",
    '{"type":"service_account","private_key":"-----BEGIN\\nabc\\n"}',
    "postgres://u:p%40ss@db.example.com:5432/app?sslmode=require",
    "a b",
    " leading",
    "trailing ",
    "tab\tinside",
    "x=y=z",
    "#hash-first",
    "has#hash",
    '"quoted"',
    "'single'",
    '"""triple"""',
    "line1\n\nline3",
    "crlf\r\nline",
    "ünïcödé — ключ — 鍵 — 🔑",
    "a".repeat(9000),
    "",
  ];
  const alphabet = "abcXYZ0129 _-=#\"'\\\n\r\t/+.:@~🔑é";
  const out = [...fixed];
  for (let i = 0; i < n; i++) {
    const len = 1 + (randomBytes(1)[0] % 40);
    let s = "";
    for (let j = 0; j < len; j++) s += [...alphabet][randomBytes(1)[0] % [...alphabet].length];
    out.push(s);
  }
  return out;
}

const optsFor = (h: Host) => ({
  name: h.id === "sst" ? "StripeSecret" : "STRIPE_SECRET_KEY",
  ...(h.target ? { target: "the-target" } : {}),
  ...(h.env?.choices ? { env: h.env.choices[0] } : {}),
});

describe("hosts: every entry is complete", () => {
  test("ids are unique, and each entry names its proof, its rules and where it was checked", () => {
    const ids = HOSTS.map((h) => h.id);
    assert.equal(new Set(ids).size, ids.length);
    for (const h of HOSTS) {
      assert.ok(h.label && h.bin, h.id);
      assert.ok(h.proof.help.length && h.proof.mustSay.length, `${h.id} has no proof`);
      assert.ok(h.checked.length, `${h.id} does not say where it was checked`);
      assert.ok(READERS[h.id], `${h.id} has no ported stdin reader in this test`);
    }
  });
});

describe("hosts: proofs against the real CLIs' help", () => {
  for (const h of HOSTS) {
    test(`${h.id}: the help its CLI prints says everything the proof needs`, () => {
      const text = help(`${h.id}.help.txt`);
      for (const s of h.proof.mustSay) assert.ok(text.includes(normalHelp(s)), `${h.id}: the real help does not say “${s}”`);
    });
  }
  test("railway 4.16.1, which has no `variable set --stdin`, fails its proof", () => {
    const text = help("railway-4.16.1.help.txt");
    assert.ok(!hostById("railway")!.proof.mustSay.every((s) => text.includes(s)));
  });
  test("versions are compared as numbers, from the first version in the output", () => {
    assert.equal(versionAtLeast(" ⛅️ wrangler 4.151.0\n", "3.0.0"), true);
    assert.equal(versionAtLeast("3.48.9", "3.49.0"), false);
    assert.equal(versionAtLeast("3.49.0", "3.49.0"), true);
    assert.equal(versionAtLeast("1.9.0", "1.27.0"), false);
    assert.equal(versionAtLeast("no version here", "1.0.0"), null);
  });
});

describe("hosts: what arrives is exactly what is sent", () => {
  for (const h of HOSTS) {
    test(`${h.id}: every value it accepts survives its CLI's own stdin reader, and never reaches a command line`, () => {
      const opts = optsFor(h);
      let accepted = 0;
      for (const value of sampleValues(400)) {
        if (h.refuses(value, opts)) continue;
        accepted++;
        const wire = h.stdin(value, opts);
        assert.equal(READERS[h.id](wire, opts.name), value, `${h.id} would store ${JSON.stringify(value)} differently`);
        for (const exists of [false, true]) {
          const argv = h.argv({ ...opts, exists });
          assert.ok(!argv.some((a) => a.includes(value) && value.length >= 3), `${h.id}'s command line holds the value`);
        }
      }
      assert.ok(accepted > 20, `${h.id} accepted almost nothing (${accepted})`);
    });
  }

  test("the values that would change are refused, with the reason", () => {
    const with_ = (id: string, value: string, name = "STRIPE_SECRET_KEY") => hostById(id)!.refuses(value, { ...optsFor(hostById(id)!), name });
    assert.match(with_("cloudflare", "abc\n")!, /whitespace/);
    assert.match(with_("github", "abc\r\ndef")!, /carriage return/);
    assert.match(with_("fly", "a#b")!, /#/);
    assert.match(with_("fly", "'quoted")!, /quote/);
    assert.match(with_("fly", "two\nlines")!, /several lines/);
    assert.match(with_("koyeb", "a\n\nb")!, /empty line/);
    assert.match(with_("vercel", "x".repeat(8193))!, /at most 8192/);
    assert.match(with_("firebase", "v", "stripeKey")!, /UPPER_SNAKE_CASE/);
    assert.match(with_("sst", "v", "stripe_secret")!, /capital letter/);
    assert.match(with_("github", "v", "GITHUB_TOKEN")!, /GITHUB_/);
    assert.match(with_("gcloud", "")!, /empty/);
    // The exact readers keep a PEM's final newline, so they take it.
    for (const id of ["firebase", "gcloud", "fastly", "pulumi"]) assert.equal(with_(id, "-----BEGIN-----\nabc\n-----END-----\n"), null, id);
  });
});

describe("planning a push", () => {
  const cf = hostById("cloudflare")!;
  test("a target or environment that could pass for a flag, or holds the value, is refused", () => {
    assert.throws(() => planPush(cf, "STRIPE_SECRET_KEY", "sk_live_123456789", { target: "--help" }), /not a name hush will put on a command line/);
    assert.throws(() => planPush(cf, "STRIPE_SECRET_KEY", "sk_live_123456789", { target: "my\nworker" }), /not a name/);
    assert.throws(() => planPush(cf, "STRIPE_SECRET_KEY", "sk_live_123456789", { target: "w-sk_live_123456789" }), /holds the value/);
  });
  test("what a host needs is required, and only what it has is accepted", () => {
    assert.throws(() => planPush(cf, "STRIPE_SECRET_KEY", "v", {}), /which Worker/);
    assert.throws(() => planPush(hostById("vercel")!, "K", "v", { env: "staging" }), /one of production, preview, development/);
    assert.throws(() => planPush(hostById("koyeb")!, "K", "v", { env: "prod" }), /no environments/);
    assert.throws(() => planPush(cf, "K", "v", { target: "w", deploy: true }), /always deploys/);
    const fly = planPush(hostById("fly")!, "K", "v", { target: "app" });
    assert.equal(fly.preview, "fly secrets import --app app --stage");
    assert.equal(planPush(hostById("fly")!, "K", "v", { target: "app", deploy: true }).preview, "fly secrets import --app app");
  });
  test("Vercel gets --sensitive except for Development, which Vercel keeps readable", () => {
    const v = hostById("vercel")!;
    assert.deepEqual(v.argv({ name: "K", env: "production" }), ["env", "add", "K", "production", "--force", "--sensitive"]);
    assert.deepEqual(v.argv({ name: "K", env: "development" }), ["env", "add", "K", "development", "--force"]);
    assert.equal(planPush(v, "K", "v", {}).opts.env, "production", "the default environment was not used");
  });
  test("hosts with separate create and update pick by whether it is there", () => {
    assert.deepEqual(hostById("gitlab")!.argv({ name: "K", exists: true }), ["variable", "update", "K"]);
    assert.deepEqual(hostById("gitlab")!.argv({ name: "K", exists: false }), ["variable", "set", "K"]);
    assert.deepEqual(hostById("gcloud")!.argv({ name: "K", exists: false }), ["secrets", "create", "K", "--data-file=-", "--replication-policy=automatic"]);
    assert.deepEqual(hostById("gcloud")!.argv({ name: "K", exists: true }), ["secrets", "versions", "add", "K", "--data-file=-"]);
    assert.deepEqual(hostById("koyeb")!.argv({ name: "K", exists: true }), ["secrets", "update", "K", "--value-from-stdin"]);
  });
});

describe("finding where a project deploys", () => {
  test("Worker, Pages project, Fly app and Firebase project from the project's own files", () => {
    const root = mkdtempSync(join(tmpdir(), "hush-hosts-"));
    try {
      writeFileSync(join(root, "wrangler.jsonc"), '{\n  // the Worker\n  "name": "linkdaisy", /* inline */\n  "main": "src/index.ts",\n}\n');
      writeFileSync(join(root, "fly.toml"), 'app = "my-fly-app" # comment\nprimary_region = "ams"\n\n[http_service]\n  app = "not-this"\n');
      writeFileSync(join(root, ".firebaserc"), JSON.stringify({ projects: { default: "my-firebase" } }));
      const found = Object.fromEntries(detectHosts(root).map((d) => [d.id, d.target]));
      assert.equal(found.cloudflare, "linkdaisy");
      assert.equal(found["cloudflare-pages"], undefined, "a Worker config was read as a Pages project");
      assert.equal(found.fly, "my-fly-app");
      assert.equal(found.firebase, "my-firebase");
      rmSync(join(root, "wrangler.jsonc"));
      writeFileSync(join(root, "wrangler.toml"), 'name = "my-pages"\npages_build_output_dir = "./dist"\n');
      const pages = Object.fromEntries(detectHosts(root).map((d) => [d.id, d.target]));
      assert.equal(pages["cloudflare-pages"], "my-pages");
      assert.equal(pages.cloudflare, undefined);
      mkdirSync(join(root, ".github", "workflows"), { recursive: true });
      assert.ok(detectHosts(root).some((d) => d.id === "github"));
      assert.ok(existsSync(root));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
