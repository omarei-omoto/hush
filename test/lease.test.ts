/**
 * Leases (src/lease.ts, the broker's /lease endpoints, `hush run --from`):
 * the one broker path where a value leaves the broker, so every fence is
 * pinned here. Made-up values; whois is a stand-in; no tailnet needed.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { generateIdentity, encodePub } from "../src/crypto.ts";
import { Vault } from "../src/vault.ts";
import { DEFAULT_POLICY } from "../src/mcp.ts";
import { createBroker } from "../src/broker.ts";
import { openLease, sealLease, LEASE_TTL_MS, type SealedLease } from "../src/lease.ts";
import type { TailnetCaller } from "../src/tailscale.ts";
import { bareFolder, CLI } from "./helpers/cli.ts";
import { spawn } from "node:child_process";

/**
 * Run the CLI without blocking this process: the broker it talks to lives in
 * this process, and bareFolder's run() is synchronous, which would deadlock.
 */
function runAsync(cwd: string, env: NodeJS.ProcessEnv, args: string[]): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (c) => (out += c));
    child.stderr.on("data", (c) => (out += c));
    const timer = setTimeout(() => child.kill(), 30_000);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, out });
    });
  });
}

const SECRET = "sk_" + "live_Lease7Tz2Lp9Wx4Mn6Kb3";
const ME: TailnetCaller = { login: "me@example.com", node: "vps.t.ts.net", tags: [], caps: {} };
let dir: string;

before(() => {
  dir = mkdtempSync(join(tmpdir(), "hush-lease-"));
  process.env.HUSH_HOME = join(dir, "home");
  process.env.HUSH_NO_DIALOG = "1";
  process.env.HUSH_BIOMETRY = "off";
});
after(() => rmSync(dir, { recursive: true, force: true }));

// ------------------------------------------------------------------ the envelope

test("a lease opens only on the machine it was sealed for, only for the command asked, only before it expires", () => {
  const client = generateIdentity();
  const stranger = generateIdentity();
  const want = { command: "./deploy.sh", args: ["--prod"] };
  const lease = sealLease({ ...want, sets: ["stripe-live"], secrets: { STRIPE_SECRET_KEY: SECRET } }, client.pub);
  assert.equal(openLease(lease, client, want).secrets.STRIPE_SECRET_KEY, SECRET);
  assert.throws(() => openLease(lease, stranger, want), "another machine's key opened it");
  assert.throws(() => openLease(lease, client, { command: "./deploy.sh", args: ["--other"] }), /different command/);
  assert.throws(() => openLease(lease, client, want, Date.now() + LEASE_TTL_MS + 1), /expired/);
  const tampered: SealedLease = { ...lease, sealed: { ...lease.sealed, ct: Buffer.from("x".repeat(40)).toString("base64") } };
  assert.throws(() => openLease(tampered, client, want));
  // The id is bound into the ciphertext: a lease cannot be passed off under another id.
  assert.throws(() => openLease({ ...lease, id: "0".repeat(32) }, client, want));
});

// ------------------------------------------------------------------ the broker

async function brokerWith(opts: { who?: TailnetCaller; approve?: string[] } = {}) {
  const owner = generateIdentity();
  const path = join(mkdtempSync(join(dir, "v-")), "vault.json");
  const vault = Vault.create(path, "lib", { name: "me", pub: owner.pub });
  vault.set(owner, "stripe-live", "STRIPE_SECRET_KEY", SECRET);
  vault.set(owner, "private", "OTHER", "never-leased-Qz81Lm02Np93");
  vault.save();
  const hushDir = join(path, "..");
  let who = opts.who ?? ME;
  const server = createBroker({
    base: { vault: Vault.open(path), hushDir, policy: { ...DEFAULT_POLICY, requireApproval: opts.approve ?? [] }, identity: { ...owner, source: "test" } as never, root: hushDir, defaultEnv: "stripe-live" },
    sets: ["stripe-live"],
    allow: ["me@example.com"],
    whois: async () => who,
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const post = async (path: string, body: unknown) => {
    const r = await fetch(base + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    return { status: r.status, json: (await r.json()) as Record<string, unknown> };
  };
  return { base, post, hushDir, as: (c: TailnetCaller) => (who = c), close: () => server.close() };
}

test("the broker leases only to an enrolled key, from the device that enrolled it, for allowed commands and sets", async () => {
  const b = await brokerWith();
  const client = generateIdentity();
  const pub = encodePub(client.pub);
  try {
    const before = await b.post("/lease", { pub, command: "./deploy.sh", args: [] });
    assert.equal(before.status, 403);
    assert.equal(before.json.enroll, true);

    assert.equal((await b.post("/lease/enroll", { pub, name: "vps" })).status, 200);

    const ok = await b.post("/lease", { pub, command: "./deploy.sh", args: ["--prod"] });
    assert.equal(ok.status, 200, JSON.stringify(ok.json));
    assert.ok(!JSON.stringify(ok.json).includes(SECRET), "the value travelled in the clear");
    const payload = openLease(ok.json as unknown as SealedLease, client, { command: "./deploy.sh", args: ["--prod"] });
    assert.deepEqual(payload.secrets, { STRIPE_SECRET_KEY: SECRET });

    const shell = await b.post("/lease", { pub, command: "sh", args: ["-c", "echo $STRIPE_SECRET_KEY"] });
    assert.equal(shell.status, 403, "a shell got a lease");
    const other = await b.post("/lease", { pub, command: "./deploy.sh", sets: ["private"] });
    assert.equal(other.status, 403, "a set that is not offered was leased");

    // The same key, offered from another device: not this enrollment.
    b.as({ ...ME, node: "someone-else.t.ts.net" });
    assert.equal((await b.post("/lease", { pub, command: "./deploy.sh" })).status, 403);
  } finally {
    b.close();
  }
});

test("with approvals on and nobody to ask, no machine is enrolled and nothing is leased", async () => {
  const b = await brokerWith({ approve: ["add", "run"] });
  const client = generateIdentity();
  try {
    assert.equal((await b.post("/lease/enroll", { pub: encodePub(client.pub) })).status, 403);
  } finally {
    b.close();
  }
});

// ------------------------------------------------------------------ the CLI

test("hush lease enroll, then hush run --from: the command gets the value, its output does not show it", { skip: process.platform === "win32" }, async () => {
  const b = await brokerWith();
  const f = bareFolder();
  try {
    const enrolled = await runAsync(f.root, f.env, ["lease", "enroll", b.base]);
    assert.equal(enrolled.code, 0, enrolled.out);
    assert.match(enrolled.out, /enrolled/);

    const script = join(f.root, "show.sh");
    writeFileSync(script, '#!/bin/sh\necho "len=${#STRIPE_SECRET_KEY}"\necho "value=$STRIPE_SECRET_KEY"\n');
    chmodSync(script, 0o755);
    const r = await runAsync(f.root, f.env, ["run", "--from", b.base, "--", script]);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, new RegExp(`len=${SECRET.length}`));
    assert.match(r.out, /value=\[redacted:STRIPE_SECRET_KEY\]/);
    assert.ok(!r.out.includes(SECRET));

    const notEnrolled = bareFolder();
    try {
      const refused = await runAsync(notEnrolled.root, notEnrolled.env, ["run", "--from", b.base, "--", script]);
      assert.notEqual(refused.code, 0);
      assert.match(refused.out, /hush lease enroll/);
    } finally {
      notEnrolled.cleanup?.();
    }
  } finally {
    b.close();
    f.cleanup?.();
  }
});
