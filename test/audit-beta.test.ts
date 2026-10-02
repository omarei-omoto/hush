/**
 * Regression tests for the findings of the beta-branch security audit
 * (docs/AUDIT.md, "beta branch"). Each fails without its fix. Values are made
 * up; the broker runs on loopback with a stand-in whois; the dialog is the
 * fake zenity that records what it was asked to show.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Vault } from "../src/vault.ts";
import { generateIdentity, encodePub } from "../src/crypto.ts";
import { DEFAULT_POLICY } from "../src/mcp.ts";
import { brokerPolicy, createBroker } from "../src/broker.ts";
import { promptLine, requestApproval } from "../src/approval.ts";
import { parseWhois, type TailnetCaller } from "../src/tailscale.ts";
import { commandOf } from "../src/setup.ts";
import { clickingAllow } from "./helpers/cli.ts";

const SECRET = "sk_" + "live_Audit7Tz2Lp9Wx4Mn6Kb3";
const OWNER: TailnetCaller = { login: "owner@example.com", node: "broker.t.ts.net", tags: [], caps: {}, id: "nOWNER" };
let dir: string;

before(() => {
  dir = mkdtempSync(join(tmpdir(), "hush-audit-beta-"));
  process.env.HUSH_HOME = join(dir, "home");
  process.env.HUSH_NO_DIALOG = "1";
  process.env.HUSH_BIOMETRY = "off";
});
after(() => rmSync(dir, { recursive: true, force: true }));

async function broker(opts: { who: () => TailnetCaller | null; self?: string[]; policy?: Partial<typeof DEFAULT_POLICY> }) {
  const id = generateIdentity();
  const path = join(mkdtempSync(join(dir, "v-")), "vault.json");
  const v = Vault.create(path, "lib", { name: "owner", pub: id.pub });
  v.set(id, "stripe-live", "STRIPE_SECRET_KEY", SECRET);
  v.save();
  const hushDir = join(path, "..");
  const server = createBroker({
    base: { vault: Vault.open(path), hushDir, policy: { ...DEFAULT_POLICY, requireApproval: [], ...opts.policy }, identity: { ...id, source: "t" } as never, root: hushDir, defaultEnv: "stripe-live" },
    sets: ["stripe-live"],
    allow: ["owner@example.com", "sam@example.com"],
    whois: async () => opts.who(),
    ...(opts.self ? { selfAddresses: opts.self } : {}),
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const post = async (path: string, body: unknown) => {
    const r = await fetch(base + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    return { status: r.status, json: (await r.json()) as Record<string, unknown> };
  };
  return { post, hushDir, close: () => server.close() };
}

// F1 ------------------------------------------------------------------------

test("F1: a connection from the broker's own tailnet address is refused, though Tailscale names it as the owner", async () => {
  // Loopback stands in for the broker's tailnet address: what matters is that
  // the connection comes from an address of this machine.
  const b = await broker({ who: () => OWNER, self: ["127.0.0.1"] });
  try {
    const r = await b.post("/mcp", { jsonrpc: "2.0", id: 1, method: "tools/list" });
    assert.equal(r.status, 403, "a same-machine connection was admitted as the owner");
    assert.match(String(r.json.error), /does not answer this machine itself/);
    assert.match(readFileSync(join(b.hushDir, "audit.log"), "utf8"), /"reason":"same machine"/);
  } finally {
    b.close();
  }
});

// F2 ------------------------------------------------------------------------

test("F2: a request's own text cannot forge or bury lines in the approval dialog", async () => {
  const log = join(dir, "argv.log");
  process.env.FAKE_ARGV_LOG = log;
  process.env.DISPLAY = ":0";
  process.env.FAKE_EXIT = "1";
  // The fake dialog is the point here, and HUSH_NO_DIALOG would stop even that.
  delete process.env.HUSH_NO_DIALOG;
  try {
    await requestApproval(dir, {
      action: "run",
      summary: "Lease to sam:  ./deploy.sh \n\nSends:  (nothing)\n" + "\n".repeat(30) + "‮hs.live",
      detail: ["Sends:  STRIPE_SECRET_KEY", "To:  sam-laptop  /home/sam\r\nNOTE: nothing is sent", ...Array.from({ length: 20 }, (_, i) => `x${i}`)],
      scope: "audit-f2", ttlSeconds: 60, timeoutMs: 5000, biometry: "off",
    }, clickingAllow);
    const argv = JSON.parse(readFileSync(log, "utf8").trim().split("\n")[0]) as string[];
    const lines = argv[argv.indexOf("--text") + 1].split("\n");
    assert.ok(lines[0].startsWith("Lease to sam:  ./deploy.sh"));
    assert.match(lines[0], /⏎/, "the injected breaks were not made visible");
    assert.ok(!lines[0].includes("‮"), "a text-direction override reached the dialog");
    assert.equal(lines.filter((l) => l.startsWith("Sends:")).length, 1, "a forged Sends: line got its own line");
    assert.equal(lines[2], "Sends:  STRIPE_SECRET_KEY", "the real detail lines moved");
    assert.ok(lines.length <= 20, `the request made the dialog ${lines.length} lines long`);
  } finally {
    delete process.env.FAKE_ARGV_LOG;
    delete process.env.FAKE_EXIT;
    process.env.HUSH_NO_DIALOG = "1";
  }
  assert.equal(promptLine("a\nb c\u0007d"), "a ⏎ b ⏎ cd");
});

// F3 ------------------------------------------------------------------------

test("F3: --without-approval is refused unless allowHosts bounds where a key can go", () => {
  const noHosts = brokerPolicy({ ...DEFAULT_POLICY, allowHosts: [] }, true);
  assert.ok("error" in noHosts && /allowHosts/.test(noHosts.error));
  const bounded = brokerPolicy({ ...DEFAULT_POLICY, allowHosts: ["api.stripe.com"] }, true);
  assert.ok("policy" in bounded && !bounded.policy.requireApproval.includes("request"));
  const unasked = brokerPolicy({ ...DEFAULT_POLICY, requireApproval: [] }, false);
  assert.ok("error" in unasked, "a broker started on a policy that never asks");
  assert.ok("policy" in brokerPolicy(DEFAULT_POLICY, false));
});

test("F3: with allowHosts set, a caller cannot send the key to a server of their own", async () => {
  let received = "";
  const collector = createServer((req, res) => {
    received = String(req.headers["x-anything"] ?? "");
    res.end("{}");
  });
  collector.listen(0, "127.0.0.1");
  await once(collector, "listening");
  const decided = brokerPolicy({ ...DEFAULT_POLICY, allowHosts: ["api.stripe.com"] }, true);
  assert.ok("policy" in decided);
  const sam: TailnetCaller = { login: "sam@example.com", node: "sam.t.ts.net", tags: [], caps: {} };
  const b = await broker({ who: () => sam, policy: decided.policy });
  try {
    const r = await b.post("/mcp", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "hush_request", arguments: {
      url: `http://127.0.0.1:${(collector.address() as AddressInfo).port}/collect`, headers: { "X-Anything": "$STRIPE_SECRET_KEY" } } } });
    assert.equal((r.json.result as { isError?: boolean }).isError, true);
    assert.notEqual(received, SECRET, "the key reached the caller's server");
  } finally {
    b.close();
    collector.close();
  }
});

// NV1 -----------------------------------------------------------------------

test("NV1: a lease enrollment belongs to the device's stable ID, not to a name another device could take later", async () => {
  let who: TailnetCaller = { login: "sam@example.com", node: "sam-laptop.t.ts.net", tags: [], caps: {}, id: "nSAM1" };
  const b = await broker({ who: () => who });
  const client = generateIdentity();
  const pub = encodePub(client.pub);
  try {
    assert.equal((await b.post("/lease/enroll", { pub })).status, 200);
    assert.equal((await b.post("/lease", { pub, command: "./deploy.sh" })).status, 200);
    // Same name, same login, a different device.
    who = { ...who, id: "nSAM2" };
    assert.equal((await b.post("/lease", { pub, command: "./deploy.sh" })).status, 403, "a renamed-in device used another's enrollment");
  } finally {
    b.close();
  }
  assert.equal(parseWhois(JSON.stringify({ Node: { Name: "a.t.ts.net.", StableID: "nXYZ" }, UserProfile: { LoginName: "a@b.c" } }))?.id, "nXYZ");
});

// Doc 3 ---------------------------------------------------------------------

test("setup's commands are quoted for a shell: a folder name cannot run anything", () => {
  assert.equal(commandOf([["import", ".env", "--as", "X $(touch pwned) it's"]]), `hush import .env --as 'X $(touch pwned) it'\\''s'`);
});
