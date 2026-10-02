/**
 * The tailnet broker (src/broker.ts): who may call, what they can reach, and
 * that a credential is used on the broker and never returned.
 *
 * `whois` is injected, so no tailnet is needed: the broker listens on
 * 127.0.0.1 and the stand-in decides who that address "is". A local echo
 * server plays the provider's API (hush allows http to loopback).
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Vault } from "../src/vault.ts";
import { generateIdentity } from "../src/crypto.ts";
import { DEFAULT_POLICY } from "../src/mcp.ts";
import { createBroker } from "../src/broker.ts";
import { admits, cachedWhois, parseSelfIPv4, parseWhois, type TailnetCaller } from "../src/tailscale.ts";

const SECRET = "sk_" + "live_Broker7Tz2Lp9Wx4Mn6Kb3";
const OTHER = "never-offered-Qz81Lm02Np93";
const ME: TailnetCaller = { login: "me@example.com", node: "laptop.tail1234.ts.net", tags: [], caps: {} };

let dir: string;
let upstream: Server;
let upstreamUrl: string;
const seenByUpstream: string[] = [];

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "hush-broker-"));
  process.env.HUSH_HOME = join(dir, "home");
  process.env.HUSH_NO_DIALOG = "1";
  process.env.HUSH_BIOMETRY = "off";
  // The "provider": echoes back the Authorization header it received.
  upstream = createServer((req, res) => {
    seenByUpstream.push(String(req.headers.authorization ?? ""));
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, youSent: req.headers.authorization }));
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}/v1/charges`;
});

after(() => {
  upstream.close();
  rmSync(dir, { recursive: true, force: true });
});

async function broker(opts: { who?: TailnetCaller | null; allow?: string[]; approval?: boolean } = {}) {
  const id = generateIdentity();
  const path = join(mkdtempSync(join(dir, "v-")), "vault.json");
  const vault = Vault.create(path, "lib", { name: "me", pub: id.pub });
  vault.set(id, "stripe-live", "STRIPE_SECRET_KEY", SECRET);
  vault.set(id, "private", "OTHER_KEY", OTHER);
  vault.save();
  const hushDir = join(path, "..");
  const policy = { ...DEFAULT_POLICY, requireApproval: opts.approval ? ["request"] : [] };
  const server = createBroker({
    base: { vault: Vault.open(path), hushDir, policy, identity: { ...id, source: "test" } as never, root: hushDir, defaultEnv: "stripe-live" },
    sets: ["stripe-live"],
    allow: opts.allow ?? ["me@example.com"],
    whois: async () => (opts.who === undefined ? ME : opts.who),
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`;
  let n = 0;
  const rpc = async (method: string, params: unknown = {}, headers: Record<string, string> = {}) => {
    const r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++n, method, params }),
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return { status: r.status, body: (r.status === 202 ? null : await r.json()) as any };
  };
  const call = async (name: string, args: unknown = {}) => {
    const r = await rpc("tools/call", { name, arguments: args });
    const text = (r.body?.result?.content ?? []).map((c: { text: string }) => c.text).join("\n");
    return { ...r, text, isError: Boolean(r.body?.result?.isError) };
  };
  return { server, url, rpc, call, hushDir, close: () => server.close() };
}

test("only a tailnet peer on the allow-list gets an answer", async () => {
  const stranger = await broker({ who: null });
  try {
    assert.equal((await stranger.rpc("tools/list")).status, 403);
  } finally {
    stranger.close();
  }
  const other = await broker({ who: { ...ME, login: "someone@else.com" } });
  try {
    const r = await other.rpc("tools/list");
    assert.equal(r.status, 403);
    assert.match(JSON.stringify(r.body), /someone@else\.com on laptop is not allowed/);
  } finally {
    other.close();
  }
  const tagged = await broker({ who: { ...ME, login: "tagged-devices", tags: ["tag:ci"] }, allow: ["tag:ci"] });
  try {
    assert.equal((await tagged.rpc("tools/list")).status, 200);
  } finally {
    tagged.close();
  }
});

test("a browser is refused, and so is anything but a JSON POST to /mcp", async () => {
  const b = await broker();
  try {
    assert.equal((await b.rpc("tools/list", {}, { origin: "https://evil.example" })).status, 403);
    assert.equal((await fetch(b.url)).status, 405);
    assert.equal((await fetch(b.url.replace("/mcp", "/other"), { method: "POST" })).status, 404);
    const text = await fetch(b.url, { method: "POST", headers: { "content-type": "text/plain" }, body: "{}" });
    assert.equal(text.status, 415);
  } finally {
    b.close();
  }
});

test("an agent sees the offered sets and key names, never a value", async () => {
  const b = await broker();
  try {
    const init = await b.rpc("initialize", { protocolVersion: "2025-06-18" });
    assert.equal(init.body.result.serverInfo.name, "hush-broker");
    assert.equal((await b.rpc("notifications/initialized")).status, 202);
    const tools = (await b.rpc("tools/list")).body.result.tools.map((t: { name: string }) => t.name);
    assert.deepEqual(tools, ["hush_list_sets", "hush_request"]);
    const list = await b.call("hush_list_sets");
    assert.match(list.text, /stripe-live: STRIPE_SECRET_KEY/);
    assert.ok(!list.text.includes("private"), "a set that is not offered was listed");
    assert.ok(!list.text.includes(SECRET));
  } finally {
    b.close();
  }
});

test("hush_request sends the credential from the broker and returns the response redacted", async () => {
  const b = await broker();
  try {
    seenByUpstream.length = 0;
    const r = await b.call("hush_request", { url: upstreamUrl, headers: { Authorization: "Bearer $STRIPE_SECRET_KEY" } });
    assert.equal(r.isError, false, r.text);
    assert.deepEqual(seenByUpstream, [`Bearer ${SECRET}`], "the provider did not get the real key");
    assert.ok(!r.text.includes(SECRET), "the key came back to the caller");
    assert.match(r.text, /\[redacted:STRIPE_SECRET_KEY\]/);
    const log = readFileSync(join(b.hushDir, "audit.log"), "utf8");
    assert.match(log, /"caller":"me@example\.com on laptop"/);
    assert.ok(!log.includes(SECRET));
  } finally {
    b.close();
  }
});

test("a set the broker does not offer, and every other tool, are refused", async () => {
  const b = await broker();
  try {
    seenByUpstream.length = 0;
    const r = await b.call("hush_request", { url: upstreamUrl, headers: { Authorization: "Bearer $OTHER_KEY" }, sets: ["private"] });
    assert.equal(r.isError, true);
    assert.match(r.text, /Not offered by this broker: private/);
    assert.equal(seenByUpstream.length, 0);
    for (const name of ["hush_run", "hush_add_secret", "hush_describe_secret", "hush_list_secrets"]) {
      const t = await b.call(name, { command: "env", key: "X" });
      assert.equal(t.isError, true, name);
      assert.match(t.text, /not offered/, name);
    }
  } finally {
    b.close();
  }
});

test("with approval required and nobody to ask, nothing is sent", async () => {
  const b = await broker({ approval: true });
  try {
    seenByUpstream.length = 0;
    const r = await b.call("hush_request", { url: upstreamUrl, headers: { Authorization: "Bearer $STRIPE_SECRET_KEY" } });
    assert.equal(r.isError, true, r.text);
    assert.equal(seenByUpstream.length, 0, "the credential went out without an approval");
  } finally {
    b.close();
  }
});

test("whois parsing and the allow-list: a tagged device is never a user", () => {
  const user = parseWhois(JSON.stringify({ Node: { Name: "box.t.ts.net." }, UserProfile: { LoginName: "me@example.com" }, CapMap: {} }))!;
  assert.deepEqual(user, { login: "me@example.com", node: "box.t.ts.net", tags: [], caps: {} });
  const ci = parseWhois(JSON.stringify({ Node: { Name: "ci.t.ts.net.", Tags: ["tag:ci"] }, UserProfile: { LoginName: "tagged-devices" } }))!;
  assert.ok(admits(["tag:ci"], ci));
  assert.ok(!admits(["tagged-devices"], ci), "the placeholder login admitted a tagged device");
  assert.ok(admits(["box.t.ts.net"], user));
  assert.ok(!admits(["tag:ci"], user));
  assert.equal(parseWhois("{}"), null);
});

test("identity is looked up once a minute per address, and a stranger is re-checked soon", async () => {
  let calls = 0;
  const lookup = cachedWhois(async (addr) => {
    calls++;
    return addr === "100.64.0.1" ? ME : null;
  });
  await lookup("100.64.0.1");
  await lookup("100.64.0.1");
  assert.equal(calls, 1, "a known peer was looked up twice within the minute");
  await lookup("100.64.0.9");
  await lookup("100.64.0.9");
  assert.equal(calls, 2, "an unknown address is cached briefly too, not hammered");
});

test("the broker's address comes from the node's own status: a tailnet IPv4, nothing else", () => {
  const status = (ips: string[], state = "Running") => JSON.stringify({ BackendState: state, Self: { TailscaleIPs: ips } });
  assert.equal(parseSelfIPv4(status(["100.100.113.66", "fd7a:115c:a1e0::1"])), "100.100.113.66");
  assert.equal(parseSelfIPv4(status(["fd7a:115c:a1e0::1"])), null);
  assert.equal(parseSelfIPv4(status(["192.168.1.5"])), null, "a LAN address is not the tailnet");
  assert.equal(parseSelfIPv4(status(["100.100.113.66"], "Stopped")), null);
});

// ------------------------------------------------------------------ https, sessions, routing

import { spawnSync } from "node:child_process";
import { request as httpsRequest } from "node:https";
import { createServer as createSocketServer } from "node:http";
import { approversFor, savePeer } from "../src/relay.ts";
import { whoisLocalApi } from "../src/tailscale.ts";

/** A throwaway certificate for 127.0.0.1, or null where openssl cannot make one. */
function selfSigned(): { cert: string; key: string } | null {
  const d = mkdtempSync(join(dir, "tls-"));
  const r = spawnSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
    "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
    "-keyout", join(d, "k.pem"), "-out", join(d, "c.pem"),
  ], { encoding: "utf8" });
  if (r.status !== 0) return null;
  return { cert: readFileSync(join(d, "c.pem"), "utf8"), key: readFileSync(join(d, "k.pem"), "utf8") };
}

test("with a certificate, the broker speaks https, and the same rules hold", async (t) => {
  const tls = selfSigned();
  if (!tls) return t.skip("openssl cannot make a certificate here");
  const id = generateIdentity();
  const path = join(mkdtempSync(join(dir, "v-")), "vault.json");
  const vault = Vault.create(path, "lib", { name: "me", pub: id.pub });
  vault.set(id, "stripe-live", "STRIPE_SECRET_KEY", SECRET);
  vault.save();
  const hushDir = join(path, "..");
  const server = createBroker({
    base: { vault: Vault.open(path), hushDir, policy: { ...DEFAULT_POLICY, requireApproval: [] }, identity: { ...id, source: "test" } as never, root: hushDir, defaultEnv: "stripe-live" },
    sets: ["stripe-live"], allow: ["me@example.com"], whois: async () => ME, tls,
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const port = (server.address() as AddressInfo).port;
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    const reply = await new Promise<{ status: number; text: string }>((resolve, reject) => {
      const req = httpsRequest({ host: "127.0.0.1", port, path: "/mcp", method: "POST", ca: tls.cert, headers: { "content-type": "application/json" } }, (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text }));
      });
      req.on("error", reject);
      req.end(body);
    });
    assert.equal(reply.status, 200);
    assert.match(reply.text, /hush_request/);
    // Plain http to an https broker gets nothing useful.
    const plain = await fetch(`http://127.0.0.1:${port}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body }).catch(() => null);
    assert.ok(!plain || plain.status !== 200);
  } finally {
    server.close();
  }
});

test("the app's own name is kept for its session, as a hint, and only for the device that started it", async () => {
  const b = await broker();
  try {
    const init = await fetch(b.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "claude-code" } } }),
    });
    const sid = init.headers.get("mcp-session-id");
    assert.match(String(sid), /^[0-9a-f]{32}$/);
    await fetch(b.url, {
      method: "POST",
      headers: { "content-type": "application/json", "mcp-session-id": String(sid) },
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "hush_list_sets", arguments: {} } }),
    });
    const log = readFileSync(join(b.hushDir, "audit.log"), "utf8");
    assert.match(log, /me@example\.com on laptop \(says it is claude-code\)/);
  } finally {
    b.close();
  }
});

test("a device paired for a person answers that person's broker requests, and nobody else's", () => {
  const box = (n: number) => "A".repeat(42) + String(n);
  const peer = (name: string, n: number, forLogins?: string[]) => ({
    kind: "approver" as const, name, relay: "https://relay.example", toApprover: box(n), toRequester: box(n + 1),
    x: `x${n}`, spk: `spk${n}`, pairedAt: new Date().toISOString(), ...(forLogins ? { for: forLogins } : {}),
  });
  savePeer(peer("owner-laptop", 1));
  savePeer(peer("sam-phone", 3, ["sam@example.com"]));
  const names = (login?: string) => approversFor(login).map((p) => p.name);
  assert.deepEqual(names("sam@example.com"), ["sam-phone"], "Sam's request did not go to Sam");
  assert.deepEqual(names("alex@example.com"), ["owner-laptop"], "someone without a device should fall back to the owner's");
  assert.deepEqual(names(), ["owner-laptop"], "an ordinary approval reached a device paired for one person");
});

test("on Linux, whois asks tailscaled over its socket and reads the same answer", async (t) => {
  if (process.platform === "win32") return t.skip("no unix sockets");
  const sock = join(mkdtempSync(join("/tmp", "hush-ts-")), "s.sock");
  const daemon = createSocketServer((req, res) => {
    if (req.headers.host !== "local-tailscaled.sock" || !req.url?.startsWith("/localapi/v0/whois?addr=100.64.0.7")) {
      res.writeHead(403);
      return res.end();
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ Node: { Name: "box.t.ts.net.", Tags: [] }, UserProfile: { LoginName: "me@example.com" }, CapMap: {} }));
  });
  daemon.listen(sock);
  await once(daemon, "listening");
  try {
    assert.deepEqual(await whoisLocalApi("100.64.0.7", sock), { login: "me@example.com", node: "box.t.ts.net", tags: [], caps: {} });
    assert.equal(await whoisLocalApi("100.64.0.8", sock), null, "a refused lookup must be no answer");
    assert.equal(await whoisLocalApi("100.64.0.7", sock + ".gone"), null);
  } finally {
    daemon.close();
  }
});
