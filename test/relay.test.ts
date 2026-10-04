/**
 * The approval relay (F-4): approvals for a machine with no one at it.
 *
 * The four refusals the plan names are the headline — a replayed answer, an
 * answer for a different request, an answer signed by a key that was never
 * paired, and a relay that alters the request — plus the pairing itself, run
 * through the real CLI on two "machines" (two HUSH_HOMEs) and a real relay.
 */
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, statSync } from "node:fs";
import { tmpdir, platform } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

import { CLI } from "./helpers/cli.ts";
import { createRelayServer } from "../src/relay-server.ts";
import {
  checkRelayUrl, decodePairingCode, encodePairingCode, httpTransport, listenForRequests, loadDevice, loadPeers, makeAnswer,
  makeHello, makeRequest, openAnswer, openHello, openRequest, pairingKeys, savePeer, setRelayTransportForTests,
  type Device, type Peer, type RelayTransport,
} from "../src/relay.ts";
import { requestApproval, approvalPromptAvailable, clearApprovalCache } from "../src/approval.ts";
import { encodePub, encodeSpk, generateIdentity, signerFromSeed } from "../src/crypto.ts";
import { qrMatrix, qrToTerminal } from "../src/qr.ts";

// ---------------------------------------------------------------- helpers

let server: Server;
let relay: string;
before(async () => {
  server = createRelayServer({ maxPerBox: 8, maxBodyBytes: 4096 });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  relay = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => {
  setRelayTransportForTests(null);
  server.close();
  server.closeAllConnections();
});

const savedHome = process.env.HUSH_HOME;
/** Run `fn` as the machine whose ~/.hush is `home`. relay.ts reads HUSH_HOME at each call. */
function as<T>(home: string, fn: () => T): T {
  process.env.HUSH_HOME = home;
  try {
    return fn();
  } finally {
    process.env.HUSH_HOME = savedHome;
  }
}

/** Two machines, paired in-process: a requester (a server) and an approver (a laptop). */
function pairedPair() {
  const requesterHome = mkdtempSync(join(tmpdir(), "hush-relay-req-"));
  const approverHome = mkdtempSync(join(tmpdir(), "hush-relay-app-"));
  const requester = as(requesterHome, () => loadDevice(true)!);
  const approver = as(approverHome, () => loadDevice(true)!);
  const boxes = pairingKeys(randomBytes(32));
  const base = { relay, toApprover: boxes.toApprover, toRequester: boxes.toRequester, pairedAt: new Date().toISOString() };
  const approverPeer: Peer = { ...base, kind: "approver", name: "laptop", x: encodePub(approver.x.pub), spk: encodeSpk(approver.signer.spk) };
  const requesterPeer: Peer = { ...base, kind: "requester", name: "server", x: encodePub(requester.x.pub), spk: encodeSpk(requester.signer.spk) };
  as(requesterHome, () => savePeer(approverPeer));
  as(approverHome, () => savePeer(requesterPeer));
  return {
    requesterHome, approverHome, requester, approver, approverPeer, requesterPeer,
    cleanup: () => {
      rmSync(requesterHome, { recursive: true, force: true });
      rmSync(approverHome, { recursive: true, force: true });
    },
  };
}

const fields = (over: Partial<Parameters<typeof makeRequest>[2]> = {}) => ({
  action: "run", summary: "run npm test", detail: ["sets: default"], code: "4821", ttlSeconds: 900, biometry: false,
  timeoutMs: 60_000, ...over,
});

/** A stranger's device: keys that were never paired with anyone. */
const stranger = (): Device => ({ x: generateIdentity(), signer: signerFromSeed(randomBytes(32)) });

/** No dialog program, no fingerprint: the machine nobody is sitting at. */
const headless = {
  authenticate: async () => "unavailable" as const,
  platform: () => "linux",
  resolveDialogProgram: () => null,
};

/**
 * The CLI as another process. Asynchronous on purpose: the relay runs in this
 * process, and spawnSync would stop it answering the child.
 */
function cli(home: string, args: string[]): Promise<{ out: string; code: number | null }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { ...process.env, HUSH_HOME: home, HOME: home, HUSH_NO_KEYCHAIN: "1", NO_COLOR: "1", HUSH_NO_NUDGE: "1" },
    });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (out += d));
    child.on("close", (code) => resolve({ out, code }));
  });
}

// ---------------------------------------------------------------- the relay

describe("hush relay serve — the mailbox", () => {
  const box = () => randomBytes(32).toString("base64url");

  test("messages are read in order, after a cursor, and reading does not consume them", async () => {
    const b = box();
    await httpTransport.post(relay, b, "one");
    await httpTransport.post(relay, b, "two");
    const all = await httpTransport.read(relay, b, 0, 0);
    assert.deepEqual(all.messages.map((m) => m.body), ["one", "two"]);
    const later = await httpTransport.read(relay, b, all.messages[0].seq, 0);
    assert.deepEqual(later.messages.map((m) => m.body), ["two"]);
    const again = await httpTransport.read(relay, b, 0, 0);
    assert.equal(again.messages.length, 2, "a read consumed messages another reader needs");
    assert.equal(again.next, all.messages[1].seq);
  });

  test("a read with nothing to return waits, up to what it asked for", async () => {
    const started = Date.now();
    const got = await httpTransport.read(relay, box(), 0, 1);
    assert.equal(got.messages.length, 0);
    assert.ok(Date.now() - started >= 900, "a long poll returned at once, so every listener spins");
  });

  test("a waiting read wakes when a message arrives", async () => {
    const b = box();
    const started = Date.now();
    const pending = httpTransport.read(relay, b, 0, 10);
    setTimeout(() => void httpTransport.post(relay, b, "hi"), 200);
    const got = await pending;
    assert.deepEqual(got.messages.map((m) => m.body), ["hi"]);
    assert.ok(Date.now() - started < 5000, "the read waited out its whole timeout");
  });

  test("it is bounded: message size, messages per box, box id shape", async () => {
    const b = box();
    const big = await fetch(`${relay}/v1/boxes/${b}`, { method: "POST", body: JSON.stringify({ body: "x".repeat(5000) }) });
    assert.ok(big.status === 400 || big.status === 413, `an oversized message was accepted (${big.status})`);
    for (let i = 0; i < 12; i++) await httpTransport.post(relay, b, `m${i}`);
    const kept = await httpTransport.read(relay, b, 0, 0);
    assert.equal(kept.messages.length, 8);
    assert.equal(kept.messages[0].body, "m4", "the oldest were not the ones dropped");
    assert.equal((await fetch(`${relay}/v1/boxes/short`)).status, 404);
    assert.equal((await fetch(`${relay}/v1/boxes/${b}`, { method: "DELETE" })).status, 405);
  });
});

// ---------------------------------------------------------------- the protocol

describe("requests and answers", () => {
  test("a request opens for the paired approver, and its answer for the requester", () => {
    const p = pairedPair();
    const made = makeRequest(p.requester, p.approverPeer, fields());
    const opened = openRequest(p.approver, p.requesterPeer, made.wire);
    assert.ok(opened);
    assert.equal(opened.request.summary, "run npm test");
    assert.equal(opened.request.code, "4821");
    const answer = makeAnswer(p.approver, p.requesterPeer, opened, "once", "dialog");
    const got = openAnswer(p.requester, [p.approverPeer], made, answer);
    assert.equal(got?.answer.decision, "once");
    p.cleanup();
  });

  test("a replayed answer is refused: it answers an earlier request", () => {
    const p = pairedPair();
    const first = makeRequest(p.requester, p.approverPeer, fields());
    const opened = openRequest(p.approver, p.requesterPeer, first.wire)!;
    const yes = makeAnswer(p.approver, p.requesterPeer, opened, "once", "dialog");
    const second = makeRequest(p.requester, p.approverPeer, fields());
    assert.equal(openAnswer(p.requester, [p.approverPeer], second, yes), null, "yesterday's Allow approved today's request");
    p.cleanup();
  });

  test("an answer for a different request id is refused, even with the right hash", () => {
    const p = pairedPair();
    const made = makeRequest(p.requester, p.approverPeer, fields());
    const opened = openRequest(p.approver, p.requesterPeer, made.wire)!;
    const forged = makeAnswer(p.approver, p.requesterPeer, { ...opened, request: { ...opened.request, id: "someone-elses-request-id" } }, "once", "dialog");
    assert.equal(openAnswer(p.requester, [p.approverPeer], made, forged), null);
    p.cleanup();
  });

  test("an answer signed by a key that was never paired is refused", () => {
    const p = pairedPair();
    const made = makeRequest(p.requester, p.approverPeer, fields());
    const opened = openRequest(p.approver, p.requesterPeer, made.wire)!;
    // Sealed to the requester correctly — anyone can do that with its public key — but signed by a stranger.
    const forged = makeAnswer(stranger(), p.requesterPeer, opened, "once", "dialog");
    assert.equal(openAnswer(p.requester, [p.approverPeer], made, forged), null);
    p.cleanup();
  });

  test("a relay that alters the request gets nothing the approver will show", () => {
    const p = pairedPair();
    const made = makeRequest(p.requester, p.approverPeer, fields());
    // Flip bits in the ciphertext…
    const sealed = JSON.parse(made.wire) as { ct: string };
    const ct = Buffer.from(sealed.ct, "base64url");
    ct[5] ^= 0x01;
    assert.equal(openRequest(p.approver, p.requesterPeer, JSON.stringify({ ...sealed, ct: ct.toString("base64url") })), null);
    // …or write a request of its own — "run a harmless thing" — sealed to the approver it can see.
    const own = makeRequest(stranger(), p.approverPeer, fields({ summary: "run npm test (harmless)" }));
    assert.equal(openRequest(p.approver, p.requesterPeer, own.wire), null, "the approver showed a request the relay wrote");
    p.cleanup();
  });

  test("an answer to an altered request does not answer the real one", () => {
    // The request the approver saw must be the request that was sent: the answer
    // carries its hash. A request re-signed from different fields is a different request.
    const p = pairedPair();
    const made = makeRequest(p.requester, p.approverPeer, fields({ summary: "run rm -rf build" }));
    const decoy = makeRequest(p.requester, p.approverPeer, fields({ summary: "run npm test" }));
    const openedDecoy = openRequest(p.approver, p.requesterPeer, decoy.wire)!;
    const yes = makeAnswer(p.approver, p.requesterPeer, { request: { ...openedDecoy.request, id: made.request.id }, hash: openedDecoy.hash }, "once", "dialog");
    assert.equal(openAnswer(p.requester, [p.approverPeer], made, yes), null);
    p.cleanup();
  });

  test("an answer cannot promise more than the request offered", () => {
    const p = pairedPair();
    const onceOnly = makeRequest(p.requester, p.approverPeer, fields({ ttlSeconds: null }));
    const o1 = openRequest(p.approver, p.requesterPeer, onceOnly.wire)!;
    assert.equal(openAnswer(p.requester, [p.approverPeer], onceOnly, makeAnswer(p.approver, p.requesterPeer, o1, "session", "dialog")), null);
    const fingerprint = makeRequest(p.requester, p.approverPeer, fields({ biometry: true }));
    const o2 = openRequest(p.approver, p.requesterPeer, fingerprint.wire)!;
    assert.equal(openAnswer(p.requester, [p.approverPeer], fingerprint, makeAnswer(p.approver, p.requesterPeer, o2, "once", "dialog")), null, "a click passed for a fingerprint");
    assert.ok(openAnswer(p.requester, [p.approverPeer], fingerprint, makeAnswer(p.approver, p.requesterPeer, o2, "once", "biometry")));
    p.cleanup();
  });

  test("an expired request, or one that claims to last too long, is not shown", () => {
    const p = pairedPair();
    const old = makeRequest(p.requester, p.approverPeer, fields(), Date.now() - 20 * 60_000);
    assert.equal(openRequest(p.approver, p.requesterPeer, old.wire), null);
    const now = Date.now();
    const long = makeRequest(p.requester, p.approverPeer, fields({ timeoutMs: 24 * 3600_000 }), now);
    assert.ok(long.request.expires - now <= 600_000, "a request asked to wait a day and got it");
    p.cleanup();
  });
});

// ---------------------------------------------------------------- end to end

describe("requestApproval through the relay", () => {
  /** Start the approver's listener (as the approver) answering with `answer`. */
  function approverAnswering(p: ReturnType<typeof pairedPair>, answer: (summary: string) => { decision: "once" | "session" | "deny"; via: "dialog" | "biometry" }) {
    const controller = new AbortController();
    const seen: string[] = [];
    process.env.HUSH_HOME = p.approverHome;
    // listenForRequests reads its keys and pairings before its first await.
    const done = listenForRequests(async (r) => {
      seen.push(r.summary);
      return answer(r.summary);
    }, { signal: controller.signal }).catch(() => {});
    process.env.HUSH_HOME = savedHome;
    return { stop: async () => { controller.abort(); await done; }, seen };
  }

  const req = (over: Record<string, unknown> = {}) => ({
    action: "run", summary: "run npm test", detail: ["sets: default"], scope: `run:${randomBytes(4).toString("hex")}`, ttlSeconds: 900,
    timeoutMs: 15_000, ...over,
  });

  test("a machine with no prompt of its own is answered from the paired device", async () => {
    const p = pairedPair();
    const a = approverAnswering(p, () => ({ decision: "once", via: "dialog" }));
    process.env.HUSH_HOME = p.requesterHome;
    try {
      assert.ok(approvalPromptAvailable(), "a paired machine still says nothing can ask");
      const r = await requestApproval(p.requesterHome, req(), headless);
      assert.equal(r.decision, "once", r.note);
      assert.equal(r.via, "relay");
      assert.match(r.note ?? "", /laptop/);
      assert.deepEqual(a.seen, ["run npm test"]);
    } finally {
      process.env.HUSH_HOME = savedHome;
      await a.stop();
      p.cleanup();
    }
  });

  test("an environment switch can only make hush refuse; it never sends the request to the relay instead (review F13)", async () => {
    const p = pairedPair();
    const a = approverAnswering(p, () => ({ decision: "once", via: "dialog" }));
    process.env.HUSH_HOME = p.requesterHome;
    const saved = { dialog: process.env.HUSH_NO_DIALOG, bio: process.env.HUSH_BIOMETRY };
    try {
      process.env.HUSH_NO_DIALOG = "1";
      const noDialog = await requestApproval(p.requesterHome, req(), headless);
      assert.equal(noDialog.decision, "deny", "HUSH_NO_DIALOG routed the request to a paired approver");
      delete process.env.HUSH_NO_DIALOG;
      process.env.HUSH_BIOMETRY = "off";
      const noBio = await requestApproval(p.requesterHome, req({ biometry: "required" }), headless);
      assert.equal(noBio.decision, "deny", "HUSH_BIOMETRY=off routed a fingerprint-required request to a paired approver");
      assert.deepEqual(a.seen, [], "the approver was asked");
    } finally {
      for (const [k, v] of [["HUSH_NO_DIALOG", saved.dialog], ["HUSH_BIOMETRY", saved.bio]] as const) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
      process.env.HUSH_HOME = savedHome;
      await a.stop();
      p.cleanup();
    }
  });

  test("Deny on the laptop is a deny here; Allow for a while is remembered here", async () => {
    const p = pairedPair();
    let next: "deny" | "session" = "deny";
    const a = approverAnswering(p, () => ({ decision: next, via: "dialog" }));
    process.env.HUSH_HOME = p.requesterHome;
    try {
      assert.equal((await requestApproval(p.requesterHome, req(), headless)).decision, "deny");
      next = "session";
      const scope = "run:remembered";
      assert.equal((await requestApproval(p.requesterHome, req({ scope }), headless)).decision, "session");
      const cached = await requestApproval(p.requesterHome, req({ scope }), headless);
      assert.equal(cached.via, "cache");
      assert.equal(a.seen.length, 2, "the cached grant asked the laptop again");
    } finally {
      process.env.HUSH_HOME = savedHome;
      clearApprovalCache();
      await a.stop();
      p.cleanup();
    }
  });

  test("a relay that replays yesterday's Allow approves nothing", async () => {
    const p = pairedPair();
    // First: a real, allowed request, to have an Allow on the wire.
    const a = approverAnswering(p, () => ({ decision: "once", via: "dialog" }));
    process.env.HUSH_HOME = p.requesterHome;
    let captured: string[] = [];
    try {
      assert.equal((await requestApproval(p.requesterHome, req(), headless)).decision, "once");
      captured = (await httpTransport.read(relay, p.approverPeer.toRequester, 0, 0)).messages.map((m) => m.body);
      assert.ok(captured.length >= 1);
    } finally {
      process.env.HUSH_HOME = savedHome;
      await a.stop();
    }
    // Now nobody is listening, and the relay answers every read with the old Allow.
    const replaying: RelayTransport = {
      post: httpTransport.post,
      read: async (_r, box, after, wait, signal) => {
        if (box !== p.approverPeer.toRequester) return httpTransport.read(relay, box, after, wait, signal);
        await new Promise((r) => setTimeout(r, 100));
        return { messages: captured.map((body, i) => ({ seq: after + i + 1, body })), next: after + captured.length };
      },
    };
    setRelayTransportForTests(replaying);
    process.env.HUSH_HOME = p.requesterHome;
    try {
      const r = await requestApproval(p.requesterHome, req({ timeoutMs: 2500 }), headless);
      assert.equal(r.decision, "timeout", "a replayed answer approved a new request");
    } finally {
      process.env.HUSH_HOME = savedHome;
      setRelayTransportForTests(null);
      p.cleanup();
    }
  });

  test("a relay that tampers with every request gets them all refused, and no answer", async () => {
    const p = pairedPair();
    const tampering: RelayTransport = {
      read: httpTransport.read,
      post: async (r, box, body) => {
        if (box !== p.approverPeer.toApprover) return httpTransport.post(r, box, body);
        const s = JSON.parse(body) as { tag: string };
        const tag = Buffer.from(s.tag, "base64url");
        tag[0] ^= 0xff;
        return httpTransport.post(r, box, JSON.stringify({ ...s, tag: tag.toString("base64url") }));
      },
    };
    const a = approverAnswering(p, () => ({ decision: "once", via: "dialog" }));
    setRelayTransportForTests(tampering);
    process.env.HUSH_HOME = p.requesterHome;
    try {
      const r = await requestApproval(p.requesterHome, req({ timeoutMs: 2500 }), headless);
      assert.equal(r.decision, "timeout");
      assert.deepEqual(a.seen, [], "the laptop showed a request the relay had changed");
    } finally {
      process.env.HUSH_HOME = savedHome;
      setRelayTransportForTests(null);
      await a.stop();
      p.cleanup();
    }
  });

  test("a request that arrived through the relay is never sent on again", async () => {
    const p = pairedPair();
    process.env.HUSH_HOME = p.requesterHome;
    try {
      const r = await requestApproval(p.requesterHome, req({ noRelay: true, timeoutMs: 1000 }), headless);
      assert.equal(r.decision, "deny");
      assert.equal(r.via, "none");
    } finally {
      process.env.HUSH_HOME = savedHome;
      p.cleanup();
    }
  });
});

// ---------------------------------------------------------------- pairing

describe("pairing through the CLI", () => {
  test("pair on the server, accept on the laptop: both sides trust exactly the other's keys", async () => {
    const serverHome = mkdtempSync(join(tmpdir(), "hush-pair-srv-"));
    const laptopHome = mkdtempSync(join(tmpdir(), "hush-pair-lap-"));
    const env = (home: string) => ({ ...process.env, HUSH_HOME: home, HOME: home, HUSH_NO_KEYCHAIN: "1", NO_COLOR: "1", HUSH_NO_NUDGE: "1" });
    const pairing = spawn(process.execPath, [CLI, "approvals", "pair", "--relay", relay, "--name", "build-box", "--timeout", "60"], { env: env(serverHome) });
    let pairOut = "";
    pairing.stdout.on("data", (d) => (pairOut += d));
    pairing.stderr.on("data", (d) => (pairOut += d));
    const code = await new Promise<string>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`no code:\n${pairOut}`)), 20_000);
      const iv = setInterval(() => {
        const m = /hushpair1:\S+/.exec(pairOut);
        if (m) {
          clearTimeout(t);
          clearInterval(iv);
          resolve(m[0]);
        }
      }, 50);
    });
    const exited = new Promise<number | null>((r) => pairing.on("close", r));
    const accepted = await cli(laptopHome, ["approvals", "accept", code, "--name", "omar-laptop"]);
    assert.equal(accepted.code, 0, accepted.out);
    assert.equal(await exited, 0, pairOut);
    assert.match(pairOut, /█|▀|▄/, "no QR code was shown");

    const serverPeers = as(serverHome, () => loadPeers());
    const laptopPeers = as(laptopHome, () => loadPeers());
    const serverDevice = as(serverHome, () => loadDevice()!);
    const laptopDevice = as(laptopHome, () => loadDevice()!);
    assert.equal(serverPeers.length, 1);
    assert.equal(serverPeers[0].kind, "approver");
    assert.equal(serverPeers[0].name, "omar-laptop");
    assert.equal(serverPeers[0].spk, encodeSpk(laptopDevice.signer.spk));
    assert.equal(laptopPeers[0].kind, "requester");
    assert.equal(laptopPeers[0].spk, encodeSpk(serverDevice.signer.spk));

    // The same safety number on both screens.
    const num = (s: string) => /safety number\s+([\d ]+)/.exec(s)?.[1].trim();
    assert.ok(num(pairOut));
    assert.equal(num(pairOut), num(accepted.out));

    if (platform() !== "win32") {
      assert.equal(statSync(join(serverHome, "relay", "peers.json")).mode & 0o077, 0, "the pairing file is readable by others");
      assert.equal(statSync(join(laptopHome, "relay", "device.json")).mode & 0o077, 0, "the device key is readable by others");
    }
    assert.match((await cli(serverHome, ["approvals", "ls"])).out, /omar-laptop/);
    assert.equal((await cli(serverHome, ["approvals", "rm", "omar-laptop"])).code, 0);
    assert.equal(as(serverHome, () => loadPeers()).length, 0);
    rmSync(serverHome, { recursive: true, force: true });
    rmSync(laptopHome, { recursive: true, force: true });
  });

  test("a relay cannot put its own keys in the middle of a pairing", () => {
    const secret = randomBytes(32);
    const honest = stranger();
    const relayOwn = stranger();
    const good = makeHello(secret, honest, "approver", "laptop", "x");
    assert.ok(openHello(secret, good, "approver"));
    // The relay swaps in its own keys but cannot recompute the MAC without the secret.
    const swapped = JSON.parse(good) as Record<string, string>;
    swapped.x = encodePub(relayOwn.x.pub);
    swapped.spk = encodeSpk(relayOwn.signer.spk);
    assert.equal(openHello(secret, JSON.stringify(swapped), "approver"), null);
    // Nor forge a hello under a secret it guessed.
    assert.equal(openHello(secret, makeHello(randomBytes(32), relayOwn, "approver", "laptop"), "approver"), null);
    // Nor pass a requester's hello off as an approver's.
    assert.equal(openHello(secret, makeHello(secret, honest, "requester", "server"), "approver"), null);
  });

  test("accept refuses a code whose pairing is not on the relay", async () => {
    const home = mkdtempSync(join(tmpdir(), "hush-pair-none-"));
    const code = encodePairingCode({ relay, secret: randomBytes(32) });
    const r = await cli(home, ["approvals", "accept", code, "--wait", "1"]);
    assert.notEqual(r.code, 0);
    assert.match(r.out, /no pairing request/);
    assert.ok(!existsSync(join(home, "relay", "peers.json")));
    rmSync(home, { recursive: true, force: true });
  });

  test("codes and relay addresses are checked", () => {
    const secret = randomBytes(32);
    assert.deepEqual(decodePairingCode(encodePairingCode({ relay: "https://relay.example", secret })).secret, secret);
    assert.throws(() => decodePairingCode("hello"), /not a hush pairing code/);
    assert.throws(() => checkRelayUrl("http://relay.example"), /https/);
    assert.equal(checkRelayUrl("http://localhost:8787/"), "http://localhost:8787");
    assert.throws(() => checkRelayUrl("https://user:pw@relay.example"), /credentials/);
    assert.throws(() => checkRelayUrl("ftp://relay.example"));
  });
});

// ---------------------------------------------------------------- the QR code

describe("the pairing QR code", () => {
  // Module-for-module hashes of the same inputs from python-qrcode 8, an
  // independent encoder (error correction and mask fixed, as it allows).
  const h = (m: boolean[][]) => createHash("sha256").update(m.map((r) => r.map((c) => (c ? "1" : "0")).join("")).join("\n")).digest("hex").slice(0, 32);
  const golden: [string, "L" | "M", number, number, string][] = [
    ["hello", "M", 0, 21, "52a7aa67e7296ede539d6be86579c718"],
    ["hello", "L", 5, 21, "9ff26b49415bb8225dfbad4e90477bbf"],
    ["hushpair1:" + "A".repeat(43) + "@https://relay.example.com", "M", 3, 37, "7e73a2d36fc22fab57106693e6df73c2"],
    ["x".repeat(300), "L", 6, 61, "433f0e8d062d4c2a86f6cbf6b4a6c845"],
    ["y".repeat(1200), "M", 7, 133, "7460e968737b8bf3d4fdb28b588d60a2"],
    ["é ünïcode ✓", "M", 2, 25, "f74ae04c84fcf284000838a71f3b3996"],
  ];
  for (const [text, ecc, mask, size, hash] of golden) {
    test(`matches an independent encoder: ${text.slice(0, 12)}… ${ecc} mask ${mask}`, () => {
      const m = qrMatrix(text, ecc, mask);
      assert.equal(m.length, size);
      assert.equal(h(m), hash);
    });
  }

  test("the terminal rendering is square, with a quiet zone", () => {
    const code = encodePairingCode({ relay: "https://relay.example.com", secret: randomBytes(32) });
    const lines = qrToTerminal(code).split("\n");
    const width = [...lines[0]].length;
    assert.equal(width, qrMatrix(code).length + 4);
    assert.equal(lines.length, Math.ceil(width / 2));
    assert.ok(lines.every((l) => [...l].length === width));
    assert.equal(lines[0], "█".repeat(width), "no light quiet zone on top");
  });
});

