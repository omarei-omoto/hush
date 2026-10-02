/**
 * The approval relay (F-4): approvals for a machine with no one at it.
 *
 * Over SSH, in a devcontainer, on a server with no desktop, there is nobody at
 * the machine to click Allow, so every gated action is refused. With a relay,
 * the machine that needs the approval (the *requester*) sends the request to a
 * device that has a person at it (the *approver*: your laptop, running `hush
 * approvals listen`), which shows the usual dialog or fingerprint prompt and
 * sends back a signed answer.
 *
 * The relay in between is a mailbox and nothing more (relay-server.ts). What it
 * can do, and what that gets it:
 *
 *   - read the messages: they are sealed to the recipient's X25519 key;
 *   - change a message, or write one of its own: the request is signed by the
 *     requester and the answer by the approver, both with Ed25519 keys fixed at
 *     pairing, and the answer names the hash of the exact request it answers;
 *   - replay an old answer: an answer is for one request id, fresh and random
 *     per request, and a requester accepts one answer per request it is waiting
 *     for;
 *   - drop or delay messages: yes. The request then times out and is refused,
 *     which is what happens without a relay.
 *
 * Pairing is where the keys are fixed. `hush approvals pair` (on the requester)
 * prints a code, as text and as a QR code, holding the relay's address and a
 * 32-byte secret. The code travels out of band: someone reads it off one screen
 * and enters it on the other. Each side's keys cross the relay in a "hello"
 * authenticated with a key derived from that secret, which the relay never
 * sees, so it cannot put its own keys in the middle. Both sides then show the
 * same safety number.
 *
 * What the relay approval is as strong as: the requester's ~/.hush. Something
 * running as you on that machine can rewrite the pairing to trust its own
 * "approver" — and can equally read a software identity key in the same
 * directory and skip hush altogether. SECURITY.md says so; the answer to both
 * is a hardware identity.
 *
 * docs/RELAY.md is the protocol, for anyone writing another client.
 */
import {
  createCipheriv, createDecipheriv, createHash, createHmac, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes,
  timingSafeEqual, createPrivateKey, createPublicKey, type KeyObject,
} from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { join } from "node:path";
import { hostname } from "node:os";
import {
  canonicalJson, decodePub, decodeSecret, decodeSpk, encodePub, encodeSecret, encodeSpk, generateIdentity, safetyNumber,
  signerFromSeed, verifySignature, type Identity, type Signer,
} from "./crypto.ts";
import { hushHome } from "./identity.ts";
import { restrictToOwner } from "./platform.ts";

export const RELAY_PROTOCOL = "hush/relay/v1";
/** A request is answered within this, or not at all; the relay keeps nothing longer. */
export const MAX_REQUEST_SECONDS = 600;
/** Clock difference tolerated between the two machines. */
const SKEW_MS = 5 * 60_000;
const BOX_ID = /^[A-Za-z0-9_-]{43}$/;

const b64u = (b: Buffer): string => b.toString("base64url");
const ub64u = (s: string): Buffer => Buffer.from(s, "base64url");
const sha256 = (s: string | Buffer): string => createHash("sha256").update(s).digest("hex");

// ------------------------------------------------------------------ this device

/** This machine's relay keys: X25519 to be sealed to, Ed25519 to sign with. One pair for both roles. */
export interface Device {
  x: Identity;
  signer: Signer;
}

const relayDir = (): string => join(hushHome(), "relay");
const deviceFile = (): string => join(relayDir(), "device.json");
const peersFile = (): string => join(relayDir(), "peers.json");

function writePrivate(path: string, text: string): void {
  mkdirSync(relayDir(), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, text, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
  restrictToOwner(path);
}

export function loadDevice(create = false): Device | null {
  if (existsSync(deviceFile())) {
    const raw = JSON.parse(readFileSync(deviceFile(), "utf8")) as { x: string; seed: string };
    return { x: decodeSecret(raw.x), signer: signerFromSeed(ub64u(raw.seed)) };
  }
  if (!create) return null;
  const x = generateIdentity();
  const seed = randomBytes(32);
  writePrivate(deviceFile(), JSON.stringify({ x: encodeSecret(x), seed: b64u(seed) }) + "\n");
  return { x, signer: signerFromSeed(seed) };
}

// -------------------------------------------------------------------- pairings

/** A device this one is paired with. `kind` is what *they* are. */
export interface Peer {
  kind: "approver" | "requester";
  name: string;
  relay: string;
  /** Box ids: requests travel to the approver in one, answers back in the other. */
  toApprover: string;
  toRequester: string;
  x: string;
  spk: string;
  pairedAt: string;
  /**
   * On an approver: the tailnet logins it answers for, when this machine is a
   * broker serving several people. A broker request from one of them goes to
   * their own device; one from anyone else goes to approvers with no list.
   */
  for?: string[];
}

export function loadPeers(): Peer[] {
  if (!existsSync(peersFile())) return [];
  try {
    const list = JSON.parse(readFileSync(peersFile(), "utf8")) as Peer[];
    return Array.isArray(list) ? list.filter(isPeer) : [];
  } catch {
    return [];
  }
}

function isPeer(p: unknown): p is Peer {
  const r = p as Peer;
  return (
    Boolean(r) && (r.kind === "approver" || r.kind === "requester") && typeof r.name === "string" &&
    typeof r.relay === "string" && BOX_ID.test(r.toApprover) && BOX_ID.test(r.toRequester) &&
    typeof r.x === "string" && typeof r.spk === "string" &&
    (r.for === undefined || (Array.isArray(r.for) && r.for.every((x) => typeof x === "string")))
  );
}

/**
 * Who answers a request. With a login (a broker request from that person):
 * the approvers paired for them, if any. Otherwise, and for everything that
 * is not a broker request, the approvers paired for nobody in particular — a
 * device paired for one person never answers for anyone else.
 */
export function approversFor(login?: string): Peer[] {
  const all = pairedApprovers();
  if (login) {
    const theirs = all.filter((p) => p.for?.includes(login));
    if (theirs.length) return theirs;
  }
  return all.filter((p) => !p.for?.length);
}

export function savePeer(peer: Peer): void {
  // A new pairing with the same device (same signing key) replaces the old one.
  const rest = loadPeers().filter((p) => !(p.kind === peer.kind && (p.spk === peer.spk || p.name === peer.name)));
  writePrivate(peersFile(), JSON.stringify([...rest, peer], null, 2) + "\n");
}

export function removePeer(name: string): Peer | null {
  const all = loadPeers();
  const gone = all.find((p) => p.name === name) ?? null;
  if (gone) writePrivate(peersFile(), JSON.stringify(all.filter((p) => p !== gone), null, 2) + "\n");
  return gone;
}

export const pairedApprovers = (): Peer[] => loadPeers().filter((p) => p.kind === "approver");

// --------------------------------------------------------------- pairing codes

export interface PairingCode {
  relay: string;
  secret: Buffer;
}

const CODE_PREFIX = "hushpair1:";

export function encodePairingCode(c: PairingCode): string {
  return `${CODE_PREFIX}${b64u(c.secret)}@${c.relay}`;
}

export function decodePairingCode(text: string): PairingCode {
  const s = text.trim();
  const m = /^hushpair1:([A-Za-z0-9_-]{43})@(\S+)$/.exec(s);
  if (!m) throw new Error("that is not a hush pairing code (it starts with hushpair1:)");
  return { secret: ub64u(m[1]), relay: checkRelayUrl(m[2]) };
}

/** The boxes and the hello key a pairing secret gives both sides. */
export function pairingKeys(secret: Buffer): { toApprover: string; toRequester: string; mac: Buffer } {
  const derive = (info: string) => Buffer.from(hkdfSync("sha256", secret, Buffer.from(RELAY_PROTOCOL), Buffer.from(info), 32));
  return {
    toApprover: b64u(derive("box/to-approver")),
    toRequester: b64u(derive("box/to-requester")),
    mac: derive("pair/hello-mac"),
  };
}

/**
 * The relay's address: https, or http to this machine only. The content is
 * sealed either way; https keeps the rest (which boxes, when) off the network.
 * Loopback is how a relay reaches a server over `ssh -R` with no third party.
 */
export function checkRelayUrl(url: string): string {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new Error(`not a URL: ${url}`);
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) {
    throw new Error("a relay is https, or http on this machine (localhost) — for instance through ssh -R");
  }
  if (u.username || u.password || u.search || u.hash) throw new Error("a relay URL has no credentials, query or fragment");
  return u.href.replace(/\/+$/, "");
}

// ---------------------------------------------------------------- hellos

export interface Hello {
  t: "hello";
  v: typeof RELAY_PROTOCOL;
  role: "approver" | "requester";
  name: string;
  x: string;
  spk: string;
  /** The approver's hello names the requester it saw, so both agree on both keys. */
  peer?: string;
  mac?: string;
}

export function makeHello(secret: Buffer, device: Device, role: Hello["role"], name: string, peerSpk?: string): string {
  const body: Hello = {
    t: "hello", v: RELAY_PROTOCOL, role, name: name.slice(0, 64), x: encodePub(device.x.pub), spk: encodeSpk(device.signer.spk),
    ...(peerSpk ? { peer: peerSpk } : {}),
  };
  const mac = createHmac("sha256", pairingKeys(secret).mac).update(canonicalJson(body)).digest();
  return JSON.stringify({ ...body, mac: b64u(mac) });
}

/** A hello from the other side, if it carries the pairing secret's MAC — otherwise null. */
export function openHello(secret: Buffer, text: string, role: Hello["role"]): Hello | null {
  let h: Hello;
  try {
    h = JSON.parse(text) as Hello;
  } catch {
    return null;
  }
  if (!h || h.t !== "hello" || h.v !== RELAY_PROTOCOL || h.role !== role || typeof h.mac !== "string") return null;
  const { mac, ...body } = h;
  const want = createHmac("sha256", pairingKeys(secret).mac).update(canonicalJson(body)).digest();
  const got = ub64u(mac);
  if (got.length !== want.length || !timingSafeEqual(got, want)) return null;
  try {
    decodePub(h.x);
    decodeSpk(h.spk);
  } catch {
    return null;
  }
  return { ...body, name: String(h.name).slice(0, 64) || "unnamed" };
}

export const pairingSafetyNumber = (a: string, b: string): string => safetyNumber(decodeSpk(a), decodeSpk(b));

export const defaultDeviceName = (): string => hostname().split(".")[0] || "this machine";

// ------------------------------------------------------------ sealed messages

interface Sealed {
  v: 1;
  epk: string;
  iv: string;
  ct: string;
  tag: string;
}

const aadFor = (recipient: Buffer) => Buffer.concat([Buffer.from(`${RELAY_PROTOCOL}|seal|`), recipient]);

function kek(shared: Buffer, epk: Buffer, recipient: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", shared, Buffer.concat([epk, recipient]), Buffer.from(`${RELAY_PROTOCOL}/seal`), 32));
}

const X25519_SPKI = Buffer.from("302a300506032b656e032100", "hex");
const X25519_PKCS8 = Buffer.from("302e020100300506032b656e04220420", "hex");
const xPublic = (raw: Buffer): KeyObject => createPublicKey({ key: Buffer.concat([X25519_SPKI, raw]), format: "der", type: "spki" });
const xPrivate = (raw: Buffer): KeyObject => createPrivateKey({ key: Buffer.concat([X25519_PKCS8, raw]), format: "der", type: "pkcs8" });

export function seal(plaintext: Buffer, recipient: Buffer): string {
  const eph = generateKeyPairSync("x25519");
  const epk = (eph.publicKey.export({ format: "der", type: "spki" }) as Buffer).subarray(-32);
  const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: xPublic(recipient) });
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", kek(shared, epk, recipient), iv);
  c.setAAD(aadFor(recipient));
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  const sealed: Sealed = { v: 1, epk: b64u(epk), iv: b64u(iv), ct: b64u(ct), tag: b64u(c.getAuthTag()) };
  return JSON.stringify(sealed);
}

export function unseal(text: string, me: Identity): Buffer | null {
  try {
    const s = JSON.parse(text) as Sealed;
    if (s.v !== 1) return null;
    const epk = ub64u(s.epk);
    const shared = diffieHellman({ privateKey: xPrivate(me.priv), publicKey: xPublic(epk) });
    const d = createDecipheriv("aes-256-gcm", kek(shared, epk, me.pub), ub64u(s.iv));
    d.setAAD(aadFor(me.pub));
    d.setAuthTag(ub64u(s.tag));
    return Buffer.concat([d.update(ub64u(s.ct)), d.final()]);
  } catch {
    return null;
  }
}

/** A signed body: the exact JSON text that was signed, and the signature over domain ‖ text. */
interface Signed {
  body: string;
  sig: string;
}

const domain = (kind: "request" | "answer") => Buffer.from(`${RELAY_PROTOCOL}/${kind}\n`);

function signBody(kind: "request" | "answer", body: object, signer: Signer): Buffer {
  const text = canonicalJson(body);
  const sig = signer.sign(Buffer.concat([domain(kind), Buffer.from(text)]));
  return Buffer.from(JSON.stringify({ body: text, sig: b64u(sig) } satisfies Signed));
}

function verifyBody<T>(kind: "request" | "answer", plaintext: Buffer, spk: string): { body: T; text: string } | null {
  try {
    const s = JSON.parse(plaintext.toString("utf8")) as Signed;
    if (typeof s.body !== "string" || typeof s.sig !== "string") return null;
    if (!verifySignature(decodeSpk(spk), Buffer.concat([domain(kind), Buffer.from(s.body)]), ub64u(s.sig))) return null;
    return { body: JSON.parse(s.body) as T, text: s.body };
  } catch {
    return null;
  }
}

// ------------------------------------------------------------ requests, answers

export interface RelayRequest {
  t: "request";
  id: string;
  /** The requester's signing key: which pairing this is, inside the signature. */
  from: string;
  created: number;
  expires: number;
  action: string;
  summary: string;
  detail: string[];
  code: string;
  /** How long "Allow for a while" lasts; null offers "Allow once" only. */
  ttlSeconds: number | null;
  /** The answer must be a fingerprint, not a click. */
  biometry: boolean;
  host: string;
}

export type RelayDecision = "once" | "session" | "deny";

export interface RelayAnswer {
  t: "answer";
  id: string;
  /** sha256 of the request's signed body: an answer is for these exact bytes. */
  request: string;
  decision: RelayDecision;
  via: "dialog" | "biometry" | "none";
  answeredAt: number;
}

export function makeRequest(
  device: Device,
  approver: Peer,
  fields: Omit<RelayRequest, "t" | "id" | "from" | "created" | "expires" | "host"> & { timeoutMs: number; host?: string },
  now = Date.now(),
): { wire: string; request: RelayRequest; hash: string } {
  const { timeoutMs, host, ...rest } = fields;
  const request: RelayRequest = {
    t: "request",
    id: b64u(randomBytes(16)),
    from: encodeSpk(device.signer.spk),
    created: now,
    expires: now + Math.min(timeoutMs, MAX_REQUEST_SECONDS * 1000),
    host: (host ?? defaultDeviceName()).slice(0, 64),
    ...rest,
    summary: rest.summary.slice(0, 500),
    detail: rest.detail.slice(0, 20).map((l) => l.slice(0, 500)),
  };
  const plaintext = signBody("request", request, device.signer);
  const { body } = JSON.parse(plaintext.toString("utf8")) as Signed;
  return { wire: seal(plaintext, decodePub(approver.x)), request, hash: sha256(body) };
}

/**
 * A request as the approver receives it: sealed to this device, signed by the
 * paired requester whose box it arrived in, current, and well-formed — or null.
 */
export function openRequest(
  device: Device,
  requester: Peer,
  wire: string,
  now = Date.now(),
): { request: RelayRequest; hash: string } | null {
  const plaintext = unseal(wire, device.x);
  if (!plaintext) return null;
  const opened = verifyBody<RelayRequest>("request", plaintext, requester.spk);
  if (!opened) return null;
  const r = opened.body;
  if (r.t !== "request" || r.from !== requester.spk || typeof r.id !== "string" || r.id.length < 16) return null;
  if (typeof r.created !== "number" || typeof r.expires !== "number") return null;
  if (r.created > now + SKEW_MS || r.expires < now || r.expires - r.created > MAX_REQUEST_SECONDS * 1000) return null;
  if (typeof r.summary !== "string" || !Array.isArray(r.detail) || !r.detail.every((l) => typeof l === "string")) return null;
  if (typeof r.code !== "string" || typeof r.action !== "string" || typeof r.biometry !== "boolean") return null;
  if (r.ttlSeconds !== null && !(Number.isInteger(r.ttlSeconds) && r.ttlSeconds > 0 && r.ttlSeconds <= 86_400)) return null;
  return { request: r, hash: sha256(opened.text) };
}

export function makeAnswer(
  device: Device,
  requester: Peer,
  opened: { request: RelayRequest; hash: string },
  decision: RelayDecision,
  via: RelayAnswer["via"],
  now = Date.now(),
): string {
  const answer: RelayAnswer = { t: "answer", id: opened.request.id, request: opened.hash, decision, via, answeredAt: now };
  return seal(signBody("answer", answer, device.signer), decodePub(requester.x));
}

/**
 * An answer as the requester receives it: sealed to this device, signed by a
 * paired approver, for the request it is waiting on (id *and* hash), with a
 * decision that request allowed — or null.
 */
export function openAnswer(
  device: Device,
  approvers: Peer[],
  pending: { request: RelayRequest; hash: string },
  wire: string,
): { answer: RelayAnswer; approver: Peer } | null {
  const plaintext = unseal(wire, device.x);
  if (!plaintext) return null;
  for (const approver of approvers) {
    const opened = verifyBody<RelayAnswer>("answer", plaintext, approver.spk);
    if (!opened) continue;
    const a = opened.body;
    if (a.t !== "answer" || a.id !== pending.request.id || a.request !== pending.hash) return null;
    if (a.decision !== "once" && a.decision !== "session" && a.decision !== "deny") return null;
    // "Allow for a while" only where it was offered; a fingerprint where one was required.
    if (a.decision === "session" && !pending.request.ttlSeconds) return null;
    if (pending.request.biometry && a.decision !== "deny" && a.via !== "biometry") return null;
    return { answer: a, approver };
  }
  return null;
}

// ------------------------------------------------------------------ the client

export interface BoxMessage {
  seq: number;
  body: string;
}

/** What talks to a relay; tests substitute one that tampers. */
export interface RelayTransport {
  post(relay: string, box: string, body: string): Promise<void>;
  read(relay: string, box: string, after: number, waitSeconds: number, signal?: AbortSignal): Promise<{ messages: BoxMessage[]; next: number }>;
}

export const httpTransport: RelayTransport = {
  async post(relay, box, body) {
    const r = await fetch(`${checkRelayUrl(relay)}/v1/boxes/${box}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ body }),
    });
    if (!r.ok) throw new Error(`the relay refused the message (${r.status})`);
  },
  async read(relay, box, after, waitSeconds, signal) {
    const r = await fetch(`${checkRelayUrl(relay)}/v1/boxes/${box}?after=${after}&wait=${waitSeconds}`, { signal });
    if (!r.ok) throw new Error(`the relay did not answer (${r.status})`);
    const data = (await r.json()) as { messages?: BoxMessage[]; next?: number };
    const messages = Array.isArray(data.messages) ? data.messages.filter((m) => typeof m?.body === "string" && Number.isInteger(m.seq)) : [];
    return { messages, next: Number.isInteger(data.next) ? (data.next as number) : after };
  },
};

let transport: RelayTransport = httpTransport;
/** Test seam: a transport that sits between hush and the relay, as a hostile relay would. */
export function setRelayTransportForTests(t: RelayTransport | null): void {
  transport = t ?? httpTransport;
}
export const currentTransport = (): RelayTransport => transport;

// ----------------------------------------------------------- the requester side

export interface RelayOutcome {
  decision: RelayDecision | "timeout";
  approver?: string;
  via?: RelayAnswer["via"];
  note?: string;
}

/**
 * Put an approval in front of every paired approver and wait for the first
 * valid answer. Anything that does not verify is ignored, not fatal: a relay
 * that sends junk can delay an answer, never supply one.
 */
export async function relayApprove(
  fields: { action: string; summary: string; detail: string[]; code: string; ttlSeconds: number | null; biometry: boolean },
  timeoutMs: number,
  forLogin?: string,
): Promise<RelayOutcome | null> {
  const approvers = approversFor(forLogin);
  const device = loadDevice(false);
  if (!approvers.length || !device) return null;

  const deadline = Date.now() + Math.min(timeoutMs, MAX_REQUEST_SECONDS * 1000);
  const t = currentTransport();
  const pending: { approver: Peer; request: RelayRequest; hash: string; after: number }[] = [];
  const failures: string[] = [];
  for (const approver of approvers) {
    try {
      // Where the answer box stands now: an answer can only come after the request.
      const { next } = await t.read(approver.relay, approver.toRequester, -1, 0);
      const made = makeRequest(device, approver, { ...fields, timeoutMs });
      await t.post(approver.relay, approver.toApprover, made.wire);
      pending.push({ approver, request: made.request, hash: made.hash, after: next });
    } catch (e) {
      failures.push(`${approver.name}: ${(e as Error).message}`);
    }
  }
  if (!pending.length) return { decision: "deny", note: `no relay reachable — ${failures.join("; ")}` };

  const controller = new AbortController();
  try {
    return await new Promise<RelayOutcome>((resolve) => {
      let open = pending.length;
      const timer = setTimeout(() => resolve({ decision: "timeout" }), Math.max(0, deadline - Date.now()));
      for (const p of pending) {
        void (async () => {
          let after = p.after;
          while (Date.now() < deadline && !controller.signal.aborted) {
            let batch: { messages: BoxMessage[]; next: number };
            try {
              const wait = Math.max(0, Math.min(25, Math.floor((deadline - Date.now()) / 1000)));
              batch = await t.read(p.approver.relay, p.approver.toRequester, after, wait, controller.signal);
            } catch {
              if (controller.signal.aborted) return;
              await new Promise((r) => setTimeout(r, 1000));
              continue;
            }
            after = batch.next;
            for (const m of batch.messages) {
              const got = openAnswer(device, [p.approver], p, m.body);
              if (got) {
                clearTimeout(timer);
                resolve({ decision: got.answer.decision, approver: got.approver.name, via: got.answer.via });
                return;
              }
            }
          }
          if (--open === 0) {
            clearTimeout(timer);
            resolve({ decision: "timeout" });
          }
        })();
      }
    });
  } finally {
    controller.abort();
  }
}

// ------------------------------------------------------------ the approver side

export interface Decider {
  (request: RelayRequest, requester: Peer): Promise<{ decision: RelayDecision; via: RelayAnswer["via"] }>;
}

/**
 * Wait for requests from every paired requester and answer each with `decide`
 * (the local dialog or fingerprint, in `hush approvals listen`). Runs until
 * `signal` aborts. A request that does not verify is reported and dropped; the
 * same request twice is answered once.
 */
export async function listenForRequests(
  decide: Decider,
  opts: { signal: AbortSignal; onEvent?: (e: { kind: "request" | "answered" | "rejected" | "error"; peer: string; detail: string }) => void },
): Promise<void> {
  const device = loadDevice(false);
  if (!device) throw new Error("this device has no relay key — pair it first (hush approvals accept <code>)");
  const requesters = loadPeers().filter((p) => p.kind === "requester");
  if (!requesters.length) throw new Error("nothing is paired with this device — run hush approvals pair on the other machine");
  const t = currentTransport();
  const seen = new Map<string, number>();

  await Promise.all(
    requesters.map(async (peer) => {
      let after = 0;
      while (!opts.signal.aborted) {
        let batch: { messages: BoxMessage[]; next: number };
        try {
          batch = await t.read(peer.relay, peer.toApprover, after, 25, opts.signal);
        } catch (e) {
          if (opts.signal.aborted) return;
          opts.onEvent?.({ kind: "error", peer: peer.name, detail: (e as Error).message });
          await new Promise((r) => setTimeout(r, 3000));
          continue;
        }
        after = batch.next;
        for (const m of batch.messages) {
          const opened = openRequest(device, peer, m.body);
          if (!opened) {
            opts.onEvent?.({ kind: "rejected", peer: peer.name, detail: "a message that is not a valid request from this pairing" });
            continue;
          }
          const now = Date.now();
          for (const [id, until] of seen) if (until < now) seen.delete(id);
          if (seen.has(opened.request.id)) continue;
          seen.set(opened.request.id, opened.request.expires);
          opts.onEvent?.({ kind: "request", peer: peer.name, detail: opened.request.summary });
          const { decision, via } = await decide(opened.request, peer);
          try {
            await t.post(peer.relay, peer.toRequester, makeAnswer(device, peer, opened, decision, via));
            opts.onEvent?.({ kind: "answered", peer: peer.name, detail: decision });
          } catch (e) {
            opts.onEvent?.({ kind: "error", peer: peer.name, detail: (e as Error).message });
          }
        }
      }
    }),
  );
}
