/**
 * `hush relay serve` — the reference approval relay (F-4). A mailbox, nothing
 * more: it stores opaque messages in boxes named by unguessable ids and hands
 * them to whoever asks for that id. Everything it carries is sealed and signed
 * end to end (relay.ts), so it holds no keys, reads nothing, and needs no
 * accounts. Run it anywhere both machines can reach — or on your laptop with
 * `ssh -R 8787:localhost:8787 server`, and no third party is involved at all.
 *
 *   POST /v1/boxes/<id>                 {"body": "<text>"}  → 201 {"seq": n}
 *   GET  /v1/boxes/<id>?after=n&wait=s  → 200 {"messages": [{"seq", "body"}], "next": n}
 *   GET  /v1/health                     → 200 {"ok": true, "protocol": "hush/relay/v1"}
 *
 * Reads do not consume: every reader of a box sees its messages until they
 * expire, which is what lets two hush processes on one server wait for answers
 * at once. Bounded everywhere: message size, messages per box, boxes, how long
 * anything is kept, how long a read waits. Nothing is logged but counts.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { MAX_REQUEST_SECONDS, RELAY_PROTOCOL } from "./relay.ts";
import { parseJson } from "./json.ts";

export interface RelayLimits {
  maxBodyBytes: number;
  maxPerBox: number;
  maxBoxes: number;
  ttlMs: number;
  maxWaitSeconds: number;
}

export const DEFAULT_LIMITS: RelayLimits = {
  maxBodyBytes: 64 * 1024,
  maxPerBox: 64,
  maxBoxes: 10_000,
  ttlMs: MAX_REQUEST_SECONDS * 1000,
  maxWaitSeconds: 25,
};

const BOX = /^\/v1\/boxes\/([A-Za-z0-9_-]{43})$/;

interface Box {
  seq: number;
  messages: { seq: number; body: string; at: number }[];
  waiters: Set<() => void>;
  touched: number;
}

export function createRelayServer(limits: Partial<RelayLimits> = {}): Server {
  const L = { ...DEFAULT_LIMITS, ...limits };
  const boxes = new Map<string, Box>();

  const sweep = () => {
    const cutoff = Date.now() - L.ttlMs;
    for (const [id, box] of boxes) {
      box.messages = box.messages.filter((m) => m.at >= cutoff);
      if (!box.messages.length && !box.waiters.size && box.touched < cutoff) boxes.delete(id);
    }
  };
  const timer = setInterval(sweep, Math.min(60_000, L.ttlMs));
  timer.unref();

  const send = (res: ServerResponse, status: number, body: unknown) => {
    const text = JSON.stringify(body);
    res.writeHead(status, {
      "content-type": "application/json",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "content-length": Buffer.byteLength(text),
    });
    res.end(text);
  };

  const boxFor = (id: string, create: boolean): Box | null => {
    let box = boxes.get(id);
    if (!box && create) {
      if (boxes.size >= L.maxBoxes) {
        sweep();
        if (boxes.size >= L.maxBoxes) return null;
      }
      box = { seq: 0, messages: [], waiters: new Set(), touched: Date.now() };
      boxes.set(id, box);
    }
    return box ?? null;
  };

  const readBody = (req: IncomingMessage): Promise<string | null> =>
    new Promise((resolve) => {
      let size = 0;
      let over = false;
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => {
        size += c.length;
        // Past the limit, keep reading and drop it, so the sender gets a 413
        // rather than a reset connection.
        if (size > L.maxBodyBytes + 64) over = true;
        else chunks.push(c);
      });
      req.on("end", () => resolve(over ? null : Buffer.concat(chunks).toString("utf8")));
      req.on("error", () => resolve(null));
    });

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://relay");
    if (url.pathname === "/v1/health" && req.method === "GET") return send(res, 200, { ok: true, protocol: RELAY_PROTOCOL });
    const m = BOX.exec(url.pathname);
    if (!m) return send(res, 404, { error: "not found" });
    const id = m[1];

    if (req.method === "POST") {
      const raw = await readBody(req);
      if (raw === null) return send(res, 413, { error: "too large" });
      let body: unknown;
      try {
        body = (parseJson(raw) as { body?: unknown }).body;
      } catch {
        return send(res, 400, { error: "expected {\"body\": \"…\"}" });
      }
      if (typeof body !== "string" || Buffer.byteLength(body) > L.maxBodyBytes) return send(res, 400, { error: "body must be a string within the size limit" });
      const box = boxFor(id, true);
      if (!box) return send(res, 503, { error: "relay full" });
      box.touched = Date.now();
      box.messages = box.messages.filter((x) => x.at >= Date.now() - L.ttlMs);
      if (box.messages.length >= L.maxPerBox) box.messages.shift();
      const seq = ++box.seq;
      box.messages.push({ seq, body, at: Date.now() });
      for (const wake of box.waiters) wake();
      return send(res, 201, { seq });
    }

    if (req.method === "GET") {
      const after = Number(url.searchParams.get("after") ?? "0");
      const wait = Math.max(0, Math.min(L.maxWaitSeconds, Number(url.searchParams.get("wait") ?? "0") || 0));
      if (!Number.isInteger(after)) return send(res, 400, { error: "after must be an integer" });
      const collect = () => {
        const box = boxes.get(id);
        const cutoff = Date.now() - L.ttlMs;
        const messages = (box?.messages ?? []).filter((x) => x.seq > after && x.at >= cutoff).map(({ seq, body }) => ({ seq, body }));
        return { messages, next: box?.seq ?? 0 };
      };
      const now = collect();
      if (now.messages.length || wait === 0) return send(res, 200, now);
      const box = boxFor(id, true);
      if (!box) return send(res, 503, { error: "relay full" });
      await new Promise<void>((resolve) => {
        const done = () => {
          clearTimeout(t);
          box.waiters.delete(done);
          resolve();
        };
        const t = setTimeout(done, wait * 1000);
        box.waiters.add(done);
        // The response's close, not the request's: a GET's request "closes" as
        // soon as its (empty) body has been read.
        res.on("close", done);
      });
      if (res.writableEnded || res.destroyed) return;
      return send(res, 200, collect());
    }

    send(res, 405, { error: "method not allowed" });
  });
  server.on("close", () => clearInterval(timer));
  // Long polls hold a request open for up to maxWaitSeconds.
  server.requestTimeout = (L.maxWaitSeconds + 10) * 1000;
  server.headersTimeout = 15_000;
  return server;
}
