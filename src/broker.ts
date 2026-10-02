/**
 * The hush broker: hush's MCP tools over HTTP on a tailnet, for agents running
 * on other machines (docs/TAILNET.md, step 2).
 *
 * Request-only by design. A caller can see which sets the broker offers and
 * the key names in them, and can have the broker make an authenticated API
 * call with `hush_request` — the secret is substituted inside this process and
 * the response comes back redacted. No tool returns a value, and nothing here
 * runs a command: the credential never leaves this machine.
 *
 * Who is calling is decided by the network, not by anything the caller sends.
 * The server listens on this machine's tailnet address only, and each
 * connection's source address is put to the local Tailscale daemon (whois),
 * which answers with the user and device that hold that address's WireGuard
 * key. That answer is checked against the allow-list before a request body is
 * even read. Identity headers are never trusted, and a request carrying a
 * browser's Origin header is refused outright (DNS rebinding).
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { TOOLS } from "./mcp.ts";
import { callTool, errText, type Ctx } from "./mcp-tools.ts";
import { admits, callerName, type TailnetCaller } from "./tailscale.ts";
import { audit, ValidationError } from "./vault.ts";
import { VERSION } from "./version.ts";
import type { Composed } from "./library.ts";

export interface BrokerOptions {
  /** The vault, identity, policy and folder the tools run against. */
  base: Omit<Ctx, "tools" | "compose" | "caller">;
  /** The sets offered, in the order they are layered when a call names none. */
  sets: string[];
  /** Logins, `tag:` names or device names allowed to call. */
  allow: string[];
  /** Who holds a tailnet address. A parameter so tests need no tailnet. */
  whois: (addr: string) => Promise<TailnetCaller | null>;
}

const OFFERED = new Set(["hush_list_sets", "hush_request"]);
const MAX_BODY = 1024 * 1024;
const PROTOCOL = "2025-06-18";

const LIST_SETS = {
  name: "hush_list_sets",
  description:
    "The sets this hush broker offers and the variable names in each — names only, never values. " +
    "Pass set names to hush_request as sets: [\"<name>\"]; a request that names none uses all of them.",
  inputSchema: { type: "object", properties: {} },
};

function toolList(sets: string[]): unknown[] {
  const request = TOOLS.find((t) => t.name === "hush_request") as { inputSchema: { properties: Record<string, unknown> } } & Record<string, unknown>;
  return [
    LIST_SETS,
    {
      ...request,
      inputSchema: {
        ...request.inputSchema,
        properties: {
          ...request.inputSchema.properties,
          sets: {
            type: "array",
            items: { type: "string", enum: sets },
            description: `Which of this broker's sets to draw secrets from. Omit for all of them, layered in this order: ${sets.join(", ")}.`,
          },
        },
      },
    },
  ];
}

function send(res: ServerResponse, status: number, body?: unknown): void {
  if (body === undefined) {
    res.writeHead(status);
    res.end();
    return;
  }
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(text);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/** IPv4 addresses arrive as `::ffff:100.x.y.z` on a dual-stack socket. */
const plainAddress = (a: string): string => a.replace(/^::ffff:/i, "");

export function createBroker(o: BrokerOptions): Server {
  const offered = new Set(o.sets);
  const { vault, identity } = o.base;

  /** Secrets from the offered sets only; anything else named is refused. */
  const compose = (extra: string[]): Composed => {
    const names = extra.length ? extra : o.sets;
    const refused = names.filter((n) => !offered.has(n));
    if (refused.length) throw new ValidationError(`Not offered by this broker: ${refused.join(", ")}. It offers ${o.sets.join(", ")}.`);
    const secrets: Record<string, string> = {};
    for (const n of names) for (const item of vault.list(n)) secrets[item.key] = vault.get(identity, n, item.key);
    return { secrets, layers: names, missing: [], unreadable: [], blocked: [] };
  };

  const listSets = () => {
    const lines = o.sets.map((n) => `  ${n}: ${vault.list(n).map((i) => i.key).join(", ") || "(empty)"}`);
    return { content: [{ type: "text", text: `This broker offers ${o.sets.length} set(s):\n${lines.join("\n")}\n\nUse them with hush_request.` }] };
  };

  type Rpc = { jsonrpc?: string; id?: string | number | null; method?: string; params?: { name?: string; arguments?: unknown; protocolVersion?: string } };
  const ok = (id: Rpc["id"], result: unknown) => ({ jsonrpc: "2.0", id, result });
  const fail = (id: Rpc["id"], code: number, message: string) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });

  async function handle(rpc: Rpc, caller: TailnetCaller): Promise<unknown | null> {
    const id = rpc.id;
    switch (rpc.method) {
      case "initialize":
        return ok(id, {
          protocolVersion: rpc.params?.protocolVersion ?? PROTOCOL,
          capabilities: { tools: {} },
          serverInfo: { name: "hush-broker", version: VERSION },
          instructions:
            "This is a hush broker on your tailnet. It holds credentials you can use but never read: " +
            "call hush_request and write $NAME where a secret belongs, and the call is made from the broker " +
            "with the response redacted. hush_list_sets shows what it offers.",
        });
      case "notifications/initialized":
      case "notifications/cancelled":
        return null;
      case "ping":
        return ok(id, {});
      case "tools/list":
        return ok(id, { tools: toolList(o.sets) });
      case "tools/call": {
        const name = String(rpc.params?.name ?? "");
        const who = callerName(caller);
        audit(o.base.hushDir, { actor: "broker", action: "call", tool: name, caller: who });
        if (name === "hush_list_sets") return ok(id, listSets());
        if (!OFFERED.has(name)) return ok(id, errText(`${name} is not offered by this broker.`));
        try {
          return ok(id, await callTool(name, rpc.params?.arguments ?? {}, { ...o.base, tools: OFFERED, compose, caller: who }));
        } catch (e) {
          return ok(id, errText((e as Error).message));
        }
      }
      default:
        return id === undefined ? null : fail(id, -32601, `Method not found: ${rpc.method}`);
    }
  }

  return createServer(async (req, res) => {
    try {
      // A browser on a tailnet machine could be steered here by a hostile page
      // (DNS rebinding). Agents do not send Origin; browsers always do.
      if (req.headers.origin) return send(res, 403, { error: "the broker does not answer browsers" });
      const url = new URL(req.url ?? "/", "http://broker");
      if (url.pathname !== "/mcp") return send(res, 404, { error: "not found" });
      if (req.method !== "POST") {
        res.setHeader("allow", "POST");
        return send(res, 405, { error: "POST JSON-RPC to /mcp" });
      }

      const addr = plainAddress(req.socket.remoteAddress ?? "");
      const caller = addr ? await o.whois(addr) : null;
      if (!caller) {
        audit(o.base.hushDir, { actor: "broker", action: "refused", reason: "not a tailnet peer", from: addr });
        return send(res, 403, { error: "not a tailnet peer" });
      }
      if (!admits(o.allow, caller)) {
        audit(o.base.hushDir, { actor: "broker", action: "refused", reason: "not allowed", caller: callerName(caller) });
        return send(res, 403, { error: `${callerName(caller)} is not allowed to use this broker` });
      }
      if (!String(req.headers["content-type"] ?? "").startsWith("application/json")) {
        return send(res, 415, { error: "send application/json" });
      }

      let rpc: Rpc;
      try {
        rpc = JSON.parse(await readBody(req));
      } catch (e) {
        return send(res, 400, fail(null, -32700, (e as Error).message === "body too large" ? "body too large" : "invalid JSON"));
      }
      if (Array.isArray(rpc) || !rpc || typeof rpc !== "object") return send(res, 400, fail(null, -32600, "one JSON-RPC message per request"));
      const out = await handle(rpc, caller);
      if (out === null) return send(res, 202);
      return send(res, 200, out);
    } catch (e) {
      return send(res, 500, { error: (e as Error).message });
    }
  });
}
