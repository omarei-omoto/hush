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
import { createServer as createTlsServer } from "node:https";
import { randomBytes } from "node:crypto";
import { TOOLS, type Policy } from "./mcp.ts";
import { callTool, errText, type Ctx } from "./mcp-tools.ts";
import { admits, callerName, type TailnetCaller } from "./tailscale.ts";
import { audit, ValidationError } from "./vault.ts";
import { VERSION } from "./version.ts";
import type { Composed } from "./library.ts";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseMemberKey } from "./vault-core.ts";
import { requestApproval } from "./approval.ts";
import { checkCommand, runScope } from "./policy.ts";
import { sealLease } from "./lease.ts";
import { parseJson } from "./json.ts";

/** A machine allowed to take leases: its hush key, and who enrolled it. */
export interface LeaseDevice {
  fp: string;
  pub: string;
  login: string;
  node: string;
  /** The device's stable ID, when Tailscale gave one: what the enrollment is bound to. */
  nodeId?: string;
  name: string;
  at: string;
}

const devicesFile = (hushDir: string): string => join(hushDir, "broker-devices.json");

export function loadDevices(hushDir: string): LeaseDevice[] {
  try {
    const list = existsSync(devicesFile(hushDir)) ? JSON.parse(readFileSync(devicesFile(hushDir), "utf8")) : [];
    return Array.isArray(list) ? list.filter((d) => d && typeof d.fp === "string" && typeof d.node === "string") : [];
  } catch {
    return [];
  }
}

function saveDevices(hushDir: string, devices: LeaseDevice[]): void {
  const tmp = `${devicesFile(hushDir)}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(devices, null, 2) + "\n", { mode: 0o600 });
  renameSync(tmp, devicesFile(hushDir));
}

export interface BrokerOptions {
  /** The vault, identity, policy and folder the tools run against. */
  base: Omit<Ctx, "tools" | "compose" | "caller">;
  /** The sets offered, in the order they are layered when a call names none. */
  sets: string[];
  /** Logins, `tag:` names or device names allowed to call. */
  allow: string[];
  /** Who holds a tailnet address. A parameter so tests need no tailnet. */
  whois: (addr: string) => Promise<TailnetCaller | null>;
  /** The certificate for this machine's tailnet name; plain http without one. */
  tls?: { cert: string; key: string };
  /**
   * This machine's own tailnet addresses. A connection from one of them was
   * made on this machine — by any account on it — and carries no tailnet
   * identity of its own, so it is refused (see the handler).
   */
  selfAddresses?: string[];
}

/**
 * The policy a broker runs with, or why it must not start. A broker asks a
 * person before a credential is sent; turning that off (`--without-approval`)
 * is allowed only with `allowHosts` set, because with neither, any allowed
 * caller can name a server of their own and read the key off the request.
 */
export function brokerPolicy(loaded: Policy, withoutApproval: boolean): { policy: Policy } | { error: string; hint: string } {
  if (!withoutApproval) {
    if (!loaded.requireApproval.includes("request")) {
      return {
        error: "This vault's policy does not ask before hush_request sends a credential, and a broker should.",
        hint: "Turn it on (hush secure approval), or pass --without-approval with allowHosts set.",
      };
    }
    return { policy: loaded };
  }
  if (!loaded.allowHosts.length) {
    return {
      error: "--without-approval needs allowHosts: with neither, an allowed caller can send a key to a server of their own and read it.",
      hint: 'List the APIs the keys are for in the vault\'s policy.json, e.g. "allowHosts": ["api.stripe.com"].',
    };
  }
  return { policy: { ...loaded, requireApproval: loaded.requireApproval.filter((x) => x !== "request") } };
}

const OFFERED = new Set(["hush_list_sets", "hush_request"]);

/**
 * The app capability a tailnet policy grants to give someone sets on a hush
 * broker:
 *
 *   "grants": [{ "src": ["group:eng"], "dst": ["tag:hush"],
 *                "app": { "github.com/omarei-omoto/cap/hush": [{ "sets": ["staging"] }] } }]
 *
 * Tailscale hands it to the broker with the caller's identity (whois CapMap).
 * A grant can only narrow: it picks from the sets the broker was started
 * with (`"*"` for all of them), and nothing in it turns approval off.
 */
export const HUSH_CAP = "github.com/omarei-omoto/cap/hush";

/** The sets a caller's tailnet grants name, malformed entries ignored. */
export function grantedSets(caps: Record<string, unknown[]>, offered: readonly string[]): string[] | null {
  const grants = caps[HUSH_CAP];
  if (!Array.isArray(grants) || !grants.length) return null;
  const out = new Set<string>();
  for (const g of grants) {
    const sets = (g as { sets?: unknown })?.sets;
    if (!Array.isArray(sets)) continue;
    for (const s of sets) {
      if (s === "*") offered.forEach((o) => out.add(o));
      else if (typeof s === "string" && offered.includes(s)) out.add(s);
    }
  }
  return [...out];
}
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

function send(res: ServerResponse, status: number, body?: unknown, headers: Record<string, string> = {}): void {
  if (body === undefined) {
    res.writeHead(status, headers);
    res.end();
    return;
  }
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...headers });
  res.end(text);
}

/**
 * Which app a session says it is (MCP's `clientInfo`). Self-reported, so it
 * is shown as a hint in prompts and the log, never used to decide anything:
 * Tailscale cannot tell two agents on one machine apart, and a name an agent
 * chooses for itself cannot either.
 */
const MAX_SESSIONS = 1000;

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

/**
 * What a caller may use: every offered set when the allow-list admits them,
 * plus whatever their tailnet grants name. Null when neither lets them in.
 */
export function permittedSets(o: Pick<BrokerOptions, "allow" | "sets">, c: TailnetCaller): string[] | null {
  const byAllow = admits(o.allow, c) ? o.sets : [];
  const byGrant = grantedSets(c.caps, o.sets) ?? [];
  if (!byAllow.length && !byGrant.length) return null;
  return o.sets.filter((s) => byAllow.includes(s) || byGrant.includes(s));
}

export function createBroker(o: BrokerOptions): Server {
  const sessions = new Map<string, { node: string; client: string }>();
  const { vault, identity } = o.base;

  /** Secrets from the sets this caller may use; anything else named is refused. */
  const composeFor = (permitted: string[]) => (extra: string[]): Composed => {
    const names = extra.length ? extra : permitted;
    const refused = names.filter((n) => !permitted.includes(n));
    if (refused.length) throw new ValidationError(`Not offered to you by this broker: ${refused.join(", ")}. You may use ${permitted.join(", ")}.`);
    const secrets: Record<string, string> = {};
    for (const n of names) for (const item of vault.list(n)) secrets[item.key] = vault.get(identity, n, item.key);
    return { secrets, layers: names, missing: [], unreadable: [], blocked: [], unconfirmed: [] };
  };

  const listSets = (permitted: string[]) => {
    const lines = permitted.map((n) => `  ${n}: ${vault.list(n).map((i) => i.key).join(", ") || "(empty)"}`);
    return { content: [{ type: "text", text: `This broker offers you ${permitted.length} set(s):\n${lines.join("\n")}\n\nUse them with hush_request.` }] };
  };

  type Rpc = { jsonrpc?: string; id?: string | number | null; method?: string; params?: { name?: string; arguments?: unknown; protocolVersion?: string } };
  const ok = (id: Rpc["id"], result: unknown) => ({ jsonrpc: "2.0", id, result });
  const fail = (id: Rpc["id"], code: number, message: string) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });

  async function handle(rpc: Rpc, caller: TailnetCaller, permitted: string[], session: string | undefined, setSession: (id: string) => void): Promise<unknown | null> {
    const id = rpc.id;
    const client = session ? sessions.get(session) : undefined;
    // A session id from another device is ignored, not trusted.
    const hint = client && client.node === caller.node && client.client ? ` (says it is ${client.client})` : "";
    switch (rpc.method) {
      case "initialize": {
        const info = (rpc.params as { clientInfo?: { name?: unknown } } | undefined)?.clientInfo;
        const name = typeof info?.name === "string" ? info.name.replace(/[^\w .@/-]/g, "").slice(0, 40) : "";
        const sid = randomBytes(16).toString("hex");
        if (sessions.size >= MAX_SESSIONS) sessions.delete(sessions.keys().next().value!);
        sessions.set(sid, { node: caller.node, client: name });
        setSession(sid);
        return ok(id, {
          protocolVersion: rpc.params?.protocolVersion ?? PROTOCOL,
          capabilities: { tools: {} },
          serverInfo: { name: "hush-broker", version: VERSION },
          instructions:
            "This is a hush broker on your tailnet. It holds credentials you can use but never read: " +
            "call hush_request and write $NAME where a secret belongs, and the call is made from the broker " +
            "with the response redacted. hush_list_sets shows what it offers.",
        });
      }
      case "notifications/initialized":
      case "notifications/cancelled":
        return null;
      case "ping":
        return ok(id, {});
      case "tools/list":
        return ok(id, { tools: toolList(permitted) });
      case "tools/call": {
        const name = String(rpc.params?.name ?? "");
        const who = callerName(caller) + hint;
        audit(o.base.hushDir, { actor: "broker", action: "call", tool: name, caller: who });
        if (name === "hush_list_sets") return ok(id, listSets(permitted));
        if (!OFFERED.has(name)) return ok(id, errText(`${name} is not offered by this broker.`));
        try {
          return ok(id, await callTool(name, rpc.params?.arguments ?? {}, {
            ...o.base, tools: OFFERED, compose: composeFor(permitted), caller: who,
            ...(caller.tags.length ? {} : { callerLogin: caller.login }),
          }));
        } catch (e) {
          return ok(id, errText((e as Error).message));
        }
      }
      default:
        return id === undefined ? null : fail(id, -32601, `Method not found: ${rpc.method}`);
    }
  }

  const policy = o.base.policy;
  const timeoutMs = Math.max(1, policy.approvalTimeoutSeconds) * 1000;
  const personOf = (c: TailnetCaller) => (c.tags.length ? {} : { approverFor: c.login });

  /** A hush public key from a request body, X25519 only for now. */
  const keyFrom = (body: Record<string, unknown>) => {
    if (typeof body.pub !== "string") return null;
    try {
      const k = parseMemberKey(body.pub);
      return k.type === "x25519" && k.pub ? k : null;
    } catch {
      return null;
    }
  };

  /**
   * Enroll this machine's hush key for leases. A person approves it once, and
   * the key is tied to the tailnet user and device that enrolled it: a key
   * offered later from anywhere else is not this enrollment.
   */
  async function enroll(body: Record<string, unknown>, caller: TailnetCaller): Promise<{ status: number; body: unknown }> {
    const key = keyFrom(body);
    if (!key) return { status: 400, body: { error: "pub must be this machine's hush key (hush id); hardware keys cannot take leases yet" } };
    const who = callerName(caller);
    const name = typeof body.name === "string" ? body.name.replace(/[^\w .@-]/g, "").slice(0, 40) : caller.node.split(".")[0];
    // Enrolling is a trust decision, gated like adding a key: on by default,
    // off only where the vault's policy turned "add" approvals off.
    const ap = !policy.requireApproval.includes("add")
      ? { decision: "once" as const, via: "none" as const, code: "-", note: undefined }
      : await requestApproval(o.base.hushDir, {
      action: "add",
      summary: `Let ${who} take leases from this broker`,
      detail: [`Machine:  ${caller.node}`, `Its hush key:  ${key.fp}`, "A lease hands it the values of sets you allow, for one command each time, after asking you."],
      scope: `lease-enroll:${key.fp}#from=${who}`,
      ttlSeconds: policy.approvalTtlSeconds,
      timeoutMs,
      biometry: policy.biometry,
      sessionGrant: false,
      ...personOf(caller),
    });
    if (ap.via !== "none" || ap.decision !== "once") {
      audit(o.base.hushDir, { actor: "broker", action: "approval", on: "lease-enroll", decision: ap.decision, via: ap.via, code: ap.code, caller: who });
    }
    if (ap.decision === "deny" || ap.decision === "timeout") {
      return { status: 403, body: { error: ap.note ?? (ap.decision === "timeout" ? "nobody answered the approval" : "enrollment was denied"), code: ap.code } };
    }
    const devices = loadDevices(o.base.hushDir).filter((d) => d.fp !== key.fp);
    devices.push({ fp: key.fp, pub: key.pk, login: caller.login, node: caller.node, ...(caller.id ? { nodeId: caller.id } : {}), name, at: new Date().toISOString() });
    saveDevices(o.base.hushDir, devices);
    audit(o.base.hushDir, { actor: "broker", action: "lease-enroll", fp: key.fp, caller: who });
    return { status: 200, body: { enrolled: true, fingerprint: key.fp, code: ap.code } };
  }

  /** One lease: an enrolled key, a permitted set, an allowed command, a person's yes. */
  async function lease(body: Record<string, unknown>, caller: TailnetCaller, permitted: string[]): Promise<{ status: number; body: unknown }> {
    const key = keyFrom(body);
    if (!key) return { status: 400, body: { error: "pub must be this machine's hush key (hush id)" } };
    const who = callerName(caller);
    // Bound to the device's stable ID where there is one: a later device that
    // is given the same name is not the device that was enrolled.
    const sameDevice = (d: LeaseDevice) => (d.nodeId ? d.nodeId === caller.id : d.node === caller.node);
    const device = loadDevices(o.base.hushDir).find((d) => d.fp === key.fp && sameDevice(d) && d.login === caller.login);
    if (!device) return { status: 403, body: { error: "this machine is not enrolled for leases here", enroll: true } };

    const command = typeof body.command === "string" ? body.command : "";
    const args = Array.isArray(body.args) ? body.args.map(String) : [];
    if (!command) return { status: 400, body: { error: "which command?" } };
    const asked = Array.isArray(body.sets) ? body.sets.map(String) : [];
    let resolved: Composed;
    try {
      // The same policy as a local run: shells, interpreters and env dumpers
      // are refused, because they can print or send every injected value.
      checkCommand(policy, command);
      resolved = composeFor(permitted)(asked);
    } catch (e) {
      return { status: 403, body: { error: (e as Error).message } };
    }
    const secrets = { ...resolved.secrets };
    for (const k of policy.denyKeys) delete secrets[k];

    if (policy.requireApproval.includes("run")) {
      const ap = await requestApproval(o.base.hushDir, {
        action: "run",
        summary: `Lease to ${who}:  ${[command, ...args].join(" ")}`,
        detail: [
          `Using sets:  ${resolved.layers.join(", ")}`,
          `Sends:  ${Object.keys(secrets).join(", ") || "(nothing)"}`,
          `To:  ${caller.node}${typeof body.cwd === "string" ? `  ${String(body.cwd).slice(0, 200)}` : ""}`,
          "The values leave this machine for that one command.",
        ],
        scope: runScope(policy, command, resolved.layers) + `#lease#from=${who}`,
        ttlSeconds: policy.approvalTtlSeconds,
        timeoutMs,
        biometry: policy.biometry,
        ...personOf(caller),
      });
      audit(o.base.hushDir, { actor: "broker", action: "approval", on: "lease", decision: ap.decision, via: ap.via, code: ap.code, caller: who });
      if (ap.decision === "deny" || ap.decision === "timeout") {
        return { status: 403, body: { error: ap.note ?? (ap.decision === "timeout" ? "nobody answered the approval" : "the lease was denied"), code: ap.code } };
      }
    }

    const sealed = sealLease({ command, args, sets: resolved.layers, secrets }, Buffer.from(key.pub!));
    audit(o.base.hushDir, { actor: "broker", action: "lease", id: sealed.id, command, sets: resolved.layers, sent: Object.keys(secrets), caller: who });
    return { status: 200, body: sealed };
  }

  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    try {
      // A browser on a tailnet machine could be steered here by a hostile page
      // (DNS rebinding). Agents do not send Origin; browsers always do.
      if (req.headers.origin) return send(res, 403, { error: "the broker does not answer browsers" });
      const url = new URL(req.url ?? "/", "http://broker");
      const route = url.pathname;
      if (route !== "/mcp" && route !== "/lease" && route !== "/lease/enroll") return send(res, 404, { error: "not found" });
      if (req.method !== "POST") {
        res.setHeader("allow", "POST");
        return send(res, 405, { error: `POST JSON to ${route}` });
      }

      const addr = plainAddress(req.socket.remoteAddress ?? "");
      // A connection from this machine's own tailnet address was made here,
      // by any account on this machine, and Tailscale would name it as the
      // owner. The owner uses hush directly on this machine; the broker is
      // for other machines.
      if (addr && o.selfAddresses?.includes(addr)) {
        audit(o.base.hushDir, { actor: "broker", action: "refused", reason: "same machine", from: addr });
        return send(res, 403, { error: "the broker does not answer this machine itself; use hush directly here" });
      }
      const caller = addr ? await o.whois(addr) : null;
      if (!caller) {
        audit(o.base.hushDir, { actor: "broker", action: "refused", reason: "not a tailnet peer", from: addr });
        return send(res, 403, { error: "not a tailnet peer" });
      }
      const permitted = permittedSets(o, caller);
      if (!permitted) {
        audit(o.base.hushDir, { actor: "broker", action: "refused", reason: "not allowed", caller: callerName(caller) });
        return send(res, 403, { error: `${callerName(caller)} is not allowed to use this broker` });
      }
      if (!String(req.headers["content-type"] ?? "").startsWith("application/json")) {
        return send(res, 415, { error: "send application/json" });
      }

      if (route !== "/mcp") {
        let body: Record<string, unknown>;
        try {
          body = parseJson(await readBody(req));
        } catch {
          return send(res, 400, { error: "invalid JSON" });
        }
        if (!body || typeof body !== "object" || Array.isArray(body)) return send(res, 400, { error: "send a JSON object" });
        const r = route === "/lease/enroll" ? await enroll(body, caller) : await lease(body, caller, permitted);
        return send(res, r.status, r.body);
      }

      let rpc: Rpc;
      try {
        rpc = parseJson(await readBody(req));
      } catch (e) {
        return send(res, 400, fail(null, -32700, (e as Error).message === "body too large" ? "body too large" : "invalid JSON"));
      }
      if (Array.isArray(rpc) || !rpc || typeof rpc !== "object") return send(res, 400, fail(null, -32600, "one JSON-RPC message per request"));
      const headers: Record<string, string> = {};
      const sessionHeader = req.headers["mcp-session-id"];
      const out = await handle(rpc, caller, permitted, typeof sessionHeader === "string" ? sessionHeader : undefined, (sid) => {
        headers["mcp-session-id"] = sid;
      });
      if (out === null) return send(res, 202, undefined, headers);
      return send(res, 200, out, headers);
    } catch (e) {
      return send(res, 500, { error: (e as Error).message });
    }
  };
  return o.tls ? createTlsServer({ cert: o.tls.cert, key: o.tls.key }, handler) : createServer(handler);
}
