/**
 * What hush asks Tailscale, when it is running on this machine. Read-only, and
 * only to print better instructions: hush never changes a Tailscale setting.
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { onPath } from "./which.ts";

/** The CLI, wherever it is: on PATH, or inside the macOS app. */
function tailscaleCli(): string | null {
  const found = onPath("tailscale");
  if (found) return found;
  const app = "/Applications/Tailscale.app/Contents/MacOS/Tailscale";
  return process.platform === "darwin" && existsSync(app) ? app : null;
}

/**
 * The macOS app's CLI takes one to two seconds per call on a busy tailnet, so
 * a two-second bound timed out on a machine that was perfectly up. Six is
 * generous and still bounded.
 */
const CLI_TIMEOUT_MS = 6000;

/** `tailscale status --self --json`, once per process. */
let selfStatus: string | null | undefined;
function statusJson(): string | null {
  if (selfStatus !== undefined) return selfStatus;
  const cli = tailscaleCli();
  try {
    selfStatus = cli ? execFileSync(cli, ["status", "--self", "--json"], { encoding: "utf8", timeout: CLI_TIMEOUT_MS, stdio: ["ignore", "pipe", "ignore"] }) : null;
  } catch {
    selfStatus = null;
  }
  return selfStatus;
}

/** This machine's name on its tailnet (`laptop.tail0f78a.ts.net`), or null when Tailscale is not up. */
export function tailnetName(): string | null {
  const out = statusJson();
  return out ? parseSelfDnsName(out) : null;
}

/** The DNS name in `tailscale status --self --json`, if the node is up. */
export function parseSelfDnsName(json: string): string | null {
  try {
    const j = JSON.parse(json) as { BackendState?: string; Self?: { DNSName?: string; Online?: boolean } };
    if (j.BackendState !== "Running") return null;
    const name = (j.Self?.DNSName ?? "").replace(/\.$/, "");
    return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(name) ? name : null;
  } catch {
    return null;
  }
}

/** Ports `tailscale serve --https=` accepts. */
export const SERVE_HTTPS_PORT = 8443;

/** The two lines that carry a local relay over the tailnet. */
export function tailnetRelayLines(dnsName: string, localPort: number): { serve: string; pair: string } {
  return {
    serve: `tailscale serve --bg --https=${SERVE_HTTPS_PORT} http://127.0.0.1:${localPort}`,
    pair: `hush approvals pair --relay https://${dnsName}:${SERVE_HTTPS_PORT}`,
  };
}

// ------------------------------------------------------------------ who is calling

/** A tailnet peer, as the local Tailscale daemon names it. */
export interface TailnetCaller {
  /** The user's login (`you@example.com`), or `tagged-devices` for a tagged node. */
  login: string;
  /** The device's tailnet name, without the trailing dot. */
  node: string;
  /** `tag:ci` and the like. A tagged device has these instead of a user. */
  tags: string[];
  /** App capabilities the tailnet policy grants this peer, by capability name. */
  caps: Record<string, unknown[]>;
}

/** `tailscale whois --json <addr>` → who it is. Null when the address is no tailnet peer. */
export function parseWhois(json: string): TailnetCaller | null {
  try {
    const j = JSON.parse(json) as {
      Node?: { Name?: string; Tags?: string[] };
      UserProfile?: { LoginName?: string };
      CapMap?: Record<string, unknown[]>;
    };
    const node = (j.Node?.Name ?? "").replace(/\.$/, "");
    const login = j.UserProfile?.LoginName ?? "";
    if (!node || !login) return null;
    return { login, node, tags: Array.isArray(j.Node?.Tags) ? j.Node!.Tags!.map(String) : [], caps: j.CapMap ?? {} };
  } catch {
    return null;
  }
}

/**
 * Ask the local daemon who owns a tailnet address. The answer is as good as
 * WireGuard: a packet from 100.x.y.z on the tailnet interface was sent by the
 * node holding that address's key. Null for anything that is not a peer.
 */
export function whois(addr: string): Promise<TailnetCaller | null> {
  const cli = tailscaleCli();
  if (!cli) return Promise.resolve(null);
  return import("node:child_process").then(
    ({ execFile }) =>
      new Promise((resolve) => {
        execFile(cli, ["whois", "--json", addr], { encoding: "utf8", timeout: CLI_TIMEOUT_MS }, (err, out) => {
          resolve(err ? null : parseWhois(out));
        });
      }),
  );
}

/** This machine's tailnet IPv4 address, or null — from the same status call as its name. */
export function tailnetIPv4(): string | null {
  const out = statusJson();
  return out ? parseSelfIPv4(out) : null;
}

/** The node's IPv4 address in `tailscale status --self --json`, in Tailscale's 100.64.0.0/10. */
export function parseSelfIPv4(json: string): string | null {
  try {
    const j = JSON.parse(json) as { BackendState?: string; Self?: { TailscaleIPs?: string[] } };
    if (j.BackendState !== "Running") return null;
    for (const ip of j.Self?.TailscaleIPs ?? []) {
      const m = /^100\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
      if (m && Number(m[1]) >= 64 && Number(m[1]) <= 127) return ip;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * whois, remembered per address for a minute. Each lookup is a CLI call that
 * takes over a second on a busy tailnet, and an agent makes several tool
 * calls in a row. A minute is the longest a removed device or a policy change
 * can go unnoticed; approvals still apply to every request in that time.
 */
export function cachedWhois(lookup: (addr: string) => Promise<TailnetCaller | null> = whois, ttlMs = 60_000) {
  const memo = new Map<string, { at: number; who: TailnetCaller | null }>();
  return async (addr: string): Promise<TailnetCaller | null> => {
    const hit = memo.get(addr);
    if (hit && Date.now() - hit.at < (hit.who ? ttlMs : 5_000)) return hit.who;
    const who = await lookup(addr);
    memo.set(addr, { at: Date.now(), who });
    return who;
  };
}

/**
 * Whether an allow-list entry admits a caller: a login (`you@example.com`), a
 * tag (`tag:ci`), or a device name (`build-box.tailnet.ts.net`). A tagged
 * device is never admitted by a login: its "user" is the placeholder
 * `tagged-devices`, which is nobody.
 */
export function admits(allow: readonly string[], c: TailnetCaller): boolean {
  return allow.some((a) =>
    a.startsWith("tag:")
      ? c.tags.includes(a)
      : a.includes("@")
        ? c.tags.length === 0 && c.login === a
        : c.node === a.replace(/\.$/, ""),
  );
}

/** How a caller is named in prompts and the audit log. */
export const callerName = (c: TailnetCaller): string =>
  `${c.tags.length ? c.tags.join(",") : c.login} on ${c.node.split(".")[0]}`;
