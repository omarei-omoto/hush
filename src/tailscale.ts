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
 * This machine's name on its tailnet (`laptop.tail0f78a.ts.net`), or null when
 * Tailscale is not installed, not running, or slow to answer. Bounded at two
 * seconds: a hint is not worth waiting for.
 */
export function tailnetName(): string | null {
  const cli = tailscaleCli();
  if (!cli) return null;
  try {
    const out = execFileSync(cli, ["status", "--self", "--json"], { encoding: "utf8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"] });
    return parseSelfDnsName(out);
  } catch {
    return null;
  }
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
