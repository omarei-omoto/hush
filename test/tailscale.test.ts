/**
 * What hush reads from Tailscale, to print the tailnet relay lines. Read-only:
 * hush never changes a Tailscale setting, so these only cover the parsing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseSelfDnsName, tailnetRelayLines, SERVE_HTTPS_PORT } from "../src/tailscale.ts";

test("the tailnet name comes from a running node, without the trailing dot", () => {
  const up = JSON.stringify({ BackendState: "Running", Self: { DNSName: "laptop.tail0f78a.ts.net.", Online: true } });
  assert.equal(parseSelfDnsName(up), "laptop.tail0f78a.ts.net");
});

test("no name when Tailscale is stopped, logged out, or answers nonsense", () => {
  assert.equal(parseSelfDnsName(JSON.stringify({ BackendState: "Stopped", Self: { DNSName: "laptop.tail0f78a.ts.net." } })), null);
  assert.equal(parseSelfDnsName(JSON.stringify({ BackendState: "NeedsLogin" })), null);
  assert.equal(parseSelfDnsName("not json"), null);
  // A name that would not be safe to print into a command line.
  assert.equal(parseSelfDnsName(JSON.stringify({ BackendState: "Running", Self: { DNSName: "x; rm -rf ~." } })), null);
});

test("the two lines carry the local relay to an https tailnet address hush accepts", async () => {
  const lines = tailnetRelayLines("laptop.tail0f78a.ts.net", 8787);
  assert.equal(lines.serve, `tailscale serve --bg --https=${SERVE_HTTPS_PORT} http://127.0.0.1:8787`);
  assert.equal(lines.pair, `hush approvals pair --relay https://laptop.tail0f78a.ts.net:${SERVE_HTTPS_PORT}`);
  const { checkRelayUrl } = await import("../src/relay.ts");
  assert.equal(checkRelayUrl(lines.pair.split(" ").pop()!), `https://laptop.tail0f78a.ts.net:${SERVE_HTTPS_PORT}`);
});
