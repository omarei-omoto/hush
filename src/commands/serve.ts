/**
 * `hush serve --tailnet` — run the hush broker on this machine's tailnet
 * address (src/broker.ts, docs/TAILNET.md step 2).
 */
import { dirname } from "node:path";
import { existsSync } from "node:fs";
import { type Args, bool, list, str } from "../cli/args.ts";
import { bold, cyan, die, dim, info, warn, yellow } from "../cli/output.ts";
import { createBroker } from "../broker.ts";
import { cachedWhois, tailnetIPv4, tailnetName, whois } from "../tailscale.ts";
import { requireIdentity } from "../identity.ts";
import { globalVaultName, globalVaultPath } from "../library.ts";
import { loadPolicy } from "../mcp.ts";
import { Vault, slugifyEnv } from "../vault.ts";

export async function cmdServe(a: Args): Promise<void> {
  if (!bool(a, "tailnet")) {
    die("hush serve runs the broker on your tailnet.", 'hush serve --tailnet --sets <set>[,<set>…] [--allow you@example.com|tag:ci]');
  }
  const ip = tailnetIPv4();
  if (!ip) die("Tailscale is not running on this machine, so there is no tailnet address to serve on.");

  // The library by default; `--vault <name>` (handled in cli.ts) picks another.
  const vaultPath = process.env.HUSH_VAULT ?? globalVaultPath();
  if (!existsSync(vaultPath)) die("You have no library to serve.", "Make one: hush global --create");
  const vault = Vault.open(vaultPath);
  const identity = requireIdentity();
  if (!vault.canRead(identity)) die(`This machine's key is not a recipient of vault "${vault.data.name}".`);
  const hushDir = dirname(vaultPath);

  // Offering a set is a decision, so there is no default: name each one.
  const asked = list(a, "sets");
  if (!asked.length) {
    die(
      "Name the sets this broker offers.",
      `hush serve --tailnet --sets ${vault.sets().map((s) => s.name).slice(0, 3).join(",") || "<set>"}   (yours: ${vault.sets().map((s) => s.name).join(", ") || "none yet"})`,
    );
  }
  const sets = asked.map((n) => {
    const hit = vault.sets().find((s) => s.name === n || s.name === slugifyEnv(n) || s.label === n);
    if (!hit) die(`No set "${n}" in ${vault.data.name}.`, `It has: ${vault.sets().map((s) => s.name).join(", ")}`);
    return hit.name;
  });

  // A network-facing broker asks a person before a credential is sent: an
  // allowed device is not an allowed request. Turning that off is a flag
  // that says so, and it does exactly that — for this broker only.
  const loaded = loadPolicy(hushDir);
  const without = bool(a, "without-approval");
  if (!without && !loaded.requireApproval.includes("request")) {
    die(
      "This vault's policy does not ask before hush_request sends a credential, and a broker should.",
      "Turn it on (hush secure approval), or pass --without-approval if you mean it.",
    );
  }
  const policy = without ? { ...loaded, requireApproval: loaded.requireApproval.filter((x) => x !== "request") } : loaded;
  if (without) warn("--without-approval: allowed callers can send these credentials without asking you.");

  // Whom to admit. Default: you, as Tailscale knows you on this machine.
  let allow = list(a, "allow");
  if (!allow.length) {
    const me = await whois(ip);
    if (!me || me.tags.length) die("Could not tell who you are on the tailnet.", "Pass --allow you@example.com (or --allow tag:<name>).");
    allow = [me.login];
  }

  const port = Number(str(a, "port") ?? 8788);
  if (!Number.isInteger(port) || port < 0 || port > 65535) die("--port is a port number");

  const server = createBroker({
    base: { vault, hushDir, policy, identity, root: hushDir, defaultEnv: sets[0] },
    sets,
    allow,
    whois: cachedWhois(),
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, ip, () => resolve());
  });
  const addr = server.address();
  const actual = typeof addr === "object" && addr ? addr.port : port;
  const host = tailnetName() ?? ip;
  const url = `http://${host}:${actual}/mcp`;

  info(`${bold("hush broker")}  →  ${cyan(url)}  ${dim("(this tailnet only)")}`);
  info(dim(`  vault:   ${vault.data.name}${vaultPath === globalVaultPath() ? ` (your library, ${globalVaultName()})` : ""}`));
  for (const n of sets) info(dim(`  offers:  ${n}  ${vault.list(n).map((i) => i.key).join(", ")}`));
  info(dim(`  allows:  ${allow.join(", ")}`));
  info(dim(`  ${policy.requireApproval.includes("request") ? "every request asks you first" : yellow("requests are NOT approved by a person")}; calls go out from this machine, values never leave it`));
  info("");
  info("  Add it to an agent on any tailnet machine:");
  info(`    ${cyan(`claude mcp add --transport http hush-broker ${url}`)}`);
  info(dim(`    or any MCP client that takes a streamable-http URL`));
  info(dim("  Plain http inside WireGuard: the tailnet encrypts it, and only tailnet peers can connect."));
  info(dim("  Ctrl-C to stop."));
  await new Promise<void>((resolve) => {
    const stop = () => server.close(() => resolve());
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
}
