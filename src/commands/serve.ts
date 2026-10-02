/**
 * `hush serve --tailnet` — run the hush broker on this machine's tailnet
 * address (src/broker.ts, docs/TAILNET.md step 2).
 */
import { dirname } from "node:path";
import { existsSync } from "node:fs";
import { type Args, bool, list, str } from "../cli/args.ts";
import { bold, cyan, die, dim, info, warn, yellow } from "../cli/output.ts";
import { createBroker, HUSH_CAP } from "../broker.ts";
import { cachedWhois, tailnetCert, tailnetIPv4, tailnetName, whois } from "../tailscale.ts";
import { approvalPromptAvailable } from "../approval.ts";
import { pairedApprovers } from "../relay.ts";
import { hushHome } from "../identity.ts";
import { join } from "node:path";
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

  // A broker that asks before sending, on a machine that cannot ask anyone,
  // refuses every request. Better to say so now than on the first call.
  const approvers = pairedApprovers();
  if (policy.requireApproval.includes("request") && !approvalPromptAvailable()) {
    die(
      "This machine cannot show an approval, and no device is paired to answer for it, so every request would be refused.",
      "Pair your laptop first:  hush approvals pair --relay <url>   (on the laptop: hush relay serve prints the url, then hush approvals accept …)",
    );
  }

  const port = Number(str(a, "port") ?? 8788);
  if (!Number.isInteger(port) || port < 0 || port > 65535) die("--port is a port number");

  // https with the tailnet name's certificate, unless asked not to or it
  // cannot be had (HTTPS certificates are a tailnet setting).
  const dns = tailnetName();
  const certDir = join(hushHome(), "broker");
  let tls: { cert: string; key: string } | undefined;
  let tlsProblem: string | null = null;
  if (!bool(a, "no-tls")) {
    if (!dns) tlsProblem = "this machine has no tailnet name";
    else {
      const got = tailnetCert(dns, certDir);
      if ("error" in got) tlsProblem = got.error;
      else tls = got;
    }
  }

  const server = createBroker({
    base: { vault, hushDir, policy, identity, root: hushDir, defaultEnv: sets[0] },
    sets,
    allow,
    whois: cachedWhois(),
    ...(tls ? { tls } : {}),
  });
  // Certificates last 90 days; `tailscale cert` renews near the end, so ask daily.
  if (tls && dns) {
    setInterval(() => {
      const fresh = tailnetCert(dns, certDir);
      if (!("error" in fresh)) (server as import("node:https").Server).setSecureContext(fresh);
    }, 24 * 3600 * 1000).unref();
  }
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, ip, () => resolve());
  });
  const addr = server.address();
  const actual = typeof addr === "object" && addr ? addr.port : port;
  const host = tls && dns ? dns : ip;
  const url = `${tls ? "https" : "http"}://${host}:${actual}/mcp`;

  info(`${bold("hush broker")}  →  ${cyan(url)}  ${dim("(this tailnet only)")}`);
  info(dim(`  vault:   ${vault.data.name}${vaultPath === globalVaultPath() ? ` (your library, ${globalVaultName()})` : ""}`));
  for (const n of sets) info(dim(`  offers:  ${n}  ${vault.list(n).map((i) => i.key).join(", ")}`));
  info(dim(`  allows:  ${allow.join(", ")}, and anyone your tailnet policy grants ${HUSH_CAP} (only the sets it names)`));
  info(dim(`  ${policy.requireApproval.includes("request") ? "every request asks first" : yellow("requests are NOT approved by a person")}; calls go out from this machine, values never leave it`));
  if (policy.requireApproval.includes("request")) {
    const forPeople = approvers.filter((p) => p.for?.length);
    for (const p of forPeople) info(dim(`  asks:    ${p.for!.join(", ")} on their own device (${p.name})`));
    const general = approvers.filter((p) => !p.for?.length).map((p) => p.name);
    info(dim(`  asks:    ${forPeople.length ? "everyone else " : ""}on this machine${general.length ? `, or on ${general.join(", ")} when it cannot show a prompt` : ""}`));
  }
  info("");
  info("  Add it to an agent on any tailnet machine:");
  info(`    ${cyan(`claude mcp add --transport http hush-broker ${url}`)}`);
  info(dim(`    or any MCP client that takes a streamable-http URL`));
  info("  Or let a machine take leases, for tools that must hold the key themselves:");
  info(`    ${cyan(`hush lease enroll ${url.replace(/\/mcp$/, "")}`)}   ${dim("once, approved here")}`);
  info(`    ${cyan(`hush run --from ${url.replace(/\/mcp$/, "")} -- <command>`)}   ${dim("each time, approved here")}`);
  if (tls) info(dim("  https with this machine's tailnet certificate; only tailnet peers can connect."));
  else {
    info(dim("  Plain http inside WireGuard: the tailnet encrypts it, and only tailnet peers can connect."));
    if (tlsProblem) info(dim(`  (no https: ${tlsProblem}. Some MCP clients want https: turn on HTTPS certificates under DNS in the Tailscale admin console.)`));
  }
  info(dim("  Ctrl-C to stop."));
  await new Promise<void>((resolve) => {
    const stop = () => server.close(() => resolve());
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
}
