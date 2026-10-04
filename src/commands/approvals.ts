/**
 * `hush approvals` and `hush relay` — approvals for a machine nobody is sitting
 * at (F-4). The protocol is relay.ts; the mailbox is relay-server.ts.
 *
 * On the server (the requester):   hush approvals pair --relay https://relay.example
 * On your laptop (the approver):   hush approvals accept hushpair1:…@https://relay.example
 *                                  hush approvals listen
 *
 * From then on, an approval the server cannot put in front of anyone goes to
 * your laptop instead: the usual dialog, or your fingerprint, and the answer
 * goes back signed.
 *
 * No relay to hand? Run one on the laptop and carry it over the SSH session:
 *
 *   hush relay serve                         (laptop, localhost:8787)
 *   ssh -R 8787:localhost:8787 server        then pair with --relay http://localhost:8787
 */
import { createHash, randomBytes } from "node:crypto";
import { requestApproval } from "../approval.ts";
import { hushHome } from "../identity.ts";
import { encodeSpk } from "../crypto.ts";
import {
  checkRelayUrl, currentTransport, decodePairingCode, defaultDeviceName, encodePairingCode, listenForRequests, loadDevice,
  loadPeers, makeHello, openHello, pairingKeys, pairingSafetyNumber, removePeer, savePeer, type Peer,
} from "../relay.ts";
import { createRelayServer } from "../relay-server.ts";
import { qrToTerminal } from "../qr.ts";
import { tailnetName, tailnetRelayLines } from "../tailscale.ts";
import { type Args, bool, list, str } from "../cli/args.ts";
import { bold, cyan, die, dim, green, info, red, shown, yellow } from "../cli/output.ts";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * What an "Allow for a while" on this device covers: the paired device that
 * asked, and exactly what the person was shown. Not the request's id — that
 * is the requester's to choose, and keying the grant on it let a reused id
 * carry a different action through an earlier allow, with no dialog.
 */
export function relayGrantScope(
  peer: { spk: string },
  r: { action: string; summary: string; detail: string[]; host: string; id?: string },
): string {
  const shownToThePerson = JSON.stringify([r.action, r.summary, r.detail, r.host]);
  return `relay:${peer.spk}:${createHash("sha256").update(shownToThePerson).digest("hex")}`;
}

export async function cmdApprovals(a: Args): Promise<void> {
  const sub = a._[0];
  if (!sub || sub === "ls" || sub === "list") return ls();
  if (sub === "pair") return pair(a);
  if (sub === "accept") return accept(a);
  if (sub === "listen") return listen(a);
  if (sub === "rm" || sub === "remove" || sub === "unpair") {
    const name = a._[1];
    if (!name) die("Which pairing?", "hush approvals ls shows them.");
    const gone = removePeer(name);
    if (!gone) die(`Nothing paired called "${name}".`, "hush approvals ls shows them.");
    return info(`${green("✓")} unpaired ${bold(shown(gone.name))} — it can no longer ${gone.kind === "approver" ? "approve for this machine" : "send requests here"}`);
  }
  die(`Unknown: hush approvals ${sub}`, "hush approvals pair | accept | listen | ls | rm");
}

function ls(): void {
  const peers = loadPeers();
  if (!peers.length) {
    info(dim("Nothing paired. On a machine with no one at it:  hush approvals pair --relay <url>"));
    return;
  }
  for (const p of peers) {
    const role = p.kind === "approver"
      ? p.for?.length ? `approves broker requests from ${p.for.join(", ")}` : "approves for this machine"
      : "sends its approvals here";
    info(`  ${bold(shown(p.name))}  ${dim(role)}  ${dim(p.relay)}  ${dim(p.spk.slice(0, 20) + "…")}`);
  }
}

/** On the requester: make a pairing code and wait for the approver to use it. */
async function pair(a: Args): Promise<void> {
  const relayArg = str(a, "relay");
  if (!relayArg) die("Which relay?", "hush approvals pair --relay https://relay.example  (or run one: hush relay serve)");
  let relay: string;
  try {
    relay = checkRelayUrl(relayArg);
  } catch (e) {
    die((e as Error).message);
  }
  const name = str(a, "name") ?? defaultDeviceName();
  // On a broker serving several people: whose device this is. Their broker
  // requests go to it; it answers nothing else.
  const forLogins = list(a, "for");
  if (forLogins.some((l) => !/^[^\s@]+@[^\s@]+$/.test(l))) die("--for takes tailnet logins, like you@example.com.");
  const waitSeconds = Math.min(Number(str(a, "timeout") ?? 600) || 600, 3600);
  const device = loadDevice(true)!;
  const secret = randomBytes(32);
  const boxes = pairingKeys(secret);
  const t = currentTransport();

  try {
    await t.post(relay, boxes.toApprover, makeHello(secret, device, "requester", name));
  } catch (e) {
    die(`Could not reach the relay: ${(e as Error).message}`);
  }
  const code = encodePairingCode({ relay, secret });
  info(bold("On the device that will approve (your laptop), run:"));
  info("");
  info(`  ${cyan(`hush approvals accept ${code}`)}`);
  if (!bool(a, "no-qr")) {
    info("");
    info(dim("  or scan:"));
    info(qrToTerminal(code));
  }
  info("");
  info(dim(`  The code is a secret until it is used: whoever enters it first becomes an approver for this machine.`));
  info(dim(`  Waiting up to ${Math.round(waitSeconds / 60)} min…`));

  const deadline = Date.now() + waitSeconds * 1000;
  let after = 0;
  while (Date.now() < deadline) {
    let batch;
    try {
      batch = await t.read(relay, boxes.toRequester, after, Math.min(25, Math.ceil((deadline - Date.now()) / 1000)));
    } catch {
      await sleep(2000);
      continue;
    }
    after = batch.next;
    for (const m of batch.messages) {
      const hello = openHello(secret, m.body, "approver");
      if (!hello || hello.peer !== encodeSpk(device.signer.spk)) continue;
      const peer: Peer = {
        kind: "approver", name: hello.name, relay, toApprover: boxes.toApprover, toRequester: boxes.toRequester,
        x: hello.x, spk: hello.spk, pairedAt: new Date().toISOString(),
        ...(forLogins.length ? { for: forLogins } : {}),
      };
      savePeer(peer);
      info("");
      info(
        forLogins.length
          ? `${green("✓")} paired with ${bold(shown(hello.name))} — broker requests from ${forLogins.join(", ")} will go there`
          : `${green("✓")} paired with ${bold(shown(hello.name))} — approvals this machine cannot show will go there`,
      );
      info(`  safety number  ${pairingSafetyNumber(peer.spk, encodeSpk(device.signer.spk))}`);
      info(dim("  The other side shows the same number. If it does not, run hush approvals rm and pair again."));
      return;
    }
  }
  die("Nobody used the pairing code in time.", "Run hush approvals pair again.");
}

/** On the approver: use a pairing code from the requester. */
async function accept(a: Args): Promise<void> {
  const text = a._[1];
  if (!text) die("Which code?", "hush approvals accept hushpair1:…  (from hush approvals pair on the other machine)");
  let code;
  try {
    code = decodePairingCode(text);
  } catch (e) {
    die((e as Error).message);
  }
  const boxes = pairingKeys(code.secret);
  const t = currentTransport();
  const device = loadDevice(true)!;
  const name = str(a, "name") ?? defaultDeviceName();

  let requester = null;
  // The pairing request is normally there already; allow for a relay that is slow to show it.
  const deadline = Date.now() + Math.min(Number(str(a, "wait") ?? 30) || 30, 300) * 1000;
  while (!requester && Date.now() < deadline) {
    let batch;
    try {
      batch = await t.read(code.relay, boxes.toApprover, 0, 5);
    } catch (e) {
      die(`Could not reach the relay: ${(e as Error).message}`);
    }
    requester = batch.messages.map((m) => openHello(code.secret, m.body, "requester")).find(Boolean) ?? null;
  }
  if (!requester) die("The relay has no pairing request for that code.", "Codes last 10 minutes; run hush approvals pair again.");

  await t.post(code.relay, boxes.toRequester, makeHello(code.secret, device, "approver", name, requester.spk));
  savePeer({
    kind: "requester", name: requester.name, relay: code.relay, toApprover: boxes.toApprover, toRequester: boxes.toRequester,
    x: requester.x, spk: requester.spk, pairedAt: new Date().toISOString(),
  });
  info(`${green("✓")} paired with ${bold(shown(requester.name))} — it will send the approvals it cannot show here`);
  info(`  safety number  ${pairingSafetyNumber(requester.spk, encodeSpk(device.signer.spk))}`);
  info("");
  info(`  Keep ${cyan("hush approvals listen")} running here to answer them.`);
}

/** On the approver: answer requests with this machine's dialog or fingerprint. */
async function listen(a: Args): Promise<void> {
  const bio = str(a, "biometry", "preferred");
  if (bio !== "required" && bio !== "preferred" && bio !== "off") die(`--biometry is required, preferred or off, not "${bio}"`);
  const controller = new AbortController();
  process.once("SIGINT", () => controller.abort());
  process.once("SIGTERM", () => controller.abort());
  const requesters = loadPeers().filter((p) => p.kind === "requester");
  if (!requesters.length) die("Nothing sends its approvals here yet.", "On the other machine: hush approvals pair --relay <url>");
  info(`${bold("Answering approvals")} for ${requesters.map((p) => shown(p.name)).join(", ")}  ${dim("Ctrl-C to stop")}`);

  try {
    await listenForRequests(
      async (r, peer) => {
        const result = await requestApproval(hushHome(), {
          action: r.action,
          summary: `${shown(peer.name, 40)}: ${r.summary}`,
          detail: [...r.detail, `from ${shown(r.host, 40)} through the relay`],
          scope: relayGrantScope(peer, r),
          ttlSeconds: r.ttlSeconds ?? 60,
          sessionGrant: r.ttlSeconds !== null,
          code: r.code,
          // A request that requires a fingerprint gets one, whatever this listener prefers.
          biometry: r.biometry ? "required" : bio,
          timeoutMs: Math.max(1000, r.expires - Date.now()),
          noRelay: true,
        });
        const decision = result.decision === "once" || result.decision === "session" ? result.decision : "deny";
        const via = result.via === "biometry" ? "biometry" : result.via === "dialog" ? "dialog" : "none";
        return { decision, via };
      },
      {
        signal: controller.signal,
        onEvent: (e) => {
          const when = new Date().toTimeString().slice(0, 8);
          if (e.kind === "request") info(`${dim(when)}  ${bold(shown(e.peer))} asks: ${shown(e.detail, 120)}`);
          else if (e.kind === "answered") info(`${dim(when)}  ${e.detail === "deny" ? red("denied") : green(`allowed (${e.detail})`)}`);
          else if (e.kind === "rejected") info(`${dim(when)}  ${yellow("!")} ${shown(e.peer)}: ${e.detail}`);
          else info(`${dim(when)}  ${yellow("!")} ${shown(e.peer)}: ${e.detail} — retrying`);
        },
      },
    );
  } catch (e) {
    die((e as Error).message);
  }
}

/** `hush relay serve` — the reference relay. */
export async function cmdRelay(a: Args): Promise<void> {
  if (a._[0] !== "serve") die("hush relay serve [--port 8787] [--host 127.0.0.1]");
  const port = Number(str(a, "port") ?? 8787);
  const host = str(a, "host") ?? "127.0.0.1";
  if (!Number.isInteger(port) || port < 0 || port > 65535) die("--port is a port number");
  const server = createRelayServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => resolve());
  });
  const addr = server.address();
  const actual = typeof addr === "object" && addr ? addr.port : port;
  const shownHost = host.includes(":") ? `[${host}]` : host;
  info(`${bold("hush relay")}  →  http://${shownHost}:${actual}`);
  info(dim("  It stores sealed messages for up to 10 minutes and cannot read any of them."));
  if (host === "127.0.0.1" || host === "localhost") {
    info(dim(`  To reach it from a server:  ssh -R ${actual}:localhost:${actual} <server>`));
    info(dim(`  then there:                 hush approvals pair --relay http://localhost:${actual}`));
    // Tailscale gives the same relay an https address only your tailnet can
    // reach — no SSH session to keep open. Printed, never run: changing
    // someone's Tailscale config is theirs to do.
    const ts = tailnetName();
    if (ts) {
      const lines = tailnetRelayLines(ts, actual);
      info("");
      info(dim("  Or over your tailnet (Tailscale is running here):"));
      info(dim(`    here:                     ${lines.serve}`));
      info(dim(`    on any tailnet machine:   ${lines.pair}`));
    }
  } else {
    info(yellow("  Listening beyond this machine: put it behind https (hush refuses a plain-http relay that is not localhost)."));
  }
  info(dim("  Ctrl-C to stop."));
  await new Promise<void>((resolve) => {
    const stop = () => server.close(() => resolve());
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
}
