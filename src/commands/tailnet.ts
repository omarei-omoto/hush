/**
 * `hush tailnet` — write the broker's grants into the tailnet policy file for
 * you (docs/TAILNET.md).
 *
 *   hush tailnet grant --to sam@example.com --sets staging    preview the change
 *   hush tailnet grant … --apply                               save it, after asking
 *   hush tailnet grants                                        the grants hush wrote
 *   hush tailnet revoke <id> [--apply]                         take one away
 *
 * With a Tailscale API key stored in hush (`hush add tailscale`), it reads the
 * policy file, inserts or removes only its own grant, shows the diff, has
 * Tailscale validate it, and saves only with --apply, after an approval, and
 * only over the version it read. Without a key it prints the grant to paste.
 */
import { existsSync } from "node:fs";
import { type Args, bool, list, str } from "../cli/args.ts";
import { bold, die, dim, green, info, red, warn } from "../cli/output.ts";
import { ctxLoose, policyFor } from "../cli/context.ts";
import { askLine } from "../cli/prompts.ts";
import { Vault, audit, locateProject } from "../vault.ts";
import { requireIdentity } from "../identity.ts";
import { globalVaultPath } from "../library.ts";
import { requestApproval } from "../approval.ts";
import { tailnetIPv4 } from "../tailscale.ts";
import { KEY_NAME, OAUTH_ID, OAUTH_SECRET, POLICY_SCOPE, policyApi, type PolicyApi, type TailscaleCredential } from "../tailscale-api.ts";
import {
  grantSnippet, hushGrants, insertGrant, lineDiff, newGrantId, removeGrant, validDestination, validPrincipal,
  type HushGrant,
} from "../tailnet-policy.ts";

const ADMIN_URL = "https://login.tailscale.com/admin/acls/file";

/**
 * The stored Tailscale credential, from `--use <set>` or the first set that
 * has one. An OAuth client (its ID and secret in one set) is preferred over an
 * API access token: it can be limited to the policy file, and what hush uses
 * of it lasts an hour.
 */
function findKey(a: Args): { cred: TailscaleCredential; where: string } | null {
  const only = str(a, "use");
  const id = requireIdentity();
  const vaults: string[] = [];
  const loc = locateProject(process.cwd());
  if (loc?.hasVault) vaults.push(loc.vaultPath);
  if (existsSync(globalVaultPath())) vaults.push(globalVaultPath());
  let token: { cred: TailscaleCredential; where: string } | null = null;
  for (const path of vaults) {
    let v: Vault;
    try {
      v = Vault.open(path);
    } catch {
      continue;
    }
    for (const s of v.sets()) {
      if (only && s.name !== only && s.label !== only) continue;
      const where = `${v.data.name} · ${s.label || s.name}`;
      try {
        if (s.keys.includes(OAUTH_ID) && s.keys.includes(OAUTH_SECRET)) {
          return { cred: { kind: "oauth", clientId: v.get(id, s.name, OAUTH_ID), clientSecret: v.get(id, s.name, OAUTH_SECRET) }, where };
        }
        if (!token && s.keys.includes(KEY_NAME)) token = { cred: { kind: "token", token: v.get(id, s.name, KEY_NAME) }, where };
      } catch {
        continue;
      }
    }
  }
  return token;
}

/** The API, with what hush noticed about the credential said once. */
function apiWith(found: { cred: TailscaleCredential; where: string }, make: (c: TailscaleCredential, onScope: (s: string[]) => void) => PolicyApi): PolicyApi {
  info(dim(`using the Tailscale ${found.cred.kind === "oauth" ? "OAuth client" : "API access token"} in ${found.where}`));
  if (found.cred.kind === "token") {
    info(dim("  An API access token can do anything its creator can, for up to 90 days. An OAuth client limited to"));
    info(dim(`  the policy file is safer: ${OAUTH_HINT}`));
  }
  return make(found.cred, (granted) => {
    const extra = granted.filter((g) => g !== POLICY_SCOPE && g !== `${POLICY_SCOPE}:read`);
    if (extra.length) warn(`This OAuth client can also do: ${extra.join(", ")}. hush needs only ${POLICY_SCOPE}; a client with just that is safer.`);
  });
}

const OAUTH_HINT = "Settings → OAuth clients → Generate, with only Policy File: write, then hush add tailscale --as tailscale --library";

function noKey(what: string): void {
  info("");
  info(dim(`  To have hush ${what} for you, give it an OAuth client that may edit only the policy file:`));
  info(dim(`    ${OAUTH_HINT}`));
  info(dim("  (an API access token works too: hush add tailscale-token --as tailscale --library)"));
}

/** The approval, or a terminal yes where approvals are off. Dies on no. */
async function confirmChange(a: Args, summary: string, detail: string[], scope: string): Promise<void> {
  const loose = ctxLoose(a);
  const policy = policyFor(loose.hushDir);
  if (policy?.requireApproval.includes("request")) {
    const ap = await requestApproval(loose.hushDir, {
      action: "request",
      summary,
      detail: [...detail, "Via:  api.tailscale.com, with your stored Tailscale credential"],
      scope,
      ttlSeconds: policy.approvalTtlSeconds,
      timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
      biometry: policy.biometry,
      sessionGrant: false,
    });
    if (ap.decision === "deny" || ap.decision === "timeout") die(`Nothing was saved: ${ap.note ?? (ap.decision === "timeout" ? "nobody answered" : "denied")} (code ${ap.code}).`);
    return;
  }
  if (bool(a, "yes")) return;
  if (!process.stdin.isTTY) die("Nothing was saved.", "Confirm in a terminal, or pass --yes.");
  const ans = (await askLine(`Save this to your tailnet's policy file? ${dim("[y/N]")} `)).trim().toLowerCase();
  if (ans !== "y" && ans !== "yes") die("Nothing was saved.");
}

/** Preview, validate, and (with --apply) save one edit to the policy file. */
async function edit(a: Args, api: PolicyApi, change: (text: string) => string, what: { summary: string; detail: string[]; scope: string; done: string }): Promise<void> {
  const { text, etag } = await api.get();
  const next = change(text);
  info("");
  info(bold("The change to your tailnet's policy file:"));
  for (const line of lineDiff(text, next).split("\n")) {
    info(line.startsWith("+ ") ? green(line) : line.startsWith("- ") ? red(line) : dim(line));
  }
  const objection = await api.validate(next);
  if (objection) die(`Tailscale would not accept it, so nothing was saved: ${objection}`);
  info("");
  info(`${green("✓")} Tailscale checked it: valid.`);
  if (!bool(a, "apply")) {
    info(dim("  Nothing is saved yet. Run the same command with --apply to save it."));
    return;
  }
  await confirmChange(a, what.summary, what.detail, what.scope);
  await api.set(next, etag);
  audit(ctxLoose(a).hushDir, { actor: "cli", action: "tailnet-policy", change: what.scope });
  info(`${green("✓")} ${what.done}`);
}

export async function cmdTailnet(
  a: Args,
  deps: { api?: (cred: TailscaleCredential, onScope: (granted: string[]) => void) => PolicyApi } = {},
): Promise<void> {
  const sub = a._[0];
  const make = deps.api ?? ((c: TailscaleCredential, onScope: (s: string[]) => void) => policyApi(c, undefined, undefined, onScope));

  if (sub === "grant") {
    const to = list(a, "to");
    const sets = list(a, "sets");
    if (!to.length || !sets.length) die("Who, and which sets?", "hush tailnet grant --to sam@example.com --sets staging");
    const bad = to.filter((p) => !validPrincipal(p));
    if (bad.length) die(`Not a tailnet user, group or tag: ${bad.join(", ")}`, "e.g. sam@example.com, group:eng, tag:ci, autogroup:member");
    if (sets.some((s) => !/^[\w.*-]+$/.test(s))) die("Set names are letters, digits, . _ - (or * for all the broker offers).");
    const dst = str(a, "dst") ?? tailnetIPv4();
    if (!dst) die("Which broker? This machine has no tailnet address.", "Pass --dst <its tailnet IP or tag:…>");
    if (!validDestination(dst)) die(`Not a tailnet destination: ${dst}`, "Its tailnet IP (100.x.y.z), a tag:…, or a host alias from the policy.");
    const port = Number(str(a, "port") ?? 8788);
    if (!Number.isInteger(port) || port < 1 || port > 65535) die("--port is a port number");
    const grant: HushGrant = { id: newGrantId(), src: to, dst: [dst], port, sets };

    const key = findKey(a);
    if (!key) {
      info(bold("Add this to \"grants\" in your tailnet policy file") + dim(`  (${ADMIN_URL})`));
      info("");
      info(grantSnippet(grant));
      noKey("add it");
      return;
    }
    return edit(a, apiWith(key, make), (t) => insertGrant(t, grant), {
      summary: `Change your tailnet's policy file: let ${to.join(", ")} use ${sets.join(", ")} on the broker`,
      detail: [`Adds:  ${to.join(", ")} → ${dst}:${port}, sets ${sets.join(", ")}`],
      scope: `tailnet-grant:${grant.id}`,
      done: `saved — ${to.join(", ")} can use ${sets.join(", ")} on the broker within seconds. Take it back with: hush tailnet revoke ${grant.id} --apply`,
    });
  }

  if (sub === "grants" || sub === "ls") {
    const key = findKey(a);
    if (!key) {
      info(dim("hush finds its grants by reading the policy file, which needs a Tailscale API key."));
      noKey("read them");
      return;
    }
    const { text } = await apiWith(key, make).get();
    const mine = hushGrants(text);
    if (!mine.length) return info(dim("No grants written by hush in your tailnet's policy file."));
    for (const g of mine) info(`  ${bold(g.id)}  ${g.src.join(", ")}  →  ${g.dst.join(", ")}:${g.port}  ${dim(`sets: ${g.sets.join(", ")}`)}`);
    return;
  }

  if (sub === "revoke") {
    const id = a._[1];
    if (!id || !/^hush-[0-9a-f]{8}$/.test(id)) die("Which grant?", "hush tailnet grants lists them, e.g. hush tailnet revoke hush-3f9a0c1d");
    const key = findKey(a);
    if (!key) {
      info(`Remove the grant marked ${bold(id)} from "grants" in your tailnet policy file ${dim(`(${ADMIN_URL})`)}.`);
      noKey("remove it");
      return;
    }
    return edit(a, apiWith(key, make), (t) => removeGrant(t, id), {
      summary: `Change your tailnet's policy file: remove hush grant ${id}`,
      detail: [`Removes:  ${id}`],
      scope: `tailnet-revoke:${id}`,
      done: `removed ${id} from your tailnet's policy file`,
    });
  }

  if (sub) warn(`Unknown: hush tailnet ${sub}`);
  die("hush tailnet grant | grants | revoke", "hush tailnet grant --to sam@example.com --sets staging   (add --apply to save)");
}
