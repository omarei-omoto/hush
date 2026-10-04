/**
 * The client side of leases (src/lease.ts, docs/TAILNET.md step 3):
 *
 *   hush lease enroll <broker>                 once per machine; approved on the broker
 *   hush run --from <broker> [--use set] -- <command>
 *
 * The values arrive sealed to this machine's hush key, live only in this
 * process and the child's environment, and the child's output is redacted as
 * in any `hush run`. Nothing is written to disk.
 */
import { type Args, bool, list, str } from "../cli/args.ts";
import { bold, die, dim, green, info } from "../cli/output.ts";
import { hushHome, requireIdentity } from "../identity.ts";
import { encodePub, fingerprint } from "../crypto.ts";
import { openLease, type SealedLease } from "../lease.ts";
import { runWithSecrets } from "../run.ts";
import { checkCommand, checkScopes, runScope } from "../policy.ts";
import { requestApproval } from "../approval.ts";
import { audit } from "../audit.ts";
import { locateProject } from "../vault-files.ts";
import { dieOnApproval, policyFor } from "../cli/context.ts";

/** `https://box.t.ts.net:8788`, from that or the MCP URL the broker printed. */
export function brokerBase(input: string): string {
  let u: URL;
  try {
    u = new URL(input);
  } catch {
    die(`Not a broker URL: ${input}`, "It is the address hush serve --tailnet printed, e.g. https://box.tailnet.ts.net:8788");
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") die(`Not a broker URL: ${input}`);
  return `${u.protocol}//${u.host}`;
}

/** This machine's software key. A lease is sealed to it, so it has to be one hush can open here. */
function leaseKey() {
  const id = requireIdentity();
  if (!id.pub || !id.priv) {
    die(
      "Leases need this machine's software hush key, and this one is hardware-only.",
      "Hardware keys (Secure Enclave, YubiKey) cannot take leases yet; hush_request through the broker still works.",
    );
  }
  return { id: { pub: id.pub, priv: id.priv }, pub: encodePub(id.pub), fp: fingerprint(id.pub) };
}

async function post(url: string, body: unknown): Promise<{ status: number; json: Record<string, unknown> }> {
  let r: Response;
  try {
    r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  } catch (e) {
    const cause = (e as { cause?: { code?: string; message?: string } }).cause;
    die(`Could not reach the broker at ${url}: ${cause?.code ?? cause?.message ?? (e as Error).message}`);
  }
  let json: Record<string, unknown> = {};
  try {
    json = (await r.json()) as Record<string, unknown>;
  } catch { /* an empty or non-JSON answer; the status says enough */ }
  return { status: r.status, json };
}

export async function cmdLease(a: Args): Promise<void> {
  const sub = a._[0];
  if (sub !== "enroll" || !a._[1]) die("hush lease enroll <broker-url>", "The broker URL is the one hush serve --tailnet printed.");
  const base = brokerBase(a._[1]);
  const key = leaseKey();
  info(`Asking ${bold(base)} to enroll this machine for leases…`);
  info(dim(`  this machine's hush key: ${key.fp} — the broker's approval prompt shows the same`));
  const r = await post(`${base}/lease/enroll`, { pub: key.pub, name: str(a, "name") });
  if (r.status !== 200) die(`Not enrolled: ${String(r.json.error ?? `the broker answered ${r.status}`)}`);
  info(`${green("✓")} enrolled — this machine can now ask for leases: hush run --from ${base} -- <command>`);
}

/** `hush run --from <broker> [--use …] -- <command>` */
export async function leaseRun(a: Args, argv: string[]): Promise<void> {
  if (!argv.length) die("Which command?", "hush run --from <broker> -- <command>");
  const base = brokerBase(str(a, "from")!);
  const key = leaseKey();
  const [command, ...args] = argv;
  const requested = list(a, "use");
  const unmasked = bool(a, "no-redact");

  // This machine's own policy decides what it will ask a broker for, the same
  // checks `hush run` makes here — a floor that refuses a command refuses it
  // whichever machine the key comes from. The broker then applies its own.
  // Skipping them made --from the way around every local gate.
  const project = locateProject();
  const policy = policyFor(project?.hushDir ?? hushHome());
  if (policy) {
    checkCommand({ ...policy, denyCommands: [] }, command);
    if (requested.length) checkScopes(policy, requested);
    if (policy.requireApproval.includes("run") || (unmasked && policy.requireApproval.includes("reveal"))) {
      const ap = await requestApproval(project?.hushDir ?? hushHome(), {
        action: unmasked ? "reveal" : "run",
        summary: `${unmasked ? "Run, output NOT masked" : "Run"} with keys from ${base}:  ${argv.join(" ")}`.trim(),
        detail: [
          ...(unmasked ? ["Unmasked:  --no-redact — anything this command prints, leased values included, is shown as is"] : []),
          `Asks for:  ${requested.join(", ") || "the sets the broker offers"}`,
          `Directory:  ${process.cwd()}`,
        ],
        scope: `${unmasked ? "unmasked:" : ""}lease:${base}:${runScope(policy, command, requested)}`,
        ttlSeconds: policy.approvalTtlSeconds,
        timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
        biometry: policy.biometry,
        sessionGrant: false,
      });
      dieOnApproval(ap, `running "${command}" with a lease`);
    }
  }
  if (!bool(a, "quiet")) process.stderr.write(dim(`hush: asking ${base} for a lease (it may ask the broker's owner first)…\n`));

  const r = await post(`${base}/lease`, { pub: key.pub, sets: requested, command, args, cwd: process.cwd() });
  if (r.status !== 200) {
    if (r.json.enroll) die("This machine is not enrolled with that broker.", `Enroll it once:  hush lease enroll ${base}`);
    die(`No lease: ${String(r.json.error ?? `the broker answered ${r.status}`)}`);
  }

  let payload;
  try {
    payload = openLease(r.json as unknown as SealedLease, key.id, { command, args });
  } catch (e) {
    die(`Refused the lease: ${(e as Error).message}`);
  }
  // The sets that came back, against this machine's policy too.
  if (policy) checkScopes(policy, payload.sets);
  if (project) audit(project.hushDir, { actor: "cli", action: "lease.run", from: base, command, sets: payload.sets, ...(unmasked ? { unmasked: true } : {}) });
  if (!bool(a, "quiet")) process.stderr.write(dim(`hush: leased ${payload.sets.join(", ")} from ${base}\n`));

  const result = await runWithSecrets(command, args, {
    cwd: process.cwd(),
    secrets: payload.secrets,
    redact: !unmasked,
    capture: false,
  }).catch((e) => die(`could not run "${command}": ${(e as Error).message}`));
  // Not process.exit(): it can drop buffered output when stdout is a pipe.
  process.exitCode = result.code;
}
