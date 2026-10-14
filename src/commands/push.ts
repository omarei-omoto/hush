/**
 * `hush push` — send keys to where your app runs: Cloudflare, Vercel, Fly,
 * GitHub and the rest in hosts.ts, each through its own CLI with the value on
 * standard input (push.ts).
 */
import { audit } from "../vault.ts";
import { requireIdentity } from "../identity.ts";
import { requestApproval } from "../approval.ts";
import { composeSets, globalVaultName, openGlobal } from "../library.ts";
import { HOSTS, detectHosts, hostById, type Host } from "../hosts.ts";
import { findCli, isStale, planPush, programLine, pushesFor, recordPush, runPush, sourceOf, type PushPlan, type PushRecord } from "../push.ts";
import { type Args, bool, list, str } from "../cli/args.ts";
import { ctxLoose, dieOnApproval, policyFor } from "../cli/context.ts";
import { bold, cyan, die, dim, green, info, red, warn, yellow } from "../cli/output.ts";

const USAGE = [
  "Usage: hush push <KEY> [<KEY>…] --to <host> [--target <name>] [--env <name>] [--as <NAME>] [--deploy] [--dry-run]",
  "       hush push --again [<KEY>…]   send the current value everywhere it was sent before",
  "       hush push --list             where this project's keys were sent",
  "       hush push --hosts            every host hush can send to, and which this project uses",
].join("\n");

interface Job {
  plan: PushPlan;
  value: string;
  source?: PushRecord["source"];
}

const where = (h: Host, target?: string, env?: string): string =>
  `${h.label}${target ? ` ${h.target?.noun ?? ""} ${target}`.replace(/\s+/g, " ") : ""}${env ? ` (${h.env?.noun ?? "env"} ${env})` : ""}`;

export async function cmdPush(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  const root = loose.root;

  if (bool(a, "hosts")) {
    const here = detectHosts(root);
    info(bold("Hosts hush can send a key to") + dim("  (the value goes to each CLI's standard input, never a command line)"));
    for (const h of HOSTS) {
      const found = here.find((d) => d.id === h.id);
      const bin = findCli(h, root);
      info(
        `  ${cyan(h.id.padEnd(17))} ${h.label.padEnd(28)} ${bin ? dim(bin) : yellow(`${h.bin} not installed`)}` +
          (found ? green(`  ← this project${found.target ? `: ${found.target}` : ""}`) : ""),
      );
    }
    info(dim("\n  Not here on purpose: hosts whose CLIs take a secret only as an argument (Netlify, Render, Heroku, Expo EAS, Deno Deploy)."));
    return;
  }

  if (bool(a, "list")) {
    const recs = pushesFor(root);
    if (!recs.length) return info(dim("No key from this project has been sent anywhere from this machine yet."));
    const project = loose.vault;
    const library = openGlobal();
    info(bold("Where this project's keys were sent"));
    for (const r of recs) {
      const h = hostById(r.host);
      const stale = isStale(r, project, library);
      info(
        `  ${bold(r.key)}${r.name && r.name !== r.key ? dim(` as ${r.name}`) : ""} → ${h ? where(h, r.target, r.env) : r.host}  ${dim(r.at.slice(0, 10))}` +
          (stale ? yellow("  changed since — hush push --again " + r.key) : ""),
      );
    }
    return;
  }

  const keys = a._;
  const again = bool(a, "again");
  const id = requireIdentity();
  const composed = composeSets(loose.vault, id, loose.hushDir, list(a, "use"));
  const library = openGlobal();
  const jobs: Job[] = [];
  const valueOf = (key: string): { value: string; source?: PushRecord["source"] } => {
    const from = str(a, "from");
    if (from) {
      const vault = loose.vault?.hasSet(from) ? loose.vault : library?.hasSet(from) ? library : null;
      if (!vault || !vault.has(from, key)) die(`No ${key} in a set called "${from}".`);
      const item = vault.list(from).find((i) => i.key === key)!;
      return { value: vault.get(id, from, key), source: { where: vault === library ? "library" : "project", set: from, updatedAt: item.updatedAt } };
    }
    const value = composed.secrets[key];
    if (value === undefined) {
      die(`${key} is not among the keys a run here gets.`, "hush ls shows what this project uses; --from <set> names a set directly.");
    }
    return { value, source: sourceOf(key, composed.layers, loose.vault, library, globalVaultName()) };
  };

  if (again) {
    const recs = pushesFor(root).filter((r) => !keys.length || keys.includes(r.key));
    if (!recs.length) die("Nothing to send again: no key from this project was sent from this machine." + (keys.length ? ` (${keys.join(", ")})` : ""));
    for (const r of recs) {
      const host = hostById(r.host);
      if (!host) {
        warn(`skipping ${r.key} → ${r.host}: this hush no longer knows that host`);
        continue;
      }
      const v = composed.secrets[r.key];
      if (v === undefined) {
        warn(`skipping ${r.key}: a run here no longer gets it`);
        continue;
      }
      try {
        jobs.push({ plan: planPush(host, r.key, v, { name: r.name, target: r.target, env: r.env }), value: v, source: sourceOf(r.key, composed.layers, loose.vault, library, globalVaultName()) });
      } catch (e) {
        warn(`skipping ${r.key} → ${host.label}: ${(e as Error).message}`);
      }
    }
  } else {
    const to = str(a, "to");
    if (!to || !keys.length) die(USAGE);
    const host = hostById(to);
    if (!host) die(`hush cannot send to "${to}".`, `It can send to: ${HOSTS.map((h) => h.id).join(", ")}`);
    const detected = host.target?.detect?.(root) ?? undefined;
    const target = str(a, "target") ?? detected;
    if (keys.length > 1 && str(a, "as")) die("--as names one key; send one key at a time to rename it.");
    for (const key of keys) {
      const { value, source } = valueOf(key);
      try {
        jobs.push({ plan: planPush(host, key, value, { name: str(a, "as"), target, env: str(a, "env"), deploy: bool(a, "deploy") }), value, source });
      } catch (e) {
        die((e as Error).message);
      }
    }
    if (detected && !str(a, "target")) info(dim(`  ${host.target!.noun} ${detected}, from this project's own config`));
  }
  if (!jobs.length) return;

  if (bool(a, "dry-run")) {
    for (const j of jobs) info(`  ${bold(j.plan.key)} → ${where(j.plan.host, j.plan.opts.target, j.plan.opts.env)}\n    ${dim("would run: " + j.plan.preview)}`);
    info(dim("  The value would go to standard input. Nothing was sent."));
    return;
  }

  // One approval for everything this command sends: it names each place.
  const policy = policyFor(loose.hushDir);
  if (policy?.requireApproval.includes("request")) {
    const one = jobs.length === 1 ? jobs[0] : null;
    const ap = await requestApproval(loose.hushDir, {
      action: "request",
      summary: one
        ? `Send ${one.plan.key} to ${where(one.plan.host, one.plan.opts.target, one.plan.opts.env)}`
        : `Send ${jobs.length} keys to ${[...new Set(jobs.map((j) => j.plan.host.label))].join(", ")}`,
      detail: [
        ...jobs.map((j) => `Runs: ${j.plan.preview}`),
        ...[...new Set(jobs.map((j) => programLine(j.plan.host, root)))],
        "The value goes to the CLI's standard input, never on a command line.",
      ],
      scope: `push:${jobs.map((j) => `${j.plan.host.id}/${j.plan.opts.target ?? ""}/${j.plan.opts.env ?? ""}/${j.plan.key}`).sort().join(",")}`,
      ttlSeconds: 0,
      timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
      biometry: policy.biometry,
      sessionGrant: false,
    });
    audit(loose.hushDir, { actor: "cli", action: "approval", on: "push", decision: ap.decision, via: ap.via, code: ap.code });
    dieOnApproval(ap, "sending " + jobs.map((j) => j.plan.key).join(", "));
  }

  let failed = 0;
  for (const j of jobs) {
    const { host, key, opts } = j.plan;
    info(`${cyan("→")} ${bold(key)} to ${where(host, opts.target, opts.env)}`);
    try {
      const r = await runPush(j.plan, j.value, root, (s) => process.stderr.write(dim(s)));
      audit(loose.hushDir, { actor: "cli", action: "push", key, host: host.id, target: opts.target, env: opts.env, ok: r.ok });
      if (!r.ok) {
        failed++;
        info(red(`  ✗ ${host.bin} did not succeed — see its output above. Nothing was recorded.`));
        continue;
      }
      recordPush(root, {
        key,
        host: host.id,
        ...(opts.name !== key ? { name: opts.name } : {}),
        ...(opts.target ? { target: opts.target } : {}),
        ...(opts.env ? { env: opts.env } : {}),
        at: new Date().toISOString(),
        ...(j.source ? { source: j.source } : {}),
      });
      info(`${green("  ✓")} sent. ${dim(host.after)}`);
    } catch (e) {
      failed++;
      info(red(`  ✗ ${(e as Error).message}`));
    }
  }
  if (failed) process.exitCode = 1;
}
