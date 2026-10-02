/**
 * `hush scan --agents` — plaintext credentials in coding agents' config files,
 * and `--fix` to move the ones hush can into your library.
 *
 * The report never prints a value: a masked preview (redact.ts preview(), the
 * same bound an agent gets) is enough to recognise a key and not enough to use
 * one. `--fix` stores each server's keys as a library set, checks they read
 * back, and only then rewrites the server entry to start through `hush run`.
 * A file that changed in between is left alone.
 */
import { existsSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { type Args, bool, parseArgs } from "../cli/args.ts";
import { ctxLoose } from "../cli/context.ts";
import { beginSetWrite } from "../cli/sets.ts";
import { absoluteSelfCommand, selfCommand } from "../cli/programs.ts";
import { consent } from "../cli/consent.ts";
import { bold, cyan, die, dim, green, info, out, red, warn, yellow } from "../cli/output.ts";
import {
  agentConfigFiles, alreadyWrapped, applyWrap, findSecrets, indentOf, planWraps,
  type AgentConfigFile, type Finding, type WrapPlan,
} from "../agent-configs.ts";
import { preview } from "../redact.ts";
import { serviceLabel } from "../services.ts";
import { requireIdentity } from "../identity.ts";
import { globalVaultExists, globalVaultName, openGlobal } from "../library.ts";
import { slugifyEnv, audit, type Vault } from "../vault.ts";
import { cmdGlobal } from "./global.ts";

interface Scanned {
  file: AgentConfigFile;
  text: string;
  findings: Finding[];
  unreadable?: string;
  /** Plans `--fix` can carry out in this file. */
  plans: WrapPlan[];
}

const tilde = (p: string): string => {
  const h = homedir();
  return p === h || p.startsWith(h + "/") ? "~" + p.slice(h.length) : p;
};

function readIf(path: string): string | null {
  try {
    return existsSync(path) && statSync(path).isFile() ? readFileSync(path, "utf8") : null;
  } catch {
    return null;
  }
}

/** Plain JSON only: rewriting a file with comments in it would drop them. */
function rewritable(file: AgentConfigFile, text: string): boolean {
  if (file.format !== "json") return false;
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
}

function scanAll(root: string): Scanned[] {
  const results: Scanned[] = [];
  for (const file of agentConfigFiles(root, process.env)) {
    const text = readIf(file.path);
    if (text === null) continue;
    const { findings, unreadable } = findSecrets(text, file.format);
    let plans: WrapPlan[] = [];
    if (findings.length && rewritable(file, text)) {
      const doc = JSON.parse(text);
      plans = planWraps(findings).filter((p) => {
        let node: unknown = doc;
        for (const k of p.entryPath) node = (node as Record<string, unknown>)?.[k];
        return node && typeof node === "object" && !alreadyWrapped(node as Record<string, unknown>);
      });
    }
    results.push({ file, text, findings, unreadable, plans });
  }
  return results;
}

/** Every plaintext credential in an agent config, with where it is — for the transcript scan. */
export function agentConfigSecrets(root: string): { agent: string; path: string; finding: Finding }[] {
  return scanAll(root).flatMap((s) => s.findings.map((finding) => ({ agent: s.file.agent, path: s.file.path, finding })));
}

/** For `hush doctor`: how many plaintext credentials, in how many files. */
export function agentCredentialCount(root: string): { count: number; files: number } {
  const hits = scanAll(root).filter((s) => s.findings.length);
  return { count: hits.reduce((n, s) => n + s.findings.length, 0), files: hits.length };
}

/**
 * What to do about a credential hush cannot move for you. Honest about the
 * cases with no good answer: a key inside a remote server's URL, or a setting
 * the agent hands its extension, is not something hush can inject — the most
 * it can say is that the file is now a secret.
 */
function byHand(f: Finding, file: AgentConfigFile): string {
  if (f.kind === "env" && file.format === "toml") {
    return "hush does not rewrite TOML yet: store it with hush add, and start the server with hush run --use <set> -- <command>";
  }
  if (f.kind === "env" && file.format === "jsonc") {
    return "this file has comments, which a rewrite would lose: store it with hush add, and start the server with hush run";
  }
  switch (f.kind) {
    case "header":
      return "sent as a request header, which hush cannot inject: keep this file private, or use a server that reads the key from its environment";
    case "url":
      return "part of the server's URL, so the URL itself is the secret: keep this file private";
    case "arg":
      return "a command-line argument, which ps shows to everyone: pass it as an env variable instead";
    case "env":
      return "not in a server hush starts: store it with hush add, and start it with hush run";
    default:
      return f.server
        ? `a setting ${file.agent} hands the server directly, which hush cannot inject: keep this file private`
        : `kept by ${file.agent} itself: keep this file private, and replace the key if it was ever shared`;
  }
}

export async function cmdScanAgents(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  const scanned = scanAll(loose.root);
  const withFindings = scanned.filter((s) => s.findings.length);
  const movable = new Set<Finding>();
  for (const s of scanned) {
    for (const p of s.plans) {
      for (const f of s.findings) if (f.kind === "env" && JSON.stringify(f.entryPath) === JSON.stringify(p.entryPath)) movable.add(f);
    }
  }
  const total = withFindings.reduce((n, s) => n + s.findings.length, 0);

  if (bool(a, "json")) {
    return out(JSON.stringify({
      checked: scanned.map((s) => ({ agent: s.file.agent, path: s.file.path, unreadable: s.unreadable ?? null })),
      findings: withFindings.flatMap((s) => s.findings.map((f) => ({
        agent: s.file.agent, path: s.file.path, server: f.server, where: f.where, name: f.name, kind: f.kind,
        service: f.service, preview: preview(f.value), movable: movable.has(f),
      }))),
    }, null, 2));
  }

  info(`${bold("agent configs")}  ${dim(`${scanned.length} file(s) found on this machine and in this folder`)}`);
  for (const s of scanned) if (s.unreadable) warn(`could not read ${tilde(s.file.path)} as ${s.file.format}: ${s.unreadable}`);
  if (!total) {
    info("");
    info(`  ${green("✓")} no plaintext credentials in any of them`);
    return;
  }
  for (const s of withFindings) {
    info("");
    info(`  ${bold(s.file.agent)}  ${dim(tilde(s.file.path))}${s.file.scope === "project" ? yellow("  (in this project — may be committed)") : ""}`);
    const width = Math.max(...s.findings.map((f) => `${f.server ?? "-"}  ${f.name}`.length));
    for (const f of s.findings) {
      const label = `${f.server ?? "-"}  ${f.name}`.padEnd(width);
      const svc = f.service ? `${serviceLabel(f.service)} · ` : "";
      info(`    ${red("✗")} ${label}  ${dim(svc + preview(f.value))}  ${movable.has(f) ? cyan("can move") : dim("by hand")}`);
    }
  }
  const nMovable = movable.size;
  info("");
  info(`  ${red(String(total))} plaintext credential(s) in ${withFindings.length} file(s). Anything running as you can read them.`);
  const hand = withFindings.flatMap((s) => s.findings.filter((f) => !movable.has(f)).map((f) => ({ f, file: s.file })));
  if (hand.length) {
    info("");
    info(dim("  By hand:"));
    for (const { f, file } of hand) info(dim(`    ${f.server ?? f.name} (${file.agent}): ${byHand(f, file)}`));
  }
  if (!bool(a, "fix")) {
    if (nMovable) {
      info("");
      info(`  Move the ${nMovable} hush can into your library:  ${cyan("hush scan --agents --fix")}`);
    }
    return;
  }
  if (!nMovable) {
    info("");
    info(dim("  Nothing here can be moved automatically."));
    return;
  }
  await fix(a, loose, scanned);
}

/** The set a server's keys go into: reuse one that already holds exactly these values, else a fresh name. */
function setFor(target: Vault, id: ReturnType<typeof requireIdentity>, server: string, keys: Record<string, string>): string {
  const base = `mcp-${slugifyEnv(server) || "server"}`;
  for (let n = 1; ; n++) {
    const name = n === 1 ? base : `${base}-${n}`;
    const existing = target.sets().find((s) => s.name === name);
    if (!existing) return name;
    const same = Object.entries(keys).every(([k, v]) => {
      try {
        return target.has(name, k) && target.get(id, name, k) === v;
      } catch {
        return false;
      }
    });
    if (same) return name;
  }
}

async function fix(a: Args, loose: ReturnType<typeof ctxLoose>, scanned: Scanned[]): Promise<void> {
  const work = scanned.filter((s) => s.plans.length);
  const count = work.reduce((n, s) => n + s.plans.reduce((m, p) => m + Object.keys(p.keys).length, 0), 0);

  info("");
  info(bold("This will:"));
  for (const s of work) {
    for (const p of s.plans) {
      info(`  ${cyan(p.server)}  ${dim(s.file.agent)}  move ${Object.keys(p.keys).join(", ")} into your library`);
    }
    info(dim(`    and rewrite ${tilde(s.file.path)} to start ${s.plans.length === 1 ? "it" : "them"} through hush run`));
  }
  if (!globalVaultExists()) info(dim(`  (and create your library first — you do not have one yet)`));
  // A person's yes: on their terminal, or in a hush dialog when an agent ran
  // this. --yes skips the question on a terminal, and stands in for it only
  // where no dialog can be shown (consent.ts) — an agent cannot answer for them.
  if (!(process.stdin.isTTY && bool(a, "yes"))) {
    const ok = await consent(`Move ${count} key(s) from your agents' configs into hush, and rewrite ${work.length} file(s)?`, {
      hushDir: loose.hushDir,
      detail: work.map((s) => `${s.file.agent}: ${tilde(s.file.path)}`),
      yes: bool(a, "yes"),
    });
    if (!ok) {
      if (!process.stdin.isTTY && !bool(a, "yes")) die("Nothing was changed.", "Run it in a terminal to confirm, or pass --yes where no dialog can be shown.");
      return info(dim("nothing changed"));
    }
  }

  if (!globalVaultExists()) await cmdGlobal(parseArgs(["--create"]));
  const { target } = await beginSetWrite(loose, a, { asLabel: "MCP server keys", count, verb: "Move", target: "library" });
  const id = requireIdentity();

  // 1. Into the vault, and saved, before any config file is touched.
  const setOf = new Map<WrapPlan, string>();
  for (const s of work) {
    for (const p of s.plans) {
      const name = setFor(target, id, p.server, p.keys);
      for (const [k, v] of Object.entries(p.keys)) target.set(id, name, k, v);
      target.describeEnv(name, { label: `MCP · ${p.server}` });
      setOf.set(p, name);
    }
  }
  target.save();

  // 2. Read them back from disk. A config file is only rewritten once its
  //    values are known to be retrievable — otherwise this would delete keys.
  const check = openGlobal();
  for (const [p, name] of setOf) {
    for (const [k, v] of Object.entries(p.keys)) {
      let back: string | null = null;
      try {
        back = check?.get(id, name, k) ?? null;
      } catch {
        back = null;
      }
      if (back !== v) die(`Stored ${k} in ${name} but could not read it back, so no config file was changed.`);
    }
  }

  // 3. Rewrite each file, only if it is still exactly what was scanned.
  const library = globalVaultName();
  let moved = 0;
  const rewritten: Scanned[] = [];
  for (const s of work) {
    const now = readIf(s.file.path);
    if (now !== s.text) {
      warn(`${tilde(s.file.path)} changed while hush was working; left alone. Its keys are already in your library, so run this again.`);
      continue;
    }
    const doc = JSON.parse(now);
    let changed = 0;
    for (const p of s.plans) {
      const runArgs = ["run", "--vault", library, "--quiet", "--use", setOf.get(p)!, "--"];
      const launch = s.file.scope === "user" ? absoluteSelfCommand(runArgs) : selfCommand(runArgs);
      const r = applyWrap(doc, p, launch);
      if (r.ok) {
        changed++;
        moved += Object.keys(p.keys).length;
      } else warn(`${p.server} in ${tilde(s.file.path)} left alone: ${r.reason}`);
    }
    if (!changed) continue;
    const text = JSON.stringify(doc, null, indentOf(now)) + (now.endsWith("\n") ? "\n" : "");
    // Written beside the original and renamed over it: an agent reading the
    // file mid-write sees the old version or the new one, never half of each.
    const tmp = `${s.file.path}.hush-${process.pid}.tmp`;
    writeFileSync(tmp, text, { mode: statSync(s.file.path).mode & 0o777 });
    renameSync(tmp, s.file.path);
    rewritten.push(s);
  }

  audit(loose.hushDir, { actor: "cli", action: "agents-fix", moved, files: rewritten.length });
  info("");
  info(`${green("✓")} moved ${moved} credential(s) into your library (${library}) and rewrote ${rewritten.length} file(s)`);
  for (const [p, name] of setOf) info(dim(`    ${p.server} → set ${name}`));
  info("");
  const agents = [...new Set(rewritten.map((s) => s.file.agent))];
  if (agents.length) info(`  Restart ${agents.join(", ")} so ${agents.length === 1 ? "it starts" : "they start"} the servers through hush.`);
  if (rewritten.some((s) => s.file.path === `${homedir()}/.claude.json`)) {
    info(dim("  Claude Code rewrites ~/.claude.json while it runs: if a server shows its old entry again, quit Claude Code and run this once more."));
  }
  info(dim("  The old values were in plaintext. If any of those files was ever synced, backed up or shared, replace the keys at the provider."));
}
