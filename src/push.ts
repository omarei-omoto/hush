/**
 * Sending a key to a host (hosts.ts): find the host's own CLI, prove it is the
 * one hush's rules describe, refuse a value it would change, run it with the
 * value on its standard input — no shell, nothing on a command line — and
 * remember where the key went, so a replaced value can follow it there.
 *
 * Where keys went is kept in ~/.hush/pushes.json, never in a repository: a
 * list a clone could edit would be a list of places to send your secrets.
 */
import { spawn } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { Redactor } from "./redact.ts";
import { spawnPlan } from "./platform.ts";
import { isExecutableFile, onPath } from "./which.ts";
import { hushHome } from "./identity.ts";
import { ValidationError, assertKeyName, writeFileAtomic } from "./vault-files.ts";
import { parseJson } from "./json.ts";
import { normalHelp, versionAtLeast, type Host, type HostOptions } from "./hosts.ts";
import type { Vault } from "./vault.ts";

// ----------------------------------------------------------- running a CLI

interface Ran {
  code: number;
  /** stdout and stderr together, as the person would see them, masked. */
  out: string;
  timedOut: boolean;
}

/**
 * The environment a host's CLI gets: this one, less hush's own variables
 * (they open the vault) and less any variable that holds the value being sent
 * — the value reaches the CLI on stdin and nowhere else.
 */
function cliEnv(value?: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const k of Object.keys(env)) {
    if (k.startsWith("HUSH_") || (value && env[k] === value)) delete env[k];
  }
  return env;
}

function runCli(
  bin: string,
  args: string[],
  o: { cwd: string; stdin: string | null; value?: string; key?: string; timeoutMs: number; write?: (s: string) => void },
): Promise<Ran> {
  return new Promise((resolve, reject) => {
    const plan = spawnPlan(bin, args);
    const child = spawn(plan.command, plan.args, {
      cwd: o.cwd,
      env: cliEnv(o.value),
      windowsHide: true,
      shell: false,
      ...(plan.windowsVerbatimArguments ? { windowsVerbatimArguments: true } : {}),
      stdio: [o.stdin === null ? "ignore" : "pipe", "pipe", "pipe"],
    });
    const redactor = new Redactor(o.value && o.key ? { [o.key]: o.value } : {});
    let out = "";
    let timedOut = false;
    const take = (chunk: Buffer) => {
      const safe = redactor.push(chunk.toString("utf8"));
      out += safe;
      o.write?.(safe);
    };
    child.stdout!.on("data", take);
    child.stderr!.on("data", take);
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, o.timeoutMs);
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      const tail = redactor.flush();
      out += tail;
      o.write?.(tail);
      resolve({ code: code ?? 1, out, timedOut });
    });
    if (o.stdin !== null) {
      // A CLI that exits before reading all of it closes the pipe: that is its
      // own error to report, not a crash here.
      child.stdin!.on("error", () => {});
      child.stdin!.end(Buffer.from(o.stdin, "utf8"));
    }
  });
}

// ------------------------------------------------------- finding the CLI

/** The host's CLI: the project's own copy first (node_modules/.bin), then PATH. */
export function findCli(host: Host, root: string, platform: string = process.platform): string | null {
  const names = [host.bin, ...(host.alt ?? [])];
  if (host.local) {
    const exts = platform === "win32" ? [".cmd", ".exe"] : [""];
    for (const n of names) {
      for (const ext of exts) {
        const p = join(root, "node_modules", ".bin", n + ext);
        if (platform === "win32" ? existsSync(p) : isExecutableFile(p)) return p;
      }
    }
  }
  for (const n of names) {
    const p = onPath(n);
    if (p) return p;
  }
  return null;
}

/**
 * The approval's line about which program runs, by path. A project's own copy
 * (node_modules/.bin) came with its dependencies, so it says so: the person
 * approving should know the code that receives the value is the project's.
 */
export function programLine(host: Host, root: string): string {
  const bin = findCli(host, root);
  if (!bin) return `Program:  ${host.bin} (not installed here, so nothing will run)`;
  const own = bin.startsWith(join(root, "node_modules") + (process.platform === "win32" ? "\\" : "/"));
  return `Program:  ${bin}${own ? "  — this project's own copy, from its dependencies" : ""}`;
}

// ------------------------------------------------------- proving the CLI

export type Proof = { ok: true; version?: string } | { ok: false; why: string };

const proofs = new Map<string, Proof>();
const proofCachePath = (): string => join(hushHome(), "cli-proofs.json");

/** A program is the same program while its path, size and modification time are. */
function fingerprintOf(bin: string, host: Host): string | null {
  try {
    const st = statSync(bin);
    return `${host.id}|${bin}|${st.size}|${st.mtimeMs}|${host.proof.mustSay.join("\u0000")}|${host.proof.minVersion?.min ?? ""}`;
  } catch {
    return null;
  }
}

function loadProofCache(): Record<string, Proof> {
  try {
    const j = parseJson(readFileSync(proofCachePath(), "utf8")) as Record<string, Proof>;
    return j && typeof j === "object" ? j : {};
  } catch {
    return {};
  }
}

/**
 * Does the installed CLI show what this host's rules rely on? Its help must
 * say every `mustSay`, and where the rules rest on behaviour help does not
 * show, its version must be at least the first one checked. A passed proof is
 * remembered for that exact program file; a failed one is asked again next
 * time, in case it was updated in between.
 */
export async function proveCli(host: Host, bin: string, cwd: string): Promise<Proof> {
  const fp = fingerprintOf(bin, host);
  if (fp) {
    const known = proofs.get(fp) ?? loadProofCache()[fp];
    if (known?.ok) return known;
  }
  const help = await runCli(bin, host.proof.help, { cwd, stdin: null, timeoutMs: 90_000 }).catch((e: Error) => ({ code: 1, out: e.message, timedOut: false }));
  const text = normalHelp(help.out);
  const missing = host.proof.mustSay.filter((s) => !text.includes(normalHelp(s)));
  let proof: Proof;
  if (missing.length) {
    proof = {
      ok: false,
      why:
        `${bin} ${host.proof.help.join(" ")} does not say “${missing[0]}”, so this ${host.bin} is not a version hush has checked ` +
        `for sending a value on stdin. Update ${host.bin} and try again.`,
    };
  } else if (host.proof.minVersion) {
    const v = await runCli(bin, host.proof.minVersion.args, { cwd, stdin: null, timeoutMs: 60_000 }).catch((e: Error) => ({ code: 1, out: e.message, timedOut: false }));
    const ok = versionAtLeast(v.out, host.proof.minVersion.min);
    const seen = /(\d+\.\d+\.\d+)/.exec(v.out)?.[1];
    proof =
      ok === true
        ? { ok: true, ...(seen ? { version: seen } : {}) }
        : {
            ok: false,
            why:
              ok === null
                ? `could not tell which version of ${host.bin} this is, and ${host.label} needs at least ${host.proof.minVersion.min}`
                : `${host.bin} is ${seen}; hush has checked ${host.label} from ${host.proof.minVersion.min} on. Update it and try again.`,
          };
  } else {
    proof = { ok: true };
  }
  if (fp) {
    proofs.set(fp, proof);
    if (proof.ok) {
      try {
        writeFileAtomic(proofCachePath(), JSON.stringify({ ...loadProofCache(), [fp]: proof }, null, 2) + "\n");
      } catch { /* a cache, not a record */ }
    }
  }
  return proof;
}

// ---------------------------------------------------------- one push

export interface PushPlan {
  host: Host;
  key: string;
  opts: HostOptions;
  /** The command, before the CLI says whether the key is there already: for the approval. */
  preview: string;
}

/**
 * Everything that can be decided before anything runs: the name and where it
 * goes are well formed, the host has what it needs, and the value can arrive
 * exactly. Throws the reason otherwise.
 */
export function planPush(host: Host, key: string, value: string, given: Partial<HostOptions>): PushPlan {
  assertKeyName(key);
  const opts: HostOptions = {
    name: given.name || key,
    ...(given.target ? { target: given.target } : {}),
    ...(given.env || host.env?.default ? { env: given.env || host.env?.default } : {}),
    ...(given.deploy ? { deploy: true } : {}),
  };
  assertKeyName(opts.name);
  // What goes on the command line, besides fixed words, is these: none may
  // pass for a flag, carry a line break, or hold the value.
  for (const [what, v] of [["target", opts.target], ["environment", opts.env]] as const) {
    if (v === undefined) continue;
    if (!v || v.startsWith("-") || /[\u0000-\u001f\u007f]/.test(v) || v.length > 200) {
      throw new ValidationError(`That ${what} (${JSON.stringify(v.slice(0, 40))}) is not a name hush will put on a command line.`);
    }
    if (value && (v === value || (value.length >= 8 && v.includes(value)))) {
      throw new ValidationError(`The ${what} holds the value itself. A value never goes on a command line.`);
    }
  }
  if (host.target?.required && !opts.target) {
    throw new ValidationError(`${host.label} needs to know which ${host.target.noun}: pass --target <name>.`);
  }
  if (host.env?.required && !opts.env) throw new ValidationError(`${host.label} needs a ${host.env.noun}: pass --env <name>.`);
  if (opts.env && host.env?.choices && !host.env.choices.includes(opts.env)) {
    throw new ValidationError(`${host.label}'s ${host.env.noun} is one of ${host.env.choices.join(", ")}.`);
  }
  if (!host.env && given.env) throw new ValidationError(`${host.label} has no environments to choose from.`);
  if (host.deploys !== "optional" && given.deploy) {
    throw new ValidationError(host.deploys === "always" ? `${host.label} always deploys when a secret is set.` : `${host.label} does not deploy when a secret is set.`);
  }
  const why = host.refuses(value, opts);
  if (why) throw new ValidationError(`${key} cannot be sent to ${host.label} exactly: ${why}.`);
  const argv = host.argv({ ...opts, exists: false });
  assertNoValue(argv, value);
  const update = host.exists ? "  (update rather than create, if it is there already)" : "";
  return { host, key, opts, preview: `${host.bin} ${argv.join(" ")}${update}` };
}

/** The last line of defence: a value is never on a command line, whatever an entry above builds. */
function assertNoValue(argv: string[], value: string): void {
  if (argv.some((a) => a === value || (value.length >= 8 && a.includes(value)))) {
    throw new ValidationError("Refused: the command line would hold the value. Nothing was sent.");
  }
}

export interface Pushed {
  ok: boolean;
  /** The CLI's own output, the value masked in it. */
  output: string;
  /** The program that ran. */
  bin: string;
  argv: string[];
}

/**
 * Run one planned push: find and prove the CLI, ask it whether the key is
 * there (for hosts with separate create and update), then send the value on
 * stdin. `write` streams the CLI's output as it comes, masked.
 */
export async function runPush(plan: PushPlan, value: string, cwd: string, write?: (s: string) => void): Promise<Pushed> {
  const { host, key, opts } = plan;
  const bin = findCli(host, cwd);
  if (!bin) {
    throw new ValidationError(`The ${host.label} CLI (${host.bin}) is not installed here, so there is nothing to send it with. Install it, sign in, and try again.`);
  }
  const proof = await proveCli(host, bin, cwd);
  if (!proof.ok) throw new ValidationError(proof.why);
  let exists: boolean | undefined;
  if (host.exists) {
    // Its output is not shown: on some hosts it holds the current value.
    const probe = await runCli(bin, host.exists(opts), { cwd, stdin: null, timeoutMs: 120_000 }).catch(() => ({ code: 1, out: "", timedOut: false }));
    exists = probe.code === 0;
  }
  const argv = host.argv({ ...opts, exists });
  assertNoValue(argv, value);
  const ran = await runCli(bin, argv, { cwd, stdin: host.stdin(value, opts), value, key, timeoutMs: 300_000, write });
  return { ok: ran.code === 0 && !ran.timedOut, output: ran.timedOut ? ran.out + "\n(stopped after 5 minutes)" : ran.out, bin, argv };
}

// ------------------------------------------------------- where keys went

export interface PushRecord {
  key: string;
  host: string;
  /** The name it has there, when not the key's own. */
  name?: string;
  target?: string;
  env?: string;
  /** When it was sent (ISO). */
  at: string;
  /** Where the value came from, and when that value was last set: so a replaced one shows. */
  source?: { where: "project" | "library"; set: string; updatedAt: string };
}

interface PushFile {
  projects: Record<string, PushRecord[]>;
}

const pushesPath = (): string => join(hushHome(), "pushes.json");

function loadPushes(): PushFile {
  try {
    const j = parseJson(readFileSync(pushesPath(), "utf8")) as PushFile;
    return j && typeof j.projects === "object" && j.projects ? j : { projects: {} };
  } catch {
    return { projects: {} };
  }
}

const sameDestination = (a: PushRecord, b: PushRecord): boolean =>
  a.key === b.key && a.host === b.host && (a.name ?? a.key) === (b.name ?? b.key) && (a.target ?? "") === (b.target ?? "") && (a.env ?? "") === (b.env ?? "");

/** Remember (or refresh) where a key of this project went. */
export function recordPush(root: string, rec: PushRecord): void {
  const f = loadPushes();
  const list = (f.projects[root] ?? []).filter((r) => !sameDestination(r, rec));
  f.projects[root] = [...list, rec];
  writeFileAtomic(pushesPath(), JSON.stringify(f, null, 2) + "\n");
}

/** Where this project's keys were sent, on this machine. */
export function pushesFor(root: string): PushRecord[] {
  const list = loadPushes().projects[root];
  return Array.isArray(list) ? list.filter((r) => r && typeof r.key === "string" && typeof r.host === "string") : [];
}

/**
 * Where a run's value of `key` came from: the last layer (composeSets order)
 * that has it — "global:stripe", "global:openai#OPENAI_API_KEY", or a project
 * set — and when that value was last set there.
 */
export function sourceOf(
  key: string,
  layers: string[],
  project: Vault | null,
  library: Vault | null,
  libraryName: string,
): PushRecord["source"] | undefined {
  for (const layer of [...layers].reverse()) {
    const inLibrary = layer.startsWith(libraryName + ":");
    const rest = inLibrary ? layer.slice(libraryName.length + 1) : layer;
    const set = rest.includes("#") ? rest.slice(0, rest.indexOf("#")) : rest;
    if (rest.includes("#") && rest.slice(rest.indexOf("#") + 1) !== key) continue;
    const v = inLibrary ? library : project;
    if (!v?.has(set, key)) continue;
    const item = v.list(set).find((i) => i.key === key);
    if (item) return { where: inLibrary ? "library" : "project", set, updatedAt: item.updatedAt };
  }
  return undefined;
}

/** Has the value changed since it was sent? Unknown when hush cannot tell where it came from. */
export function isStale(rec: PushRecord, project: Vault | null, library: Vault | null): boolean | null {
  if (!rec.source) return null;
  const v = rec.source.where === "library" ? library : project;
  const item = v?.hasSet(rec.source.set) ? v.list(rec.source.set).find((i) => i.key === rec.key) : undefined;
  if (!item) return null;
  return item.updatedAt !== rec.source.updatedAt;
}
