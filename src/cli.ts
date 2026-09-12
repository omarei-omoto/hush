#!/usr/bin/env node
/**
 * hush — envelope-encrypted team secrets your agent can use but never read.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync, chmodSync } from "node:fs";
import { join, dirname, basename, resolve as resolvePath } from "node:path";
import { createInterface } from "node:readline";
import {
  Vault,
  resolveVaultPath,
  namedVaultPath,
  audit,
  loadUse,
  saveUse,
  slugifyEnv,
  type LinkFile,
} from "./vault.ts";
import { CATALOG, knownVars, scopeOf, parseWith, serviceLabel } from "./services.ts";
import { loadIdentity, createIdentity, requireIdentity, publicKeyOf, hushHome } from "./identity.ts";
import { scanRepo, reconcile, parseEnvFile } from "./scan.ts";
import { runWithSecrets, toEnvFile, toShellExports } from "./run.ts";
import { preview } from "./redact.ts";
import { serveMcp, loadPolicy, DEFAULT_POLICY } from "./mcp.ts";
import { serveUi } from "./ui.ts";
import {
  compose, librarySets, loadLinks, saveLinks, openGlobal,
  globalVaultName, globalVaultExists, globalVaultPath, namedVaults, saveConfig,
} from "./library.ts";
import { VERSION } from "./version.ts";
import { assess } from "./posture.ts";
import { checkAndRecord, inspect, acceptCurrent, describeRollback } from "./integrity.ts";
import { renderLevel, runSecure, maybeNudge, snooze } from "./secure.ts";
import { pendingRequests, answerRequest, nativeDialogsAvailable } from "./approval.ts";
import { biometryStatus, ensureHelper, authenticate } from "./biometry.ts";
import {
  ageAvailable, ageVersion, ageBinary, ageIdentityPath,
  identityPlugin, recipientsForIdentity, isAgeRecipient,
} from "./age.ts";


// ------------------------------------------------------------------- output

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = c("1");
const dim = c("2");
const red = c("31");
const green = c("32");
const yellow = c("33");
const cyan = c("36");

const out = (s = ""): void => void process.stdout.write(s + "\n");
const info = (s: string): void => out(s);
const warn = (s: string): void => void process.stderr.write(yellow(`! ${s}`) + "\n");

function die(message: string, hint?: string): never {
  process.stderr.write(red(`✗ ${message}`) + "\n");
  if (hint) process.stderr.write(dim(`  ${hint}`) + "\n");
  process.exit(1);
}

// --------------------------------------------------------------- arg parsing

interface Args {
  _: string[];
  /** Everything after a bare `--`. */
  rest: string[];
  /** A repeated flag (`--with a --with b`) collects into an array. */
  flags: Record<string, string | boolean | string[]>;
}

function parseArgs(argv: string[]): Args {
  const _: string[] = [];
  const flags: Record<string, string | boolean | string[]> = {};
  let rest: string[] = [];

  const put = (name: string, value: string | boolean) => {
    const prev = flags[name];
    if (prev === undefined) flags[name] = value;
    else if (Array.isArray(prev)) prev.push(String(value));
    else flags[name] = [String(prev), String(value)];
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") {
      rest = argv.slice(i + 1);
      break;
    }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq !== -1) {
        put(a.slice(2, eq), a.slice(eq + 1));
      } else {
        const name = a.slice(2);
        const next = argv[i + 1];
        if (next && !next.startsWith("-")) {
          put(name, next);
          i++;
        } else {
          put(name, true);
        }
      }
    } else if (a.startsWith("-") && a.length > 1) {
      put(a.slice(1), true);
    } else {
      _.push(a);
    }
  }
  return { _, rest, flags };
}

const str = (a: Args, name: string, fallback?: string): string | undefined => {
  const v = a.flags[name];
  if (Array.isArray(v)) return v[v.length - 1];
  return typeof v === "string" ? v : fallback;
};

/** A repeatable flag. Also accepts one comma-separated value. */
const list = (a: Args, name: string): string[] => {
  const v = a.flags[name];
  const raw = Array.isArray(v) ? v : typeof v === "string" ? [v] : [];
  return raw.flatMap((x) => x.split(",")).map((x) => x.trim()).filter(Boolean);
};
const bool = (a: Args, name: string): boolean => a.flags[name] === true || a.flags[name] === "true";

// ------------------------------------------------------------------ prompts

/** Piped stdin is read once, then served one line per prompt. */
let pipedLines: string[] | null = null;

function readAllStdin(): Promise<string> {
  return new Promise((res) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (d) => (data += d));
    process.stdin.on("end", () => res(data));
  });
}

/**
 * @param whole  Take everything piped in as one value.
 *
 * Multi-variable flows (`hush add aws`) read one line per prompt, but a single
 * secret must not be split: `cat key.pem | hush set PRIVATE_KEY` was silently
 * storing only "-----BEGIN PRIVATE KEY-----".
 */
async function promptSecret(label: string, whole = false): Promise<string> {
  if (!process.stdin.isTTY) {
    if (whole && pipedLines === null) {
      return (await readAllStdin()).replace(/\r?\n$/, "");
    }
    if (pipedLines === null) {
      pipedLines = (await readAllStdin()).split(/\r?\n/);
      if (pipedLines.at(-1) === "") pipedLines.pop();
    }
    return pipedLines.shift() ?? "";
  }
  return new Promise((res) => {
    process.stderr.write(`${label}: `);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    let value = "";
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") {
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdin.removeListener("data", onData);
          process.stderr.write("\n");
          return res(value);
        }
        if (ch === "\u0003") { // Ctrl-C
          process.stdin.setRawMode(false);
          process.stderr.write("\n");
          process.exit(130);
        }
        if (ch === "\u007f" || ch === "\b") { // backspace
          value = value.slice(0, -1);
          continue;
        }
        value += ch;
      }
    };
    process.stdin.on("data", onData);
  });
}

// A throw between setRawMode(true) and the handler would otherwise leave the
// user's terminal with no echo and no line editing after hush exits.
process.on("exit", () => {
  if (process.stdin.isTTY && process.stdin.isRaw) {
    try { process.stdin.setRawMode(false); } catch { /* already gone */ }
  }
});

function confirm(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) return Promise.resolve(false);
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((res) =>
    rl.question(`${question} ${dim("[y/N]")} `, (a) => {
      rl.close();
      res(/^y(es)?$/i.test(a.trim()));
    }),
  );
}

/**
 * A single visible line of input, echoed as typed — unlike `promptSecret`,
 * which hides input and is for values that must never appear on screen. Only
 * ever called once the caller has confirmed `process.stdin.isTTY`, so there is
 * no non-TTY branch here to silently do the wrong thing.
 */
function promptLine(label: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((res) =>
    rl.question(label, (a) => {
      rl.close();
      res(a.trim());
    }),
  );
}

// -------------------------------------------------------------- vault access

interface Ctx {
  vault: Vault;
  hushDir: string;
  vaultPath: string;
  env: string;
  root: string;
}

function ctx(a: Args): Ctx {
  const loc = resolveVaultPath(process.cwd());
  if (!loc) {
    die("No hush vault found from this directory.", "Run `hush init` here, or `hush link <vault>`.");
  }
  const vault = Vault.open(loc.vaultPath);

  // Freshness, not just authenticity: a rolled-back vault decrypts perfectly.
  const rollback = checkAndRecord(vault);
  if (rollback) {
    process.stderr.write("\n" + red("  ⚠  VAULT ROLLBACK DETECTED") + "\n");
    for (const line of describeRollback(rollback)) {
      process.stderr.write(line ? `  ${dim(line)}\n` : "\n");
    }
    process.stderr.write("\n");
  }

  const env = str(a, "env") || loc.env || "default";
  return {
    vault,
    hushDir: loc.hushDir,
    vaultPath: loc.vaultPath,
    env,
    root: loc.hushDir.replace(/[/\\]\.hush$/, ""),
  };
}

function ensureGitignore(hushDir: string): void {
  const p = join(hushDir, ".gitignore");
  const body = ["audit.log", "pending/", "*.local.json", "identity", "*.lock", "*.tmp", ""].join("\n");
  if (!existsSync(p)) writeFileSync(p, body);

  // Stop git from line-merging the vault. A three-way merge of two independent
  // edits produces a file that is valid JSON but has a data key wrapped for one
  // branch and values sealed under another — unopenable, and it looks fine.
  // Marking it unmergeable forces a whole-file choice instead.
  const attrs = join(hushDir, ".gitattributes");
  if (!existsSync(attrs)) {
    // -merge only, never -diff: the diff is how a reviewer notices that a
    // recipient was added, and key names are not secret.
    writeFileSync(attrs, ["vault.json -merge", "use.json -merge", ""].join("\n"));
  }
}

// ----------------------------------------------------------------- commands

async function cmdInit(a: Args): Promise<void> {
  const name = a._[0] || require_basename();
  const global = bool(a, "global") || bool(a, "personal");
  const vaultPath = global ? namedVaultPath(name) : join(process.cwd(), ".hush", "vault.json");
  const hushDir = dirname(vaultPath);
  if (existsSync(vaultPath) && !bool(a, "force")) {
    die(`A vault already exists at ${vaultPath}.`, "Pass --force to replace it.");
  }

  let id = loadIdentity();
  if (!id) {
    info(dim("No identity on this machine yet — creating one."));
    id = createIdentity();
    info(`${green("✓")} identity created  ${dim(`(stored in ${id.source})`)}`);
  }

  const memberName = str(a, "as") || process.env.USER || "me";
  mkdirSync(hushDir, { recursive: true });
  Vault.create(
    vaultPath,
    name,
    id.pub
      ? { name: memberName, pub: id.pub }
      : { name: memberName, ageRecipient: id.age!.recipients[0] },
  );
  ensureGitignore(hushDir);

  info("");
  info(`${green("✓")} vault ${bold(name)} created at ${cyan(vaultPath)}`);
  info(`  you are ${bold(memberName)} (admin)  ${dim(publicKeyOf(id))}`);
  info("");
  info(dim("  This file is safe to commit — it holds only ciphertext and public keys."));
  info("");
  info("Next:");
  if (global) {
    info(`  ${cyan(`hush ui --vault ${name}`)}${dim("      add keys in the browser")}`);
    info(`  ${cyan(`hush link ${name}`)}${dim("            use it from a project (run this inside the project)")}`);
  }
  info(`  ${cyan("hush import .env")}         bring in what you already have`);
  info(`  ${cyan("hush set STRIPE_KEY")}      add one secret`);
  info(`  ${cyan("hush install-mcp")}         let your coding agent use them (blind)`);
}

function require_basename(): string {
  return process.cwd().split(/[/\\]/).filter(Boolean).pop() || "vault";
}

async function cmdId(a: Args): Promise<void> {
  if (bool(a, "create")) {
    const id = createIdentity("default", bool(a, "force"));
    info(`${green("✓")} identity created  ${dim(`(stored in ${id.source})`)}`);
    info("");
    info(bold("Your public key — send this to whoever runs the vault:"));
    info(cyan(publicKeyOf(id)));
    return;
  }
  const id = loadIdentity();
  if (!id) die("No identity on this machine.", "Run `hush id --create`.");
  if (bool(a, "quiet")) return out(publicKeyOf(id));
  info(bold("Your public key:"));
  info(cyan(publicKeyOf(id)));
  info(dim(`stored in: ${id.source}`));
}

async function cmdSet(a: Args): Promise<void> {
  const { vault, env, hushDir, vaultPath } = ctx(a);
  const id = requireIdentity();
  let key = a._[0];
  if (!key) die("Usage: hush set <KEY> [--env <env>] [--note <text>]");

  let value: string;
  const inline = key.indexOf("=");
  if (inline > 0) {
    value = key.slice(inline + 1);
    key = key.slice(0, inline);
    warn("Value passed on the command line — it is now in your shell history.");
  } else {
    value = await promptSecret(`value for ${bold(key)}`, true);
  }
  if (!value) die("Empty value, nothing written.");

  const existed = vault.has(env, key);
  vault.set(id, env, key, value, str(a, "note"));
  vault.save();
  audit(hushDir, { actor: "cli", action: existed ? "update" : "create", env, key });
  info(`${green("✓")} ${existed ? "updated" : "added"} ${bold(key)} in env ${cyan(env)}  ${dim(preview(value))}`);
  info(dim(`  commit ${vaultPath} to share it with the team`));
  maybeNudge(vault, hushDir, ctx(a).root);
}

async function cmdGet(a: Args): Promise<void> {
  const { vault, env, hushDir } = ctx(a);
  const id = requireIdentity();
  const key = a._[0];
  if (!key) die("Usage: hush get <KEY>");
  if (!vault.has(env, key)) die(`No secret "${key}" in env "${env}".`);

  if (!bool(a, "yes")) {
    warn("This prints a live credential to your terminal, where it stays in scrollback.");
    if (!(await confirm(`Reveal ${bold(key)}?`))) return info(dim("aborted"));
  }
  const value = vault.get(id, env, key);
  audit(hushDir, { actor: "cli", action: "reveal", env, key });
  out(value);
}

async function cmdLs(a: Args): Promise<void> {
  const { vault, env } = ctx(a);
  const items = vault.list(env);
  if (bool(a, "names")) {
    for (const i of items) out(i.key);
    return;
  }
  if (bool(a, "json")) return out(JSON.stringify(items, null, 2));
  const others = vault.plainEnvs().filter((e) => e !== env);
  const accounts = vault.accounts();

  if (!items.length) {
    info(dim(`No secrets in env "${env}". Add one with \`hush set <KEY>\`.`));
    // Without this, a vault whose secrets all live elsewhere looks empty.
    if (others.length) info(dim(`  other envs: ${others.join(", ")}`));
    if (accounts.length) info(dim(`  ${accounts.length} service account(s) — hush accounts`));
    return;
  }
  info(`${bold(vault.data.name)} ${dim("/")} ${cyan(env)}  ${dim(`(${items.length} secrets)`)}`);
  const width = Math.max(...items.map((i) => i.key.length));
  for (const i of items) {
    info(
      `  ${i.key.padEnd(width)}  ${dim(`${i.updatedBy} · ${i.updatedAt.slice(0, 10)}`)}` +
        (i.note ? `  ${dim("— " + i.note)}` : ""),
    );
  }
  if (others.length) info(dim(`\n  other envs: ${others.join(", ")}`));
  if (accounts.length) info(dim(`  ${accounts.length} service account(s) — hush accounts`));
}

async function cmdRm(a: Args): Promise<void> {
  const { vault, env, hushDir } = ctx(a);
  requireIdentity();
  const key = a._[0];
  if (!key) die("Usage: hush rm <KEY>");
  if (!vault.delete(env, key)) die(`No secret "${key}" in env "${env}".`);
  vault.save();
  audit(hushDir, { actor: "cli", action: "delete", env, key });
  info(`${green("✓")} removed ${bold(key)} from ${cyan(env)}`);
  warn("The old value is still in git history. Rotate it upstream if it was ever live.");
}

/**
 * Guess a set name from the filename, the same way the UI's "Save all of this
 * as one named set" bar does (src/ui.ts, `stagingPanel`'s `guess`): strip the
 * .env prefix and separators, then capitalize. `.env` alone has nothing left
 * to name it from, so it yields no guess rather than an empty label.
 */
function guessSetName(file: string): string {
  const guess = basename(file).replace(/^\.env\.?/, "").replace(/[-_.]+/g, " ").trim();
  return guess ? guess.charAt(0).toUpperCase() + guess.slice(1) : "";
}

/**
 * Import every key from `file` into a single env, applying the same
 * `--overwrite` rule the plain import path uses. Shared so a named set behaves
 * identically whether it is brand new or already has keys in it.
 */
function importInto(
  vault: Vault,
  id: ReturnType<typeof requireIdentity>,
  env: string,
  parsed: Record<string, string>,
  overwrite: boolean,
): { added: number; skipped: number } {
  let added = 0;
  let skipped = 0;
  for (const [key, value] of Object.entries(parsed)) {
    if (vault.has(env, key) && !overwrite) {
      skipped++;
      continue;
    }
    vault.set(id, env, key, value);
    added++;
  }
  return { added, skipped };
}

async function cmdImport(a: Args): Promise<void> {
  const { vault, env, hushDir, root } = ctx(a);
  const id = requireIdentity();
  const file = a._[0] || ".env";
  if (!existsSync(file)) die(`No such file: ${file}`);

  const parsed = parseEnvFile(readFileSync(file, "utf8"));
  const names = Object.keys(parsed);
  if (!names.length) die(`No variables found in ${file}.`);

  const overwrite = bool(a, "overwrite");
  // `hush import` is the command the quick-start tells people to run, so it is
  // the one place most piles of unrelated keys under "default" get born. Ask
  // once, but only when there is a human here to ask — a script, CI run or
  // agent gets no prompt and no change in behaviour, ever (never block).
  const envGiven = a.flags.env !== undefined;
  let asLabel = str(a, "as");
  if (!asLabel && !envGiven && process.stdin.isTTY) {
    const guess = guessSetName(file);
    const answer = await promptLine(
      `Name this set? (enter to keep in ${env}${guess ? `, e.g. "${guess}"` : ""}) `,
    );
    if (answer) asLabel = answer;
  }

  if (asLabel) {
    const slug = slugifyEnv(asLabel);
    const { added, skipped } = importInto(vault, id, slug, parsed, overwrite);
    // A second import into the same named set is someone adding to the set
    // they already named, not re-describing it — leaving out --description
    // here must not blank out the description the first import set.
    const meta: Parameters<typeof vault.describeEnv>[1] = { label: asLabel, source: file };
    const description = str(a, "description");
    const when = str(a, "when");
    if (description !== undefined) meta.description = description;
    if (when !== undefined) meta.whenToUse = when;
    if (!added) vault.ensureEnvExists(slug); // describeEnv requires the env to exist
    vault.describeEnv(slug, meta);
    vault.save();
    audit(hushDir, { actor: "cli", action: "import", env: slug, as: asLabel, file, added, skipped });
    info(`${green("✓")} imported ${bold(String(added))} secret(s) into ${bold(asLabel)} ${dim(`(${slug})`)} from ${file}`);
    if (skipped) info(dim(`  ${skipped} already present (pass --overwrite to replace)`));
    info("");
    info(yellow(`  Now delete ${file} — or at least make sure it is gitignored.`));
    if (globalVaultExists()) {
      info(dim(`  hush env new --from puts a set in your library instead, so every project can use it.`));
    }
    maybeNudge(vault, hushDir, root);
    return;
  }

  const { added, skipped } = importInto(vault, id, env, parsed, overwrite);
  vault.save();
  audit(hushDir, { actor: "cli", action: "import", env, file, added, skipped });
  info(`${green("✓")} imported ${bold(String(added))} secret(s) into ${cyan(env)} from ${file}`);
  if (skipped) info(dim(`  ${skipped} already present (pass --overwrite to replace)`));
  info("");
  info(yellow(`  Now delete ${file} — or at least make sure it is gitignored.`));
  info(dim(`  From here on: hush run -- <your command>`));
  // Only when nothing was said either way: --env asked for exactly today's
  // behaviour, and a declined prompt already gave the human the chance.
  if (!envGiven && !process.stdin.isTTY) {
    info(dim(`  Tip: hush import ${file} --as "Name" keeps these together as a named set.`));
  }
  maybeNudge(vault, hushDir, root);
}

/**
 * Which service accounts this run should use: the project's pinned defaults
 * from .hush/use.json, then any `--with service:account` on the command line.
 */
function chooseAccounts(a: Args, hushDir: string): { service: string; account: string }[] {
  const chosen = new Map<string, string>();
  for (const [service, account] of Object.entries(loadUse(hushDir))) chosen.set(service, account);
  for (const spec of list(a, "with")) {
    const { service, account } = parseWith(spec);
    chosen.set(service, account);
  }
  return [...chosen].map(([service, account]) => ({ service, account }));
}

async function cmdRun(a: Args): Promise<void> {
  const { vault, env, hushDir } = ctx(a);
  const id = requireIdentity();
  const argv = a.rest.length ? a.rest : a._;
  if (!argv.length) die("Usage: hush run [--with <service>:<account>] -- <command> [args...]");

  const choices = chooseAccounts(a, hushDir);
  // Library sets this project links, then its own env, then the chosen accounts.
  const { secrets, layers, missing } = compose(vault, id, hushDir, env, choices);
  if (missing.length) {
    warn(`This project uses ${missing.join(", ")}, which your library does not have.`);
    info(dim(`  Make your own:  hush env new ${missing[0]} --from .env`));
  }
  if (!bool(a, "quiet") && choices.length) {
    process.stderr.write(
      dim(`hush: using ${choices.map((ch) => `${ch.service}:${ch.account}`).join(", ")}\n`),
    );
  }
  audit(hushDir, { actor: "cli", action: "run", layers, command: argv[0], injected: Object.keys(secrets).length });

  const result = await runWithSecrets(argv[0], argv.slice(1), {
    cwd: process.cwd(),
    secrets,
    redact: !bool(a, "no-redact"),
    capture: false,
  }).catch((e) => die(`could not run "${argv[0]}": ${e.message}`));

  // Not process.exit(): it discards buffered stdout when stdout is a pipe, so
  // `hush run -- cmd | head` could lose the tail of the child's output.
  process.exitCode = result.code;
}

async function cmdScan(a: Args): Promise<void> {
  const { vault, env, root } = ctx(a);
  const target = a._[0] ? resolvePath(a._[0]) : root;
  const usages = scanRepo(target);
  const r = reconcile(usages, vault.list(env).map((i) => i.key));

  if (bool(a, "json")) return out(JSON.stringify(r, null, 2));

  info(`${bold("scan")} ${dim(target)}  ${dim("against")} ${cyan(env)}`);
  info("");
  info(`  ${green("✓")} ${r.satisfied.length} satisfied by the vault`);
  info(`  ${r.missing.length ? red("✗") : green("✓")} ${r.missing.length} missing`);
  if (r.unused.length) info(`  ${dim("·")} ${r.unused.length} in vault but unreferenced`);

  if (r.missing.length) {
    info("");
    info(bold("Missing:"));
    const width = Math.max(...r.missing.map((m) => m.name.length));
    for (const m of r.missing) {
      info(`  ${red(m.name.padEnd(width))}  ${dim(m.sites.slice(0, 3).join(", "))}`);
    }
    info("");
    info(dim(`  add them:  hush set <KEY> --env ${env}`));
  }
  if (r.unused.length && bool(a, "verbose")) {
    info("");
    info(dim(`Unreferenced: ${r.unused.join(", ")}`));
  }
}

async function cmdExport(a: Args): Promise<void> {
  const { vault, env, hushDir } = ctx(a);
  const id = requireIdentity();

  // Must match `hush run` exactly. Materialising only the base environment meant
  // export silently omitted every service-account secret, so the shell hook and
  // any generated .env disagreed with what the app actually got at run time.
  const choices = chooseAccounts(a, hushDir);
  // Must match `hush run` exactly, library links included.
  const { secrets, missing } = compose(vault, id, hushDir, env, choices);
  if (missing.length) warn(`Not exported: ${missing.join(", ")} — your library does not have them.`);

  // Used by the shell hook to know what to unset again on the way out.
  if (bool(a, "names")) {
    for (const k of Object.keys(secrets).sort()) out(k);
    return;
  }
  const format = str(a, "format") || (bool(a, "shell") ? "shell" : "env");
  const outFile = str(a, "out");

  const body =
    format === "json"
      ? JSON.stringify(secrets, null, 2) + "\n"
      : format === "shell"
        ? toShellExports(secrets)
        : toEnvFile(secrets, `generated by hush from vault "${vault.data.name}" env "${env}" — do not commit`);

  audit(hushDir, { actor: "cli", action: "export", env, format, to: outFile ?? "stdout" });

  if (outFile) {
    writeFileSync(outFile, body, { mode: 0o600 });
    // writeFileSync only applies mode on creation; an existing file keeps its
    // old permissions, which for a stray .env is usually 0644.
    chmodSync(outFile, 0o600);
    const gi = join(process.cwd(), ".gitignore");
    const entry = outFile.replace(/^\.\//, "");
    const current = existsSync(gi) ? readFileSync(gi, "utf8") : "";
    if (!current.split(/\r?\n/).includes(entry)) {
      appendFileSync(gi, (current.endsWith("\n") || !current ? "" : "\n") + entry + "\n");
      info(dim(`  added ${entry} to .gitignore`));
    }
    warn(`Wrote ${Object.keys(secrets).length} plaintext secret(s) to ${outFile} (mode 0600).`);
    // A .env is a format to be *parsed*. Its quoting is dotenv's, not a shell's,
    // and it cannot be both — so a value containing a command substitution is
    // inert to every dotenv loader and live to `source`. `--shell` exists for
    // the shell case and is quoted for it.
    info(dim(`  Parse it, don't source it: \`set -a; . ${outFile}\` would let a value run.`));
    info(dim(`  For a shell, use: eval "$(hush export --shell)"`));
    info(dim("  Better still, `hush run -- <cmd>` keeps them off disk entirely."));
  } else {
    process.stdout.write(body);
  }
}

async function cmdTeam(a: Args): Promise<void> {
  const sub = a._[0];
  const { vault, hushDir, vaultPath } = ctx(a);

  if (!sub || sub === "ls" || sub === "list") {
    const members = vault.members();
    info(`${bold(vault.data.name)}  ${dim(`DEK generation ${vault.data.dek.generation}`)}`);
    const width = Math.max(...members.map((m) => m.name.length));
    for (const m of members) {
      info(
        `  ${m.name.padEnd(width)}  ${m.role === "admin" ? yellow("admin ") : dim("member")}  ` +
          `${dim(m.pk.slice(0, 20) + "…")}  ${m.kind === "age" ? cyan("age") : dim("key")}  ${m.canDecrypt ? green("✓") : red("revoked")}`,
      );
    }
    return;
  }

  const id = requireIdentity();

  if (sub === "add") {
    const [name, pk] = [a._[1], a._[2]];
    if (!name || !pk) die("Usage: hush team add <name> <hush_pk_… | age1…>");
    if (isAgeRecipient(pk) && !ageAvailable()) {
      die("That is an age recipient, but the age binary is not installed.", "brew install age");
    }
    const fp = vault.addRecipient(id, name, pk, str(a, "role") === "admin" ? "admin" : "member");
    vault.save();
    audit(hushDir, { actor: "cli", action: "team.add", name, fingerprint: fp });
    info(`${green("✓")} ${bold(name)} can now decrypt this vault`);
    info(dim(`  commit ${vaultPath} and they are in — no server, no invite email`));
    return;
  }

  if (sub === "rm" || sub === "remove") {
    const name = a._[1];
    if (!name) die("Usage: hush team rm <name>");
    const { removed, reEncrypted } = vault.removeRecipient(id, name);
    vault.save();
    audit(hushDir, { actor: "cli", action: "team.remove", name, reEncrypted });
    info(`${green("✓")} removed ${bold(removed.name)}`);
    info(`  new DEK generation ${vault.data.dek.generation}; re-sealed ${reEncrypted} value(s)`);
    info("");
    warn("They can still use any value they read before now.");
    info(dim("  Rotate those credentials at the provider (Stripe, AWS, …) — hush cannot do that for you."));
    return;
  }

  die(`Unknown: hush team ${sub}`, "Try: ls | add | rm");
}

async function cmdRotate(a: Args): Promise<void> {
  const { vault, hushDir } = ctx(a);
  const id = requireIdentity();
  const n = vault.rotate(id);
  vault.save();
  audit(hushDir, { actor: "cli", action: "rotate", generation: vault.data.dek.generation });
  info(`${green("✓")} rotated to DEK generation ${vault.data.dek.generation}, re-sealed ${n} value(s)`);
  info(dim("  This rotates the vault key, not your provider credentials."));
}

async function cmdLink(a: Args): Promise<void> {
  const name = a._[0];
  if (!name) die("Usage: hush link <vault-name|path> [--env <env>]");
  const target = name.includes("/") ? resolvePath(name) : namedVaultPath(name);
  if (!existsSync(target)) {
    die(`No vault at ${target}.`, `Create it with: HUSH_VAULT=${target} hush init ${name}`);
  }
  const hushDir = join(process.cwd(), ".hush");
  mkdirSync(hushDir, { recursive: true });
  const link: LinkFile = { vault: name.includes("/") ? target : name, env: str(a, "env") || "default" };
  writeFileSync(join(hushDir, "link.json"), JSON.stringify(link, null, 2) + "\n");
  ensureGitignore(hushDir);
  info(`${green("✓")} this project now uses vault ${bold(name)} (env ${cyan(link.env!)})`);
  info(dim(`  .hush/link.json is safe to commit — it names a vault, it holds nothing`));
}

async function cmdEnvs(a: Args): Promise<void> {
  // Deliberately does not require a project. Your library is yours wherever you
  // are standing, and needing to be inside a repo to look at it is exactly the
  // kind of thing that makes a tool annoying.
  const loc = resolveVaultPath(process.cwd());
  const hushDir = loc?.hushDir ?? null;
  const linked = hushDir ? loadLinks(hushDir) : [];
  const library = librarySets(hushDir);

  if (library.length) {
    info(bold("Your library") + dim(`  (${globalVaultName()})`));
    for (const set of library) {
      info(
        `  ${set.linked ? green("●") : " "} ${bold(set.label)} ${dim(`(${set.name})`)}  ` +
          dim(`${set.keys.length} key(s)`),
      );
      if (set.description) info(`      ${dim(set.description)}`);
      if (set.whenToUse) info(`      ${dim("when: " + set.whenToUse)}`);
    }
    if (hushDir) info(dim("\n  ● = used by this project.  hush env use <name> / hush env drop <name>"));
  } else if (globalVaultExists()) {
    info(bold("Your library") + dim(`  (${globalVaultName()})`) + " — empty");
    info(dim('  hush env new "Acme Production" --from .env'));
  } else {
    info(dim(`No library yet.  ${cyan("hush global --create")}`));
  }

  if (!loc) {
    info("");
    info(dim("No project here, so nothing to show for one. `hush init` starts one."));
    return;
  }

  const { vault, env } = ctx(a);
  info("");
  info(bold("This project"));
  const sets = vault.envSets();
  for (const e of vault.plainEnvs()) {
    const set = sets.find((x) => x.name === e);
    const n = vault.list(e).length;
    info(`  ${e === env ? green("●") : " "} ${bold(set?.label ?? e)} ${dim(`(${e})`)}  ${dim(`${n} key(s)`)}`);
    if (set?.description) info(`      ${dim(set.description)}`);
    if (set?.whenToUse) info(`      ${dim("when: " + set.whenToUse)}`);
  }

  const accounts = vault.accounts();
  if (accounts.length) info(dim(`\n  ${accounts.length} service account(s) — hush accounts`));
  for (const name of linked) {
    if (!library.some((s) => s.name === name)) {
      warn(`this project uses "${name}", which your library does not have`);
    }
  }
}

/**
 * `hush env` — the named sets, which is how people actually think about this.
 *
 * An environment used to be a bare map key with no name, no description and no
 * note about when to use it, so a dropped .env became a flat list of loose keys
 * under "default" with nothing tying them together or explaining them.
 *
 * Acts on your library unless `--project` is given, because the library is where
 * a named set normally belongs: one copy, used by as many projects as you like.
 */
async function cmdEnv(a: Args): Promise<void> {
  const sub = a._[0];
  const rest = a._.slice(1);
  if (!sub || sub === "ls" || sub === "list") return cmdEnvs(a);

  const onProject = bool(a, "project");
  const loc = resolveVaultPath(process.cwd());
  const hushDir = loc?.hushDir ?? null;

  const target = (): { vault: Vault; save: () => void; where: string } => {
    if (onProject) {
      if (!loc) die("No project vault here.", "Run `hush init`, or drop --project to act on your library.");
      const v = Vault.open(loc.vaultPath);
      return { vault: v, save: () => v.save(), where: "this project" };
    }
    const g = openGlobal();
    if (!g) {
      die(
        `You have no library yet (looked for a vault called "${globalVaultName()}").`,
        namedVaults().length
          ? `Adopt one you already have:  hush global ${namedVaults()[0]}`
          : "Make one:  hush global --create",
      );
    }
    return { vault: g, save: () => g.save(), where: `your library (${globalVaultName()})` };
  };

  switch (sub) {
    case "new": {
      const label = rest.join(" ").trim();
      if (!label) die("Usage: hush env new <name> [--from <file>] [--description <text>] [--when <text>]");
      const { vault, save, where } = target();
      const id = requireIdentity();
      const name = slugifyEnv(label);
      if (vault.data.envs[name]) die(`"${name}" already exists in ${where}.`);

      const from = str(a, "from");
      let added = 0;
      if (from) {
        if (!existsSync(from)) die(`No such file: ${from}`);
        for (const [k, v] of Object.entries(parseEnvFile(readFileSync(from, "utf8")))) {
          vault.set(id, name, k, v);
          added++;
        }
      }
      if (!added) vault.ensureEnvExists(name);
      vault.describeEnv(name, {
        label,
        description: str(a, "description"),
        whenToUse: str(a, "when"),
        ...(from ? { source: from } : {}),
      });
      save();
      info(`${green("✓")} created ${bold(label)} ${dim(`(${name})`)} in ${where}` + (added ? `, ${added} key(s)` : ""));
      if (!onProject) info(dim(`  use it in a project:  hush env use ${name}`));
      return;
    }

    case "rename": {
      const [from, ...to] = rest;
      const label = to.join(" ").trim();
      if (!from || !label) die("Usage: hush env rename <name> <new name>");
      const { vault, save, where } = target();
      const id = requireIdentity();
      const next = slugifyEnv(label);

      // The name is bound into every value's AAD, so this re-seals them all.
      const { moved } = vault.renameEnv(id, from, next);
      vault.describeEnv(next, { label });
      save();

      // Anything pinned to the old name follows it, or the rename quietly
      // breaks every project that was using it.
      let repinned = false;
      if (!onProject && hushDir) {
        const links = loadLinks(hushDir);
        if (links.includes(from)) {
          saveLinks(hushDir, links.map((l) => (l === from ? next : l)));
          repinned = true;
        }
      }
      info(`${green("✓")} ${from} → ${bold(label)} ${dim(`(${next})`)} in ${where}, ${moved} key(s) re-sealed`);
      if (repinned) info(dim("  this project's link was updated to match"));
      return;
    }

    case "describe": {
      const name = rest[0];
      if (!name) die("Usage: hush env describe <name> [--description <text>] [--when <text>] [--label <text>]");
      const { vault, save, where } = target();
      vault.describeEnv(name, {
        label: str(a, "label"),
        description: str(a, "description"),
        whenToUse: str(a, "when"),
      });
      save();
      info(`${green("✓")} updated ${bold(name)} in ${where}`);
      return;
    }

    case "move": {
      const keys = rest;
      const to = str(a, "to");
      if (!keys.length || !to) {
        die(
          "Usage: hush env move <KEY> [<KEY>…] --to <set> [--from <set>]",
          'e.g. hush env move STRIPE_SECRET_KEY CONVEX_DEPLOYMENT --to "Acme Production"',
        );
      }
      const { vault, save, where } = target();
      const id = requireIdentity();
      const from = str(a, "from") || "default";
      const dest = vault.data.envs[to] ? to : slugifyEnv(to);
      if (!vault.data.envs[dest]) {
        die(
          `No set called "${to}" in ${where}.`,
          `Make it first:  hush env new "${to}"${onProject ? " --project" : ""}`,
        );
      }
      for (const key of keys) vault.moveSecret(id, key, from, dest);
      save();
      info(`${green("✓")} moved ${keys.length} key(s) from ${bold(from)} to ${bold(dest)} in ${where}`);
      return;
    }

    case "use": {
      const name = rest[0];
      if (!name) die("Usage: hush env use <name>");
      if (!hushDir) die("No project here.", "Run `hush init` first.");
      const library = librarySets(hushDir);
      if (!library.some((s) => s.name === name)) {
        die(
          `Your library has no set called "${name}".`,
          library.length
            ? `you have: ${library.map((s) => s.name).join(", ")}`
            : "make one: hush env new <name> --from .env",
        );
      }
      saveLinks(hushDir, [...loadLinks(hushDir), name]);
      info(`${green("✓")} this project now uses ${bold(name)}`);
      info(dim("  recorded in .hush/envs.json — it names the set, never the keys"));
      return;
    }

    case "drop": {
      const name = rest[0];
      if (!name) die("Usage: hush env drop <name>");
      if (!hushDir) die("No project here.");
      saveLinks(hushDir, loadLinks(hushDir).filter((l) => l !== name));
      info(`${green("✓")} this project no longer uses ${bold(name)}`);
      return;
    }

    default:
      die(`Unknown: hush env ${sub}`, "Try: ls, new, rename, describe, move, use, drop");
  }
}

/** `hush global` — which vault holds your library. */
async function cmdGlobal(a: Args): Promise<void> {
  const name = a._[0];

  if (bool(a, "create")) {
    const target = name || globalVaultName();
    const path = namedVaultPath(target);
    if (existsSync(path)) die(`A vault called "${target}" already exists.`, `Adopt it with: hush global ${target}`);
    const id = loadIdentity() ?? createIdentity();
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    Vault.create(path, target, { name: "me", pub: id.pub, ageRecipient: id.age?.recipients[0] });
    saveConfig({ globalVault: target });
    info(`${green("✓")} your library is vault ${bold(target)}`);
    info(dim(`  ${path}`));
    info("");
    info(`  ${cyan('hush env new "Acme Production" --from .env')}   put something in it`);
    return;
  }

  if (!name) {
    info(`Your library is vault ${bold(globalVaultName())}` + (globalVaultExists() ? "" : dim("  (not created yet)")));
    if (globalVaultExists()) info(dim(`  ${globalVaultPath()}`));
    const others = namedVaults().filter((v) => v !== globalVaultName());
    if (others.length) info(dim(`  other vaults you have: ${others.join(", ")}`));
    if (!globalVaultExists()) {
      info("");
      info(`  ${cyan("hush global --create")}          make one`);
      if (namedVaults().length) {
        info(`  ${cyan(`hush global ${namedVaults()[0]}`)}      adopt one you already have`);
      }
    }
    return;
  }

  if (!existsSync(namedVaultPath(name))) {
    die(
      `No vault called "${name}".`,
      namedVaults().length ? `you have: ${namedVaults().join(", ")}` : "make one: hush global --create",
    );
  }
  saveConfig({ globalVault: name });
  info(`${green("✓")} your library is now vault ${bold(name)}`);
}

async function cmdInstallMcp(a: Args): Promise<void> {
  const { root } = ctx(a);
  const cliPath = resolvePath(new URL(import.meta.url).pathname);
  const target = join(root, ".mcp.json");
  const existing = existsSync(target) ? JSON.parse(readFileSync(target, "utf8")) : {};
  existing.mcpServers ??= {};
  existing.mcpServers.hush = { command: "node", args: [cliPath, "mcp"] };
  writeFileSync(target, JSON.stringify(existing, null, 2) + "\n");

  const policyPath = join(root, ".hush", "policy.json");
  if (!existsSync(policyPath)) {
    // Serialised from the live defaults rather than retyped. The hand-written
    // copy that used to live here is how a setting that no longer exists
    // (`allowReveal`) kept being written into every new project.
    const template = { ...DEFAULT_POLICY, denyCommands: [] };
    writeFileSync(policyPath, JSON.stringify(template, null, 2) + "\n");
    info(`${green("✓")} wrote ${cyan(".hush/policy.json")} ${dim("(what the agent may run)")}`);
  }

  info(`${green("✓")} registered hush in ${cyan(".mcp.json")}`);
  info("");
  info("Your agent can now:");
  info(`  ${dim("·")} see which secrets exist`);
  info(`  ${dim("·")} run commands with them injected`);
  info(`  ${dim("·")} ${bold("not")} read a single value`);
}

async function cmdHook(a: Args): Promise<void> {
  const shell = a._[0] || "zsh";
  warn("The shell hook exports secrets into your interactive shell, so every process you");
  warn("launch from it — including your coding agent — inherits them. `hush run` is safer.");
  process.stderr.write("\n");

  if (shell === "fish") {
    out(`function _hush_unload
  if set -q HUSH_LOADED_KEYS
    for k in (string split " " -- $HUSH_LOADED_KEYS)
      set -e $k
    end
    set -e HUSH_LOADED_KEYS HUSH_LOADED_DIR
  end
end

function _hush_hook --on-variable PWD
  set -l root (hush root 2>/dev/null)
  if test "$root" = "$HUSH_LOADED_DIR"
    return
  end
  _hush_unload
  test -z "$root"; and return
  set -l keys (hush export --names 2>/dev/null | tr '\\n' ' ')
  hush export --shell 2>/dev/null | source
  or return
  set -gx HUSH_LOADED_DIR $root
  set -gx HUSH_LOADED_KEYS $keys
end`);
    return;
  }

  // The important half is the unload. Without it you keep production
  // credentials in your shell after cd-ing away, and hand them to every
  // unrelated process you start afterwards.
  const SPLIT = shell === "bash" ? "$HUSH_LOADED_KEYS" : "${=HUSH_LOADED_KEYS}";
  out(`_hush_unload() {
  if [ -n "$HUSH_LOADED_KEYS" ]; then
    for k in ${SPLIT}; do unset "$k"; done
    unset HUSH_LOADED_KEYS HUSH_LOADED_DIR
  fi
}
_hush_hook() {
  local root keys
  root="$(hush root 2>/dev/null)"
  [ "$root" = "$HUSH_LOADED_DIR" ] && return 0
  _hush_unload
  [ -z "$root" ] && return 0
  keys="$(hush export --names 2>/dev/null | tr '\\n' ' ')" || return 0
  eval "$(hush export --shell 2>/dev/null)" || return 0
  export HUSH_LOADED_DIR="$root"
  export HUSH_LOADED_KEYS="$keys"
}`);
  out(shell === "bash"
    ? 'PROMPT_COMMAND="_hush_hook;$PROMPT_COMMAND"'
    : "autoload -U add-zsh-hook && add-zsh-hook chpwd _hush_hook");
  out("_hush_hook");
}
async function cmdRoot(): Promise<void> {
  const loc = resolveVaultPath(process.cwd());
  if (!loc) process.exit(1);
  out(loc.hushDir.replace(/[/\\]\.hush$/, ""));
}

async function cmdDoctor(_a: Args): Promise<void> {
  const check = (okFlag: boolean, label: string, detail = "") =>
    info(`  ${okFlag ? green("✓") : red("✗")} ${label}${detail ? dim(`  ${detail}`) : ""}`);

  info(bold(`hush ${VERSION}`));
  info("");
  const id = loadIdentity();
  check(Boolean(id), "identity", id ? id.source : "run `hush id --create`");
  if (id) info(`    ${dim(publicKeyOf(id))}`);

  const loc = resolveVaultPath(process.cwd());
  check(Boolean(loc), "vault", loc ? loc.vaultPath : "run `hush init`");
  if (!loc || !id) return;

  let vault: Vault;
  try {
    vault = Vault.open(loc.vaultPath);
  } catch (e) {
    return check(false, "vault readable", (e as Error).message);
  }
  check(vault.canRead(id), "you are a recipient", vault.canRead(id) ? `as "${vault.memberName(id)}"` : "ask an admin to `hush team add` you");
  check(true, "members", String(vault.members().length));

  // Accounts are not environments. Reporting "default, fal/personal" as envs
  // invites treating an account like one, which is not how they work.
  check(true, "environments", vault.plainEnvs().join(", "));
  const accounts = vault.accounts();
  const pinned = loadUse(loc.hushDir);
  check(
    true,
    "service accounts",
    accounts.length
      ? `${accounts.length} — ${accounts.map((a) => a.scope + (pinned[a.service] === a.account ? "*" : "")).join(", ")}`
      : "none",
  );
  if (accounts.length && !Object.keys(pinned).length) {
    info(`    ${dim("none pinned — hush run will not inject any of them (hush use <svc>=<acct>)")}`);
  }

  const root = loc.hushDir.replace(/[/\\]\.hush$/, "");
  const mcp = join(root, ".mcp.json");
  check(existsSync(mcp), "MCP registered", existsSync(mcp) ? mcp : "run `hush install-mcp`");

  const skill = join(root, ".claude", "skills", "hush", "SKILL.md");
  const globalSkill = join(process.env.HOME ?? "~", ".claude", "skills", "hush", "SKILL.md");
  const hasSkill = existsSync(skill) || existsSync(globalSkill);
  check(hasSkill, "agent skill", hasSkill ? (existsSync(skill) ? "this project" : "global") : "run `hush install-skill`");

  // What the agent is actually allowed to do, rather than what it could be.
  const policy = loadPolicy(loc.hushDir);
  check(
    policy.requireApproval.length > 0,
    "approval required",
    policy.requireApproval.length ? policy.requireApproval.join(", ") : "nothing is gated — see .hush/policy.json",
  );
  const bio = biometryStatus();
  const enforcing = policy.biometry === "required" && bio.available;
  check(
    enforcing,
    "biometry",
    !bio.available
      ? (bio.reason ?? "unavailable")
      : policy.biometry === "required"
        ? bio.kind
        : `${bio.kind} available, but policy is "${policy.biometry}" — a click still works`,
  );

  // The hardware bridge, only when it is relevant.
  if (ageAvailable()) {
    const agePath = ageIdentityPath();
    const plugin = agePath ? identityPlugin(agePath) : null;
    check(Boolean(plugin), "hardware key", plugin ? `age-plugin-${plugin}` : "age installed, but the identity is a software key");
  }

  // Loose .env files are the thing hush exists to remove.
  const stray = [".env", ".env.local", ".env.production"].filter((f) => existsSync(join(root, f)));
  check(stray.length === 0, "no plaintext .env in repo", stray.length ? `found ${stray.join(", ")}` : "");

  // Freshness, and where this machine sits on the ladder.
  const stale = inspect(vault);
  if (stale) check(false, "vault freshness", `rolled back to generation ${stale.nowGeneration} — hush verify`);

  const posture = assess(vault, loc.hushDir, root);
  info("");
  info(`  ${posture.rung === 5 ? green("●".repeat(5)) : green("●".repeat(posture.rung)) + dim("○".repeat(5 - posture.rung))}  ${bold(`rung ${posture.rung} of 5`)} ${dim("— " + posture.name)}`);
  if (posture.next) info(`    ${dim("next: " + posture.next.label)}  ${cyan("hush secure")}`);
}

// ------------------------------------------------------- services & accounts

/** `hush add fal --account acme` — store one service's keys under one account. */
async function cmdAdd(a: Args): Promise<void> {
  const { vault, hushDir, vaultPath } = ctx(a);
  const id = requireIdentity();
  const service = (a._[0] ?? "").toLowerCase();

  if (!service) {
    info(bold("Usage:") + "  hush add <service> --account <name>");
    info("");
    info("  e.g.  " + cyan("hush add fal --account acme"));
    info("        " + cyan("hush add gemini --account team"));
    info("");
    info(dim("  known services: " + Object.keys(CATALOG).sort().join(", ")));
    info(dim("  anything else:  hush add <service> --account <name> --vars KEY1,KEY2"));
    return;
  }

  const account = str(a, "account") ?? str(a, "as");
  if (!account) {
    const existing = vault.accountsFor(service);
    die(
      `Which account? Use --account <name>.`,
      existing.length
        ? `existing ${service} accounts: ${existing.join(", ")}`
        : `e.g. hush add ${service} --account personal`,
    );
  }

  const vars = list(a, "vars").length ? list(a, "vars") : knownVars(service);
  if (!vars.length) {
    die(
      `"${service}" is not a known service, so hush doesn't know which variables it needs.`,
      `Tell it: hush add ${service} --account ${account} --vars API_KEY,API_SECRET`,
    );
  }

  const scope = scopeOf(service, account);
  info(`${bold(serviceLabel(service))} ${dim("/")} account ${cyan(account)}`);
  info(dim(`  ${vars.length} variable(s). Leave blank to skip one.`));
  info("");

  let stored = 0;
  const skipped: string[] = [];
  for (const v of vars) {
    const had = vault.has(scope, v);
    const value = await promptSecret(`  ${v}${had ? dim(" (set — enter to keep)") : ""}`);
    if (!value) {
      skipped.push(v);
      continue;
    }
    vault.set(id, scope, v, value);
    stored++;
  }

  if (!stored) {
    // Skipping every prompt is a real choice when a human is at the keyboard.
    // With no terminal there were no prompts to skip: something piped in one
    // value fewer than expected, or nothing at all — and reporting success for
    // that told a CI job the credential was stored when the vault was untouched.
    if (!process.stdin.isTTY) {
      die(
        `Nothing was stored for ${service}/${account}: no value arrived on stdin.`,
        `Pipe one line per variable (${vars.join(", ")}):  ` +
          `printf '%s\\n' "$KEY" | hush add ${service} --account ${account}`,
      );
    }
    return info(dim("nothing entered, nothing changed"));
  }

  // A partial write is not a failure, but it must not look like a complete one.
  if (skipped.length) {
    warn(`Left unset: ${skipped.join(", ")}${process.stdin.isTTY ? "" : " (stdin ran out of lines)"}`);
  }

  vault.save();
  audit(hushDir, { actor: "cli", action: "account.add", service, account, stored });
  info("");
  info(`${green("✓")} stored ${stored} value(s) for ${bold(service)}/${bold(account)}`);
  info("");
  info("Use it:");
  info(`  ${cyan(`hush run --with ${service}:${account} -- <your command>`)}`);
  info(`  ${cyan(`hush use ${service}=${account}`)}  ${dim("← make it this project's default")}`);
  info(dim(`  commit ${vaultPath} to share it`));
}

/** `hush accounts` / `hush accounts fal` — what do I have, and for whom. */
async function cmdAccounts(a: Args): Promise<void> {
  const { vault, hushDir } = ctx(a);
  const filter = (a._[0] ?? "").toLowerCase();
  const all = vault.accounts().filter((x) => !filter || x.service === filter);
  const pinned = loadUse(hushDir);

  if (bool(a, "json")) return out(JSON.stringify({ accounts: all, pinned }, null, 2));

  if (!all.length) {
    info(dim(filter ? `No accounts for "${filter}".` : "No service accounts yet."));
    info("");
    info(`Add one:  ${cyan("hush add fal --account personal")}`);
    return;
  }

  let currentService = "";
  for (const acct of all) {
    if (acct.service !== currentService) {
      currentService = acct.service;
      info("");
      info(`${bold(serviceLabel(acct.service))} ${dim(`(${acct.service})`)}`);
    }
    const isDefault = pinned[acct.service] === acct.account;
    info(
      `  ${isDefault ? green("●") : " "} ${acct.account.padEnd(14)}` +
        `${dim(acct.vars.join(", "))}${isDefault ? dim("   ← this project's default") : ""}`,
    );
  }
  info("");
  info(dim("  ● = used automatically here.  Override per run with --with <service>:<account>"));
}

/** `hush use fal=acme gemini=team` — pin this project's default accounts. */
async function cmdUse(a: Args): Promise<void> {
  const { vault, hushDir } = ctx(a);
  const specs = [...a._, ...list(a, "with")];
  const use = loadUse(hushDir);

  if (!specs.length) {
    if (!Object.keys(use).length) {
      info(dim("This project pins no default accounts."));
      info(`  ${cyan("hush use fal=acme gemini=team")}`);
      return;
    }
    info(bold("This project uses:"));
    for (const [service, account] of Object.entries(use)) {
      info(`  ${service.padEnd(14)} ${cyan(account)}`);
    }
    return;
  }

  for (const spec of specs) {
    const { service, account } = parseWith(spec);
    if (account === "none" || account === "-") {
      delete use[service];
      info(`${green("✓")} ${service} unpinned`);
      continue;
    }
    const known = vault.accountsFor(service);
    if (!known.includes(account)) {
      die(
        `No account "${account}" for "${service}".`,
        known.length
          ? `known: ${known.join(", ")}`
          : `add it first: hush add ${service} --account ${account}`,
      );
    }
    use[service] = account;
    info(`${green("✓")} ${service} → ${bold(account)}`);
  }
  saveUse(hushDir, use);
  info(dim("\n  saved to .hush/use.json — commit it so the team picks the same accounts"));
}

/** `hush approve` — answer requests when native dialogs aren't available. */
async function cmdApprove(a: Args): Promise<void> {
  const { hushDir } = ctx(a);
  const pending = pendingRequests(hushDir);
  if (!pending.length) {
    info(dim("Nothing waiting for approval."));
    if (nativeDialogsAvailable()) {
      info(dim("On macOS, approvals appear as a dialog on screen instead."));
    }
    return;
  }
  for (const r of pending) {
    info("");
    info(`${bold(r.summary)}   ${dim("code " + r.code)}`);
    for (const d of r.detail) info(`  ${dim(d)}`);
    const yes = await confirm("  Allow?");
    answerRequest(hushDir, r.id, yes ? (bool(a, "session") ? "session" : "once") : "deny");
    info(yes ? `  ${green("✓")} allowed` : `  ${red("✗")} denied`);
  }
}

/**
 * `hush age` — status of the age bridge, which is how hardware keys get in.
 * hush never talks to a YubiKey or the Secure Enclave itself; it hands the data
 * key to `age`, and age drives whichever plugin owns that recipient.
 */
async function cmdAge(_a: Args): Promise<void> {
  const has = ageAvailable();
  info(bold("age bridge"));
  info("");
  info(`  ${has ? green("\u2713") : red("\u2717")} age  ${dim(has ? ageVersion() + "  (" + ageBinary() + ")" : "not installed")}`);
  if (!has) {
    info("");
    info("  Install it to use a YubiKey, the Secure Enclave, or a TPM:");
    info("    " + cyan("brew install age"));
    info(dim("    then a plugin, e.g.  brew install age-plugin-yubikey"));
    return;
  }

  const path = ageIdentityPath();
  info("  " + (path ? green("\u2713") : dim("\u00b7")) + " identity  " + dim(path ?? "none found"));
  if (!path) {
    info("");
    info("  Point hush at one of these, or set HUSH_AGE_IDENTITY:");
    info(dim("    " + hushHome() + "/age-identity.txt"));
    info(dim("    ~/.config/age/keys.txt"));
    info("");
    info("  Software key:   " + cyan("age-keygen -o ~/.hush/age-identity.txt"));
    info("  YubiKey:        " + cyan("age-plugin-yubikey") + dim("  (writes a plugin identity)"));
    info("  Secure Enclave: " + cyan("age-plugin-se keygen -o ~/.hush/age-identity.txt"));
    return;
  }

  const plugin = identityPlugin(path);
  info("  " + (plugin ? green("\u2713") : dim("\u00b7")) + " backend   " +
    dim(plugin ? "age-plugin-" + plugin + " (hardware)" : "software key file"));

  const recipients = recipientsForIdentity(path);
  if (!recipients.length) {
    warn("Could not read a recipient from that identity — is the plugin installed?");
    return;
  }
  info("");
  info("  Your age recipient — hand this to whoever runs the vault:");
  for (const r of recipients) info("    " + cyan(r));
  info("");
  info(dim("    hush team add <you> " + recipients[0].slice(0, 24) + "\u2026"));
  if (plugin) {
    info("");
    info(dim("  Unwrapping the vault key prompts on the hardware, every time."));
  }
}

/** `hush verify` — can everything still be decrypted, and is the vault fresh? */
async function cmdVerify(a: Args): Promise<void> {
  const { vault, hushDir } = ctx(a);
  const id = requireIdentity();

  if (bool(a, "accept")) {
    acceptCurrent(vault);
    info(`${green("✓")} accepted the current state as the newest you have seen`);
    info(dim(`  generation ${vault.data.dek.generation}, ${vault.members().length} member(s)`));
    return;
  }

  const stale = inspect(vault);
  info(`${stale ? red("✗") : green("✓")} freshness  ${dim(stale ? `rolled back to generation ${stale.nowGeneration}` : `generation ${vault.data.dek.generation}`)}`);

  let ok = 0;
  const broken: string[] = [];
  for (const scope of vault.envNames()) {
    for (const { key } of vault.list(scope)) {
      try {
        vault.get(id, scope, key);
        ok++;
      } catch (e) {
        broken.push(`${scope}/${key}: ${(e as Error).message.split("\n")[0]}`);
      }
    }
  }
  info(`${broken.length ? red("✗") : green("✓")} decryption  ${dim(`${ok} value(s) readable`)}`);
  for (const b of broken) info(`    ${red(b)}`);

  const orphaned = Object.keys(vault.data.recipients).filter((fp) => !vault.data.dek.wraps[fp]);
  info(`${orphaned.length ? yellow("!") : green("✓")} members  ${dim(`${vault.members().length} listed, ${orphaned.length} without a key wrap`)}`);

  // The other direction, and the one that matters: a key wrap nobody is listed
  // for opens every secret here while `hush team ls` shows no such member.
  const unlisted = vault.unlistedWraps();
  info(
    `${unlisted.length ? red("✗") : green("✓")} wraps  ` +
      dim(
        unlisted.length
          ? `${unlisted.length} key wrap(s) belong to no listed member — someone can decrypt this vault invisibly`
          : "every key wrap belongs to a listed member",
      ),
  );
  for (const fp of unlisted.slice(0, 10)) info(`    ${red(fp)}`);
  if (unlisted.length) info(`    ${dim("rotate to cut them out:")} hush rotate`);

  // A value left on an older generation means a rotation did not finish, so a
  // revoked member's old key still opens it. Worth failing the command over.
  const behind = vault.staleValues();
  info(
    `${behind.length ? red("✗") : green("✓")} re-seal  ` +
      dim(
        behind.length
          ? `${behind.length} value(s) still sealed under an older key — rotation did not complete`
          : `every value is on generation ${vault.data.dek.generation}`,
      ),
  );
  for (const b of behind.slice(0, 10)) info(`    ${red(`${b.env}/${b.key}`)} ${dim(`generation ${b.gen}`)}`);
  if (behind.length) info(`    ${dim("fix with:")} hush rotate`);

  audit(hushDir, {
    actor: "cli",
    action: "verify",
    ok,
    broken: broken.length,
    stale: Boolean(stale),
    behind: behind.length,
    unlisted: unlisted.length,
  });
  if (broken.length || stale || behind.length || unlisted.length) process.exitCode = 1;
}

/** `hush level` — where you are on the security ladder, and what is next. */
async function cmdLevel(a: Args): Promise<void> {
  const loc = resolveVaultPath(process.cwd());
  const vault = loc && existsSync(loc.vaultPath) ? Vault.open(loc.vaultPath) : null;
  const root = loc ? loc.hushDir.replace(/[/\\]\.hush$/, "") : null;
  const p = assess(vault, loc?.hushDir ?? null, root);
  if (bool(a, "json")) return out(JSON.stringify(p, null, 2));
  renderLevel(p);
}

/** `hush secure` — actually climb the next rung. */
async function cmdSecure(a: Args): Promise<void> {
  if (str(a, "snooze")) {
    const days = Number(str(a, "snooze")) || 7;
    snooze(days);
    return info(dim(`reminders paused for ${days} day(s)`));
  }
  const loc = resolveVaultPath(process.cwd());
  const vault = loc && existsSync(loc.vaultPath) ? Vault.open(loc.vaultPath) : null;
  const root = loc ? loc.hushDir.replace(/[/\\]\.hush$/, "") : null;

  const explicit = ["biometry", "hardware", "approval", "keychain", "no-plaintext"]
    .find((id) => bool(a, id)) ?? a._[0];
  await runSecure({ vault, hushDir: loc?.hushDir ?? null, root }, explicit);
}

/** `hush biometry` — set up, check, or try the Touch ID gate. */
async function cmdBiometry(a: Args): Promise<void> {
  const sub = a._[0] ?? "status";

  if (sub === "setup") {
    const r = ensureHelper();
    if (!r.ok) die(`Can't set up biometry: ${r.reason}`);
    info(`${green("✓")} helper compiled at ${cyan(r.path!)}`);
  }

  const st = biometryStatus();
  info("");
  info(`  ${st.available ? green("✓") : red("✗")} ${st.kind === "none" ? "biometry" : st.kind}` +
    (st.reason ? dim(`  ${st.reason}`) : ""));

  if (sub === "test") {
    if (!st.available) die("Biometry isn't available, so there is nothing to test.");
    info("");
    const r = await authenticate("confirm this is you — hush biometry test");
    info(r === "ok" ? `  ${green("✓")} authenticated` : `  ${red("✗")} ${r}`);
    return;
  }

  info("");
  info(bold("  What this protects, and what it doesn't"));
  info(dim("    ✓  nothing runs with your credentials unless you are physically here"));
  info(dim("    ✓  your agent cannot approve its own request"));
  info(dim("    ✗  it does NOT protect the key at rest — anything running as you"));
  info(dim("       can still read the identity from the login keychain"));
  info("");
  info(dim("  Turn it on in .hush/policy.json:  \"biometry\": \"required\""));
  info(dim("  See docs/BIOMETRY.md for the hardware-backed version."));
}

/** `hush install-skill` — teach the coding agent how to use all of this. */
async function cmdInstallSkill(a: Args): Promise<void> {
  const global = bool(a, "global");
  const src = resolvePath(new URL("../skills/hush/SKILL.md", import.meta.url).pathname);
  if (!existsSync(src)) die(`Skill template missing at ${src}`);

  const base = global
    ? join(process.env.HOME ?? "~", ".claude", "skills", "hush")
    : join(ctx(a).root, ".claude", "skills", "hush");
  mkdirSync(base, { recursive: true });
  const dest = join(base, "SKILL.md");
  writeFileSync(dest, readFileSync(src, "utf8"));

  info(`${green("✓")} skill installed at ${cyan(dest)}`);
  info("");
  info("Your coding agent now knows to:");
  info(`  ${dim("·")} never ask you to paste a key into the chat`);
  info(`  ${dim("·")} open a secure prompt on your screen instead`);
  info(`  ${dim("·")} pick the right account when you name one`);
  info("");
  info(dim(global ? "  applies to every project" : "  applies to this project — pass --global for all of them"));
}

// --------------------------------------------------------------------- help

const HELP = `${bold("hush")} ${dim(VERSION)} — envelope-encrypted team secrets your agent can use but never read

${bold("setup")}
  hush init [name]              create a vault here (.hush/vault.json — commit it)
  hush id [--create]            show or create this machine's key
  hush link <vault> [--env e]   point this repo at a vault you already have
  hush ui                       open the local app to manage everything
  hush install-mcp              register hush with your coding agent
  hush install-skill            teach the agent the rules (--global for all projects)
  hush approve                  answer a pending approval (non-macOS)
  hush biometry [setup|test]    gate approvals behind Touch ID
  hush age                      use a YubiKey / Secure Enclave / TPM via age
  hush doctor                   check this machine's setup
  hush verify                   check the vault decrypts and has not been rolled back
  hush level                    where you are on the security ladder
  hush secure                   climb the next rung

${bold("accounts")} ${dim("— when you have several keys for the same service")}
  hush add <service> --account <name>    e.g. hush add fal --account acme
  hush accounts [service]                what you have, and for whom
  hush use fal=acme gemini=team        pin this project's defaults
  hush run --with fal:client -- <cmd>      override for a single run

${bold("secrets")}
  hush set <KEY> [--env e]      add or update (prompts, never echoes)
  hush get <KEY>                reveal one value (asks first)
  hush ls [--env e]             list names — never values
  hush rm <KEY>
  hush import [file] [--as <name>]  pull in an existing .env, optionally as a named set
  hush export [--out .env]      write plaintext out (last resort)
  hush export --names           just the variable names this project resolves

${bold("using them")}
  hush run -- <cmd> [args]      run with secrets injected, output redacted
  hush scan [dir]               what does this codebase need, and is it in the vault?
  hush envs                     your library and this project's sets

${bold("named env sets")}          — a .env you name, describe and reuse
  hush env                      list them (same as hush envs)
  hush env new <name> [--from <file>] [--description <t>] [--when <t>]
  hush env rename <name> <new name>    re-seals every value under the new name
  hush env describe <name> [--description <t>] [--when <t>]
  hush env move <KEY>… --to <set>      carve one big pile into named sets
  hush env use <name>           this project uses that library set
  hush env drop <name>          stop using it here
  hush global [<vault>|--create]  which vault holds your library
  hush hook <zsh|bash|fish>     auto-load on cd (least safe; unloads on leave)

${bold("team")}
  hush team ls
  hush team add <name> <pk>     re-wraps the key for them; commit and they're in
  hush team rm <name>           removes them and re-encrypts everything
  hush rotate                   new vault key, same values

${bold("flags")}
  --env <name>    which environment (default: the linked one, else "default")
  --json          machine-readable output where it makes sense

${dim("Vault files hold only ciphertext and public keys. Your private key never leaves this machine.")}
`;

// --------------------------------------------------------------------- main

const COMMANDS: Record<string, (a: Args) => Promise<void>> = {
  init: cmdInit,
  id: cmdId,
  set: cmdSet,
  add: cmdAdd,
  accounts: cmdAccounts,
  account: cmdAccounts,
  use: cmdUse,
  get: cmdGet,
  ls: cmdLs,
  list: cmdLs,
  rm: cmdRm,
  remove: cmdRm,
  import: cmdImport,
  export: cmdExport,
  run: cmdRun,
  exec: cmdRun,
  scan: cmdScan,
  team: cmdTeam,
  rotate: cmdRotate,
  link: cmdLink,
  envs: cmdEnvs,
  env: cmdEnv,
  global: cmdGlobal,
  "install-mcp": cmdInstallMcp,
  "install-skill": cmdInstallSkill,
  approve: cmdApprove,
  biometry: cmdBiometry,
  level: cmdLevel,
  verify: cmdVerify,
  secure: cmdSecure,
  age: cmdAge,
  hook: cmdHook,
  root: cmdRoot,
  doctor: cmdDoctor,
};

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const command = argv[0];

  if (!command || command === "help" || command === "--help" || command === "-h") {
    process.stdout.write(HELP);
    return;
  }
  if (command === "--version" || command === "-v" || command === "version") {
    return out(VERSION);
  }
  if (command === "mcp") return serveMcp();
  if (command === "ui") {
    const a = parseArgs(argv.slice(1));
    const namedUi = str(a, "vault");
    if (namedUi) process.env.HUSH_VAULT = namedUi.includes("/") ? resolvePath(namedUi) : namedVaultPath(namedUi);
    const portRaw = str(a, "port");
    return serveUi({ port: portRaw ? Number(portRaw) : undefined, open: !bool(a, "no-open") });
  }

  const handler = COMMANDS[command];
  if (!handler) die(`Unknown command: ${command}`, "Run `hush help`.");

  const parsed = parseArgs(argv.slice(1));
  // `--vault personal` targets a named vault in ~/.hush/vaults, from anywhere.
  const named = str(parsed, "vault");
  if (named) process.env.HUSH_VAULT = named.includes("/") ? resolvePath(named) : namedVaultPath(named);
  await handler(parsed);
}

main().catch((e) => {
  die(e instanceof Error ? e.message : String(e));
});
