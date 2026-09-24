#!/usr/bin/env node
/**
 * hush — envelope-encrypted team secrets your agent can use but never read.
 */
import {
  existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync, chmodSync,
  statSync, accessSync, constants as fsConstants, lstatSync, unlinkSync, realpathSync,
} from "node:fs";
import { join, dirname, basename, resolve as resolvePath } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import {
  Vault,
  resolveVaultPath,
  locateProject,
  namedVaultPath,
  audit,
  slugifyEnv,
  safeText,
  type LinkFile,
  assertScopeName,
  isValidKeyName,
  assertProjectHushDir,
} from "./vault.ts";
import { CATALOG, knownVars, serviceLabel, setNameFor } from "./services.ts";
import { loadIdentity, createIdentity, requireIdentity, publicKeyOf, hushHome } from "./identity.ts";
import { scanRepo, reconcile, parseEnvFile } from "./scan.ts";
import { runWithSecrets, toEnvFile, toShellExports } from "./run.ts";
import { preview, MIN_REDACTABLE } from "./redact.ts";
import { serveMcp, loadPolicy, DEFAULT_POLICY, type Policy } from "./mcp.ts";
import {
  checkCommand, checkScopes, checkHost, runScope, requestScope,
  approvalCoverageLine, requestCoverageLine, readPolicyFile, policyWeakenings,
} from "./policy.ts";
import {
  parseHeader, prepare, requestWithSecrets, renderRequest, requestSummary, statusLine,
  requestSecretNames, type RequestInput,
} from "./request.ts";
import { materialize, describeMaterialize, parseMaterializeSpec } from "./materialize.ts";
import { loadSchema, validate, unsensitiveForOutput, describeProblems } from "./schema.ts";
import { AGENTS, renderMcp, skillDescription, mcpRegistrations } from "./agents.ts";
import { parseImport, IMPORT_FORMATS, type ImportFormat } from "./import.ts";
import { copyToClipboard, findClipboard, clipboardNames } from "./clipboard.ts";
import {
  findEnvFiles, isGitignored, detectDevCommand, openingLines,
  keySourceChoices, importRecipe, closingLines,
} from "./start.ts";
import { serveUi } from "./ui.ts";
import {
  usedSets, composeSets, librarySets, loadLinks, saveLinks, openGlobal,
  globalVaultName, globalVaultExists, globalVaultPath, namedVaults, saveConfig,
  ensureProjectVault, writeProjectDotfiles, suggestSets,
} from "./library.ts";
import { VERSION } from "./version.ts";
import { assess } from "./posture.ts";
import { checkAndRecord, inspect, acceptCurrent, describeRollback } from "./integrity.ts";
import { renderLevel, runSecure, maybeNudge, snooze, parseDuration } from "./secure.ts";
import { requestApproval, approvalPromptAvailable } from "./approval.ts";
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

/** Indent every line of a multi-line block, so a pasted snippet stays aligned. */
const indent = (s: string, pad: string): string => pad + s.split("\n").join("\n" + pad);
const info = (s: string): void => out(s);
const warn = (s: string): void => void process.stderr.write(yellow(`! ${s}`) + "\n");

/**
 * A vault-supplied name on its way to the terminal. Set names are an identity,
 * not free text, so they are kept intact for lookups and only scrubbed where
 * they are printed: an ANSI sequence in a name would otherwise repaint the
 * lines above it rather than show up as part of the name.
 */
const shown = (name: string, max = 80): string => safeText(name, max) ?? "<unprintable>";

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
/**
 * A repeatable flag whose values must not be split on commas: file paths, and
 * `KEY=value` pairs that may legitimately contain one. `list()` is the right
 * helper for set names and the wrong one for anything path-shaped.
 */
const repeat = (a: Args, name: string): string[] => {
  const v = a.flags[name];
  return (Array.isArray(v) ? v : typeof v === "string" ? [v] : []).map((x) => x.trim()).filter(Boolean);
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

function readIfExists(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

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

/**
 * A visible line of input, usable over a pipe as well as a real terminal —
 * unlike `promptLine`, which every existing call site only ever reaches after
 * checking `process.stdin.isTTY`. The setup dialogue (below) has to be
 * answerable non-interactively too, for HUSH_INTERACTIVE=1 tests to drive it.
 *
 * A fresh `readline.Interface` per question — what `promptLine` does — only
 * ever sees the first line piped in: a non-TTY stdin typically arrives as one
 * buffered chunk, and a closed Interface does not hand the unread remainder to
 * the next one. Reusing `promptSecret`'s `pipedLines` buffer sidesteps that by
 * reading the whole pipe once and serving it back one line per call.
 */
async function askLine(label: string): Promise<string> {
  if (process.stdin.isTTY) return promptLine(label);
  // promptLine's `rl.question(label, …)` writes the label as part of asking;
  // reading pipedLines directly bypasses readline entirely, so the question
  // has to be written out here or a piped run of the dialogue would apply
  // each answer to a question nobody — human or test assertion — ever saw.
  process.stderr.write(label);
  if (pipedLines === null) {
    pipedLines = (await readAllStdin()).split(/\r?\n/);
    if (pipedLines.at(-1) === "") pipedLines.pop();
  }
  return (pipedLines.shift() ?? "").trim();
}

// ------------------------------------------------------------------ programs

/**
 * Resolve an executable from PATH ourselves, the way src/age.ts does for
 * `age` — `which` is missing on Windows and from plenty of minimal container
 * images, so shelling out to it would make pass-through and `hush dev` report
 * "not found" on exactly the machines where that is hardest to debug.
 *
 * Duplicated rather than imported: age.ts's copy is private to that module,
 * and the brief for this change asked for a small local one rather than
 * reaching into an unrelated file for it.
 */
function onPath(name: string): string | null {
  // A path — "./dev.sh", "/opt/bin/x" — is not looked up on PATH, it is checked.
  if (name.includes("/") || name.includes("\\")) {
    try {
      if (statSync(name).isFile()) {
        accessSync(name, fsConstants.X_OK);
        return resolvePath(name);
      }
    } catch { /* not runnable */ }
    return null;
  }
  const dirs = (process.env.PATH ?? "").split(process.platform === "win32" ? ";" : ":");
  const extensions = process.platform === "win32" ? (process.env.PATHEXT ?? ".EXE;.CMD;.BAT").split(";") : [""];
  for (const dir of dirs) {
    if (!dir) continue;
    for (const ext of extensions) {
      const candidate = join(dir, name + ext.toLowerCase());
      try {
        if (statSync(candidate).isFile()) {
          accessSync(candidate, fsConstants.X_OK);
          return candidate;
        }
      } catch { /* not this one */ }
    }
  }
  return null;
}

/** Walk up from `start` looking for `filename`. Used by `hush dev` to find package.json. */
function findUpward(filename: string, start: string): string | null {
  let dir = resolvePath(start);
  for (;;) {
    const candidate = join(dir, filename);
    if (existsSync(candidate)) return candidate;
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/** Which package manager owns a project, guessed the only reliable way: its lockfile. */
function packageManagerFor(dir: string): "bun" | "pnpm" | "yarn" | "npm" {
  if (existsSync(join(dir, "bun.lock")) || existsSync(join(dir, "bun.lockb"))) return "bun";
  if (existsSync(join(dir, "pnpm-lock.yaml"))) return "pnpm";
  if (existsSync(join(dir, "yarn.lock"))) return "yarn";
  return "npm";
}

// -------------------------------------------------------------- vault access

interface Ctx {
  vault: Vault;
  hushDir: string;
  vaultPath: string;
  env: string;
  root: string;
}

/**
 * Like Ctx, but for a command that must work whether or not this folder has a
 * vault of its own — a folder can be perfectly usable on library sets alone.
 * `hasVault` is the file's actual presence; `exists` is whether a project was
 * found here at all (a vault, a link, or just `.hush/envs.json`) — the two
 * differ exactly for a folder that only uses library sets.
 */
interface LooseCtx {
  vault: Vault | null;
  hushDir: string;
  vaultPath: string;
  hasVault: boolean;
  exists: boolean;
  root: string;
  env: string;
}

/**
 * Freshness, not just authenticity: a rolled-back vault decrypts perfectly.
 * Shared by ctx(), ctxLoose() and cmdLs's <set> lookup, so every path that
 * opens a project vault runs this check once, in one place.
 */
function checkRollback(vault: Vault): void {
  const rollback = checkAndRecord(vault);
  if (rollback) {
    process.stderr.write("\n" + red("  ⚠  VAULT ROLLBACK DETECTED") + "\n");
    for (const line of describeRollback(rollback)) {
      process.stderr.write(line ? `  ${dim(line)}\n` : "\n");
    }
    process.stderr.write("\n");
  }
}

function ctx(a: Args): Ctx {
  const loc = locateProject(process.cwd());
  if (!loc) {
    die("No hush vault found from this directory.", "Run `hush init` here, or `hush link <vault>`.");
  }
  // findHushDir() also matches a folder whose .hush/ holds only envs.json —
  // library sets, no vault of its own — so a command that genuinely needs
  // this project's own vault has to say so, rather than let Vault.open() fail
  // with "No vault at .../vault.json. Run `hush init`.", which reads like the
  // folder is not a hush project at all when it plainly is one.
  if (!loc.hasVault) {
    die(
      "This folder uses library sets and has no vault of its own yet.",
      "hush add <KEY>=<value> --project, or hush team add, makes one.",
    );
  }
  const vault = Vault.open(loc.vaultPath);
  checkRollback(vault);

  const env = str(a, "env") || loc.env || "default";
  return {
    vault,
    hushDir: loc.hushDir,
    vaultPath: loc.vaultPath,
    env,
    root: loc.hushDir.replace(/[/\\]\.hush$/, ""),
  };
}

/**
 * The loose counterpart: never dies. A folder with no `.hush` anywhere above
 * it gets a hushDir as if it were about to become one (`<cwd>/.hush`), so a
 * caller that goes on to write into it (saveLinks, writeProjectDotfiles) does
 * not need its own fallback path — and `hasVault`/`exists` are both false,
 * which is the whole signal a caller needs to tell "nothing here yet" apart
 * from "a vault-less project that already picked its library sets".
 */
function ctxLoose(a: Args): LooseCtx {
  const loc = locateProject(process.cwd());
  const hushDir = loc?.hushDir ?? join(process.cwd(), ".hush");
  const vaultPath = loc?.vaultPath ?? join(hushDir, "vault.json");
  const hasVault = loc?.hasVault ?? false;
  const root = loc ? loc.hushDir.replace(/[/\\]\.hush$/, "") : process.cwd();
  const env = str(a, "env") || loc?.env || "default";
  let vault: Vault | null = null;
  if (hasVault) {
    vault = Vault.open(vaultPath);
    checkRollback(vault);
  }
  return { vault, hushDir, vaultPath, hasVault, exists: Boolean(loc), root, env };
}

/**
 * The CLI is opt-in: with neither a repo `.hush/policy.json` nor a user-level
 * `~/.hush/policy.json` floor, every command behaves exactly as it always
 * has — that is rung 1 of the security ladder (see posture.ts and the
 * README), and it must never gain a gate nobody asked for. `loadPolicy()`
 * cannot tell "no file anywhere" from "a file with nothing unusual in it" —
 * both return DEFAULT_POLICY — so the distinction is made here with
 * `existsSync` before ever calling it. A floor with no repo policy is enough
 * on its own: that is the entire point of a floor the repo cannot see.
 */
function policyFor(hushDir: string): Policy | null {
  const hasRepoPolicy = existsSync(join(hushDir, "policy.json"));
  const hasFloor = existsSync(join(hushHome(), "policy.json"));
  return hasRepoPolicy || hasFloor ? loadPolicy(hushDir) : null;
}

/**
 * Turn a deny/timeout approval decision into the same kind of exit this
 * command would take for any other refusal. Denied and timed-out are worded
 * differently because a human said no is not the same event as nobody
 * answering, even though both refuse the action.
 */
function dieOnApproval(ap: { decision: string; note?: string }, what: string): void {
  if (ap.decision !== "deny" && ap.decision !== "timeout") return;
  const reason = ap.decision === "deny" ? "denied" : "timed out";
  die(`Approval ${reason} for ${what}.` + (ap.note ? ` ${ap.note}.` : ""));
}

/**
 * Make this folder's own vault the moment something first needs one: a
 * project secret via `--project`, or `hush team add` on a folder that has
 * only ever used library sets. Identity resolution mirrors cmdInit exactly
 * (create one lazily if this machine has none), so the very first vault on a
 * machine can be born this way instead of only through `hush init`.
 */
function makeProjectVault(hushDir: string, root: string, quiet = false): Vault {
  const id = loadIdentity() ?? createIdentity();
  const memberName = process.env.USER || "me";
  const vaultName = basename(root);
  const { vault, created } = ensureProjectVault(
    hushDir,
    id.pub ? { name: memberName, pub: id.pub } : { name: memberName, ageRecipient: id.age!.recipients[0] },
    vaultName,
  );
  if (created) {
    // Silent for `hush start`, which says the same thing in words the person
    // reading it already has: a guided run should not interrupt itself to
    // explain its own storage model halfway through a sentence.
    if (!quiet) info(`${green("✓")} made this folder's own vault at ${cyan(".hush/vault.json")} — commit it`);
  }
  return vault;
}

/**
 * Which vault a named set lives in, or should be created in. An explicit
 * --library / --project wins; otherwise the set's existing home, project
 * first — so `hush add K=v --to work-fal` reaches a library set without a
 * flag, and a new name lands in the project unless asked otherwise.
 *
 * `loose.vault` may be null: a folder that only uses library sets, or one not
 * set up at all. With no project vault, a *new* name defaults to the library
 * instead — there is nowhere else to put it, and library-first is the model a
 * vault-less folder is built around. `rm` reaches this same fallback without
 * ever triggering vault creation, because a name nothing owns yet just falls
 * through to "no such key" a few lines further down its own caller.
 */
function pickVault(
  loose: { vault: Vault | null; hushDir: string; root: string },
  a: Args,
  name: string | null,
): { vault: Vault; where: "project" | "library" } {
  const wantLibrary = bool(a, "library");
  const wantProject = bool(a, "project");
  if (wantLibrary && wantProject) die("Pass only one of --library or --project.");
  const library = openGlobal();
  if (wantLibrary) {
    if (!library) die("You have no library yet.", "Make one: hush global --create");
    return { vault: library, where: "library" };
  }
  if (wantProject) {
    return { vault: loose.vault ?? makeProjectVault(loose.hushDir, loose.root), where: "project" };
  }
  if (name && loose.vault?.hasSet(name)) return { vault: loose.vault, where: "project" };
  if (name && library?.hasSet(name)) return { vault: library, where: "library" };
  if (loose.vault) return { vault: loose.vault, where: "project" };
  if (library) return { vault: library, where: "library" };
  die(
    "This folder has no vault of its own yet, and you have no library either.",
    `hush add ${name ?? "<KEY>"}=<value> --project makes a vault here, or hush global --create makes a library.`,
  );
}

/**
 * The set a --to / --from names, typed as either its slug or its label
 * ("work-fal" or "Work fal"). An existing set matches either way; a new name
 * is kept as typed when it is a valid one — so "fal/acme" is not mangled into
 * "fal-acme" — and slugified otherwise.
 */
function resolveSetName(name: string, vaults: (Vault | null)[]): string {
  const slug = slugifyEnv(name);
  for (const v of vaults) {
    if (v?.hasSet(name)) return name;
    if (v?.hasSet(slug)) return slug;
  }
  try {
    assertScopeName(name);
    return name;
  } catch {
    return slug;
  }
}

/**
 * A set made from inside a project is a set this project wants: `hush add
 * .env --as Dev` followed by `hush npm run dev` has to inject it, or the
 * quick start runs with nothing and says so only in a dim line. --no-use
 * opts out; a set already used stays where it is in the order.
 */
function useHere(hushDir: string, slug: string, a: Args): void {
  if (bool(a, "no-use")) return;
  if (usedSets(hushDir).includes(slug)) return;
  // The folder may not have a `.hush` at all yet — a brand new set can be the
  // very first thing that ever lands in it — so this has to lay down the same
  // dotfiles `hush use` does, not just the links file.
  writeProjectDotfiles(hushDir);
  saveLinks(hushDir, [...loadLinks(hushDir), slug]);
  info(`${green("✓")} this project now uses ${bold(slug)}  ${dim(`(hush use --not ${slug} to stop)`)}`);
}

/** @deprecated body moved to writeProjectDotfiles() in library.ts, which cmdInit/cmdLink also need without a circular import back into cli.ts. */
function ensureGitignore(hushDir: string): void {
  writeProjectDotfiles(hushDir);
}

// ------------------------------------------------------------ folder set-up
//
// "Set up" means `.hush/envs.json` exists — a vault alone counts too, since
// that could only get there through `hush init`, which is itself an explicit
// choice to use hush here. Below this line, `hush run` (and `dev` and
// pass-through, which share it), and `hush use` with no arguments, run the
// dialogue below instead of resolving nothing and running the command anyway
// — silence here is the exact dead end this whole feature exists to close.

function isSetUp(loose: { hushDir: string; hasVault: boolean }): boolean {
  return loose.hasVault || existsSync(join(loose.hushDir, "envs.json"));
}

/**
 * HUSH_INTERACTIVE=1 turns *prompting* on even when stdin is not a real TTY,
 * so a test can drive the setup dialogue with piped answers. It cannot make
 * the dialogue accept anything it would otherwise refuse — every check it
 * runs (which sets exist, whether a typed name is one of them) is identical
 * either way — it only decides whether a question gets asked at all instead
 * of the command refusing outright.
 */
function interactiveSetup(): boolean {
  return Boolean(process.stdin.isTTY) || process.env.HUSH_INTERACTIVE === "1";
}

/**
 * The non-interactive refusal. Never runs the command with nothing injected —
 * that silent no-op, not an error, is the dead end this whole feature exists
 * to prevent — and never blocks waiting for an answer nobody can give.
 */
function dieNotSetUp(): never {
  const names = librarySets().map((s) => s.name);
  process.stderr.write(red("✗ This folder isn't set up for hush yet.") + "\n");
  // The guided run goes first: the other two lines assume you already know what
  // a set is, and someone reading this message by definition does not.
  process.stderr.write(`  ${cyan("hush start")}             walk through it, a few questions\n`);
  if (names.length) {
    process.stderr.write(
      `  ${cyan("hush use <set> …")}        pick from your library: ${names.map((n) => shown(n)).join(", ")}\n`,
    );
  }
  process.stderr.write(`  ${cyan("hush add .env --as Dev")}  start from a .env file\n`);
  if (!names.length) {
    process.stderr.write(`  ${cyan("hush global --create")}\n`);
  }
  process.exit(1);
}

/**
 * "Which sets should this folder use?" — the fallback when nothing was
 * suggested, either because the scan found no variable names at all or
 * because none of them matched anything in the library. Replaces the whole
 * list on every call, which is also what makes it double as the `edit` step:
 * a typo is refused by name rather than silently dropped.
 */
async function manualPick(sets: ReturnType<typeof librarySets>): Promise<string[]> {
  info(`Which sets should this folder use? ${dim("(space-separated, enter for none)")}`);
  if (sets.length) info(dim(`  ${sets.map((s) => shown(s.name)).join(", ")}`));
  const typed = (await askLine("> ")).split(/\s+/).filter(Boolean);
  if (!typed.length) return [];
  const unknown = typed.filter((n) => !sets.some((s) => s.name === n));
  if (unknown.length) {
    die(
      `No set called "${unknown[0]}".`,
      `you have: ${sets.map((s) => shown(s.name)).join(", ") || "none yet"}`,
    );
  }
  return typed;
}

/**
 * "Will an AI agent use secrets here?" — asked once, by `hush init` and by
 * the setup dialogue, since both are the first moment a folder becomes
 * usable and this is the only place hush ever asks about its threat model up
 * front. `y` writes the same `requireApproval` policy.json `hush secure
 * approval` would; `N` (or never asking, off a TTY with neither flag) writes
 * nothing at all — an absent policy file is rung 1 of the ladder by design
 * (see policy.ts), and writing an empty one here would look identical on
 * disk while foreclosing "never asked" from "asked and declined".
 */
async function askAgentQuestion(hushDir: string, a: Args): Promise<void> {
  const forced = bool(a, "agent") ? true : bool(a, "no-agent") ? false : null;
  let wantsAgent: boolean;
  if (forced !== null) {
    wantsAgent = forced;
  } else if (interactiveSetup()) {
    const ans = (
      await askLine(`Will an AI agent use secrets here? ${dim("(yes = every run asks you first) [y/N]")} `)
    ).toLowerCase();
    wantsAgent = ans === "y" || ans === "yes";
  } else {
    return;
  }
  if (!wantsAgent) return;
  // In ~/.hush this file would be the floor for every project, not this one's policy.
  assertProjectHushDir(hushDir);
  mkdirSync(hushDir, { recursive: true });
  const policyPath = join(hushDir, "policy.json");
  if (!existsSync(policyPath)) {
    // DEFAULT_POLICY.requireApproval, not a retyped literal — the drift check
    // "the default policy is not retyped anywhere" exists because a
    // hand-written copy is exactly how `allowReveal` kept being written into
    // every new project after it stopped meaning anything.
    writeFileSync(
      policyPath,
      JSON.stringify({ requireApproval: DEFAULT_POLICY.requireApproval }, null, 2) + "\n",
    );
  }
  info(`${green("✓")} approvals on  ${dim("— hush install-mcp when you're ready")}`);
  describePolicyEffect();
}

/**
 * What a project policy.json does to the person's *own* terminal, said once at
 * the moment one is written. The CLI enforces the same policy as the MCP tools
 * (an agent with a shell would otherwise walk around it), so turning approvals
 * on for an agent also puts a prompt in front of every `hush run` here and
 * refuses interpreters outright — and on a machine with no dialog program the
 * prompt can never appear, so every run is refused. Neither was said anywhere.
 */
function describePolicyEffect(): void {
  info(dim("  every hush run here now asks first — yours too — and node, python, bash and"));
  info(dim("  other interpreters are refused (run a script instead). Undo: rm .hush/policy.json"));
  if (!approvalPromptAvailable()) {
    warn("this machine has no way to show an approval prompt (no desktop dialog or fingerprint");
    warn("reader), so every hush run here will be refused until .hush/policy.json is removed.");
  }
}

/**
 * The dialogue a folder that isn't set up runs once, interactively: what its
 * code references, which library sets cover that, and — the one thing hush
 * ever asks up front — whether an agent will be anywhere near the secrets.
 * Only ever reached when interactiveSetup() is true; the non-interactive
 * path (dieNotSetUp) never gets here at all, so this never has to guess at an
 * answer nobody typed.
 */
async function runSetupDialogue(loose: { hushDir: string; root: string }, a: Args): Promise<void> {
  info(bold("This folder isn't set up for hush yet."));

  const sets = librarySets();
  const usages = scanRepo(loose.root);
  const needed = usages.map((u) => u.name);

  let picks: string[];

  if (!needed.length) {
    picks = await manualPick(sets);
  } else {
    const files = new Set(usages.flatMap((u) => u.sites)).size;
    info(`Its code references: ${needed.join(", ")}   ${dim(`(${files} file${files === 1 ? "" : "s"})`)}`);

    const suggestion = suggestSets(needed, sets);
    const byName = new Map(sets.map((s) => [s.name, s]));
    // Filled in with the ambiguous keys' choices below, so the final grouping
    // (picks + what each covers) comes from one map either way.
    const providerFor: Record<string, string> = { ...suggestion.provider };

    for (const { key, options } of suggestion.ambiguous) {
      const labels = options.map((n) => byName.get(n)?.label ?? n);
      const raw = await askLine(
        `${key} is in ${labels.join(" and ")} — which one? ${dim(`[${options.map((_, i) => i + 1).join("/")}]`)} `,
      );
      const idx = Number(raw) - 1;
      providerFor[key] = options[idx] ?? options[0];
    }

    const chosenSets = new Map<string, string[]>();
    for (const [key, name] of Object.entries(providerFor)) {
      if (!chosenSets.has(name)) chosenSets.set(name, []);
      chosenSets.get(name)!.push(key);
    }
    picks = [...chosenSets.keys()];

    if (picks.length) {
      info("Your library covers them:");
      for (const name of picks) {
        const label = byName.get(name)?.label;
        const shown = label && label !== name ? `${label}  ${dim(`(${name})`)}` : name;
        info(`  ${green("●")} ${bold(shown)}   ${chosenSets.get(name)!.join(", ")}`);
      }
    }
    if (suggestion.uncovered.length) {
      info(
        dim(
          `Not in your library: ${suggestion.uncovered.join(", ")}   ` +
            `(hush add ${suggestion.uncovered[0]}=… --to <set> later)`,
        ),
      );
    }

    if (!picks.length) {
      // Nothing the library offers matched what the scan found; fall back to
      // asking outright rather than proposing an empty list as if it were a
      // real suggestion.
      picks = await manualPick(sets);
    } else {
      const ans = (await askLine(`Use these here? ${dim("[Y/n/edit]")} `)).trim().toLowerCase();
      if (ans === "n" || ans === "no") {
        die("Nothing set up.", "hush use <set> when you're ready.");
      } else if (ans === "edit" || ans === "e") {
        picks = await manualPick(sets);
      }
      // Blank or "y": keep the proposed `picks` as they stand.
    }
  }

  saveLinks(loose.hushDir, picks);
  writeProjectDotfiles(loose.hushDir);
  info(
    picks.length
      ? `${green("✓")} this folder uses ${picks.join(", ")}   ${dim("(.hush/envs.json — commit it if the team should too)")}`
      : `${green("✓")} .hush/envs.json created   ${dim("(commit it if the team should too)")}`,
  );

  await askAgentQuestion(loose.hushDir, a);
}

// ----------------------------------------------------------------- commands

/**
 * `hush start` — the guided first run.
 *
 * Everything else in this file assumes you already know what a set is and why
 * you would want one. This assumes nothing: it finds out where your keys are,
 * gets them in, asks the one question hush always asks up front, and ends by
 * naming the three commands worth knowing. The wording lives in src/start.ts so
 * it can be read and tested on its own.
 */
async function cmdStart(a: Args): Promise<void> {
  if (!interactiveSetup()) {
    die(
      "`hush start` is a conversation, so it needs a terminal.",
      "For scripts: hush import <file> --as <name>, hush add KEY=value, hush use <name>.",
    );
  }

  const loose = ctxLoose(a);
  const root = loose.root;
  // A first run can be the very first thing on the machine, so the key that
  // makes a vault readable is created here rather than demanded.
  const id = loadIdentity() ?? createIdentity();
  const envFiles = findEnvFiles(root);
  const library = librarySets();
  const devCommand = detectDevCommand(root, packageManagerFor);

  out();
  for (const line of openingLines({ envFiles })) info(line);
  out();

  for (const choice of keySourceChoices({ envFiles, librarySetCount: library.length })) {
    info(`  ${choice.key}. ${choice.label}${choice.note ? `  ${dim(`(${choice.note})`)}` : ""}`);
  }
  const source = (await askLine(`\nWhere are your keys? ${dim("[1]")} `)) || "1";

  if (source === "2") {
    const tool = (await askLine("Which one? ")).trim();
    const label = (await askLine(`What should I call them here? ${dim("[Prod]")} `)).trim() || "Prod";
    const recipe = importRecipe(tool, label);
    out();
    info(`Run this to copy them in:`);
    out();
    info(`  ${cyan(recipe ?? `YOUR-EXPORT-COMMAND | hush import - --as "${label}"`)}`);
    out();
    info(dim("Then run `hush start` again and I'll finish up."));
    return;
  }

  if (source === "4" && library.length) {
    for (const [i, s] of library.entries()) {
      info(`  ${i + 1}. ${s.label}${s.keys.length ? dim(`  (${s.keys.length} key(s))`) : ""}`);
    }
    const chosen = library[Number((await askLine("\nWhich one? ")).trim()) - 1];
    if (!chosen) die("That was not one of the numbers above.");
    useHere(loose.hushDir, chosen.name, a);
    info(`${green("✓")} this project now uses ${bold(chosen.label)}`);
    return finishStart(loose, a, devCommand);
  }

  const setLabel =
    (await askLine(`What should I call this group of keys? ${dim("[Production]")} `)).trim() || "Production";

  if (source === "3") {
    // One key by hand: typed into a hidden prompt, so it never appears on
    // screen and never needs pasting into a chat window.
    const thing = (await askLine("What's it for? " + dim("(e.g. stripe, openai, fal) "))).trim();
    const known = thing ? CATALOG[thing.toLowerCase()] : undefined;
    const vars = known ? knownVars(thing.toLowerCase()) : [];
    const keyName = vars.length ? vars[0] : (await askLine("What should I call the key? ")).trim().toUpperCase();
    if (!keyName || !isValidKeyName(keyName)) die("That is not a usable key name.", "Try something like STRIPE_KEY.");

    const value = await promptSecret(`  ${keyName}`, true);
    if (!value) die("Nothing entered, nothing changed.");
    const slug = slugifyEnv(setLabel);
    const { target, where } = await beginSetWrite(loose, a, {
      asLabel: setLabel,
      count: 1,
      verb: "Add set",
      target: targetFor(a),
    });
    importInto(target, id, slug, { [keyName]: value }, false);
    target.describeEnv(slug, { label: setLabel });
    target.save();
    const warning = shortValueWarning(keyName, value);
    if (warning) warn(warning);
    out();
    info(`${green("✓")} stored ${bold(keyName)} as ${bold(setLabel)} in ${where}`);
    useHere(loose.hushDir, slug, a);
    return finishStart(loose, a, devCommand);
  }

  // 1: from a file in this folder. The common case, and the one worth getting
  // exactly right.
  let file = envFiles[0];
  if (!file) {
    file = (await askLine(`What's the file called? ${dim("[.env]")} `)).trim() || ".env";
    if (!existsSync(join(root, file))) {
      die(
        `I can't find ${file} in this folder.`,
        "Put your keys in a file and run `hush start` again, or pick another answer.",
      );
    }
  }

  const parsed = parseEnvFile(readFileSync(join(root, file), "utf8"));
  const names = Object.keys(parsed);
  if (!names.length) die(`I didn't find any KEY=value lines in ${file}.`);

  const slug = slugifyEnv(setLabel);
  const { target, where } = await beginSetWrite(loose, a, {
    asLabel: setLabel,
    count: names.length,
    verb: "Add set",
    target: targetFor(a),
  });
  const { added, short } = importInto(target, id, slug, parsed, false);
  target.describeEnv(slug, { label: setLabel, source: file });
  target.save();
  audit(loose.hushDir, { actor: "cli", action: "add", kind: "start", env: slug, file, added, where });

  out();
  info(`${green("✓")} stored ${bold(String(added))} key(s) as ${bold(setLabel)} in ${where}`);
  warnShort(short);
  // The plaintext file is the one thing that undoes the work, so say what to do
  // about it once, plainly. Never delete it for them.
  if (isGitignored(root, file)) {
    info(dim(`  ${file} is already gitignored, so it cannot be committed.`));
    info(dim("  You can delete it now: hush has everything it needs."));
  } else {
    warn(`${file} is not in .gitignore, so it could be committed by accident.`);
    info(dim(`  Add it, then delete ${file}. hush has everything it needs.`));
  }
  useHere(loose.hushDir, slug, a);
  return finishStart(loose, a, devCommand);
}

/** `--library` is honoured; otherwise a first run writes into this project. */
const targetFor = (a: Args): "library" | "project" => (bool(a, "library") ? "library" : "project");

/**
 * The tail of the guided run: the one question hush always asks up front, an
 * offer to run the thing, and the commands worth knowing.
 */
async function finishStart(
  loose: ReturnType<typeof ctxLoose>,
  a: Args,
  devCommand: { pm: string; script: string } | null,
): Promise<void> {
  out();
  await askAgentQuestion(loose.hushDir, a);

  if (devCommand) {
    const run = await askLine(`\nWant to run it now? ${dim(`(${devCommand.pm} run ${devCommand.script}) [y/N]`)} `);
    if (/^y/i.test(run.trim())) {
      // quiet: the "using <sets>" line has already been said in plain words.
      await runCommand({ _: [], rest: [], flags: { ...a.flags, quiet: true } }, [
        devCommand.pm,
        "run",
        devCommand.script,
      ]);
      return;
    }
  }

  for (const line of closingLines({ devCommand })) info(line);
}

async function cmdInit(a: Args): Promise<void> {
  const name = a._[0] || require_basename();
  const global = bool(a, "global") || bool(a, "personal");
  const vaultPath = global ? namedVaultPath(name) : join(process.cwd(), ".hush", "vault.json");
  const hushDir = dirname(vaultPath);
  if (!global) assertProjectHushDir(hushDir);
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
  info(`  ${cyan('hush add .env --as "Dev"')}  bring in what you already have, as a set`);
  info(`  ${cyan("hush add STRIPE_KEY")}      add one secret`);
  info(`  ${cyan("hush install-mcp")}         let your coding agent use them (blind)`);
  // A global vault's directory is never what policyFor() looks at — policy.json
  // lives beside a *project's* vault — so asking here would write a file
  // nothing ever reads.
  if (!global) await askAgentQuestion(hushDir, a);
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

/**
 * `hush set` is the pre-unification name for storing one KEY=value. It is now
 * a thin alias for `hush add KEY=value`: same target-resolution rule (--to,
 * falling back to --env for old scripts, falling back to "default"), no
 * prompt and no --to tip, because a script that already types `hush set` was
 * never going to see either.
 */
async function cmdSet(a: Args): Promise<void> {
  warn("`hush set` is deprecated; use `hush add KEY=value` instead.");
  const key = a._[0];
  if (!key) die("Usage: hush set <KEY> [--env <env>] [--note <text>]");
  const to = str(a, "to") ?? str(a, "env") ?? "default";
  // An alias keeps the old behaviour, and `hush set K --env prod` never made
  // the project use "prod" — that was `hush run --env prod`, run by run.
  return cmdAddKeyValue({ _: [key], rest: [], flags: { ...a.flags, to, "no-use": true } });
}

async function cmdGet(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  const id = requireIdentity();
  const key = a._[0];
  if (!key) die("Usage: hush get <KEY>");

  // Resolved through the same layering `hush run`/`hush export` use — a
  // library link included — not a single literal env, so a key that only a
  // used library set provides is findable at all in a vault-less folder.
  const extra = collectExtraSets(a);
  const { secrets, layers, missing } = composeSets(loose.vault, id, loose.hushDir, extra);
  if (!Object.prototype.hasOwnProperty.call(secrets, key)) {
    die(
      `No secret "${key}" in any set this project uses.`,
      missing.length ? `Your library is missing: ${missing.join(", ")}` : undefined,
    );
  }

  const policy = policyFor(loose.hushDir);
  if (policy) {
    checkScopes(policy, layers);
    if (policy.requireApproval.includes("reveal")) {
      const ap = await requestApproval(loose.hushDir, {
        action: "reveal",
        summary: `Reveal ${key}`,
        scope: `reveal:${layers.join("+")}/${key}`,
        ttlSeconds: policy.approvalTtlSeconds,
        timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
        biometry: policy.biometry,
        // One-shot: a grant cannot outlive this command (approval.ts sessionGrant).
        sessionGrant: false,
      });
      // --yes only skips the scrollback warning below; it never skips policy.
      dieOnApproval(ap, `revealing ${key}`);
    }
  }

  // --copy is the same reveal with less residue: the value goes to the
  // clipboard through a pipe and is never written to stdout, so it misses the
  // scrollback, the tmux buffer, and the session recording.
  if (bool(a, "copy")) {
    const found = findClipboard();
    if (!found) {
      die(
        "No clipboard tool found.",
        `Looked for: ${clipboardNames().join(", ")}. Install one, or drop --copy to print it instead.`,
      );
    }
    if (!bool(a, "yes")) {
      warn(`This puts a live credential on the clipboard, which other applications can read (via ${found.cmd}).`);
      if (!(await confirm(`Copy ${bold(key)}?`))) return info(dim("aborted"));
    }
    const copied = copyToClipboard(secrets[key]);
    if (!copied.ok) die(`Could not copy: ${copied.reason}.`);
    audit(loose.hushDir, { actor: "cli", action: "reveal", key, layers, to: `clipboard:${copied.via}` });
    // The length, never the value: enough to know the whole thing arrived.
    info(`${green("✓")} copied ${bold(key)} to the clipboard ${dim(`(${secrets[key].length} characters)`)}`);
    return;
  }

  if (!bool(a, "yes")) {
    warn("This prints a live credential to your terminal, where it stays in scrollback.");
    if (!(await confirm(`Reveal ${bold(key)}?`))) return info(dim("aborted"));
  }
  audit(loose.hushDir, { actor: "cli", action: "reveal", key, layers });
  out(secrets[key]);
}

/**
 * `hush ls` — the one-screen overview: your library, this project, and which
 * of the library's sets this project actually uses. Replaces `hush env`,
 * `hush envs` and `hush accounts` — a set with a "/" in its name is listed
 * like any other, because that is all it has ever been.
 */
async function cmdLs(a: Args): Promise<void> {
  const setName = a._[0];
  const loose = ctxLoose(a);
  const project = loose.vault;
  const library = openGlobal();

  if (setName) {
    const home = project?.hasSet(setName) ? project : library?.hasSet(setName) ? library : null;
    if (!home) die(`No set called "${setName}".`);
    const meta = home.sets().find((s) => s.name === setName)!;
    if (bool(a, "json")) return out(JSON.stringify(meta, null, 2));
    info(`${bold(meta.label)} ${dim(`(${shown(meta.name)})`)}`);
    if (meta.description) info(`  ${dim(meta.description)}`);
    if (meta.whenToUse) info(`  ${dim("when: " + meta.whenToUse)}`);
    info("");
    if (!meta.keys.length) info(dim("  (no keys yet)"));
    for (const k of meta.keys) info(`  ${k}`);
    return;
  }

  const setUp = isSetUp(loose);
  const used = new Set(setUp ? usedSets(loose.hushDir) : []);
  const libSets = librarySets();

  if (bool(a, "json")) {
    return out(
      JSON.stringify(
        {
          library: libSets.map((s) => ({ ...s, used: used.has(s.name) })),
          project: project ? project.sets().map((s) => ({ ...s, used: used.has(s.name) })) : [],
          setUp,
        },
        null,
        2,
      ),
    );
  }

  const line = (s: { name: string; label: string; description?: string; whenToUse?: string; keys: string[] }, where: "library" | "project") => {
    // The library's default is the one set with a meaning beyond its name.
    const role = where === "library" && s.name === "default" ? dim("  — your global environment, under everything") : "";
    info(
      `  ${used.has(s.name) ? green("●") : " "} ${bold(s.label)} ${dim(`(${shown(s.name)})`)}  ${dim(`${s.keys.length} key(s)`)}${role}`,
    );
    if (s.description) info(`      ${dim(s.description)}`);
    if (s.whenToUse) info(`      ${dim("when: " + s.whenToUse)}`);
  };

  info(bold("YOUR LIBRARY") + (globalVaultExists() ? dim(`  (${globalVaultName()})`) : ""));
  if (!globalVaultExists()) {
    info(dim(`  none yet.  hush global --create`));
  } else if (!libSets.length) {
    info(dim(`  empty.  hush add <file> --as "Name" --library`));
  } else {
    for (const s of libSets) line(s, "library");
  }

  info("");
  info(bold("THIS PROJECT"));
  if (!setUp) {
    info(dim("  not set up yet."));
    info(`  ${cyan("hush use <set>")}       pick one from your library`);
    info(`  ${cyan("hush run -- <cmd>")}    or just run something — hush will ask`);
  } else if (!project) {
    info(dim("  no vault yet — this folder uses library sets only"));
    for (const name of used) {
      const s = libSets.find((x) => x.name === name);
      if (s) line(s, "project");
    }
  } else {
    for (const s of project.sets()) line(s, "project");
  }

  info("");
  info(dim("  ● = used by this project."));
}

/**
 * `hush rm KEY [--from <set>]` removes a key; `hush rm <set>` removes a whole
 * set. A name that is both (a key in one set and the name of another) refuses
 * rather than guessing which was meant.
 */
async function cmdRm(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  requireIdentity();
  const name = a._[0];
  if (!name) die("Usage: hush rm <KEY> [--from <set>]  |  hush rm <set> [--yes]");

  const from0 = str(a, "from");
  // The vault the named set — or the set --from names — lives in, so a library
  // set can be removed, or trimmed, from the same command as a project one.
  // With no project vault this targets the library, since that is the only
  // place a set could be.
  const { vault, where } = pickVault(loose, a, from0 ?? name);
  const isSet = vault.hasSet(name);
  const holders = vault.envNames().filter((e) => vault.has(e, name));
  const isKey = holders.length > 0;
  const wantSet = bool(a, "set");

  if (isSet && isKey && !from0 && !wantSet) {
    die(`"${name}" is both a key and a set name.`, "Say which: --from <set> for the key, or --set to remove the set.");
  }

  if (isSet && (wantSet || !isKey)) {
    const count = vault.sets().find((s) => s.name === name)?.keys.length ?? 0;
    if (!bool(a, "yes")) {
      if (process.stdin.isTTY) {
        if (!(await confirm(`Remove the whole set "${name}" and its ${count} key(s)?`))) {
          return info(dim("aborted"));
        }
      } else {
        die(`Removing a whole set needs confirmation.`, `Pass --yes: hush rm ${name} --yes`);
      }
    }
    delete vault.data.envs[name];
    if (vault.data.meta) delete vault.data.meta[name];
    vault.markStructural();
    vault.save();
    audit(loose.hushDir, { actor: "cli", action: "rm.set", set: name, where });
    info(`${green("✓")} removed set ${bold(name)}`);
    return;
  }

  let from = from0;
  if (!from) {
    if (!isKey) die(`No secret "${name}" in any set, and no set called "${name}".`);
    if (holders.length > 1) {
      if (process.stdin.isTTY) {
        const answer = await promptLine(`"${name}" is in ${holders.join(", ")} — which one? `);
        if (!holders.includes(answer)) die(`"${answer}" is not one of: ${holders.join(", ")}`);
        from = answer;
      } else {
        die(`"${name}" is in more than one set: ${holders.join(", ")}.`, `Say which: hush rm ${name} --from <set>`);
      }
    } else {
      from = holders[0];
    }
  } else if (!vault.has(from, name)) {
    die(`No secret "${name}" in "${from}".`);
  }

  vault.delete(from, name);
  vault.save();
  audit(loose.hushDir, { actor: "cli", action: "delete", env: from, key: name, where });
  info(`${green("✓")} removed ${bold(name)} from ${cyan(from)}`);
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
): { added: number; overwritten: number; skipped: number; short: string[] } {
  let added = 0;
  let overwritten = 0;
  let skipped = 0;
  const short: string[] = [];
  for (const [key, value] of Object.entries(parsed)) {
    if (vault.has(env, key) && !overwrite) {
      skipped++;
      continue;
    }
    if (vault.has(env, key)) overwritten++;
    else added++;
    if (shortValueWarning(key, value)) short.push(key);
    vault.set(id, env, key, value);
  }
  return { added, overwritten, skipped, short };
}

/**
 * Everything `hush add` and `hush import` must decide identically before a set
 * is written: which vault it lands in, and whether the policy wants the `add`
 * approval first.
 *
 * One function rather than two copies, for the same reason policy.ts exists:
 * two surfaces that each decide this for themselves drift, and the drift here
 * is either "stored somewhere the user did not expect" or "skipped the
 * approval", which is the control that matters.
 */
async function beginSetWrite(
  loose: ReturnType<typeof ctxLoose>,
  a: Args,
  opts: {
    asLabel: string;
    count: number;
    verb: string;
    /**
     * Skip the "Where?" question by deciding up front. `hush start` uses this:
     * it already asked several questions, and a first run should not also be a
     * quiz about hush's own storage model.
     */
    target?: "library" | "project";
  },
): Promise<{ target: Vault; where: string; toLibrary: boolean }> {
  const wantLibrary = bool(a, "library") || opts.target === "library";
  const wantProject = bool(a, "project") || opts.target === "project";
  if (wantLibrary && wantProject) die("Pass only one of --library or --project.");

  const isTTY = Boolean(process.stdin.isTTY);
  // Neither flag, no vault of this folder's own, and no library to fall back
  // to: a script has nowhere sensible to land, so it fails here rather than
  // reporting success having stored nothing. A real terminal gets the prompt.
  if (!wantLibrary && !wantProject && !isTTY && !loose.vault && !globalVaultExists()) {
    die(
      "Nothing was stored: this folder has no vault yet, and you have no library either.",
      "Pass --project to make a vault here, or hush global --create to make a library.",
    );
  }

  let toLibrary: boolean;
  if (wantLibrary) toLibrary = true;
  else if (wantProject) toLibrary = false;
  else if (isTTY) {
    const def = globalVaultExists() ? "library" : "project";
    const answer = (await promptLine(`Where? [library/project] (enter for ${def}) `)).trim().toLowerCase();
    toLibrary = (answer || def) === "library";
  } else {
    toLibrary = globalVaultExists();
  }

  let target: Vault;
  let where: string;
  if (toLibrary) {
    const g = openGlobal();
    if (!g) die("You have no library yet.", "Make one: hush global --create");
    target = g;
    where = `your library (${globalVaultName()})`;
  } else {
    // Silent while a guided run is driving: see makeProjectVault's own note.
    target = loose.vault ?? makeProjectVault(loose.hushDir, loose.root, opts.target !== undefined);
    where = "this project";
  }

  const slug = slugifyEnv(opts.asLabel);
  const policy = policyFor(loose.hushDir);
  if (policy?.requireApproval.includes("add")) {
    const ap = await requestApproval(loose.hushDir, {
      action: "add",
      summary: `${opts.verb} "${opts.asLabel}" (${opts.count} key(s)) in ${where}`,
      scope: `add:${slug}`,
      ttlSeconds: policy.approvalTtlSeconds,
      timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
      biometry: policy.biometry,
      // One-shot: a grant cannot outlive this command (approval.ts sessionGrant).
      sessionGrant: false,
    });
    dieOnApproval(ap, `adding ${opts.asLabel}`);
  }

  return { target, where, toLibrary };
}

/**
 * The one thing worth saying about a value too short to mask.
 *
 * `redact.ts` refuses to track anything under MIN_REDACTABLE characters, on
 * the grounds that masking a three-character value is noise. The consequence
 * is that a short secret is injected, used, and printed in full with nothing
 * having said so — and `hush request` sharpened it, because a response that
 * reflects the value back is printed too.
 */
function shortValueWarning(key: string, value: string): string | null {
  if (!value.length || value.length >= MIN_REDACTABLE) return null;
  return `${key} is ${value.length} character(s): hush will not mask a value that short in command output`;
}

function warnShort(keys: string[]): void {
  if (!keys.length) return;
  warn(
    `${keys.length} value(s) are shorter than ${MIN_REDACTABLE} characters, so hush will not mask them ` +
      `in output: ${keys.join(", ")}`,
  );
}

/**
 * `hush add <file>` — the file-shaped input of `hush add`. Asks (on a TTY)
 * what to call the set and whether it belongs in the library or the project;
 * off a TTY it needs `--as`, because a run that stores nothing must not look
 * like one that did.
 */
async function cmdAddFile(a: Args, file: string): Promise<void> {
  const loose = ctxLoose(a);
  let project = loose.vault;
  const id = requireIdentity();
  if (!existsSync(file)) die(`No such file: ${file}`);

  const parsed = parseEnvFile(readFileSync(file, "utf8"));
  const names = Object.keys(parsed);
  if (!names.length) die(`No variables found in ${file}.`);

  const isTTY = Boolean(process.stdin.isTTY);
  let asLabel = str(a, "as");
  if (!asLabel) {
    if (!isTTY) {
      die(
        `Nothing was stored from ${file}: no name given for the set.`,
        `Pass one:  hush add ${file} --as "Name"`,
      );
    }
    const guess = guessSetName(file);
    const answer = await promptLine(`Name this set?${guess ? ` (e.g. "${guess}")` : ""} `);
    asLabel = answer || guess;
    if (!asLabel) die(`Nothing was stored from ${file}: no name given for the set.`);
  }

  const { target, where, toLibrary } = await beginSetWrite(loose, a, {
    asLabel,
    count: names.length,
    verb: "Add set",
  });
  project = toLibrary ? project : target;
  const slug = slugifyEnv(asLabel);

  const { added, skipped, short } = importInto(target, id, slug, parsed, bool(a, "overwrite"));
  // A second import into the same named set is someone adding to the set they
  // already named, not re-describing it — leaving out --description here must
  // not blank out the description the first import set.
  const meta: Parameters<typeof target.describeEnv>[1] = { label: asLabel, source: file };
  const description = str(a, "description");
  const when = str(a, "when");
  if (description !== undefined) meta.description = description;
  if (when !== undefined) meta.whenToUse = when;
  if (!added) target.ensureEnvExists(slug); // describeEnv requires the env to exist
  target.describeEnv(slug, meta);
  target.save();
  audit(loose.hushDir, { actor: "cli", action: "add", kind: "file", env: slug, as: asLabel, file, added, skipped, where: toLibrary ? "library" : "project" });

  info(`${green("✓")} stored ${bold(String(added))} secret(s) as ${bold(asLabel)} ${dim(`(${slug})`)} in ${where}`);
  if (skipped) info(dim(`  ${skipped} already present (pass --overwrite to replace)`));
  warnShort(short);
  useHere(loose.hushDir, slug, a);
  info("");
  info(yellow(`  Now delete ${file} — or at least make sure it is gitignored.`));
  maybeNudge(project, loose.hushDir, loose.root);
}

/**
 * `hush import` grew up, and its two old shapes had to go somewhere.
 *
 * It was the pre-unification name for `hush add <file>`, plus a `--env <name>`
 * shortcut that stored into an existing set with no prompt. Now that the name
 * has a real job (reading another tool's export), each old form that used to
 * work fails with the exact replacement rather than quietly doing something
 * else — a script that means one thing and gets another is the worst outcome.
 *
 * For a `.env`, `hush import <file> --as <set>` is what `hush add` already did,
 * so the migration is one flag.
 */
async function cmdImport(a: Args): Promise<void> {
  if (a.flags.env !== undefined) {
    const file = a._[0] || ".env";
    die(
      "`hush import --env <set>` was removed: `hush import` now reads another tool's export.",
      `For what that did:  hush add ${file} --to ${String(a.flags.env)}`,
    );
  }
  return cmdImportExport(a);
}

/**
 * Extra sets for one run: `--use` (repeatable), `--with service:account`
 * (deprecated alias for `--use service/account`) and `--env` (now just
 * another set, appended like `--use`). Order among the three is fixed rather
 * than reflecting the command line, but composeSets()'s last-mention-wins
 * dedupe means that only matters when the same name appears in more than one
 * of them, which is not a case any of these flags were ever meant to express.
 */
function collectExtraSets(a: Args): string[] {
  const extra: string[] = [...list(a, "use")];
  for (const spec of list(a, "with")) {
    const { service, account } = parseColonPair(spec);
    const name = setNameFor(service, account);
    warn(`--with ${spec} is deprecated; use --use ${name} instead.`);
    extra.push(name);
  }
  extra.push(...list(a, "env"));
  return extra;
}

/** Parse `fal:acme` / `fal=acme` from a --with flag. Not exported: services.ts's parseWith() is deprecated. */
function parseColonPair(spec: string): { service: string; account: string } {
  const m = spec.match(/^([A-Za-z0-9_.-]+)[:=]([A-Za-z0-9_.-]+)$/);
  if (!m) die(`Bad --with "${spec}". Use --with <service>:<account>, e.g. --with fal:acme`);
  return { service: m[1].toLowerCase(), account: m[2] };
}

/**
 * Shared by `hush run`, `hush dev` and pass-through, so all three inherit one
 * policy gate instead of each reimplementing it slightly differently.
 */
async function runCommand(a: Args, argv: string[]): Promise<void> {
  const loose = ctxLoose(a);
  if (!argv.length) die("Usage: hush run [--use <set>…] [--env <set>] -- <command> [args...]");

  // A folder nobody has told hush anything about must never run the command
  // anyway with nothing injected — that silent no-op is worse than refusing,
  // because it looks like success. Off a TTY (and without HUSH_INTERACTIVE=1)
  // there is nobody to ask, so this refuses outright instead of guessing.
  // Checked before the identity, so a brand-new machine is pointed at
  // `hush start` rather than at `hush id --create`, a step it would skip.
  if (!isSetUp(loose) && !interactiveSetup()) dieNotSetUp();
  const id = requireIdentity();
  if (!isSetUp(loose)) await runSetupDialogue(loose, a);

  const extra = collectExtraSets(a);
  const { secrets, layers, missing } = composeSets(loose.vault, id, loose.hushDir, extra);

  // Same checks the MCP server applies to hush_run, so a plain shell cannot
  // walk around a policy an agent's MCP tools would have been refused by.
  // checkEnv() is not needed here: "default" and every used/extra set already
  // appear in `layers`, so checkScopes() alone covers what a single base env
  // used to need a separate check for.
  const policy = policyFor(loose.hushDir);

  // The schema first: a value of the wrong shape is a failure that should not
  // reach an approval dialog, let alone a spawned process.
  const schema = loadSchema(loose.root);
  // A repo file may *ask* for a key to stay unmasked, but only the user's own
  // floor (~/.hush/policy.json) can grant it — otherwise a repository could
  // turn output masking off for a value it can never read.
  const { omit: redactOmit, ignored: unmaskIgnored } = schema
    ? unsensitiveForOutput(schema.rules, policy?.unmaskKeys ?? [])
    : { omit: [] as string[], ignored: [] as string[] };
  if (unmaskIgnored.length) {
    warn(
      `.env.schema asks to leave ${unmaskIgnored.join(", ")} unmasked; your floor has not allowed that, so they stay masked`,
    );
  }
  if (schema && !bool(a, "no-validate")) {
    const problems = validate(secrets, schema.rules, Object.keys(secrets));
    if (problems.length) {
      for (const line of describeProblems(problems)) process.stderr.write(red(`✗ ${line}`) + "\n");
      die(
        `.env.schema rejected ${problems.length} value(s); nothing was run.`,
        "Fix the values, or pass --no-validate to run anyway.",
      );
    }
  }

  // Parsed and described before any approval, so the dialog can name the files
  // and a bad spec fails without a prompt in the way. Nothing is written yet.
  const specs = repeat(a, "materialize").map(parseMaterializeSpec);
  const materializePlan = specs.length ? describeMaterialize(specs, secrets) : [];

  if (policy) {
    checkCommand(policy, argv[0]);
    checkScopes(policy, layers);
    // Materialising is a reveal, not a run: it writes plaintext to a path the
    // caller chose, which an agent holding a file-read tool could then read.
    // Gating it on "run" would make "you may use it but never read it" false.
    if (specs.length && policy.requireApproval.includes("reveal")) {
      const ap = await requestApproval(loose.hushDir, {
        action: "reveal",
        summary: `Write ${specs.length} secret${specs.length === 1 ? "" : "s"} to disk`,
        detail: [...materializePlan.map((l) => `writes:  ${l}`), `Directory:  ${process.cwd()}`],
        // One grant for the whole set of paths, because keying it per key would
        // mean a dialog each. Memory-only, like every other reveal: a file in
        // the repo must not be able to pre-authorise writing a credential out.
        scope: `materialize:${layers.join("+")}/${specs.map((s) => s.key).sort().join(",")}`,
        ttlSeconds: policy.approvalTtlSeconds,
        timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
        biometry: policy.biometry,
        // One-shot: a grant cannot outlive this command (approval.ts sessionGrant).
        sessionGrant: false,
      });
      audit(loose.hushDir, {
        actor: "cli", action: "approval", on: "materialize", decision: ap.decision, via: ap.via, code: ap.code,
      });
      dieOnApproval(ap, `writing ${specs.map((s) => s.key).join(", ")} to disk`);
    }
    if (policy.requireApproval.includes("run")) {
      const ap = await requestApproval(loose.hushDir, {
        action: "run",
        summary: `Run:  ${argv.join(" ")}`.trim(),
        detail: [
          `Using sets:  ${layers.join(", ") || "(none)"}`,
          `Injects:  ${Object.keys(secrets).join(", ") || "(nothing)"}`,
          `Directory:  ${process.cwd()}`,
          approvalCoverageLine(policy, argv[0], layers),
        ],
        // Built by runScope() — the same helper mcp.ts's hush_run calls — so a
        // grant cached by one surface (a "session" approval from either) is
        // honoured by the other for the same command and sets.
        scope: runScope(policy, argv[0], layers),
        ttlSeconds: policy.approvalTtlSeconds,
        timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
        biometry: policy.biometry,
        // One-shot: a grant cannot outlive this command (approval.ts sessionGrant).
        sessionGrant: false,
      });
      audit(loose.hushDir, { actor: "cli", action: "approval", on: "run", decision: ap.decision, via: ap.via, code: ap.code });
      // Denied or timed out: exit before the child is ever spawned.
      dieOnApproval(ap, `running "${argv[0]}"`);
    }
  }

  if (missing.length) {
    warn(`This project uses ${missing.join(", ")}, which your library does not have.`);
    info(dim(`  Make your own:  hush add <file> --as "${missing[0]}" --library`));
  }
  if (!bool(a, "quiet") && layers.length) {
    process.stderr.write(dim(`hush: using ${layers.join(", ")}\n`));
  }

  // Past every gate, so the plaintext may be written now.
  //
  // A materialised key leaves the *environment* but stays in the *redaction
  // set*: `env` is merged over `secrets` in runWithSecrets, so the child sees
  // the path where the value was, while a child that prints the file still gets
  // `[redacted:KEY]` in its output. Dropping it from `secrets` instead would
  // have been simpler and would have made `cat "$GOOGLE_APPLICATION_CREDENTIALS"`
  // print the credential straight into the scrollback.
  let extraEnv: Record<string, string> = {};
  let cleanupFiles: () => void = () => {};
  if (specs.length) {
    const files = materialize(specs, secrets, (m) => warn(m));
    extraEnv = files.env;
    cleanupFiles = files.cleanup;
    if (!bool(a, "quiet")) {
      for (const line of files.written) process.stderr.write(dim(`hush: wrote ${line}\n`));
    }
    // A hard kill cannot be caught, so this is the best-effort half; the other
    // half is the finally around the run below, which covers every ordinary
    // exit including a signal the child relayed.
    process.once("exit", cleanupFiles);
  }

  audit(loose.hushDir, {
    actor: "cli",
    action: "run",
    layers,
    command: argv[0],
    // Materialised keys are not injected; the child gets a path, not a value.
    injected: Object.keys(secrets).filter((k) => !specs.some((s) => s.key === k)).length,
    ...(specs.length ? { materialized: specs.map((s) => s.key) } : {}),
  });

  // `ps` shows the command line to every user on the machine, and hush has no
  // way to pass a secret as an argument on purpose. Nothing noticed when one
  // arrived anyway. A warning rather than a refusal: by the time argv exists
  // the value is already in the process table, so blocking would add an
  // obstacle without removing the exposure.
  for (const [k, v] of Object.entries(secrets)) {
    if (v.length < MIN_REDACTABLE) continue;
    if (argv.some((arg) => arg.includes(v))) {
      warn(`the value of ${k} appears in the command line, which ps shows to every user on this machine`);
    }
  }

  const result = await runWithSecrets(argv[0], argv.slice(1), {
    cwd: process.cwd(),
    secrets,
    env: extraEnv,
    redact: !bool(a, "no-redact"),
    redactOmit,
    capture: false,
  })
    .catch((e) => die(`could not run "${argv[0]}": ${e.message}`))
    .finally(cleanupFiles);

  // Not process.exit(): it discards buffered stdout when stdout is a pipe, so
  // `hush run -- cmd | head` could lose the tail of the child's output.
  process.exitCode = result.code;
}

async function cmdRun(a: Args): Promise<void> {
  const argv = a.rest.length ? a.rest : a._;
  return runCommand(a, argv);
}

/**
 * `hush import` — read what another tool exports and store it as a set.
 *
 * The point is the recipes, not a plugin system: every provider can already
 * export, so hush reads the shape rather than learning each vendor's API.
 */
async function cmdImportExport(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  const id = requireIdentity();

  const source = a._[0] ?? a.rest[0];
  if (!source) {
    die(
      "Usage: hush import <file|-> --as <set> [--format dotenv|json|1password]",
      "Pipe one in:  doppler secrets download --format json --no-file | hush import - --as Prod",
    );
  }
  const rawFormat = str(a, "format") ?? "dotenv";
  if (!IMPORT_FORMATS.includes(rawFormat as ImportFormat)) {
    die(`Unknown --format "${rawFormat}".`, `Known: ${IMPORT_FORMATS.join(", ")}.`);
  }
  const format = rawFormat as ImportFormat;

  let text: string;
  let where: string;
  if (source === "-") {
    // Everything piped in, as one value: an export is a document, and splitting
    // it into lines the way `hush set` does would corrupt any JSON.
    text = readFileSync(0, "utf8");
    where = "stdin";
  } else {
    if (!existsSync(source)) die(`No such file: ${source}`);
    text = readFileSync(source, "utf8");
    where = source;
  }

  const { values, notes } = parseImport(text, format, where);
  const names = Object.keys(values);
  if (!names.length) {
    // The common mistake is a JSON export read as dotenv: `{"A":"1"}` has no
    // `KEY=value` lines, so it parses to nothing and reads as an empty file.
    const looksLikeJson = text.trimStart().startsWith("{") || text.trimStart().startsWith("[");
    die(
      `Nothing to import from ${where}.`,
      format === "dotenv" && looksLikeJson
        ? "That looks like JSON — pass --format json (or --format 1password for an op item)."
        : `Is --format ${format} right for this input? Known: ${IMPORT_FORMATS.join(", ")}.`,
    );
  }

  const asLabel = str(a, "as");
  if (!asLabel) die("Give the set a name.", `hush import ${source} --as "Prod"`);
  const slug = slugifyEnv(asLabel);

  if (bool(a, "dry-run")) {
    // Before any target is resolved on purpose: a dry run must not create a
    // vault, make a library, prompt, or ask for an approval.
    const would = bool(a, "library")
      ? `your library (${globalVaultName()})`
      : loose.vault
        ? "this project"
        : "this project (a vault would be created)";
    info(bold(`${names.length} secret(s) would be stored as ${asLabel} ${dim(`(${slug})`)} in ${would}:`));
    for (const n of names) info(`  ${n}`);
    for (const n of notes) info(dim(`  note: ${n}`));
    info("");
    info(dim("Nothing was written. Drop --dry-run to store them."));
    return;
  }

  const { target, where: landed, toLibrary } = await beginSetWrite(loose, a, {
    asLabel,
    count: names.length,
    verb: "Import",
  });

  const { added, overwritten, skipped, short } = importInto(target, id, slug, values, bool(a, "overwrite"));
  // Same rule as `hush add <file>`: a second write into the same named set is
  // someone adding to it, not re-describing it, so an absent --description must
  // not blank the one a previous import set.
  const meta: Parameters<typeof target.describeEnv>[1] = { label: asLabel, source: where };
  const description = str(a, "description");
  const when = str(a, "when");
  if (description !== undefined) meta.description = description;
  if (when !== undefined) meta.whenToUse = when;
  if (!added && !overwritten) target.ensureEnvExists(slug);
  target.describeEnv(slug, meta);
  target.save();
  audit(loose.hushDir, {
    actor: "cli",
    action: "add",
    kind: "import",
    env: slug,
    as: asLabel,
    source: where,
    format,
    added,
    overwritten,
    skipped,
    where: toLibrary ? "library" : "project",
  });

  info(
    `${green("✓")} imported ${bold(String(added + overwritten))} secret(s) as ` +
      `${bold(asLabel)} ${dim(`(${slug})`)} in ${landed}`,
  );
  if (overwritten) info(dim(`  ${overwritten} replaced an existing value`));
  if (skipped) info(dim(`  ${skipped} already present (pass --overwrite to replace)`));
  warnShort(short);
  for (const n of notes) warn(n);
  useHere(loose.hushDir, slug, a);
}

/**
 * The body of `hush request`, from a flag literal or from somewhere else.
 *
 * `@file` exists because the interesting bodies are JSON documents and
 * fixtures, and pasting one into an argv on a shell is how quoting bugs
 * happen. `@-` reads stdin so `hush request ... --data @- <<< "$json"` and
 * `... | hush request --data @-` both work.
 */
function requestBody(a: Args): string | undefined {
  const raw = str(a, "data") ?? str(a, "body") ?? str(a, "json");
  if (raw === undefined) return undefined;
  if (raw === "@-") return readFileSync(0, "utf8");
  if (raw.startsWith("@")) {
    const path = raw.slice(1);
    try {
      return readFileSync(path, "utf8");
    } catch (e) {
      die(`Could not read ${path}: ${(e as Error).message}`);
    }
  }
  return raw;
}

/**
 * `hush request` — make the call here, so the credential is never handed to
 * the caller or to a child process.
 *
 * `hush run` covers a program that already knows how to authenticate itself.
 * This covers the other half: "call this endpoint with my key" when there is
 * no such program, which previously had no answer at all — `curl` is in the
 * deny list precisely because a shell can read the whole injected environment
 * and post it somewhere redaction cannot see. Here the value goes vault ->
 * this process -> the wire, and the response comes back through the redactor.
 *
 *   hush request POST https://api.stripe.com/v1/refunds \
 *     --header 'Authorization: Bearer $STRIPE_KEY' \
 *     --data '{"charge": "ch_123"}'
 */
async function cmdRequest(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  const id = requireIdentity();

  const rest = a._;
  let method = str(a, "method");
  let target: string | undefined;
  if (rest.length === 1) target = rest[0];
  else if (rest.length === 2) {
    method = method ?? rest[0];
    target = rest[1];
  }
  if (!target) {
    die(
      "Usage: hush request [METHOD] <url> [--header 'Name: value'] [--data body] [--use <set>]",
      "Example: hush request POST https://api.stripe.com/v1/refunds --header 'Authorization: Bearer $STRIPE_KEY'",
    );
  }
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) {
    die(`Not a URL: ${target}`, `Did you mean https://${target}?`);
  }

  let parsed: URL;
  try {
    parsed = new URL(target);
  } catch {
    die(`Not a URL: ${target}`);
  }

  // Same refusal `hush run` makes, for the same reason: a folder nobody has
  // told hush about must not quietly send something with nothing injected.
  if (!isSetUp(loose)) {
    if (!interactiveSetup()) dieNotSetUp();
    await runSetupDialogue(loose, a);
  }

  const extra = collectExtraSets(a);
  const { secrets, layers, missing } = composeSets(loose.vault, id, loose.hushDir, extra);

  const policy = policyFor(loose.hushDir);
  if (policy) {
    for (const k of policy.denyKeys) delete secrets[k];
  }

  // The same schema gate as `hush run`, before a request is built or sent.
  const schema = loadSchema(loose.root);
  const { omit: redactOmit, ignored: unmaskIgnored } = schema
    ? unsensitiveForOutput(schema.rules, policy?.unmaskKeys ?? [])
    : { omit: [] as string[], ignored: [] as string[] };
  if (unmaskIgnored.length) {
    warn(
      `.env.schema asks to leave ${unmaskIgnored.join(", ")} unmasked; your floor has not allowed that, so they stay masked`,
    );
  }
  if (schema && !bool(a, "no-validate")) {
    const problems = validate(secrets, schema.rules, Object.keys(secrets));
    if (problems.length) {
      for (const line of describeProblems(problems)) process.stderr.write(red(`✗ ${line}`) + "\n");
      die(
        `.env.schema rejected ${problems.length} value(s); nothing was sent.`,
        "Fix the values, or pass --no-validate to send anyway.",
      );
    }
  }

  const input: RequestInput = {
    url: target,
    method,
    headers: list(a, "header").map(parseHeader),
    body: requestBody(a),
    secrets,
    substitute: list(a, "substitute"),
    insecure: bool(a, "insecure"),
    redactOmit,
    timeoutMs: (() => {
      const raw = str(a, "timeout");
      if (raw === undefined) return policy?.maxRunMs ?? 30_000;
      const n = Number(raw);
      if (!Number.isFinite(n) || n <= 0) die(`Bad --timeout "${raw}". Give milliseconds, e.g. 30000.`);
      return n;
    })(),
  };

  if (policy) {
    // The command check has no analogue here — hush is the client — so the
    // host check takes its place: it is the one thing an agent actually picks.
    checkHost(policy, parsed);
    checkScopes(policy, layers);
    if (policy.requireApproval.includes("request")) {
      // Build the request first, so a bad one (an unresolvable $NAME, a secret
      // in the path, cleartext) is refused without a dialog in the way.
      prepare(input);
      const sends = requestSecretNames(input, secrets);
      const ap = await requestApproval(loose.hushDir, {
        action: "request",
        summary: `Request:  ${requestSummary(input, secrets)}`,
        detail: [
          `Sends:  ${sends.join(", ") || "(no secret)"}`,
          `Using sets:  ${layers.join(", ") || "(none)"}`,
          `Directory:  ${process.cwd()}`,
          requestCoverageLine(policy, parsed.host, layers),
        ],
        scope: requestScope(policy, parsed.host, layers),
        ttlSeconds: policy.approvalTtlSeconds,
        timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
        biometry: policy.biometry,
        // One-shot: a grant cannot outlive this command (approval.ts sessionGrant).
        sessionGrant: false,
      });
      audit(loose.hushDir, { actor: "cli", action: "approval", on: "request", decision: ap.decision, via: ap.via, code: ap.code });
      dieOnApproval(ap, `requesting ${parsed.host}`);
    }
  }

  if (missing.length) {
    warn(`This project uses ${missing.join(", ")}, which your library does not have.`);
  }

  const result = await requestWithSecrets(input).catch((e) => die((e as Error).message));

  if (bool(a, "include")) {
    out(renderRequest(result, { includeHeaders: true }));
  } else if (result.body) {
    process.stdout.write(result.body.endsWith("\n") ? result.body : result.body + "\n");
  }
  // The status line always goes somewhere a human can see it: a 404 with a
  // body that happens to be empty would otherwise look like success.
  if (!bool(a, "quiet")) process.stderr.write(dim(`hush: ${statusLine(result)}\n`));

  audit(loose.hushDir, {
    actor: "cli",
    action: "request",
    url: result.url,
    method: result.method,
    status: result.status,
    layers,
    sent: result.used,
    redactions: result.redactions,
  });

  // curl's shape: a completed response is not a failed command unless asked.
  if (bool(a, "fail") && result.status >= 400) process.exitCode = 1;
}

/**
 * `hush dev` — find package.json upward from cwd, run its "dev" script (or
 * another named one) through the same path as `hush run`, with the package
 * manager its lockfile names.
 */
async function cmdDev(a: Args): Promise<void> {
  const pkgPath = findUpward("package.json", process.cwd());
  if (!pkgPath) die("No package.json found.", "Try: hush run -- <your command>");
  const dir = dirname(pkgPath);
  const script = a._[0] || "dev";
  const pm = packageManagerFor(dir);
  if (!onPath(pm)) {
    die(`This project uses ${pm} (from its lockfile), but ${pm} is not on PATH.`, `Or run it directly: hush run -- ${pm} run ${script}`);
  }
  return runCommand(a, [pm, "run", script]);
}

/**
 * Anything after `hush` that is not a built-in and not a known command: run
 * it exactly as `hush run -- <argv>` would. `main()` only reaches this after
 * the COMMANDS lookup has already failed, so a real hush command always wins
 * over a same-named program on PATH — `hush ls` is never `/bin/ls`.
 */
async function runPassThrough(argv: string[]): Promise<void> {
  return runCommand({ _: [], rest: [], flags: {} }, argv);
}

async function cmdScan(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  const target = a._[0] ? resolvePath(a._[0]) : loose.root;
  const usages = scanRepo(target);

  // Reconciled against every set this project actually uses — a library link
  // included, project winning over library on a shared name, same as
  // composeSets() — not just the literal keys of one named env. Checking only
  // `vault.list(env)` reported a key as missing even when a used library set
  // already provided it.
  const extra = collectExtraSets(a);
  const names = [...new Set([...usedSets(loose.hushDir), ...extra])];
  const keysOf = new Map<string, string[]>();
  for (const s of librarySets()) keysOf.set(s.name, s.keys);
  for (const s of loose.vault?.sets() ?? []) keysOf.set(s.name, s.keys);
  const vaultKeys = [...new Set(names.flatMap((n) => keysOf.get(n) ?? []))];

  const r = reconcile(usages, vaultKeys);

  if (bool(a, "json")) return out(JSON.stringify(r, null, 2));

  info(`${bold("scan")} ${dim(target)}  ${dim("against")} ${cyan(names.join(", ") || "(nothing used)")}`);
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
    info(dim(`  add them:  hush add <KEY> --to <set>`));
  }
  if (r.unused.length && bool(a, "verbose")) {
    info("");
    info(dim(`Unreferenced: ${r.unused.join(", ")}`));
  }
}

async function cmdExport(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  const id = requireIdentity();

  // Must match `hush run` exactly, library links included — materialising only
  // one set used to mean export silently omitted whatever else `hush run`
  // would have injected, so the shell hook and any generated .env disagreed
  // with what the app actually got at run time.
  const extra = collectExtraSets(a);
  const { secrets, layers, missing } = composeSets(loose.vault, id, loose.hushDir, extra);
  if (missing.length) warn(`Not exported: ${missing.join(", ")} — your library does not have them.`);

  // Used by the shell hook to know what to unset again on the way out. Reveals
  // no value, so this is never gated — the hook depends on it always working.
  if (bool(a, "names")) {
    for (const k of Object.keys(secrets).sort()) out(k);
    return;
  }

  // Everything past here writes values somewhere (stdout or --out), so it is
  // the "reveal" action regardless of format. checkEnv() is not needed: every
  // set in `layers` (including "default") is exactly what checkScopes() checks.
  const policy = policyFor(loose.hushDir);
  if (policy) {
    checkScopes(policy, layers);
    if (policy.requireApproval.includes("reveal")) {
      const ap = await requestApproval(loose.hushDir, {
        action: "reveal",
        summary: `Export ${Object.keys(secrets).length} secret(s)`,
        detail: [`Using sets:  ${layers.join(", ") || "(none)"}`],
        scope: `reveal:export:${layers.join("+")}`,
        ttlSeconds: policy.approvalTtlSeconds,
        timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
        biometry: policy.biometry,
        // One-shot: a grant cannot outlive this command (approval.ts sessionGrant).
        sessionGrant: false,
      });
      dieOnApproval(ap, "export");
    }
  }

  const format = str(a, "format") || (bool(a, "shell") ? "shell" : "env");
  const outFile = str(a, "out");

  const source = loose.vault ? `vault "${loose.vault.data.name}"` : "your library";
  const body =
    format === "json"
      ? JSON.stringify(secrets, null, 2) + "\n"
      : format === "shell"
        ? toShellExports(secrets)
        : toEnvFile(secrets, `generated by hush from ${source} (${layers.join(", ") || "nothing"}) — do not commit`);

  audit(loose.hushDir, { actor: "cli", action: "export", layers, format, to: outFile ?? "stdout" });

  if (outFile) {
    // writeFileSync and chmodSync both follow a symlink at the destination, so
    // a link planted in the repo (git stores them, and .env is a plausible
    // target) would send the whole plaintext set to a file outside the project
    // and re-permission that file. Refuse anything that is not a regular file;
    // a regular file is still overwritten on purpose, which is the 0600
    // re-mode below. The same "never write through a symlink" refusal the
    // grants file used to need — it is gone, this one is not.
    const existingOut = lstatSync(outFile, { throwIfNoEntry: false });
    if (existingOut && !existingOut.isFile()) {
      die(
        `${outFile}: not a regular file — hush will not write plaintext through a ` +
          `symlink or special file placed at that path.`,
      );
    }
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

  // `team add` is the other door into a vault, alongside `--project`: a
  // folder that has only ever used library sets gets one the moment someone
  // needs to share it, exactly like `hush add K=v --project` does. Every
  // other subcommand needs a vault that already exists, so those stay on the
  // strict ctx() below, unchanged.
  if (sub === "add") {
    const loose = ctxLoose(a);
    const [name, pk] = [a._[1], a._[2]];
    if (!name || !pk) die("Usage: hush team add <name> <hush_pk_… | age1…>");
    if (isAgeRecipient(pk) && !ageAvailable()) {
      die("That is an age recipient, but the age binary is not installed.", "brew install age");
    }
    const vault = loose.vault ?? makeProjectVault(loose.hushDir, loose.root);
    const id = requireIdentity();
    const fp = vault.addRecipient(id, name, pk, str(a, "role") === "admin" ? "admin" : "member");
    vault.save();
    audit(loose.hushDir, { actor: "cli", action: "team.add", name, fingerprint: fp });
    info(`${green("✓")} ${bold(name)} can now decrypt this vault`);
    info(dim(`  commit ${loose.vaultPath} and they are in — no server, no invite email`));
    return;
  }

  const { vault, hushDir } = ctx(a);

  if (!sub || sub === "ls" || sub === "list") {
    const members = vault.members();
    info(`${bold(shown(vault.data.name))}  ${dim(`DEK generation ${vault.data.dek.generation}`)}`);
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

/** `hush envs` / `hush env` / `hush env ls` — pre-unification names for `hush ls`. */
async function cmdEnvs(a: Args): Promise<void> {
  warn("`hush envs` / `hush env` is deprecated; use `hush ls` instead.");
  return cmdLs(a);
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
      // ctx() carries the same "no vault of its own yet" distinction this
      // needs: a folder with .hush/envs.json but no vault.json is a project
      // that only ever used library sets, not one with nothing here at all.
      const { vault: v } = ctx(a);
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
      warn("`hush env new` is deprecated; use `hush add <file>` instead.");
      const label = rest.join(" ").trim();
      const from = str(a, "from");
      if (!label || !from) die('Usage: hush env new <name> --from <file> [--description <text>] [--when <text>]');
      return cmdAddFile(
        { _: [from], rest: [], flags: { ...a.flags, as: label, ...(onProject ? { project: true } : { library: true }) } },
        from,
      );
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
      warn("`hush env use` is deprecated; use `hush use` instead.");
      const name = rest[0];
      if (!name) die("Usage: hush env use <name>");
      return cmdUse({ _: [name], rest: [], flags: {} });
    }

    case "drop": {
      warn("`hush env drop` is deprecated; use `hush use --not` instead.");
      const name = rest[0];
      if (!name) die("Usage: hush env drop <name>");
      return cmdUse({ _: [], rest: [], flags: { not: name } });
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
    info(`  ${cyan('hush add .env --as "Acme Production" --library')}   put something in it`);
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

/**
 * The entry an agent's config gets. A bare `hush mcp` whenever the `hush` on
 * PATH is this very install: `.mcp.json` and `.cursor/mcp.json` are committed,
 * and the absolute path to one machine's node_modules (an nvm version
 * directory, a home folder) is wrong on every teammate's machine and on this
 * one after the next Node upgrade. `node` itself was already resolved from
 * PATH, so `hush` is no less reachable. Anything else — a local install, a
 * different hush first on PATH — keeps the absolute path, which is at least
 * the right program.
 */
function mcpEntry(): { command: string; args: string[] } {
  const cliPath = fileURLToPath(import.meta.url);
  const onPathHush = onPath("hush");
  try {
    if (onPathHush && realpathSync(onPathHush) === realpathSync(join(dirname(cliPath), "..", "bin", "hush.js"))) {
      return { command: "hush", args: ["mcp"] };
    }
  } catch { /* fall through to the absolute path */ }
  return { command: "node", args: [cliPath, "mcp"] };
}

/**
 * On a terminal, show every file about to be written and ask once. Detection
 * is broad on purpose — a `~/.cursor` from a trial months ago counts — so
 * without this, registering hush for the one agent someone uses also dropped
 * a `.cursor/` into their repo and appended to their user-wide Codex config.
 * `--yes`, `--for`, and a non-TTY caller skip the question.
 */
async function confirmWrites(a: Args, plan: { name: string; file: string; note?: string }[]): Promise<boolean[]> {
  if (!plan.length || !process.stdin.isTTY || bool(a, "yes") || str(a, "for")) return plan.map(() => true);
  info("This will write:");
  const width = Math.max(...plan.map((p) => p.name.length));
  for (const p of plan) info(`  ${p.name.padEnd(width)}  ${cyan(p.file)}${p.note ? `  ${dim(p.note)}` : ""}`);
  const ans = (await askLine(`Go ahead? ${dim(plan.length > 1 ? "[Y/n/pick]" : "[Y/n]")} `)).trim().toLowerCase();
  if (ans === "n" || ans === "no") return plan.map(() => false);
  if (plan.length > 1 && (ans === "p" || ans === "pick")) {
    const picks: boolean[] = [];
    for (const p of plan) picks.push(/^y(es)?$|^$/i.test((await askLine(`  ${p.name}? ${dim("[Y/n]")} `)).trim()));
    return picks;
  }
  return plan.map(() => true);
}

/** Said next to a file outside the project, which changes more than this project. */
const outsideNote = (file: string, root: string): string | undefined =>
  file.startsWith(resolvePath(root) + "/") ? undefined : "your user config — applies to every project";

async function cmdInstallMcp(a: Args): Promise<void> {
  // Registering an agent needs the folder, not a vault: "approvals on — hush
  // install-mcp when you're ready" is printed by setup in a vault-less folder.
  const { root } = ctxLoose(a);
  const entry = mcpEntry();

  const policyPath = join(root, ".hush", "policy.json");
  assertProjectHushDir(dirname(policyPath));
  const writePolicy = !existsSync(policyPath);

  // One file is not enough any more: Claude Code, Codex and Cursor each read a
  // different one, and writing the wrong one produced a tick with nothing behind
  // it. See src/agents.ts.
  info("");
  const forced = str(a, "for");
  const candidates = forced ? AGENTS.filter((g) => g.id === forced) : AGENTS.filter((g) => g.present(root, process.env, existsSync));
  if (forced && !candidates.length) die(`Unknown agent "${forced}".`, `known: ${AGENTS.map((g) => g.id).join(", ")}`);

  let registered = 0;
  const pending: { agent: (typeof AGENTS)[number]; file: string; text: string }[] = [];
  for (const agent of candidates) {
    const file = agent.mcp.path(root, process.env);
    const before = existsSync(file) ? readFileSync(file, "utf8") : null;
    const merged = renderMcp(agent.mcp.format, before, "hush", entry);
    if (!merged.ok) {
      warn(`${agent.name}: leaving ${file} alone — ${merged.reason}.`);
      info(dim(indent(`  paste this yourself: ${agent.manual(entry, root)}`, "  ")));
      continue;
    }
    if (!merged.changed) {
      info(`${green("✓")} ${agent.name}: hush is already registered in ${cyan(file)}`);
      registered++;
      continue;
    }
    pending.push({ agent, file, text: merged.text });
  }

  // The policy is on the same list: it changes what *you* may run here, which
  // is no less a change to the project than an agent's config file.
  const plan = pending.map((p) => ({ name: p.agent.name, file: p.file, note: outsideNote(p.file, root) }));
  if (writePolicy) plan.unshift({ name: "Policy", file: policyPath, note: "approvals on for every hush run here" });
  const go = await confirmWrites(a, plan);
  if (writePolicy && go.shift()) {
    // Serialised from the live defaults rather than retyped. The hand-written
    // copy that used to live here is how a setting that no longer exists
    // (`allowReveal`) kept being written into every new project.
    const template = { ...DEFAULT_POLICY, denyCommands: [] };
    // A folder with no `.hush/` yet is exactly the case this command is for,
    // and this used to die with ENOENT before writing anything.
    mkdirSync(dirname(policyPath), { recursive: true });
    writeFileSync(policyPath, JSON.stringify(template, null, 2) + "\n");
    info(`${green("✓")} wrote ${cyan(".hush/policy.json")} ${dim("(what the agent may run)")}`);
    describePolicyEffect();
  } else if (writePolicy) {
    info(dim("  Policy: skipped — nothing will ask before your agent uses a key"));
  }
  for (const [i, { agent, file, text }] of pending.entries()) {
    if (!go[i]) {
      info(dim(`  ${agent.name}: skipped`));
      continue;
    }
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, text);
    info(`${green("✓")} ${agent.name}: registered hush in ${cyan(file)}`);
    registered++;
  }

  if (!candidates.length) {
    // Nothing recognised. Say so, and hand over the two lines that work, rather
    // than writing a file no agent reads and calling it done.
    warn(`No coding agent detected here (looked for ${AGENTS.map((g) => g.name).join(", ")}).`);
    info("");
    info(`  To register hush by hand, either of these is enough:`);
    for (const agent of AGENTS.filter((g) => g.id !== "cursor")) {
      info(indent(`    ${agent.name}: ${cyan(agent.manual(entry, root))}`, "    "));
    }
    info(dim(`  Force one anyway with: hush install-mcp --for codex`));
  } else if (forced) {
    info(dim(`  --for ${forced}: wrote the file whether or not it looked installed`));
  } else {
    // Named rather than listed as a flag menu: someone who has one agent does
    // not need to read the ids of the two they do not have.
    const others = AGENTS.filter((g) => !candidates.includes(g));
    if (others.length) {
      info(dim(`  Not on this machine: ${others.map((g) => g.name).join(", ")} — register one with --for <id>`));
    }
  }

  info("Your agent can now:");
  info(`  ${dim("·")} see which secrets exist`);
  info(`  ${dim("·")} run commands with them injected`);
  info(`  ${dim("·")} ${bold("not")} read a single value`);
  if (!registered) info(dim("  (once it is registered, that is)"));
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

  const loc = locateProject(process.cwd());
  check(
    Boolean(loc),
    "project",
    !loc
      ? "not set up — run something with hush here, or `hush use <set>`"
      : loc.hasVault
        ? loc.vaultPath
        : `${loc.hushDir}  (no vault yet — uses library sets only)`,
  );
  if (!loc || !id) return;

  // A folder that only uses library sets has nothing to be a recipient *of*;
  // the checks below that read the vault simply do not apply to it.
  let vault: Vault | null = null;
  if (loc.hasVault) {
    try {
      vault = Vault.open(loc.vaultPath);
    } catch (e) {
      return check(false, "vault readable", (e as Error).message);
    }
    check(vault.canRead(id), "you are a recipient", vault.canRead(id) ? `as "${vault.memberName(id)}"` : "ask an admin to `hush team add` you");
    check(true, "members", String(vault.members().length));
  }

  // One vocabulary here too: every set, project and library, marked the way
  // `hush ls` marks it.
  const used = new Set(usedSets(loc.hushDir));
  const projectNames = vault ? vault.sets().map((s) => s.name) : [];
  const libraryNames = librarySets().map((s) => s.name).filter((n) => !projectNames.includes(n));
  check(
    true,
    "sets",
    [...projectNames, ...libraryNames].map((s) => s + (used.has(s) ? " ●" : "")).join(", ") + dim("   ● = used by this project"),
  );

  const root = loc.hushDir.replace(/[/\\]\.hush$/, "");
  // Asked of every agent hush knows, not just Claude Code: on a Codex machine
  // the old check looked for `.mcp.json`, did not find it, and told someone with
  // a working setup to run the installer again.
  const registered = mcpRegistrations(root, process.env, readIfExists);
  check(
    registered.length > 0,
    "MCP registered",
    registered.length
      ? registered.map((x) => `${x.agent.name}: ${x.file}`).join(", ")
      : "run `hush install-mcp`",
  );

  const skills = AGENTS.flatMap((g) =>
    [g.skill.project(root), g.skill.global?.(process.env)].filter((p): p is string => !!p && existsSync(p)),
  );
  check(skills.length > 0, "agent skill", skills.length ? skills.join(", ") : "run `hush install-skill`");

  // What the agent is actually allowed to do, rather than what it could be.
  const policy = loadPolicy(loc.hushDir);
  check(
    policy.requireApproval.length > 0,
    "approval required",
    policy.requireApproval.length ? policy.requireApproval.join(", ") : "nothing is gated — see .hush/policy.json",
  );

  // The floor lives outside the repo on purpose (see policy.ts's
  // mergePolicies), so it is worth spelling out here that it exists at all —
  // and, when the repo tried to loosen something it sets, exactly what got
  // refused rather than leaving that invisible.
  const floorPath = join(hushHome(), "policy.json");
  check(existsSync(floorPath), "policy floor", existsSync(floorPath) ? floorPath : "none — only .hush/policy.json gates this project");
  const weakenings = policyWeakenings(readPolicyFile(floorPath), readPolicyFile(join(loc.hushDir, "policy.json")));
  for (const w of weakenings) info(`    ${dim(w)}`);

  // `.env.schema`, when the project has one. This is the only check anywhere
  // that says whether a value is the *right shape*; everything above is about
  // where it lives and who can read it.
  const schema = loadSchema(root);
  if (!schema) {
    check(true, ".env.schema", dim("none — add one to have value shapes checked"));
  } else {
    let problems: ReturnType<typeof validate> = [];
    try {
      problems = validate(composeSets(vault, id, loc.hushDir, []).secrets, schema.rules);
    } catch {
      /* nothing resolves yet; the set checks above already said so */
    }
    check(
      problems.length === 0,
      ".env.schema",
      problems.length ? `${problems.length} value(s) do not match` : `${schema.rules.length} rule(s)`,
    );
    for (const line of describeProblems(problems)) info(`    ${dim(line)}`);
  }

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
  const stale = vault ? inspect(vault) : null;
  if (stale) check(false, "vault freshness", `rolled back to generation ${stale.nowGeneration} — hush verify`);

  const posture = assess(vault, loc.hushDir, root);
  info("");
  info(`  ${posture.rung === 5 ? green("●".repeat(5)) : green("●".repeat(posture.rung)) + dim("○".repeat(5 - posture.rung))}  ${bold(`rung ${posture.rung} of 5`)} ${dim("— " + posture.name)}`);
  if (posture.next) info(`    ${dim("next: " + posture.next.label)}  ${cyan("hush secure")}`);
}

// -------------------------------------------------------------------- add

function cmdAddUsage(): void {
  info(bold("Usage:"));
  info("  hush add <file> [--as <name>] [--library|--project]");
  info("  hush add KEY=value [KEY=value…] [--to <set>]");
  info("  hush add <service> [--as <name>]      " + dim("e.g. hush add fal"));
  info("");
  info(dim("  known services: " + Object.keys(CATALOG).sort().join(", ")));
}

/**
 * `hush add` — the one way to put secrets in, however they arrive: a file, a
 * KEY=value on the command line, or a known service prompted one variable at
 * a time. Dispatch order matters: `--account`/`--vars` force the service
 * form even for a name outside CATALOG (the pre-unification `hush add` took
 * any service name at all, and this keeps that working), a bare "=" forces
 * key/value, and only then does an existing path win — so a CATALOG name
 * never has to also collide with a file to be recognised as a service.
 */
async function cmdAdd(a: Args): Promise<void> {
  const first = a._[0];
  if (!first) return void cmdAddUsage();

  if (a._.some((x) => x.includes("="))) return cmdAddKeyValue(a);

  const service = first.toLowerCase();
  if (CATALOG[service] || str(a, "account") !== undefined || list(a, "vars").length) {
    return cmdAddService(a, service);
  }

  if (existsSync(first)) return cmdAddFile(a, first);

  // Not a file, not a known service: the same shape `hush set <KEY>` always
  // had — a bare key name, prompted for its value.
  return cmdAddKeyValue(a);
}

/** `hush add KEY=value [KEY=value…] [--to <set>]` — the direct-value form. */
async function cmdAddKeyValue(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  const id = requireIdentity();
  const pairs = a._;
  if (!pairs.length) die("Usage: hush add <KEY>[=value] [<KEY>=value…] [--to <set>]");

  let to = str(a, "to");
  if (!to) {
    if (process.stdin.isTTY) {
      const answer = await promptLine(`Which set? (enter for ${dim("default")}) `);
      to = answer || "default";
    } else {
      to = "default";
      info(dim(`  Tip: hush add ${pairs[0]} --to <set> keeps this out of "default".`));
    }
  }
  const slug = resolveSetName(to, [loose.vault, openGlobal()]);
  const { vault, where } = pickVault(loose, a, slug);
  const isNew = !vault.hasSet(slug);
  const policy = policyFor(loose.hushDir);

  for (const spec of pairs) {
    let key = spec;
    let value: string;
    const eq = spec.indexOf("=");
    if (eq > 0) {
      key = spec.slice(0, eq);
      value = spec.slice(eq + 1);
      warn("Value passed on the command line — it is now in your shell history.");
    } else {
      value = await promptSecret(`value for ${bold(key)}`, true);
    }
    if (!value) die("Empty value, nothing written.");

    if (policy?.requireApproval.includes("add")) {
      const ap = await requestApproval(loose.hushDir, {
        action: "add",
        summary: `Set ${key} (${slug})`,
        scope: `add:${slug}/${key}`,
        ttlSeconds: policy.approvalTtlSeconds,
        timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
        biometry: policy.biometry,
        // One-shot: a grant cannot outlive this command (approval.ts sessionGrant).
        sessionGrant: false,
      });
      dieOnApproval(ap, `setting ${key}`);
    }

    const existed = vault.has(slug, key);
    vault.set(id, slug, key, value, str(a, "note"));
    vault.save();
    const short = shortValueWarning(key, value);
    if (short) warn(short);
    audit(loose.hushDir, { actor: "cli", action: existed ? "update" : "create", env: slug, key, where });
    info(`${green("✓")} ${existed ? "updated" : "added"} ${bold(key)} in ${cyan(slug)}  ${dim(preview(value))}`);
  }
  if (isNew) useHere(loose.hushDir, slug, a);
  if (where === "library") info(dim(`  in your library (${globalVaultName()}) — never in the repo`));
  else info(dim(`  commit ${loose.vaultPath} to share it with the team`));
  maybeNudge(where === "project" ? vault : loose.vault, loose.hushDir, loose.root);
}

/**
 * `hush add <service>` — prompt for a known service's variables one at a
 * time, into a set named by `--as` or by prompt. `--account <x>` is the
 * deprecated alias for `--as "<service>/<x>"`.
 */
async function cmdAddService(a: Args, service: string): Promise<void> {
  const loose = ctxLoose(a);
  const id = requireIdentity();

  const accountAlias = str(a, "account");
  let asLabel = str(a, "as");
  let slug: string;
  if (accountAlias !== undefined) {
    const aliasName = setNameFor(service, accountAlias);
    warn(`--account is deprecated; use --as "${aliasName}" instead.`);
    slug = aliasName;
    asLabel ??= aliasName;
  } else if (asLabel) {
    slug = slugifyEnv(asLabel);
  } else if (process.stdin.isTTY) {
    const answer = await promptLine(`Name this set? e.g. "Personal ${serviceLabel(service)}" `);
    if (!answer) die(`Nothing was stored for ${service}: no name given for the set.`);
    asLabel = answer;
    slug = slugifyEnv(asLabel);
  } else {
    die(
      `Nothing was stored for ${service}: no name given for the set.`,
      `Pass one:  hush add ${service} --as "Personal ${serviceLabel(service)}"`,
    );
  }

  const { vault, where } = pickVault(loose, a, slug);
  const vars = list(a, "vars").length ? list(a, "vars") : knownVars(service);
  if (!vars.length) {
    die(
      `"${service}" is not a known service, so hush doesn't know which variables it needs.`,
      `Tell it: hush add ${service} --as "${asLabel}" --vars API_KEY,API_SECRET`,
    );
  }

  const policy = policyFor(loose.hushDir);
  if (policy?.requireApproval.includes("add")) {
    const ap = await requestApproval(loose.hushDir, {
      action: "add",
      summary: `Add ${serviceLabel(service)} set "${asLabel}" (${vars.join(", ")})`,
      scope: `add:${slug}`,
      ttlSeconds: policy.approvalTtlSeconds,
      timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
      biometry: policy.biometry,
      // One-shot: a grant cannot outlive this command (approval.ts sessionGrant).
      sessionGrant: false,
    });
    dieOnApproval(ap, `adding ${slug}`);
  }

  info(`${bold(serviceLabel(service))} ${dim("/")} ${bold(asLabel!)}`);
  info(dim(`  ${vars.length} variable(s). Leave blank to skip one.`));
  info("");

  let stored = 0;
  const skipped: string[] = [];
  const short: string[] = [];
  for (const v of vars) {
    const had = vault.has(slug, v);
    const value = await promptSecret(`  ${v}${had ? dim(" (set — enter to keep)") : ""}`);
    if (!value) {
      skipped.push(v);
      continue;
    }
    vault.set(id, slug, v, value);
    if (shortValueWarning(v, value)) short.push(v);
    stored++;
  }

  if (!stored) {
    // Skipping every prompt is a real choice when a human is at the keyboard.
    // With no terminal there were no prompts to skip: something piped in one
    // value fewer than expected, or nothing at all — and reporting success for
    // that told a CI job the credential was stored when the vault was untouched.
    if (!process.stdin.isTTY) {
      die(
        `Nothing was stored for ${slug}: no value arrived on stdin.`,
        `Pipe one line per variable (${vars.join(", ")}):  ` +
          `printf '%s\\n' "$KEY" | hush add ${service} --as "${asLabel}"`,
      );
    }
    return info(dim("nothing entered, nothing changed"));
  }

  // A partial write is not a failure, but it must not look like a complete one.
  if (skipped.length) {
    warn(`Left unset: ${skipped.join(", ")}${process.stdin.isTTY ? "" : " (stdin ran out of lines)"}`);
  }
  warnShort(short);

  if (!accountAlias) vault.describeEnv(slug, { label: asLabel });
  vault.save();
  audit(loose.hushDir, { actor: "cli", action: "add", kind: "service", service, env: slug, stored, where });
  info("");
  info(`${green("✓")} stored ${stored} value(s) for ${bold(slug)}`);
  // The --account alias promises the old behaviour, and the old behaviour
  // was "stored, not pinned" — scripts then ran `hush use` themselves.
  if (accountAlias === undefined) useHere(loose.hushDir, slug, a);
  info("");
  info("Use it:");
  info(`  ${cyan("hush npm run dev")}  ${dim("← or any command; the set is injected")}`);
  info(`  ${cyan(`hush run --use ${slug} -- <cmd>`)}  ${dim("← from a project that does not use it")}`);
  if (where === "library") info(dim(`  in your library (${globalVaultName()}) — never in the repo`));
  else info(dim(`  commit ${loose.vaultPath} to share it`));
}

/** `hush accounts` — pre-unification name for `hush ls`. */
async function cmdAccounts(a: Args): Promise<void> {
  warn("`hush accounts` is deprecated; use `hush ls` instead.");
  return cmdLs(a);
}

/** Parse `fal=acme` — the pre-unification pin syntax — into the set name `fal/acme` names today. */
function convertLegacyPin(spec: string): string {
  const m = spec.match(/^([A-Za-z0-9_.-]+)=([A-Za-z0-9_.-]+)$/);
  if (!m) return spec;
  const name = setNameFor(m[1], m[2]);
  warn(`"${spec}" is deprecated; use "${name}" instead.`);
  return name;
}

/**
 * `hush use <set> [<set>…]` — this project uses these, appended to
 * `.hush/envs.json`. `hush use` alone lists what is used, in resolution
 * order, with where each comes from. `hush use --not <set>` stops using it.
 */
async function cmdUse(a: Args): Promise<void> {
  const loose = ctxLoose(a);

  const notSpecs = list(a, "not").map(convertLegacyPin);
  if (notSpecs.length) {
    saveLinks(loose.hushDir, loadLinks(loose.hushDir).filter((l) => !notSpecs.includes(l)));
    for (const n of notSpecs) info(`${green("✓")} this project no longer uses ${bold(n)}`);
    return;
  }

  if (!a._.length) {
    // No arguments in a folder nobody has set up yet is exactly the moment
    // the dialogue exists for — the same one `hush run` falls into, minus
    // actually running anything afterward.
    if (!isSetUp(loose)) {
      if (!interactiveSetup()) dieNotSetUp();
      return runSetupDialogue(loose, a);
    }
    const used = usedSets(loose.hushDir);
    const library = librarySets();
    if (!used.length) {
      info(dim("This project uses nothing yet."));
      info(`  ${cyan("hush use <set> [<set>…]")}`);
      return;
    }
    info(bold("This project uses:") + dim("  (in resolution order — later wins)"));
    const width = Math.max(...used.map((n) => n.length));
    for (const name of used) {
      const source = loose.vault?.hasSet(name) ? "project" : library.some((s) => s.name === name) ? "library" : "missing";
      info(`  ${name.padEnd(width)}  ${dim(source)}`);
    }
    return;
  }

  const names = a._.map(convertLegacyPin);
  const library = librarySets();
  const unknown = names.filter((n) => !loose.vault?.hasSet(n) && !library.some((s) => s.name === n));
  if (unknown.length) {
    const known = [...new Set([...(loose.vault ? loose.vault.envNames() : []), ...library.map((s) => s.name)])];
    die(`No set called "${unknown[0]}".`, `you have: ${known.length ? known.join(", ") : "none yet"}`);
  }

  // A folder with no `.hush` at all yet gets one here — this is one of the
  // two ways in, alongside the setup dialogue above.
  writeProjectDotfiles(loose.hushDir);
  saveLinks(loose.hushDir, [...loadLinks(loose.hushDir), ...names]);
  for (const n of names) info(`${green("✓")} this project now uses ${bold(n)}`);
  info(dim("\n  recorded in .hush/envs.json — commit it so the team resolves the same sets"));
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
  // `--for 30m` sets how long an "Allow" lasts, which is also how someone with
  // approvals already on asks for a longer window.
  const forRaw = str(a, "for");
  let ttlSeconds: number | undefined;
  if (forRaw !== undefined) {
    try {
      ttlSeconds = parseDuration(forRaw);
    } catch (e) {
      die((e as Error).message);
    }
  }
  await runSecure({ vault, hushDir: loc?.hushDir ?? null, root }, explicit, ttlSeconds);
}

/** `hush biometry` — set up, check, or try the Touch ID gate. */
async function cmdBiometry(a: Args): Promise<void> {
  const sub = a._[0] ?? "status";

  if (sub === "setup") {
    const r = ensureHelper();
    if (!r.ok) die(`Can't set up biometry: ${r.reason}`);
    // Nothing is installed: the helper is built fresh for each process that
    // needs it, so there is no path worth naming here.
    info(`${green("✓")} the Touch ID helper builds and runs on this machine`);

    // What an older hush left in `~/.hush/bin/` is dead weight that looks
    // authoritative. Nothing reads it any more; clear it so the only copy in
    // play is one this machine built for itself.
    const stale = ["hush-touchid", "hush-touchid.stamp"]
      .map((f) => join(hushHome(), "bin", f))
      .filter((f) => existsSync(f));
    for (const f of stale) {
      try { unlinkSync(f); } catch { /* leave it: it is ignored either way */ }
    }
    if (stale.length) info(dim(`  removed the old cached copy in ~/.hush/bin (no longer used)`));
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
  const src = fileURLToPath(new URL("../skills/hush/SKILL.md", import.meta.url));
  if (!existsSync(src)) die(`Skill template missing at ${src}`);

  const root = ctxLoose(a).root;
  const markdown = readFileSync(src, "utf8");
  const forced = str(a, "for");
  const targets = forced
    ? AGENTS.filter((g) => g.id === forced)
    : AGENTS.filter((g) => g.present(root, process.env, existsSync));
  if (forced && !targets.length) die(`Unknown agent "${forced}".`, `known: ${AGENTS.map((g) => g.id).join(", ")}`);

  const written: string[] = [];
  const pending: { name: string; dest: string; body: string; note?: string }[] = [];
  for (const agent of targets) {
    const dest = global ? agent.skill.global?.(process.env) : agent.skill.project(root);
    if (!dest) {
      warn(`${agent.name}: no ${global ? "global " : ""}skill location — nothing written for it.`);
      continue;
    }
    const body = agent.skill.transform ? agent.skill.transform(markdown, skillDescription(markdown)) : markdown;
    const before = existsSync(dest) ? readFileSync(dest, "utf8") : null;
    if (before === body) {
      info(`${green("✓")} ${agent.name}: ${cyan(dest)} ${dim("(already up to date)")}`);
      written.push(dest);
      continue;
    }
    // The file may have been edited by hand; say so before replacing it.
    pending.push({ name: agent.name, dest, body, note: before === null ? undefined : "replaces the file that is there" });
  }

  const go = await confirmWrites(a, pending.map((p) => ({ name: p.name, file: p.dest, note: p.note })));
  for (const [i, { name, dest, body }] of pending.entries()) {
    if (!go[i]) {
      info(dim(`  ${name}: skipped`));
      continue;
    }
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, body);
    info(`${green("✓")} ${name}: ${cyan(dest)}`);
    written.push(dest);
  }

  if (!targets.length) {
    info("");
    info(`  No coding agent detected here (looked for ${AGENTS.map((g) => g.name).join(", ")}).`);
    info(`  The skill is one file; put it wherever your agent reads instructions from:`);
    for (const agent of AGENTS) {
      const dest = global ? agent.skill.global?.(process.env) : agent.skill.project(root);
      if (dest) info(`    ${agent.name}: ${cyan(dest)}`);
    }
    info(dim(`  Force one anyway with: hush install-skill --for codex`));
  }

  info("");
  if (written.length) info("Your coding agent now knows to:");
  else info("Once it is in place, your coding agent will know to:");
  info(`  ${dim("·")} never ask you to paste a key into the chat`);
  info(`  ${dim("·")} open a secure prompt on your screen instead`);
  info(`  ${dim("·")} pick the right account when you name one`);
  info("");
  if (written.length) {
    info(dim(global ? "  applies to every project" : "  applies to this project — pass --global for all of them"));
  }
}

// --------------------------------------------------------------------- help

/**
 * `hush help` — eight lines, chosen after watching people bounce off a 35-command
 * screen with two vocabularies (environments and service accounts) fighting for
 * the same idea. `hush help --all` (below) still lists everything.
 */
const SHORT_HELP = `${bold("hush")} ${dim(VERSION)}

  hush add <file|KEY=value>   save secrets as a named set
  hush use <set> ...          this project uses these sets
  hush run -- <cmd>           run with them injected
  hush dev                    run your dev script with them
  hush ls                     library, project, what is used
  hush rm <KEY|set>           remove
  hush ui                     the app
  hush team add|rm            share this project's vault

  hush help --all             every command
`;

const FULL_HELP = `${bold("hush")} ${dim(VERSION)} — envelope-encrypted team secrets your agent can use but never read

${bold("daily")}
  hush start                               never used this? a few questions, and you're set up
  hush add <file>                          save a .env-shaped file as a named set
  hush add KEY=value [KEY=value…]          save one or more values directly
  hush add <service>                       e.g. hush add fal — prompted, hidden input
  hush import <file|-> --as <set>           bring in another tool's export (dotenv, json, 1password)
  hush use <set> [<set>…]                  this project uses these sets, in order (later wins)
  hush use                                 show what this project uses, and where from
  hush use --not <set>                     stop using it here
  hush run [--use <set>…] -- <cmd>         run with them injected, output redacted
  hush run --materialize KEY -- <cmd>      write that secret to a file; the child gets the path
  ${dim("(pass-through: npm run dev, python app.py, … run the same way)")}
  ${dim("(in a folder that isn't set up yet, hush asks which of your sets it should use)")}
  hush dev [script]                        find package.json, run it with them injected
  hush request [METHOD] <url> [--header 'Name: $VAR'] [--data @file]
                                           call an API with a secret injected, response redacted
  hush ls [<set>]                          library, project, what is used — or one set's keys
  hush rm <KEY> [--from <set>]             remove a key
  hush rm <set> [--yes]                    remove a whole set
  hush ui                                  open the local app to manage everything
  hush team ls|add|rm                      share this project's vault

${bold("sets")}          — a set you name, describe and reuse
  hush env rename <name> <new name>    re-seals every value under the new name
  hush env describe <name> [--description <t>] [--when <t>]
  hush env move <KEY>… --to <set>      carve one big pile into named sets
  hush global [<vault>|--create]       which vault holds your library

${bold("sharing")}
  hush team ls
  hush team add <name> <pk>     re-wraps the key for them; commit and they're in
  hush team rm <name>           removes them and re-encrypts everything
  hush id [--create]            show or create this machine's key
  hush link <vault> [--env e]   point this repo at a vault you already have

${bold("hardening")}
  hush level                    where you are on the security ladder
  hush secure                   climb the next rung
  hush secure approval --for 30m  ask before anything uses a key; 30m is how long an "Allow" lasts
  hush biometry [setup|test]    gate approvals behind Touch ID
  hush age                      use a YubiKey / Secure Enclave / TPM via age
  hush verify                   check the vault decrypts and has not been rolled back
  hush rotate                   new vault key, same values

${bold("agents")}
  hush install-mcp              register hush with your coding agent
  hush install-skill            teach the agent the rules (--global for all projects)

${bold("other")}
  hush init [name]               create a vault here (.hush/vault.json — commit it)
  hush doctor                    check this machine's setup
  hush hook <zsh|bash|fish>      auto-load on cd (least safe; unloads on leave)
  hush export [--out .env]       write plaintext out (last resort)
  hush get <KEY>                 reveal one value (asks first)
  hush scan [dir]                what does this codebase need, and is it in the vault?
  hush root                      the project root hush would act on

${bold("flags")}
  --use <set>     an extra set for this run only (repeatable; --env is an alias)
  --materialize   (run) KEY or KEY=/path: write that secret to a file, hand the
                  child the path, remove it afterwards. Needs "reveal", not "run".
  --header        (request) 'Name: value'; put $KEY where the secret goes (repeatable)
  --data          (request) the body, or @file / @- to read one
  --substitute    (request) extra places for $KEY: body, query (headers are always allowed)
  --include       (request) print the status line and response headers too
  --for <30m|1h>  (secure approval) how long the dialog's "Allow" lasts
  --json          machine-readable output where it makes sense

${dim("Deprecated, still work — each prints a one-line notice: hush set,")}
${dim("hush accounts, hush env ls / env / env use / env drop / env new, --with a:b, use a=b.")}

${dim("Vault files hold only ciphertext and public keys. Your private key never leaves this machine.")}
`;

// --------------------------------------------------------------------- main

const COMMANDS: Record<string, (a: Args) => Promise<void>> = {
  init: cmdInit,
  id: cmdId,
  set: cmdSet,
  add: cmdAdd,
  start: cmdStart,
  import: cmdImport,
  accounts: cmdAccounts,
  account: cmdAccounts,
  use: cmdUse,
  get: cmdGet,
  ls: cmdLs,
  list: cmdLs,
  rm: cmdRm,
  remove: cmdRm,
  export: cmdExport,
  run: cmdRun,
  exec: cmdRun,
  request: cmdRequest,
  dev: cmdDev,
  scan: cmdScan,
  team: cmdTeam,
  rotate: cmdRotate,
  link: cmdLink,
  envs: cmdEnvs,
  env: cmdEnv,
  global: cmdGlobal,
  "install-mcp": cmdInstallMcp,
  "install-skill": cmdInstallSkill,
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

  if (!command || command === "--help" || command === "-h") {
    // In a folder nobody has set up, the eight-command screen is still a wall
    // of text to someone who has never used this. One line that names the way
    // in, and only there: once a folder is set up the pointer is noise.
    let fresh = false;
    try {
      const loc = resolveVaultPath(process.cwd());
      fresh = !loc || (!existsSync(loc.vaultPath) && !existsSync(join(loc.hushDir, "envs.json")));
    } catch {
      fresh = false;
    }
    process.stdout.write(
      fresh
        ? `${bold("New here?")} Run ${cyan("hush start")} and it walks you through it.\n\n${SHORT_HELP}`
        : SHORT_HELP,
    );
    return;
  }
  if (command === "help") {
    process.stdout.write(argv[1] === "--all" ? FULL_HELP : SHORT_HELP);
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
  if (handler) {
    const parsed = parseArgs(argv.slice(1));
    // `--vault personal` targets a named vault in ~/.hush/vaults, from anywhere.
    const named = str(parsed, "vault");
    if (named) process.env.HUSH_VAULT = named.includes("/") ? resolvePath(named) : namedVaultPath(named);
    await handler(parsed);
    return;
  }

  // Pass-through: `hush npm run dev`, `hush python app.py`, … run exactly as
  // `hush run -- …` would. Only reached once every built-in and known command
  // above has already failed to match, so a real hush command always wins
  // over a same-named program on PATH.
  if (!command.startsWith("-") && onPath(command)) {
    return runPassThrough(argv);
  }

  die(`Unknown command: ${command}`, "Run `hush help`.");
}

main().catch((e) => {
  die(e instanceof Error ? e.message : String(e));
});
