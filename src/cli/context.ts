/**
 * Which project and vault a command acts on, the policy that governs it, and the
 * one-time setup dialogue for a folder hush has not been told about yet.
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join, basename, dirname } from "node:path";
import { Vault, locateProject, slugifyEnv, assertScopeName, assertProjectHushDir } from "../vault.ts";
import { loadIdentity, createIdentity, hushHome } from "../identity.ts";
import { scanRepo } from "../scan.ts";
import { loadPolicy, DEFAULT_POLICY, type Policy } from "../mcp.ts";
import { ensureFloor } from "../policy.ts";
import { usedSets, librarySets, loadLinks, saveLinks, openGlobal, ensureProjectVault, writeProjectDotfiles, suggestSets, linkNameFor, placeOf, allowedAt } from "../library.ts";
import { checkAndRecord, describeRollback } from "../integrity.ts";
import { approvalPromptAvailable } from "../approval.ts";
import { bold, cyan, die, dim, green, info, red, shown, warn, yellow } from "../cli/output.ts";
import { type Args, bool, str } from "../cli/args.ts";
import { askLine } from "../cli/prompts.ts";

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
  // A merge that left keys to choose keeps this branch's side in the file
  // until each is picked; say so on every command until it is done.
  if (existsSync(join(dirname(vault.path), "merge-conflicts.json"))) {
    process.stderr.write(yellow("! a vault merge still has keys to choose — hush merge status") + "\n");
  }
}

export function ctx(a: Args): Ctx {
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
export function ctxLoose(a: Args): LooseCtx {
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
export function policyFor(hushDir: string): Policy | null {
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
export function dieOnApproval(ap: { decision: string; note?: string }, what: string): void {
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
export function makeProjectVault(hushDir: string, root: string, quiet = false): Vault {
  const id = loadIdentity() ?? createIdentity();
  const memberName = process.env.USER || process.env.USERNAME || "me";
  const vaultName = basename(root);
  const { vault, created } = ensureProjectVault(
    hushDir,
    id.pub ? { name: memberName, pub: id.pub, priv: id.priv } : { name: memberName, ageRecipient: id.age!.recipients[0] },
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
export function pickVault(
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
export function resolveSetName(name: string, vaults: (Vault | null)[]): string {
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
export function useHere(hushDir: string, slug: string, a: Args): void {
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
export function ensureGitignore(hushDir: string): void {
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

export function isSetUp(loose: { hushDir: string; hasVault: boolean }): boolean {
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
export function interactiveSetup(): boolean {
  return Boolean(process.stdin.isTTY) || process.env.HUSH_INTERACTIVE === "1";
}

/**
 * The non-interactive refusal. Never runs the command with nothing injected —
 * that silent no-op, not an error, is the dead end this whole feature exists
 * to prevent — and never blocks waiting for an answer nobody can give.
 */
export function dieNotSetUp(): never {
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
  info(`Which sets should this folder use? ${dim("(space-separated, enter to skip)")}`);
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
export async function askAgentQuestion(hushDir: string, a: Args): Promise<void> {
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
  ensureFloorSaying();
  describePolicyEffect();
}

/**
 * Write the empty policy floor if there is none, and say so in one line. An
 * agent is about to be near the vault; see policy.ts's ensureFloor for why the
 * file's existence is what matters.
 */
export function ensureFloorSaying(): void {
  const floor = ensureFloor(hushHome());
  if (floor.created) {
    info(`${green("✓")} wrote ${cyan(floor.path)} ${dim("(your policy floor — no repo can switch approvals off below it)")}`);
  }
}

/**
 * What a project policy.json does to the person's *own* terminal, said once at
 * the moment one is written. The CLI enforces the same policy as the MCP tools
 * (an agent with a shell would otherwise walk around it), so turning approvals
 * on for an agent also puts a prompt in front of every `hush run` here and
 * refuses interpreters outright — and on a machine with no dialog program the
 * prompt can never appear, so every run is refused. Neither was said anywhere.
 */
export function describePolicyEffect(): void {
  info(dim("  every hush run here now asks first, yours too. Your agent's tools also cannot"));
  info(dim("  run node, python, bash and the like. Undo: rm .hush/policy.json"));
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
export async function runSetupDialogue(loose: { hushDir: string; root: string }, a: Args): Promise<boolean> {
  info(bold("This folder isn't set up for hush yet."));

  // Only what may be used here: a set kept for other folders is not offered.
  const place = placeOf(loose.hushDir);
  const sets = librarySets().filter((s) => !s.onlyIn || allowedAt(s.onlyIn, place));
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
        picks = [];
      } else if (ans === "edit" || ans === "e") {
        picks = await manualPick(sets);
      }
      // Blank or "y": keep the proposed `picks` as they stand.
    }
  }

  // Declining is an answer, not an error: nothing is written, and the folder
  // is asked again next time rather than marked as "set up with nothing".
  if (!picks.length) {
    info(dim("Nothing saved here.  hush use <set> whenever you want this folder to have some."));
    return false;
  }
  saveLinks(loose.hushDir, picks.map((n) => linkNameFor("library", n)));
  writeProjectDotfiles(loose.hushDir);
  info(`${green("✓")} this folder uses ${picks.join(", ")}   ${dim("(.hush/envs.json — commit it if the team should too)")}`);

  await askAgentQuestion(loose.hushDir, a);
  return true;
}
