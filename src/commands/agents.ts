/**
 * `hush install-mcp` and `hush install-skill` — tell coding agents about hush.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, dirname, sep, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";
import { assertProjectHushDir } from "../vault.ts";
import { hushHome } from "../identity.ts";
import { DEFAULT_POLICY } from "../mcp.ts";
import { AGENTS, renderMcp, skillDescription } from "../agents.ts";
import { selfCommand } from "../cli/programs.ts";
import { type Args, bool, str } from "../cli/args.ts";
import { bold, cyan, die, dim, green, indent, info, warn } from "../cli/output.ts";
import { askLine } from "../cli/prompts.ts";
import { ctxLoose, describePolicyEffect, ensureFloorSaying } from "../cli/context.ts";

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
  return selfCommand(["mcp"]);
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
  file.startsWith(resolvePath(root) + sep) ? undefined : "your user config — applies to every project";

export async function cmdInstallMcp(a: Args): Promise<void> {
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
  // The floor goes on the same list: it is the file that keeps approvals on
  // when the agent reaches the vault some other way (red-team finding 4).
  const floorPath = join(hushHome(), "policy.json");
  const writeFloor = !existsSync(floorPath);
  if (writeFloor) plan.unshift({ name: "Floor", file: floorPath, note: "your user config — no repo can go below it" });
  const go = await confirmWrites(a, plan);
  if (writeFloor && go.shift()) ensureFloorSaying();
  else if (writeFloor) info(dim("  Floor: skipped — a copy of this vault opened elsewhere would have no policy"));
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

/** `hush install-skill` — teach the coding agent how to use all of this. */
export async function cmdInstallSkill(a: Args): Promise<void> {
  const global = bool(a, "global");
  // src/commands/ (or dist/commands/) → the package root → skills/.
  const src = fileURLToPath(new URL("../../skills/hush/SKILL.md", import.meta.url));
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
  // Several agents read the same place (Codex, Gemini CLI and Zed all read
  // .agents/skills/): one file, named for all of them, written once.
  const upToDate = new Map<string, string>();
  for (const agent of targets) {
    const dest = global ? agent.skill.global?.(process.env) : agent.skill.project(root);
    if (!dest) {
      warn(`${agent.name}: no ${global ? "global " : ""}skill location — nothing written for it.`);
      continue;
    }
    const shared = pending.find((p) => p.dest === dest);
    if (shared) {
      shared.name += `, ${agent.name}`;
      continue;
    }
    if (upToDate.has(dest)) {
      upToDate.set(dest, `${upToDate.get(dest)}, ${agent.name}`);
      continue;
    }
    const body = agent.skill.transform ? agent.skill.transform(markdown, skillDescription(markdown)) : markdown;
    const before = existsSync(dest) ? readFileSync(dest, "utf8") : null;
    if (before === body) {
      upToDate.set(dest, agent.name);
      written.push(dest);
      continue;
    }
    // The file may have been edited by hand; say so before replacing it.
    pending.push({ name: agent.name, dest, body, note: before === null ? undefined : "replaces the file that is there" });
  }

  for (const [dest, names] of upToDate) info(`${green("✓")} ${names}: ${cyan(dest)} ${dim("(already up to date)")}`);
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

  // An agent that has been taught to use hush is an agent near the vault.
  if (written.length) ensureFloorSaying();

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
