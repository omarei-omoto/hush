/**
 * Setting hush up, as one list of steps that every front end reads: the
 * terminal walkthrough (`hush start`), coding agents (`hush setup --json`),
 * and anyone checking where they are (`hush setup`).
 *
 * Each step is worked out from what is on disk now, so the list is always
 * current, re-running never repeats a finished step, and two front ends can
 * never disagree about what is done. Each step also says what kind it is:
 *
 * - **auto** — safe for anyone to run as given, an agent included: it touches
 *   no secret in a way a person must see, and decides nothing about trust.
 * - **choice** — a decision with a recommended default. An agent asks the
 *   person in the chat, then runs the command with their answer.
 * - **person** — needs a person: consent to something hard to undo, or a
 *   secret typed in. The command asks on the person's terminal, or in a hush
 *   dialog on their screen; an agent runs it and waits, and never answers it.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { loadIdentity, hushHome } from "./identity.ts";
import { globalVaultExists, librarySets, usedSets } from "./library.ts";
import { Vault, locateProject } from "./vault.ts";
import { AGENTS, mcpRegistrations } from "./agents.ts";
import { assess } from "./posture.ts";
import { findEnvFiles, detectDevCommand } from "./start.ts";
import { packageManagerFor } from "./cli/programs.ts";
import { agentCredentialCount } from "./commands/scan-agents.ts";

export type StepKind = "auto" | "choice" | "person";
export type StepStatus = "done" | "todo" | "skipped" | "optional";

export interface SetupStep {
  id: string;
  title: string;
  kind: StepKind;
  status: StepStatus;
  /** One line about where this stands. */
  detail: string;
  /** The command that does it, exactly as a person or an agent would type it. */
  command?: string;
  /** The same, as argv lists, for the walkthrough to run in order. */
  argv?: string[][];
  /** For a choice: the options, recommended first, each with its own command. For a person step: what they will be asked. */
  options?: SetupOption[];
}

export interface SetupOption {
  label: string;
  argv?: string[][];
}

/** `hush a b && hush c`, from argv lists. */
export const commandOf = (argv: string[][]): string =>
  argv.map((a) => ["hush", ...a.map((x) => quote(x))].join(" ")).join(" && ");

export interface SetupState {
  root: string;
  steps: SetupStep[];
  /** The first step to do, or null when everything required is done. */
  next: SetupStep | null;
  done: number;
  total: number;
}

// ------------------------------------------------------------------ skips

const skipsFile = (): string => join(hushHome(), "setup-skips.json");

function loadSkips(): Record<string, string[]> {
  try {
    const j = JSON.parse(readFileSync(skipsFile(), "utf8"));
    return j && typeof j === "object" && !Array.isArray(j) ? j : {};
  } catch {
    return {};
  }
}

/** Remember that a person skipped a step here, so neither front end asks again. */
export function setSkip(root: string, id: string, skip: boolean): void {
  const all = loadSkips();
  const here = new Set(all[root] ?? []);
  if (skip) here.add(id);
  else here.delete(id);
  all[root] = [...here];
  mkdirSync(hushHome(), { recursive: true, mode: 0o700 });
  writeFileSync(skipsFile(), JSON.stringify(all, null, 2) + "\n", { mode: 0o600 });
}

// ------------------------------------------------------------------ the steps

/**
 * Quoted for a POSIX shell, because people and agents paste these commands
 * into one: single quotes, where nothing is expanded. JSON's double quotes
 * would let a "$(…)" in a folder name run as a command.
 */
const quote = (s: string): string => (/^[\w./@:=-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);

/** A name for a folder's keys: "My App" from my-app. */
function setLabelFor(root: string): string {
  const base = basename(root).replace(/[-_.]+/g, " ").trim() || "Dev";
  return base.replace(/\b\w/g, (c) => c.toUpperCase());
}

export function setupState(cwd: string, env: NodeJS.ProcessEnv = process.env): SetupState {
  const loc = locateProject(cwd);
  const root = loc ? loc.hushDir.replace(/[/\\]\.hush$/, "") : cwd;
  const skipped = new Set(loadSkips()[root] ?? []);
  const steps: SetupStep[] = [];
  const add = (s: SetupStep) => steps.push(s.status === "todo" && skipped.has(s.id) ? { ...s, status: "skipped" } : s);

  // 1. A key for this machine.
  const id = loadIdentity();
  add({
    id: "key",
    title: "Your key",
    kind: "auto",
    status: id ? "done" : "todo",
    detail: id ? `on this machine (${id.source})` : "this machine has no hush key yet",
    command: "hush id --create",
    argv: [["id", "--create"]],
  });

  // 2. A library: your own sets, usable in any project.
  const libraryCount = globalVaultExists() ? librarySets().length : -1;
  add({
    id: "library",
    title: "Your library",
    kind: "auto",
    status: libraryCount >= 0 ? "done" : "todo",
    detail: libraryCount >= 0 ? `${libraryCount} set(s), usable in any project` : "a place for keys you use across projects",
    command: "hush global --create",
    argv: [["global", "--create"]],
  });

  // 3. This project's keys.
  const linked = loc ? usedSets(loc.hushDir).filter((s) => s !== "default") : [];
  const hasVault = Boolean(loc?.hasVault);
  const envFiles = findEnvFiles(root);
  const projectDone = hasVault || linked.length > 0;
  const label = setLabelFor(root);
  if (projectDone) {
    add({ id: "project", title: "This project's keys", kind: "auto", status: "done", detail: hasVault ? "a vault in this repo" : `uses ${linked.join(", ")}` });
  } else if (envFiles.length) {
    add({
      id: "project",
      title: "This project's keys",
      kind: "choice",
      status: "todo",
      detail: `${envFiles.join(", ")} found. hush reads it itself; nobody needs to open it.`,
      command: `hush import ${quote(envFiles[0])} --as ${quote(label)} --project`,
      argv: [["import", envFiles[0], "--as", label, "--project"]],
      options: [
        { label: "in a vault in this repo, shared with whoever you add (a team project)", argv: [["import", envFiles[0], "--as", label, "--project"]] },
        { label: "in your library: only on this machine, usable in other projects too", argv: [["import", envFiles[0], "--as", label, "--library"]] },
      ],
    });
  } else {
    const library = libraryCount > 0 ? librarySets().map((s) => s.name) : [];
    add({
      id: "project",
      title: "This project's keys",
      kind: library.length ? "choice" : "person",
      status: "todo",
      detail: library.length ? "no .env here; use a set you already have, or add keys" : "no .env here; add keys (typed into a hidden prompt, never the chat)",
      command: library.length ? `hush use ${library[0]}` : "hush add <service>",
      ...(library.length ? { argv: [["use", library[0]]] } : {}),
      options: [
        ...library.map((n) => ({ label: `use your set ${n}`, argv: [["use", n]] })),
        { label: "add keys: hush add <service> (e.g. stripe, openai) asks for each one, hidden" },
      ],
    });
  }

  // 4. The agents on this machine know about hush.
  const read = (p: string): string | null => {
    try {
      return existsSync(p) ? readFileSync(p, "utf8") : null;
    } catch {
      return null;
    }
  };
  const registered = mcpRegistrations(root, env, read);
  const present = AGENTS.filter((g) => g.present(root, env, existsSync)).map((g) => g.name);
  add({
    id: "agents",
    title: "Your agents",
    kind: "choice",
    status: registered.length ? "done" : present.length ? "todo" : "optional",
    detail: registered.length
      ? `connected: ${[...new Set(registered.map((r) => r.agent.name))].join(", ")}`
      : present.length ? `found ${present.join(", ")}; none connected to hush yet` : "no coding agent found on this machine",
    command: "hush install-mcp --yes && hush install-skill",
    argv: [["install-mcp", "--yes"], ["install-skill"]],
    options: [{ label: `connect ${present.join(", ") || "your agents"} (each file is shown before it is written)`, argv: [["install-mcp", "--yes"], ["install-skill"]] }],
  });

  // 5. Plaintext keys sitting in those agents' own config files.
  const plain = agentCredentialCount(root);
  add({
    id: "agent-configs",
    title: "Keys in your agents' configs",
    kind: "person",
    status: plain.count ? "todo" : "done",
    detail: plain.count ? `${plain.count} plaintext key(s) in ${plain.files} file(s)` : "no plaintext keys in any agent config",
    command: "hush scan --agents --fix",
    argv: [["scan", "--agents", "--fix"]],
    options: [{ label: "moves each key into your library and rewrites the file to start the server through hush; asks first" }],
  });

  // 6. The two safety steps that belong in a first run, from the security
  //    ladder (posture.ts) so `hush level` and this never disagree.
  if (projectDone) {
    const vault = hasVault ? Vault.open(loc!.vaultPath) : null;
    const p = assess(vault, loc!.hushDir, root);
    for (const checkId of ["no-plaintext", "approval"] as const) {
      const c = p.checks.find((x) => x.id === checkId);
      if (!c) continue;
      // `hush secure --<rung>` does the step itself (secure.ts), asking where
      // it has to; the ladder's own hint is for a person reading `hush level`.
      const argv = [["secure", `--${checkId}`]];
      add({
        id: checkId,
        title: checkId === "no-plaintext" ? "No plaintext .env left" : "Asked before a key is used",
        // Removing a file needs a yes; turning approvals on only adds a prompt, so it is a choice.
        kind: checkId === "no-plaintext" ? "person" : "choice",
        status: c.pass ? "done" : "todo",
        detail: c.pass ? c.label : c.gap,
        command: commandOf(argv),
        argv,
        options: checkId === "approval"
          ? [{ label: "a click dialog for each use (recommended)", argv }, { label: "Touch ID for each use", argv: [...argv, ["secure", "--biometry"]] }]
          : [{ label: c.why ?? "imports the file into the vault, then deletes it; asks first" }],
      });
    }
    if (p.next && p.rung >= 3) {
      add({ id: "stronger", title: "Stronger", kind: "person", status: "optional", detail: p.next.label, command: "hush secure", argv: [["secure"]] });
    }
  }

  // 6b. Your floor: rules in ~/.hush/policy.json that a repository's own
  //     policy.json can tighten but not loosen. Without one, a project's
  //     committed policy decides whether you are asked at all.
  const floor = existsSync(join(hushHome(), "policy.json"));
  add({
    id: "floor",
    title: "Your own rules",
    kind: "auto",
    status: floor ? "done" : "todo",
    detail: floor ? "a repository's policy can tighten them, never loosen them" : "without them, a project's own policy.json decides whether you are asked",
    command: "hush secure --floor",
    argv: [["secure", "--floor"]],
  });

  // 7. Worth knowing, never required: what past conversations already hold.
  add({
    id: "conversations",
    title: "Keys in past conversations",
    kind: "auto",
    status: "optional",
    detail: "reads what your agents saved for your keys, word for word; read-only, about half a minute",
    command: "hush scan --transcripts",
    argv: [["scan", "--transcripts"]],
  });

  // 8. See it work.
  const dev = detectDevCommand(root, packageManagerFor);
  if (dev && projectDone) {
    add({
      id: "first-run",
      title: "See it work",
      kind: "auto",
      status: "optional",
      detail: "run your app once; any key it prints shows as [redacted:…]",
      command: `hush ${dev.pm} run ${dev.script}`,
      argv: [[dev.pm, "run", dev.script]],
    });
  }

  const required = steps.filter((s) => s.status !== "optional");
  return {
    root,
    steps,
    next: steps.find((s) => s.status === "todo") ?? null,
    done: required.filter((s) => s.status === "done").length,
    total: required.length,
  };
}

/** What an agent should know before driving setup. Printed with --json. */
export const AGENT_RULES = [
  "Run each step's command as written, one at a time, and run hush setup --json again after each.",
  "kind auto: run it.",
  "kind choice: ask the person in the chat which option they want, then run the command with their answer.",
  "kind person: run the command and wait. It asks the person on their own terminal or in a hush dialog on their screen. Never answer it for them, and never add --yes to it.",
  "Never open a .env file, and never ask for a key in the chat: hush import reads files itself, and hush add asks in a hidden prompt.",
  "A step marked skipped was skipped by the person. Leave it.",
];
