/**
 * `hush setup` — where this machine and this project stand, as one checklist
 * (src/setup.ts), for a person or for a coding agent.
 *
 *   hush setup                 the checklist, and the next command
 *   hush setup --json          the same for an agent, with the rules it follows
 *   hush setup skip <step>     never offer that step here again (unskip undoes it)
 *
 * `hush start` walks the same list step by step on a terminal (walkSetup).
 */
import { spawn } from "node:child_process";
import { homedir } from "node:os";
import { type Args, bool } from "../cli/args.ts";
import { bold, cyan, die, dim, green, info, out, red, yellow } from "../cli/output.ts";
import { selfCommand } from "../cli/programs.ts";
import { AGENT_RULES, commandOf, setSkip, setupState, type SetupState, type SetupStep } from "../setup.ts";

const tilde = (p: string): string => (p.startsWith(homedir() + "/") ? "~" + p.slice(homedir().length) : p);

const mark = (s: SetupStep): string =>
  s.status === "done" ? green("✓") : s.status === "todo" ? red("✗") : s.status === "skipped" ? dim("–") : dim("○");

export function renderSetup(st: SetupState): void {
  const meter = green("●".repeat(st.done)) + dim("○".repeat(Math.max(0, st.total - st.done)));
  info(`${bold("hush · set up")}  ${meter}  ${st.done} of ${st.total}  ${dim(tilde(st.root))}`);
  info("");
  const width = Math.max(...st.steps.map((s) => s.title.length));
  for (const s of st.steps) {
    const note = s.status === "optional" ? dim("  (optional)") : s.status === "skipped" ? dim("  (skipped)") : "";
    info(`  ${mark(s)} ${s.title.padEnd(width)}  ${dim(s.detail)}${note}`);
    if ((s.status === "todo" || s.status === "optional") && s.command) info(`    ${" ".repeat(width)}  ${cyan(s.command)}`);
  }
  info("");
  if (st.next) {
    info(`  Next:  ${cyan(st.next.command ?? st.next.title)}`);
    info(dim("  Walk through it here:  hush start      Or tell your coding agent:  \"set up hush: run hush setup --json and follow it\""));
  } else {
    info(`  ${green("✓")} set up. ${dim("The optional steps above are there when you want them.")}`);
  }
}

export async function cmdSetup(a: Args): Promise<void> {
  const sub = a._[0];
  if (sub === "skip" || sub === "unskip") {
    const id = a._[1];
    const st = setupState(process.cwd());
    if (!id || !st.steps.some((s) => s.id === id)) die("Which step?", `One of: ${st.steps.map((s) => s.id).join(", ")}`);
    setSkip(st.root, id, sub === "skip");
    return info(`${green("✓")} ${sub === "skip" ? "skipped" : "offering again"}: ${id}`);
  }
  if (sub) die(`Unknown: hush setup ${sub}`, "hush setup | hush setup --json | hush setup skip <step>");

  const st = setupState(process.cwd());
  if (bool(a, "json")) {
    return out(JSON.stringify({
      root: st.root,
      done: st.done,
      total: st.total,
      next: st.next?.id ?? null,
      steps: st.steps.map((s) => ({
        id: s.id, title: s.title, kind: s.kind, status: s.status, detail: s.detail,
        ...(s.command ? { command: s.command } : {}),
        ...(s.options?.length ? { options: s.options.map((o) => ({ label: o.label, ...(o.argv ? { command: commandOf(o.argv) } : {}) })) } : {}),
      })),
      agent: AGENT_RULES,
    }, null, 2));
  }
  renderSetup(st);
}

// ------------------------------------------------------------------ the walkthrough

export interface WalkIO {
  state: () => SetupState;
  ask: (question: string) => Promise<string>;
  /** Run one hush command; resolves with its exit code. */
  run: (argv: string[]) => Promise<number>;
  skip: (id: string) => void;
  print: (line: string) => void;
}

/** Run `hush <argv>` as a child of this one, on this terminal. */
export function runHush(argv: string[]): Promise<number> {
  const cmd = selfCommand(argv);
  return new Promise((resolve) => {
    const child = spawn(cmd.command, cmd.args, { stdio: "inherit" });
    child.on("error", () => resolve(1));
    child.on("exit", (code) => resolve(code ?? 1));
  });
}

/**
 * The required steps still to do, one at a time: what it is, why, and "do it
 * now?". A step is offered once per walk; "s" skips it for good. Each command
 * asks for whatever it needs itself, so the walk never handles a secret.
 */
export async function walkSetup(io: WalkIO): Promise<void> {
  const offered = new Set<string>();
  for (;;) {
    const step = io.state().steps.find((s) => s.status === "todo" && !offered.has(s.id));
    if (!step) break;
    offered.add(step.id);
    io.print("");
    io.print(`${bold(step.title)}  ${dim(step.detail)}`);
    let argv = step.argv;
    const choices = (step.options ?? []).filter((o) => o.argv);
    if (choices.length > 1) {
      choices.forEach((o, i) => io.print(`  ${i + 1}. ${o.label}${i === 0 ? dim("  (recommended)") : ""}`));
      const pick = (await io.ask(`Which? ${dim("[1, or s to skip, n for not now]")} `)).trim().toLowerCase();
      if (pick === "s") {
        io.skip(step.id);
        continue;
      }
      if (pick === "n") continue;
      argv = choices[(Number(pick) || 1) - 1]?.argv ?? choices[0].argv;
    } else {
      for (const o of step.options ?? []) io.print(dim(`  ${o.label}`));
      if (!argv) {
        io.print(`  Run this when you are ready:  ${cyan(step.command ?? "")}`);
        continue;
      }
      const ans = (await io.ask(`Do it now? ${dim("[Y/n, s to skip for good]")} `)).trim().toLowerCase();
      if (ans === "s") {
        io.skip(step.id);
        continue;
      }
      if (ans === "n" || ans === "no") continue;
    }
    for (const one of argv ?? []) {
      const code = await io.run(one);
      if (code !== 0) {
        io.print(yellow(`  That did not finish. Run it again when you are ready: ${commandOf(argv!)}`));
        break;
      }
    }
  }

  const st = io.state();
  io.print("");
  const optional = st.steps.filter((s) => s.status === "optional" && s.id === "conversations");
  if (optional.length) {
    const ans = (await io.ask(`Check whether your keys already appear in past agent conversations? ${dim("(read-only, about half a minute) [y/N]")} `)).trim().toLowerCase();
    if (ans === "y" || ans === "yes") await io.run(["scan", "--transcripts"]);
  }
  const end = io.state();
  io.print("");
  io.print(end.next
    ? `${end.done} of ${end.total} done. ${dim("Run hush start again any time to pick up where you left off.")}`
    : `${green("✓")} all set — ${end.done} of ${end.total}.`);
}
