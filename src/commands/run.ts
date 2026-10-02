/**
 * `hush run`, `hush dev` and pass-through (`hush npm run dev`) — run a command with secrets injected.
 */
import { dirname, basename } from "node:path";
import { audit, type Vault } from "../vault.ts";
import type { Opener } from "../crypto.ts";
import { requireIdentity } from "../identity.ts";
import { runWithSecrets } from "../run.ts";
import { MIN_REDACTABLE } from "../redact.ts";
import { checkCommand, checkScopes, runScope, approvalCoverageLine } from "../policy.ts";
import { materialize, describeMaterialize, parseMaterializeSpec } from "../materialize.ts";
import { loadSchema, validate, unsensitiveForOutput, describeProblems } from "../schema.ts";
import { composeSets } from "../library.ts";
import { requestApproval } from "../approval.ts";
import { type Args, bool, repeat, str } from "../cli/args.ts";
import { ctxLoose, dieNotSetUp, dieOnApproval, interactiveSetup, isSetUp, policyFor, runSetupDialogue } from "../cli/context.ts";
import { die, dim, info, red, warn } from "../cli/output.ts";
import { collectExtraSets } from "../cli/sets.ts";
import { findUpward, onPath, packageManagerFor } from "../cli/programs.ts";
import { leaseRun } from "./lease.ts";

/**
 * Shared by `hush run`, `hush dev` and pass-through, so all three inherit one
 * policy gate instead of each reimplementing it slightly differently.
 */
export async function runCommand(a: Args, argv: string[]): Promise<void> {
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
  if (!isSetUp(loose) && !(await runSetupDialogue(loose, a))) {
    // Declined: run it anyway, with nothing injected, and say so plainly.
    process.stderr.write(dim("hush: running without secrets\n"));
  }

  const extra = collectExtraSets(a);
  const { secrets, layers, missing, unreadable, blocked } = composeSets(loose.vault, id, loose.hushDir, extra);
  // A scoped member or CI identity in a project that also uses sets they were
  // never given: skipped, and said, so a missing variable has an explanation.
  if (unreadable.length) process.stderr.write(dim(`hush: not yours to read, skipped: ${unreadable.join(", ")}\n`));
  // A set limited to other folders: skipped, and said, for the same reason.
  for (const b of blocked) warn(`skipped ${b.name}: it is only for ${b.onlyIn.join(", ")}`);

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

  // The deny list (node, python, bash, curl, …) exists for the agent's tools,
  // where nobody typed the command. Here it becomes a warning in the approval
  // prompt rather than a refusal: the prompt is the control that holds (an
  // agent shelling out to `hush run` still has to get past a dialog it cannot
  // click), and refusing `hush node server.js` or `hush bun dev` to the person
  // who typed it is exactly the friction 1Password's `op run` and varlock do
  // not impose. An allowCommands list the person wrote still narrows.
  const riskyCommand = policy?.denyCommands.includes(basename(argv[0])) ?? false;
  if (policy) {
    checkCommand({ ...policy, denyCommands: [] }, argv[0]);
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
          ...(riskyCommand
            ? [`Note:  ${basename(argv[0])} can print or send any injected value — allow it only if you started this`]
            : []),
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

  githubMasks(loose.vault, id, secrets);

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

export async function cmdRun(a: Args): Promise<void> {
  const argv = a.rest.length ? a.rest : a._;
  // From a tailnet broker instead of a vault here (commands/lease.ts).
  if (str(a, "from")) return leaseRun(a, argv);
  return runCommand(a, argv);
}

/**
 * `hush dev` — find package.json upward from cwd, run its "dev" script (or
 * another named one) through the same path as `hush run`, with the package
 * manager its lockfile names.
 */
export async function cmdDev(a: Args): Promise<void> {
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
export async function runPassThrough(argv: string[]): Promise<void> {
  return runCommand({ _: [], rest: [], flags: {} }, argv);
}

/**
 * In GitHub Actions, have GitHub mask every injected value in the job log too,
 * on top of hush's own redaction: `::add-mask::` per line of each value (a PEM
 * is several lines, and GitHub masks line by line).
 *
 * Only for a CI identity (`hush ci create`). The mask command carries the
 * value on stdout, and on a person's own machine — where an agent could set
 * GITHUB_ACTIONS=true itself — that would print it straight into the agent's
 * transcript. A CI identity's key is only ever in the CI.
 */
function githubMasks(vault: Vault | null, id: Opener, secrets: Record<string, string>): void {
  if (process.env.GITHUB_ACTIONS !== "true" || !vault) return;
  if (!vault.data.recipients[vault.meFingerprint(id)]?.ci) return;
  const lines = new Set<string>();
  for (const v of Object.values(secrets)) {
    for (const line of v.split(/\r?\n/)) if (line.trim().length >= 3) lines.add(line);
  }
  for (const line of lines) process.stdout.write(`::add-mask::${line}\n`);
}
