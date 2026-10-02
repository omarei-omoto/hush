#!/usr/bin/env node
/**
 * hush — envelope-encrypted team secrets your agent can use but never read.
 */
import { existsSync } from "node:fs";
import { join, resolve as resolvePath } from "node:path";
import { resolveVaultPath, namedVaultPath, setTrustHook, withoutControls } from "./vault.ts";
import { serveMcp } from "./mcp.ts";
import { serveUi } from "./ui.ts";
import { VERSION } from "./version.ts";
import { verifyTrust, recordTrusted, isTrustError } from "./integrity.ts";
import { type Args, bool, parseArgs, str } from "./cli/args.ts";
import { cmdInit } from "./commands/init.ts";
import { cmdId } from "./commands/id.ts";
import { cmdAdd, cmdSet } from "./commands/add.ts";
import { cmdStart } from "./commands/start.ts";
import { cmdImport } from "./commands/import.ts";
import { cmdAccounts, cmdEnvs, cmdLs } from "./commands/ls.ts";
import { cmdUse } from "./commands/use.ts";
import { cmdGet } from "./commands/get.ts";
import { cmdRm } from "./commands/rm.ts";
import { cmdExport } from "./commands/export.ts";
import { cmdDev, cmdRun, runPassThrough } from "./commands/run.ts";
import { cmdRequest } from "./commands/request.ts";
import { cmdScan } from "./commands/scan.ts";
import { cmdRotate, cmdTeam } from "./commands/team.ts";
import { cmdLink } from "./commands/link.ts";
import { cmdEnv } from "./commands/env.ts";
import { cmdGlobal } from "./commands/global.ts";
import { cmdInstallMcp, cmdInstallSkill } from "./commands/agents.ts";
import { cmdBiometry, cmdLevel, cmdSecure } from "./commands/secure.ts";
import { cmdVerify } from "./commands/verify.ts";
import { cmdAudit } from "./commands/audit.ts";
import { cmdAge } from "./commands/age.ts";
import { cmdHook, cmdRoot } from "./commands/hook.ts";
import { cmdDoctor } from "./commands/doctor.ts";
import { cmdMerge, cmdMergeDriver } from "./commands/merge.ts";
import { cmdCi } from "./commands/ci.ts";
import { cmdExposed } from "./commands/exposed.ts";
import { cmdApprovals, cmdRelay } from "./commands/approvals.ts";
import { cmdServe } from "./commands/serve.ts";
import { bold, cyan, die, dim, out, red } from "./cli/output.ts";
import { FULL_HELP, SHORT_HELP } from "./cli/help.ts";
import { onPath } from "./cli/programs.ts";

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
  audit: cmdAudit,
  secure: cmdSecure,
  age: cmdAge,
  hook: cmdHook,
  root: cmdRoot,
  doctor: cmdDoctor,
  merge: cmdMerge,
  ci: cmdCi,
  exposed: cmdExposed,
  approvals: cmdApprovals,
  relay: cmdRelay,
  serve: cmdServe,
  "merge-driver": cmdMergeDriver,
};

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const command = argv[0];

  // Every decryption this process makes — the CLI, `hush mcp`, `hush ui` —
  // first checks the vault is one a person on this machine accepted (V-1).
  setTrustHook({
    verify: (view) => {
      for (const n of verifyTrust(view)) process.stderr.write(dim(`hush: ${n}\n`));
    },
    record: (view) => recordTrusted(view),
  });

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
  if (isTrustError(e)) {
    // Several lines, and the last two are the way out: printed as a block
    // rather than one red paragraph.
    const [first, ...rest] = withoutControls(e.message).split("\n");
    process.stderr.write(red(`✗ ${first}`) + "\n");
    for (const line of rest) process.stderr.write(`${line}\n`);
    process.exit(1);
  }
  die(e instanceof Error ? e.message : String(e));
});
