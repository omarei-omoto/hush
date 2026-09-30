/**
 * `hush init` — make a vault here (or a named one with --global).
 */
import { existsSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { Vault, namedVaultPath, assertProjectHushDir } from "../vault.ts";
import { loadIdentity, createIdentity, publicKeyOf } from "../identity.ts";
import { type Args, bool, str } from "../cli/args.ts";
import { bold, cyan, die, dim, green, info } from "../cli/output.ts";
import { askAgentQuestion, ensureGitignore } from "../cli/context.ts";

export async function cmdInit(a: Args): Promise<void> {
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
