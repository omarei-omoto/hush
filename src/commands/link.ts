/**
 * `hush link` — point this project at a vault that lives elsewhere.
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join, resolve as resolvePath } from "node:path";
import { namedVaultPath, type LinkFile } from "../vault.ts";
import { type Args, str } from "../cli/args.ts";
import { bold, cyan, die, dim, green, info } from "../cli/output.ts";
import { ensureGitignore } from "../cli/context.ts";

export async function cmdLink(a: Args): Promise<void> {
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
