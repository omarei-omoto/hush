/**
 * `hush global` — which vault holds your library.
 */
import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { Vault, namedVaultPath } from "../vault.ts";
import { loadIdentity, createIdentity } from "../identity.ts";
import { globalVaultName, globalVaultExists, globalVaultPath, namedVaults, saveConfig } from "../library.ts";
import { type Args, bool } from "../cli/args.ts";
import { bold, cyan, die, dim, green, info } from "../cli/output.ts";

/** `hush global` — which vault holds your library. */
export async function cmdGlobal(a: Args): Promise<void> {
  const name = a._[0];

  if (bool(a, "create")) {
    const target = name || globalVaultName();
    const path = namedVaultPath(target);
    if (existsSync(path)) die(`A vault called "${target}" already exists.`, `Adopt it with: hush global ${target}`);
    const id = loadIdentity() ?? createIdentity();
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    Vault.create(path, target, { name: "me", pub: id.pub, priv: id.priv, ageRecipient: id.age?.recipients[0] });
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
