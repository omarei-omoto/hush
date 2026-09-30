/**
 * `hush env` — rename, describe and move keys between sets.
 */
import { Vault, resolveVaultPath, slugifyEnv } from "../vault.ts";
import { requireIdentity } from "../identity.ts";
import { loadLinks, saveLinks, openGlobal, globalVaultName, namedVaults } from "../library.ts";
import { type Args, bool, str } from "../cli/args.ts";
import { cmdEnvs } from "../commands/ls.ts";
import { ctx } from "../cli/context.ts";
import { bold, die, dim, green, info, warn } from "../cli/output.ts";
import { cmdAddFile } from "../commands/add.ts";
import { cmdUse } from "../commands/use.ts";

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
export async function cmdEnv(a: Args): Promise<void> {
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
