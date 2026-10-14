/**
 * `hush env` — rename, describe and move keys between sets; make one global
 * or keep it for one project (placement.ts); file global sets into groups.
 */
import { Vault, resolveVaultPath, slugifyEnv } from "../vault.ts";
import { requireIdentity } from "../identity.ts";
import { loadLinks, saveLinks, openGlobal, globalVaultName, namedVaults, ownerOf, placeOf, sameFolder, libraryGroups, groupSlug } from "../library.ts";
import { fileUnder, keepHere, makeGlobal, renameGroup, ungroup, type Placed } from "../placement.ts";
import { consent } from "../cli/consent.ts";
import { ctxLoose } from "../cli/context.ts";
import { type Args, bool, repeat, str } from "../cli/args.ts";
import { cmdEnvs } from "../commands/ls.ts";
import { ctx, resolveSetName } from "../cli/context.ts";
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
      warn("`hush env new` is deprecated (removed in hush 2.0); use `hush add <file>` instead.");
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
      const typedName = rest[0];
      if (!typedName) {
        die(
          "Usage: hush env describe <name> [--description <text>] [--when <text>] [--label <text>] [--only-in <folder>…] [--anywhere]",
          'e.g. hush env describe "FAL MODIO" --only-in "~/code/modio-*"',
        );
      }
      // An unquoted "~/code/modio-*" is expanded by the shell into several
      // folders, and only the first would reach --only-in; the rest land here.
      if (rest.length > 1) {
        die(
          `Unexpected: ${rest.slice(1).join(" ")}`,
          'Quote a folder pattern so the shell leaves it alone: --only-in "~/code/modio-*"',
        );
      }
      const onlyIn = repeat(a, "only-in");
      if (onlyIn.length && bool(a, "anywhere")) die("--only-in and --anywhere say opposite things; pick one.");
      const { vault, save, where } = target();
      // The name as shown ("FAL MODIO") or as stored ("fal-modio"), the same
      // as --use accepts.
      const name = vault.sets().find((x) => x.label === typedName)?.name ?? resolveSetName(typedName, [vault]);
      // Only what was given: a flag left out keeps its current value.
      vault.describeEnv(name, {
        label: str(a, "label"),
        description: str(a, "description"),
        whenToUse: str(a, "when"),
        ...(onlyIn.length ? { onlyIn } : bool(a, "anywhere") ? { onlyIn: [] } : {}),
      });
      save();
      info(`${green("✓")} updated ${bold(name)} in ${where}`);
      const now = vault.envMeta(name).onlyIn;
      if (now?.length) info(dim(`  only usable in ${now.join(", ")} — hush refuses it anywhere else, for people and agents alike`));
      else if (bool(a, "anywhere")) info(dim("  usable in any folder again"));
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
      warn("`hush env use` is deprecated (removed in hush 2.0); use `hush use` instead.");
      const name = rest[0];
      if (!name) die("Usage: hush env use <name>");
      return cmdUse({ _: [name], rest: [], flags: {} });
    }

    case "drop": {
      warn("`hush env drop` is deprecated (removed in hush 2.0); use `hush use --not` instead.");
      const name = rest[0];
      if (!name) die("Usage: hush env drop <name>");
      return cmdUse({ _: [], rest: [], flags: { not: name } });
    }

    /**
     * `hush env global <set>` — one of this project's own sets becomes one of
     * your global keys; `hush env global <KEY> --from <set> --to <global set>`
     * does the same for one key. The project keeps getting it either way.
     */
    case "global": {
      const name = rest[0];
      if (!name) die("Usage: hush env global <set> [--group <name>]", "   or: hush env global <KEY> --from <set> --to <global set>");
      const loose = ctxLoose(a);
      const id = requireIdentity();
      const from = str(a, "from");
      const set = from ?? name;
      const lib = openGlobal();
      const place = placeOf(loose.hushDir);
      const owned = lib?.hasSet(set) && ownerOf(lib, set) && sameFolder(ownerOf(lib, set)!, place);
      const where = owned ? "library" : loose.vault?.hasSet(set) ? "project" : null;
      if (!where) die(`"${set}" is not one of this project's own sets.`, "hush ls shows them under THIS PROJECT");
      const to = str(a, "to");
      if (from && !to) die(`Say which global set ${name} goes into:  hush env global ${name} --from ${from} --to <global set>`);
      // An existing global set by that name, or a new one called that.
      const existing = to && lib?.hasSet(slugifyEnv(to)) && !ownerOf(lib, slugifyEnv(to)) ? slugifyEnv(to) : undefined;
      const go = (force: boolean): Placed =>
        makeGlobal({ id, hushDir: loose.hushDir, where, set, key: from ? name : undefined, to: existing, toLabel: existing ? undefined : to, group: str(a, "group"), force });
      let r = go(false);
      if ("confirm" in r) {
        const ok = await consent(`Take ${from ? name : set} out of this project's vault? ${r.confirm.teammates!.join(", ")} read it there, and a global key is yours alone.`, { hushDir: loose.hushDir, yes: bool(a, "yes") });
        if (!ok) die("Nothing was moved.");
        r = go(true);
      }
      if ("done" in r) info(`${green("✓")} ${r.done}`);
      return;
    }

    /**
     * `hush env here <set>` — one of your global sets, kept for this project
     * only: out of your global keys, refused anywhere else. `--from <set>`
     * keeps just one key of it. Other projects using it are named first.
     */
    case "here": {
      const name = rest[0];
      if (!name) die("Usage: hush env here <set>", "   or: hush env here <KEY> --from <global set>");
      const loose = ctxLoose(a);
      const id = requireIdentity();
      const from = str(a, "from");
      const go = (force: boolean): Placed => keepHere({ id, hushDir: loose.hushDir, set: from ?? name, key: from ? name : undefined, force });
      let r = go(false);
      if ("confirm" in r) {
        const who = r.confirm.projects!.map((u) => u.name + (u.viaGroup ? " (through its group)" : "")).join(", ");
        const ok = await consent(`${who} use ${name} too. Keep it for this project only, and take it from them?`, { hushDir: loose.hushDir, yes: bool(a, "yes") });
        if (!ok) die("Nothing was moved.");
        r = go(true);
      }
      if ("done" in r) info(`${green("✓")} ${r.done}`);
      return;
    }

    /**
     * `hush env group <set> <group>` files a global set under a group (a
     * folder a project can use whole); `--none` takes it out. `--rename <new>`
     * renames the group named first; `--ungroup` empties it.
     */
    case "group": {
      const [first, second] = rest;
      if (!first) {
        const groups = libraryGroups(openGlobal());
        if (!groups.length) return info(dim('No groups yet.  hush env group <set> "<group>"'));
        for (const g of groups) info(`${bold(g.label)} ${dim(`(group:${g.slug})`)}  ${g.sets.join(", ")}`);
        return;
      }
      const rename = str(a, "rename");
      if (rename !== undefined) return info(`${green("✓")} ${renameGroup(groupSlug(first), rename)}`);
      if (bool(a, "ungroup")) return info(`${green("✓")} ${ungroup(groupSlug(first))}`);
      if (!second && !bool(a, "none")) die('Usage: hush env group <set> "<group>"   (--none takes it out of its group)');
      return info(`${green("✓")} ${fileUnder(first, bool(a, "none") ? null : second)}`);
    }

    default:
      die(`Unknown: hush env ${sub}`, "Try: ls, new, rename, describe, move, global, here, group, use, drop");
  }
}
