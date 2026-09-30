/**
 * `hush ls` — your library, this project, and what is used (plus the old `envs` / `accounts` names).
 */
import { usedSets, librarySets, openGlobal, globalVaultName, globalVaultExists, linkNameFor } from "../library.ts";
import { type Args, bool } from "../cli/args.ts";
import { ctxLoose, isSetUp } from "../cli/context.ts";
import { bold, cyan, die, dim, green, info, out, shown, warn } from "../cli/output.ts";

/**
 * `hush ls` — the one-screen overview: your library, this project, and which
 * of the library's sets this project actually uses. Replaces `hush env`,
 * `hush envs` and `hush accounts` — a set with a "/" in its name is listed
 * like any other, because that is all it has ever been.
 */
export async function cmdLs(a: Args): Promise<void> {
  const setName = a._[0];
  const loose = ctxLoose(a);
  const project = loose.vault;
  const library = openGlobal();

  if (setName) {
    const home = project?.hasSet(setName) ? project : library?.hasSet(setName) ? library : null;
    if (!home) die(`No set called "${setName}".`);
    const meta = home.sets().find((s) => s.name === setName)!;
    if (bool(a, "json")) return out(JSON.stringify(meta, null, 2));
    info(`${bold(meta.label)} ${dim(`(${shown(meta.name)})`)}`);
    if (meta.description) info(`  ${dim(meta.description)}`);
    if (meta.whenToUse) info(`  ${dim("when: " + meta.whenToUse)}`);
    info("");
    if (!meta.keys.length) info(dim("  (no keys yet)"));
    for (const k of meta.keys) info(`  ${k}`);
    return;
  }

  const setUp = isSetUp(loose);
  const used = new Set(setUp ? usedSets(loose.hushDir) : []);
  const libSets = librarySets();

  if (bool(a, "json")) {
    return out(
      JSON.stringify(
        {
          library: libSets.map((s) => ({ ...s, used: used.has(linkNameFor("library", s.name)) })),
          project: project ? project.sets().map((s) => ({ ...s, used: used.has(s.name) })) : [],
          setUp,
        },
        null,
        2,
      ),
    );
  }

  const line = (s: { name: string; label: string; description?: string; whenToUse?: string; keys: string[] }, where: "library" | "project") => {
    // The library's default is the one set with a meaning beyond its name.
    const role = where === "library" && s.name === "default" ? dim("  — your catch-all; hush use default --library to use it in a folder") : "";
    info(
      `  ${used.has(linkNameFor(where, s.name)) ? green("●") : " "} ${bold(s.label)} ${dim(`(${shown(s.name)})`)}  ${dim(`${s.keys.length} key(s)`)}${role}`,
    );
    if (s.description) info(`      ${dim(s.description)}`);
    if (s.whenToUse) info(`      ${dim("when: " + s.whenToUse)}`);
  };

  info(bold("YOUR LIBRARY") + (globalVaultExists() ? dim(`  (${globalVaultName()})`) : ""));
  if (!globalVaultExists()) {
    info(dim(`  none yet.  hush global --create`));
  } else if (!libSets.length) {
    info(dim(`  empty.  hush add <file> --as "Name" --library`));
  } else {
    for (const s of libSets) line(s, "library");
  }

  info("");
  info(bold("THIS PROJECT"));
  if (!setUp) {
    info(dim("  not set up yet."));
    info(`  ${cyan("hush use <set>")}       pick one from your library`);
    info(`  ${cyan("hush run -- <cmd>")}    or just run something — hush will ask`);
  } else if (!project) {
    info(dim("  no vault yet — this folder uses library sets only"));
    for (const name of used) {
      const s = libSets.find((x) => x.name === name);
      if (s) line(s, "project");
    }
  } else {
    for (const s of project.sets()) line(s, "project");
  }

  info("");
  info(dim("  ● = used by this project."));
}

/** `hush envs` / `hush env` / `hush env ls` — pre-unification names for `hush ls`. */
export async function cmdEnvs(a: Args): Promise<void> {
  warn("`hush envs` / `hush env` is deprecated; use `hush ls` instead.");
  return cmdLs(a);
}

/** `hush accounts` — pre-unification name for `hush ls`. */
export async function cmdAccounts(a: Args): Promise<void> {
  warn("`hush accounts` is deprecated; use `hush ls` instead.");
  return cmdLs(a);
}
