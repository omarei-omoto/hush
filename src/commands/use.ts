/**
 * `hush use` — which sets this project uses, in order.
 */
import { usedSets, librarySets, loadLinks, saveLinks, writeProjectDotfiles, LIBRARY_DEFAULT } from "../library.ts";
import { type Args, bool, list } from "../cli/args.ts";
import { ctxLoose, dieNotSetUp, interactiveSetup, isSetUp, runSetupDialogue } from "../cli/context.ts";
import { convertLegacyPin } from "../cli/sets.ts";
import { bold, cyan, die, dim, green, info } from "../cli/output.ts";

/**
 * `hush use <set> [<set>…]` — this project uses these, appended to
 * `.hush/envs.json`. `hush use` alone lists what is used, in resolution
 * order, with where each comes from. `hush use --not <set>` stops using it.
 */
export async function cmdUse(a: Args): Promise<void> {
  const loose = ctxLoose(a);

  const notSpecs = list(a, "not").map(convertLegacyPin);
  if (notSpecs.length) {
    saveLinks(loose.hushDir, loadLinks(loose.hushDir).filter((l) => !notSpecs.includes(l)));
    for (const n of notSpecs) info(`${green("✓")} this project no longer uses ${bold(n)}`);
    return;
  }

  if (!a._.length) {
    // No arguments in a folder nobody has set up yet is exactly the moment
    // the dialogue exists for — the same one `hush run` falls into, minus
    // actually running anything afterward.
    if (!isSetUp(loose)) {
      if (!interactiveSetup()) dieNotSetUp();
      await runSetupDialogue(loose, a);
      return;
    }
    const used = usedSets(loose.hushDir);
    const library = librarySets();
    if (!used.length) {
      info(dim("This project uses nothing yet."));
      info(`  ${cyan("hush use <set> [<set>…]")}`);
      return;
    }
    info(bold("This project uses:") + dim("  (in resolution order — later wins)"));
    const width = Math.max(...used.map((n) => n.length));
    for (const name of used) {
      const source = name === LIBRARY_DEFAULT
        ? library.some((s) => s.name === "default") ? "library" : "missing"
        : loose.vault?.hasSet(name) ? "project" : library.some((s) => s.name === name) ? "library" : "missing";
      info(`  ${name.padEnd(width)}  ${dim(source)}`);
    }
    return;
  }

  const library = librarySets();
  // `default` is this project's own; the library's is `default --library`
  // (recorded as library:default), since nothing from the library reaches a
  // folder until the folder asks for it.
  const names = a._.map(convertLegacyPin).map((n) =>
    n === "default" && (bool(a, "library") || !loose.vault?.hasSet("default")) && library.some((s) => s.name === "default")
      ? LIBRARY_DEFAULT
      : n,
  );
  const unknown = names.filter(
    (n) =>
      !loose.vault?.hasSet(n) &&
      !library.some((s) => s.name === n || (n === LIBRARY_DEFAULT && s.name === "default")),
  );
  if (unknown.length) {
    const known = [...new Set([...(loose.vault ? loose.vault.envNames() : []), ...library.map((s) => s.name)])];
    die(`No set called "${unknown[0]}".`, `you have: ${known.length ? known.join(", ") : "none yet"}`);
  }

  // A folder with no `.hush` at all yet gets one here — this is one of the
  // two ways in, alongside the setup dialogue above.
  writeProjectDotfiles(loose.hushDir);
  saveLinks(loose.hushDir, [...loadLinks(loose.hushDir), ...names]);
  for (const n of names) info(`${green("✓")} this project now uses ${bold(n)}`);
  info(dim("\n  recorded in .hush/envs.json — commit it so the team resolves the same sets"));
}
