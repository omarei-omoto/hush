/**
 * `hush use` — which sets this project uses, in order.
 */
import { usedSets, librarySets, loadLinks, saveLinks, writeProjectDotfiles, LIBRARY_DEFAULT, confirmLinks, confirmedLinks, placeOf } from "../library.ts";
import { consent } from "../cli/consent.ts";
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

  // `hush use --confirm`: let this project's committed list reach your
  // library on this machine (library.ts, confirmedLinks). It asks, on the
  // terminal or in a hush dialog, naming the sets — never on a flag alone.
  if (bool(a, "confirm")) {
    const lib = new Set(librarySets().map((s) => s.name));
    const done = confirmedLinks(loose.hushDir);
    const waiting = loadLinks(loose.hushDir).filter((l) => (l === LIBRARY_DEFAULT || lib.has(l)) && !done.has(l));
    if (!waiting.length) return info(dim("Nothing to confirm: this project uses no library set that is not confirmed here."));
    const ok = await consent(`Let this project use your library set${waiting.length > 1 ? "s" : ""} ${waiting.join(", ")}?`, {
      hushDir: loose.hushDir,
      detail: [`Project:  ${placeOf(loose.hushDir)}`, "Remembered for this project, on this machine only."],
    });
    if (!ok) die("Nothing was confirmed.");
    confirmLinks(loose.hushDir, waiting);
    return info(`${green("✓")} this project may use ${waiting.map((w) => bold(w)).join(", ")} from your library on this machine`);
  }

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
  // Naming a set yourself confirms it for this project, even one already listed.
  confirmLinks(loose.hushDir, names);
  for (const n of names) info(`${green("✓")} this project now uses ${bold(n)}`);
  info(dim("\n  recorded in .hush/envs.json — commit it so the team resolves the same sets"));
}
