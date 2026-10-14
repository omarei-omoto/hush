/**
 * `hush use` — which sets this project uses, in order.
 */
import { parseKeyLink, parseGroupLink, usedSets, librarySets, loadLinks, saveLinks, writeProjectDotfiles, LIBRARY_DEFAULT, confirmLinks, confirmedLinks, placeOf, libraryGroups, openGlobal, groupSlug, GROUP_PREFIX } from "../library.ts";
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
    // Whole library sets, groups of them, and single keys taken from one (set#KEY).
    const inLibrary = (l: string) => {
      if (parseGroupLink(l) !== null) return true;
      const pick = parseKeyLink(l);
      const set = pick ? pick.set : l;
      return set === LIBRARY_DEFAULT || lib.has(set);
    };
    const waiting = loadLinks(loose.hushDir).filter((l) => inLibrary(l) && !done.has(l));
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
    const groups = libraryGroups(openGlobal());
    for (const name of used) {
      const group = parseGroupLink(name);
      const own = library.find((s) => s.name === name)?.project;
      const source = group !== null
        ? groups.some((g) => g.slug === group) ? "group of global sets" : "missing"
        : name === LIBRARY_DEFAULT
          ? library.some((s) => s.name === "default") ? "library" : "missing"
          : loose.vault?.hasSet(name) ? "project" : own ? "only this project" : library.some((s) => s.name === name) ? "library" : "missing";
      info(`  ${name.padEnd(width)}  ${dim(source)}`);
    }
    return;
  }

  const library = librarySets();
  const groups = libraryGroups(openGlobal());
  // `default` is this project's own; the library's is `default --library`
  // (recorded as library:default), since nothing from the library reaches a
  // folder until the folder asks for it. A name that is no set but is a
  // group of global sets ("AI stack", or group:ai-stack) means the group.
  const names = a._.map(convertLegacyPin).map((n) => {
    if (n === "default" && (bool(a, "library") || !loose.vault?.hasSet("default")) && library.some((s) => s.name === "default")) return LIBRARY_DEFAULT;
    if (loose.vault?.hasSet(n) || library.some((s) => s.name === n)) return n;
    const slug = parseGroupLink(n) ?? groupSlug(n);
    return groups.some((g) => g.slug === slug) ? GROUP_PREFIX + slug : n;
  });
  const unknown = names.filter(
    (n) =>
      !loose.vault?.hasSet(n) &&
      !groups.some((g) => g.link === n) &&
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
  for (const n of names) {
    const g = groups.find((x) => x.link === n);
    info(`${green("✓")} this project now uses ${bold(g ? g.label : n)}${g ? dim(` — every set in the group (${g.sets.join(", ")})`) : ""}`);
  }
  info(dim("\n  recorded in .hush/envs.json — commit it so the team resolves the same sets"));
}
