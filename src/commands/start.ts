/**
 * `hush start` — the guided first run.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { audit, slugifyEnv, isValidKeyName } from "../vault.ts";
import { CATALOG, knownVars } from "../services.ts";
import { loadIdentity, createIdentity } from "../identity.ts";
import { parseEnvFile } from "../scan.ts";
import { findEnvFiles, isGitignored, detectDevCommand, openingLines, keySourceChoices, importRecipe, closingLines } from "../start.ts";
import { librarySets, linkNameFor } from "../library.ts";
import { type Args } from "../cli/args.ts";
import { askAgentQuestion, ctxLoose, interactiveSetup, useHere } from "../cli/context.ts";
import { bold, cyan, die, dim, green, info, out, warn } from "../cli/output.ts";
import { packageManagerFor } from "../cli/programs.ts";
import { askLine, promptSecret } from "../cli/prompts.ts";
import { beginSetWrite, importInto, shortValueWarning, targetFor, warnShort } from "../cli/sets.ts";
import { runCommand } from "../commands/run.ts";

// ----------------------------------------------------------------- commands

/**
 * `hush start` — the guided first run.
 *
 * Everything else in this file assumes you already know what a set is and why
 * you would want one. This assumes nothing: it finds out where your keys are,
 * gets them in, asks the one question hush always asks up front, and ends by
 * naming the three commands worth knowing. The wording lives in src/start.ts so
 * it can be read and tested on its own.
 */
export async function cmdStart(a: Args): Promise<void> {
  if (!interactiveSetup()) {
    die(
      "`hush start` is a conversation, so it needs a terminal.",
      "For scripts: hush import <file> --as <name>, hush add KEY=value, hush use <name>.",
    );
  }

  const loose = ctxLoose(a);
  const root = loose.root;
  // A first run can be the very first thing on the machine, so the key that
  // makes a vault readable is created here rather than demanded.
  const id = loadIdentity() ?? createIdentity();
  const envFiles = findEnvFiles(root);
  const library = librarySets();
  const devCommand = detectDevCommand(root, packageManagerFor);

  out();
  for (const line of openingLines({ envFiles })) info(line);
  out();

  for (const choice of keySourceChoices({ envFiles, librarySetCount: library.length })) {
    info(`  ${choice.key}. ${choice.label}${choice.note ? `  ${dim(`(${choice.note})`)}` : ""}`);
  }
  const source = (await askLine(`\nWhere are your keys? ${dim("[1]")} `)) || "1";

  if (source === "2") {
    const tool = (await askLine("Which one? ")).trim();
    const label = (await askLine(`What should I call them here? ${dim("[Prod]")} `)).trim() || "Prod";
    const recipe = importRecipe(tool, label);
    out();
    info(`Run this to copy them in:`);
    out();
    info(`  ${cyan(recipe ?? `YOUR-EXPORT-COMMAND | hush import - --as "${label}"`)}`);
    out();
    info(dim("Then run `hush start` again and I'll finish up."));
    return;
  }

  if (source === "4" && library.length) {
    for (const [i, s] of library.entries()) {
      info(`  ${i + 1}. ${s.label}${s.keys.length ? dim(`  (${s.keys.length} key(s))`) : ""}`);
    }
    const chosen = library[Number((await askLine("\nWhich one? ")).trim()) - 1];
    if (!chosen) die("That was not one of the numbers above.");
    useHere(loose.hushDir, linkNameFor("library", chosen.name), a);
    info(`${green("✓")} this project now uses ${bold(chosen.label)}`);
    return finishStart(loose, a, devCommand);
  }

  const setLabel =
    (await askLine(`What should I call this group of keys? ${dim("[Production]")} `)).trim() || "Production";

  if (source === "3") {
    // One key by hand: typed into a hidden prompt, so it never appears on
    // screen and never needs pasting into a chat window.
    const thing = (await askLine("What's it for? " + dim("(e.g. stripe, openai, fal) "))).trim();
    const known = thing ? CATALOG[thing.toLowerCase()] : undefined;
    const vars = known ? knownVars(thing.toLowerCase()) : [];
    const keyName = vars.length ? vars[0] : (await askLine("What should I call the key? ")).trim().toUpperCase();
    if (!keyName || !isValidKeyName(keyName)) die("That is not a usable key name.", "Try something like STRIPE_KEY.");

    const value = await promptSecret(`  ${keyName}`, true);
    if (!value) die("Nothing entered, nothing changed.");
    const slug = slugifyEnv(setLabel);
    const { target, where } = await beginSetWrite(loose, a, {
      asLabel: setLabel,
      count: 1,
      verb: "Add set",
      target: targetFor(a),
    });
    importInto(target, id, slug, { [keyName]: value }, false);
    target.describeEnv(slug, { label: setLabel });
    target.save();
    const warning = shortValueWarning(keyName, value);
    if (warning) warn(warning);
    out();
    info(`${green("✓")} stored ${bold(keyName)} as ${bold(setLabel)} in ${where}`);
    useHere(loose.hushDir, slug, a);
    return finishStart(loose, a, devCommand);
  }

  // 1: from a file in this folder. The common case, and the one worth getting
  // exactly right.
  let file = envFiles[0];
  if (!file) {
    file = (await askLine(`What's the file called? ${dim("[.env]")} `)).trim() || ".env";
    if (!existsSync(join(root, file))) {
      die(
        `I can't find ${file} in this folder.`,
        "Put your keys in a file and run `hush start` again, or pick another answer.",
      );
    }
  }

  const parsed = parseEnvFile(readFileSync(join(root, file), "utf8"));
  const names = Object.keys(parsed);
  if (!names.length) die(`I didn't find any KEY=value lines in ${file}.`);

  const slug = slugifyEnv(setLabel);
  const { target, where } = await beginSetWrite(loose, a, {
    asLabel: setLabel,
    count: names.length,
    verb: "Add set",
    target: targetFor(a),
  });
  const { added, short } = importInto(target, id, slug, parsed, false);
  target.describeEnv(slug, { label: setLabel, source: file });
  target.save();
  audit(loose.hushDir, { actor: "cli", action: "add", kind: "start", env: slug, file, added, where });

  out();
  info(`${green("✓")} stored ${bold(String(added))} key(s) as ${bold(setLabel)} in ${where}`);
  warnShort(short);
  // The plaintext file is the one thing that undoes the work, so say what to do
  // about it once, plainly. Never delete it for them.
  if (isGitignored(root, file)) {
    info(dim(`  ${file} is already gitignored, so it cannot be committed.`));
    info(dim("  You can delete it now: hush has everything it needs."));
  } else {
    warn(`${file} is not in .gitignore, so it could be committed by accident.`);
    info(dim(`  Add it, then delete ${file}. hush has everything it needs.`));
  }
  useHere(loose.hushDir, slug, a);
  return finishStart(loose, a, devCommand);
}

/**
 * The tail of the guided run: the one question hush always asks up front, an
 * offer to run the thing, and the commands worth knowing.
 */
async function finishStart(
  loose: ReturnType<typeof ctxLoose>,
  a: Args,
  devCommand: { pm: string; script: string } | null,
): Promise<void> {
  out();
  await askAgentQuestion(loose.hushDir, a);

  if (devCommand) {
    const run = await askLine(`\nWant to run it now? ${dim(`(${devCommand.pm} run ${devCommand.script}) [y/N]`)} `);
    if (/^y/i.test(run.trim())) {
      // quiet: the "using <sets>" line has already been said in plain words.
      await runCommand({ _: [], rest: [], flags: { ...a.flags, quiet: true } }, [
        devCommand.pm,
        "run",
        devCommand.script,
      ]);
      return;
    }
  }

  for (const line of closingLines({ devCommand })) info(line);
}
