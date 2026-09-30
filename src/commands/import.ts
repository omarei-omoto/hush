/**
 * `hush import` — read another tool's export (dotenv, JSON, 1Password) into a set.
 */
import { existsSync, readFileSync } from "node:fs";
import { audit, slugifyEnv } from "../vault.ts";
import { requireIdentity } from "../identity.ts";
import { parseImport, IMPORT_FORMATS, type ImportFormat } from "../import.ts";
import { globalVaultName } from "../library.ts";
import { type Args, bool, str } from "../cli/args.ts";
import { bold, die, dim, green, info, warn } from "../cli/output.ts";
import { ctxLoose, useHere } from "../cli/context.ts";
import { beginSetWrite, importInto, warnShort } from "../cli/sets.ts";

/**
 * `hush import` grew up, and its two old shapes had to go somewhere.
 *
 * It was the pre-unification name for `hush add <file>`, plus a `--env <name>`
 * shortcut that stored into an existing set with no prompt. Now that the name
 * has a real job (reading another tool's export), each old form that used to
 * work fails with the exact replacement rather than quietly doing something
 * else — a script that means one thing and gets another is the worst outcome.
 *
 * For a `.env`, `hush import <file> --as <set>` is what `hush add` already did,
 * so the migration is one flag.
 */
export async function cmdImport(a: Args): Promise<void> {
  if (a.flags.env !== undefined) {
    const file = a._[0] || ".env";
    die(
      "`hush import --env <set>` was removed: `hush import` now reads another tool's export.",
      `For what that did:  hush add ${file} --to ${String(a.flags.env)}`,
    );
  }
  return cmdImportExport(a);
}

/**
 * `hush import` — read what another tool exports and store it as a set.
 *
 * The point is the recipes, not a plugin system: every provider can already
 * export, so hush reads the shape rather than learning each vendor's API.
 */
async function cmdImportExport(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  const id = requireIdentity();

  const source = a._[0] ?? a.rest[0];
  if (!source) {
    die(
      "Usage: hush import <file|-> --as <set> [--format dotenv|json|1password]",
      "Pipe one in:  doppler secrets download --format json --no-file | hush import - --as Prod",
    );
  }
  const rawFormat = str(a, "format") ?? "dotenv";
  if (!IMPORT_FORMATS.includes(rawFormat as ImportFormat)) {
    die(`Unknown --format "${rawFormat}".`, `Known: ${IMPORT_FORMATS.join(", ")}.`);
  }
  const format = rawFormat as ImportFormat;

  let text: string;
  let where: string;
  if (source === "-") {
    // Everything piped in, as one value: an export is a document, and splitting
    // it into lines the way `hush set` does would corrupt any JSON.
    text = readFileSync(0, "utf8");
    where = "stdin";
  } else {
    if (!existsSync(source)) die(`No such file: ${source}`);
    text = readFileSync(source, "utf8");
    where = source;
  }

  const { values, notes } = parseImport(text, format, where);
  const names = Object.keys(values);
  if (!names.length) {
    // The common mistake is a JSON export read as dotenv: `{"A":"1"}` has no
    // `KEY=value` lines, so it parses to nothing and reads as an empty file.
    const looksLikeJson = text.trimStart().startsWith("{") || text.trimStart().startsWith("[");
    die(
      `Nothing to import from ${where}.`,
      format === "dotenv" && looksLikeJson
        ? "That looks like JSON — pass --format json (or --format 1password for an op item)."
        : `Is --format ${format} right for this input? Known: ${IMPORT_FORMATS.join(", ")}.`,
    );
  }

  const asLabel = str(a, "as");
  if (!asLabel) die("Give the set a name.", `hush import ${source} --as "Prod"`);
  const slug = slugifyEnv(asLabel);

  if (bool(a, "dry-run")) {
    // Before any target is resolved on purpose: a dry run must not create a
    // vault, make a library, prompt, or ask for an approval.
    const would = bool(a, "library")
      ? `your library (${globalVaultName()})`
      : loose.vault
        ? "this project"
        : "this project (a vault would be created)";
    info(bold(`${names.length} secret(s) would be stored as ${asLabel} ${dim(`(${slug})`)} in ${would}:`));
    for (const n of names) info(`  ${n}`);
    for (const n of notes) info(dim(`  note: ${n}`));
    info("");
    info(dim("Nothing was written. Drop --dry-run to store them."));
    return;
  }

  const { target, where: landed, toLibrary } = await beginSetWrite(loose, a, {
    asLabel,
    count: names.length,
    verb: "Import",
  });

  const { added, overwritten, skipped, short } = importInto(target, id, slug, values, bool(a, "overwrite"));
  // Same rule as `hush add <file>`: a second write into the same named set is
  // someone adding to it, not re-describing it, so an absent --description must
  // not blank the one a previous import set.
  const meta: Parameters<typeof target.describeEnv>[1] = { label: asLabel, source: where };
  const description = str(a, "description");
  const when = str(a, "when");
  if (description !== undefined) meta.description = description;
  if (when !== undefined) meta.whenToUse = when;
  if (!added && !overwritten) target.ensureEnvExists(slug);
  target.describeEnv(slug, meta);
  target.save();
  audit(loose.hushDir, {
    actor: "cli",
    action: "add",
    kind: "import",
    env: slug,
    as: asLabel,
    source: where,
    format,
    added,
    overwritten,
    skipped,
    where: toLibrary ? "library" : "project",
  });

  info(
    `${green("✓")} imported ${bold(String(added + overwritten))} secret(s) as ` +
      `${bold(asLabel)} ${dim(`(${slug})`)} in ${landed}`,
  );
  if (overwritten) info(dim(`  ${overwritten} replaced an existing value`));
  if (skipped) info(dim(`  ${skipped} already present (pass --overwrite to replace)`));
  warnShort(short);
  for (const n of notes) warn(n);
  useHere(loose.hushDir, slug, a);
}
