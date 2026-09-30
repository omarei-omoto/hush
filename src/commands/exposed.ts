/**
 * `hush exposed` — values someone removed could still use (F-6).
 *
 * `hush team rm` re-keys the vault, so the removed person decrypts nothing new;
 * but whatever they already read, they have. Every value they could read is
 * marked, and stays marked until it is set again — which is what rotating it
 * at the provider and pasting in the new one does. This is the list to work
 * through, with where to go for each.
 */
import { openGlobal } from "../library.ts";
import { keyAges, describeAge, type KeyAge } from "../freshness.ts";
import { type Args, bool } from "../cli/args.ts";
import { ctxLoose } from "../cli/context.ts";
import { bold, cyan, dim, green, info, out, shown, yellow } from "../cli/output.ts";

export async function cmdExposed(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  const library = openGlobal();
  const rows: (KeyAge & { where: string })[] = [
    ...(loose.vault ? keyAges(loose.vault, null).map((k) => ({ ...k, where: "this project" })) : []),
    ...(library ? keyAges(library, null).map((k) => ({ ...k, where: "your library" })) : []),
  ].filter((k) => k.exposed.length);

  if (bool(a, "json")) return out(JSON.stringify(rows, null, 2));
  if (!rows.length) return info(`${green("✓")} nothing exposed: no value here was readable by someone who has been removed`);

  info(bold(`${rows.length} value(s) were readable by someone who has since been removed:`));
  info("");
  for (const k of rows) {
    info(`  ${bold(k.key)} ${dim(`${shown(k.set)} · ${k.where} · set ${describeAge(k.days)} ago`)}`);
    info(`    ${yellow(`readable by ${k.exposed.join(", ")}`)}`);
    info(`    ${k.rotate ? `replace it at ${cyan(k.rotate)}` : dim("replace it wherever it was issued")}`);
  }
  info("");
  info(dim("  Then store the new one — hush add KEY=value --to <set> — and it drops off this list."));
}
