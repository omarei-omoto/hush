/**
 * `hush scan` — which variables the code reads, and which of them the vault provides.
 */
import { resolve as resolvePath } from "node:path";
import { scanTree, reconcile } from "../scan.ts";
import { usedSets, librarySets } from "../library.ts";
import { type Args, bool } from "../cli/args.ts";
import { ctxLoose } from "../cli/context.ts";
import { collectExtraSets } from "../cli/sets.ts";
import { bold, cyan, dim, green, info, out, red } from "../cli/output.ts";

export async function cmdScan(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  const target = a._[0] ? resolvePath(a._[0]) : loose.root;
  const { usages, truncated } = scanTree(target);

  // Reconciled against every set this project actually uses — a library link
  // included, project winning over library on a shared name, same as
  // composeSets() — not just the literal keys of one named env. Checking only
  // `vault.list(env)` reported a key as missing even when a used library set
  // already provided it.
  const extra = collectExtraSets(a);
  const names = [...new Set([...usedSets(loose.hushDir), ...extra])];
  const keysOf = new Map<string, string[]>();
  for (const s of librarySets()) keysOf.set(s.name, s.keys);
  for (const s of loose.vault?.sets() ?? []) keysOf.set(s.name, s.keys);
  const vaultKeys = [...new Set(names.flatMap((n) => keysOf.get(n) ?? []))];

  const r = reconcile(usages, vaultKeys);

  if (bool(a, "json")) return out(JSON.stringify({ ...r, truncated }, null, 2));

  info(`${bold("scan")} ${dim(target)}  ${dim("against")} ${cyan(names.join(", ") || "(nothing used)")}`);
  info("");
  if (truncated) {
    info(`  ${red("!")} stopped early: this folder is too big to read in full, so the counts below are partial.`);
    info(dim(`    Run hush scan inside the project, or give it the project's path.`));
  }
  info(`  ${green("✓")} ${r.satisfied.length} satisfied by the vault`);
  info(`  ${r.missing.length ? red("✗") : green("✓")} ${r.missing.length} missing`);
  if (r.unused.length) info(`  ${dim("·")} ${r.unused.length} in vault but unreferenced`);

  if (r.missing.length) {
    info("");
    info(bold("Missing:"));
    const width = Math.max(...r.missing.map((m) => m.name.length));
    for (const m of r.missing) {
      info(`  ${red(m.name.padEnd(width))}  ${dim(m.sites.slice(0, 3).join(", "))}`);
    }
    info("");
    info(dim(`  add them:  hush add <KEY> --to <set>`));
  }
  if (r.unused.length && bool(a, "verbose")) {
    info("");
    info(dim(`Unreferenced: ${r.unused.join(", ")}`));
  }
}
