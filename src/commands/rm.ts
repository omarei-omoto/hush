/**
 * `hush rm` — remove a key, or a whole set.
 */
import { audit } from "../vault.ts";
import { requireIdentity } from "../identity.ts";
import { type Args, bool, str } from "../cli/args.ts";
import { ctxLoose, pickVault } from "../cli/context.ts";
import { bold, cyan, die, dim, green, info, warn } from "../cli/output.ts";
import { confirm, promptLine } from "../cli/prompts.ts";

/**
 * `hush rm KEY [--from <set>]` removes a key; `hush rm <set>` removes a whole
 * set. A name that is both (a key in one set and the name of another) refuses
 * rather than guessing which was meant.
 */
export async function cmdRm(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  requireIdentity();
  const name = a._[0];
  if (!name) die("Usage: hush rm <KEY> [--from <set>]  |  hush rm <set> [--yes]");

  const from0 = str(a, "from");
  // The vault the named set — or the set --from names — lives in, so a library
  // set can be removed, or trimmed, from the same command as a project one.
  // With no project vault this targets the library, since that is the only
  // place a set could be.
  const { vault, where } = pickVault(loose, a, from0 ?? name);
  const isSet = vault.hasSet(name);
  const holders = vault.envNames().filter((e) => vault.has(e, name));
  const isKey = holders.length > 0;
  const wantSet = bool(a, "set");

  if (isSet && isKey && !from0 && !wantSet) {
    die(`"${name}" is both a key and a set name.`, "Say which: --from <set> for the key, or --set to remove the set.");
  }

  if (isSet && (wantSet || !isKey)) {
    const count = vault.sets().find((s) => s.name === name)?.keys.length ?? 0;
    if (!bool(a, "yes")) {
      if (process.stdin.isTTY) {
        if (!(await confirm(`Remove the whole set "${name}" and its ${count} key(s)?`))) {
          return info(dim("aborted"));
        }
      } else {
        die(`Removing a whole set needs confirmation.`, `Pass --yes: hush rm ${name} --yes`);
      }
    }
    delete vault.data.envs[name];
    if (vault.data.meta) delete vault.data.meta[name];
    vault.markStructural();
    vault.save();
    audit(loose.hushDir, { actor: "cli", action: "rm.set", set: name, where });
    info(`${green("✓")} removed set ${bold(name)}`);
    return;
  }

  let from = from0;
  if (!from) {
    if (!isKey) die(`No secret "${name}" in any set, and no set called "${name}".`);
    if (holders.length > 1) {
      if (process.stdin.isTTY) {
        const answer = await promptLine(`"${name}" is in ${holders.join(", ")} — which one? `);
        if (!holders.includes(answer)) die(`"${answer}" is not one of: ${holders.join(", ")}`);
        from = answer;
      } else {
        die(`"${name}" is in more than one set: ${holders.join(", ")}.`, `Say which: hush rm ${name} --from <set>`);
      }
    } else {
      from = holders[0];
    }
  } else if (!vault.has(from, name)) {
    die(`No secret "${name}" in "${from}".`);
  }

  vault.delete(from, name);
  vault.save();
  audit(loose.hushDir, { actor: "cli", action: "delete", env: from, key: name, where });
  info(`${green("✓")} removed ${bold(name)} from ${cyan(from)}`);
  warn("The old value is still in git history. Rotate it upstream if it was ever live.");
}
