/**
 * `hush ci` — identities for CI (F-3).
 *
 * A CI job used to be a full member: its key opened every set in the vault. A
 * CI identity made here is a *scoped* member of just the sets it names, marked
 * as a machine: it can never be an admin, never sign a change, and removing it
 * rotates only the sets it could read.
 *
 *   hush ci create github --sets ci,staging | gh secret set HUSH_IDENTITY
 *
 * The private key is printed once and stored nowhere: piped, stdout carries the
 * key alone so it can go straight into the CI's secret store; on a terminal it
 * comes with a warning about scrollback. `--out <file>` writes it to a new
 * 0600 file instead.
 */
import { openSync, writeSync, closeSync } from "node:fs";
import { generateIdentity, encodePub, encodeSecret } from "../crypto.ts";
import { requireIdentity } from "../identity.ts";
import { audit, safeText } from "../vault.ts";
import { type Args, list, str, bool } from "../cli/args.ts";
import { ctx } from "../cli/context.ts";
import { bold, cyan, die, dim, green, info, warn } from "../cli/output.ts";

const err = (s = ""): void => void process.stderr.write(s + "\n");

export async function cmdCi(a: Args): Promise<void> {
  const sub = a._[0];
  const { vault, hushDir } = ctx(a);

  if (!sub || sub === "ls" || sub === "list") {
    const machines = vault.members().filter((m) => m.ci);
    if (!machines.length) return info(dim("No CI identities in this vault.  hush ci create <name> --sets <set>,…"));
    for (const m of machines) info(`  ${bold(m.name)}  ${dim(`reads ${m.sets?.join(", ") || "nothing"}`)}`);
    return;
  }

  const id = requireIdentity();

  if (sub === "create") {
    const name = a._[1] || "ci";
    const sets = list(a, "sets");
    if (!sets.length) die("A CI identity reads only the sets you give it.", `hush ci create ${name} --sets ci,staging`);
    const machine = generateIdentity();
    vault.addRecipient(id, name, encodePub(machine.pub), "member", { sets, ci: true });
    vault.save();
    audit(hushDir, { actor: "cli", action: "ci.create", name, sets });
    const secret = encodeSecret(machine);

    const out = str(a, "out");
    if (out) {
      // wx: never over an existing file, never through a planted link.
      const fd = openSync(out, "wx", 0o600);
      try {
        writeSync(fd, secret + "\n");
      } finally {
        closeSync(fd);
      }
      err(`${green("✓")} CI identity ${bold(name)} reads ${sets.join(", ")}; its key is in ${cyan(out)} (0600)`);
    } else if (!process.stdout.isTTY) {
      // Piped: the key alone, for `| gh secret set HUSH_IDENTITY`.
      process.stdout.write(secret + "\n");
      err(`${green("✓")} CI identity ${bold(name)} reads ${sets.join(", ")} — its key went to the pipe, and nowhere else`);
    } else {
      err(`${green("✓")} CI identity ${bold(name)} reads ${sets.join(", ")}`);
      err("");
      warn("This is the only time the key is shown. It is now in your scrollback — clear it after copying.");
      err("");
      process.stdout.write(secret + "\n");
      err("");
      err(dim("  Next time, pipe it straight into the secret store:"));
      err(dim(`    hush ci create ${name} --sets ${sets.join(",")} | gh secret set HUSH_IDENTITY`));
    }
    err("");
    err(`  Store it as ${bold("HUSH_IDENTITY")} in your CI, commit the vault, then:`);
    err(dim("    - uses: omarei-omoto/hush@v1"));
    err(dim("      with: { identity: ${{ secrets.HUSH_IDENTITY }} }"));
    err(dim("    - run: hush run -- npm test"));
    return;
  }

  if (sub === "rm" || sub === "remove") {
    const name = a._[1];
    if (!name) die("Usage: hush ci rm <name>");
    const target = Object.values(vault.data.recipients).find((r) => r.name === name);
    if (!target?.ci) die(`"${name}" is not a CI identity in this vault.`, "hush ci ls");
    if (!bool(a, "yes") && process.stdin.isTTY) warn(`Removing ${name}: every job using its key stops working at its next run.`);
    const { reEncrypted } = vault.removeRecipient(id, name);
    vault.save();
    audit(hushDir, { actor: "cli", action: "ci.remove", name, reEncrypted });
    info(`${green("✓")} removed ${bold(safeText(name, 64) ?? name)}; re-sealed ${reEncrypted} value(s) it could read`);
    return;
  }

  die(`Unknown: hush ci ${sub}`, "Try: hush ci create <name> --sets <set>,… | hush ci ls | hush ci rm <name>");
}
