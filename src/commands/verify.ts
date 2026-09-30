/**
 * `hush verify` — does everything decrypt, and is this still the vault you accepted?
 */
import { audit } from "../vault.ts";
import { requireIdentity } from "../identity.ts";
import { inspect, acceptCurrent, pendingChanges, hasProblems, describeTrustProblems } from "../integrity.ts";
import { type Args, bool } from "../cli/args.ts";
import { ctx } from "../cli/context.ts";
import { dim, green, info, red, yellow } from "../cli/output.ts";

/** `hush verify` — can everything still be decrypted, and is the vault fresh? */
export async function cmdVerify(a: Args): Promise<void> {
  const { vault, hushDir } = ctx(a);
  const id = requireIdentity();

  if (bool(a, "accept")) {
    acceptCurrent(vault);
    info(`${green("✓")} accepted the current state as the newest you have seen`);
    info(dim(`  generation ${vault.data.dek.generation}, ${vault.members().length} member(s)`));
    return;
  }

  const stale = inspect(vault);
  info(`${stale ? red("✗") : green("✓")} freshness  ${dim(stale ? `rolled back to generation ${stale.nowGeneration}` : `generation ${vault.data.dek.generation}`)}`);

  // Every check below this one is about the vault as it stands. This one is
  // about whether it is the vault this machine accepted at all: a vault rebuilt
  // by a non-member decrypts perfectly and passes every other line (V-1).
  const pending = pendingChanges(vault.trustView(vault.dekForReview(id)));
  const untrusted = hasProblems(pending);
  if (untrusted) {
    info(`${red("✗")} trust  ${dim("this vault changed in a way nobody on this machine accepted")}`);
    for (const line of describeTrustProblems(pending)) info(`    ${line.trim() ? red(line.trim()) : ""}`);
  } else {
    info(
      `${green("✓")} trust  ` +
        dim(pending.firstUse ? "first look from this machine — members and key pinned from now on" : "members and data key are the ones this machine accepted"),
    );
  }

  let ok = 0;
  const broken: string[] = [];
  for (const scope of untrusted ? [] : vault.envNames()) {
    for (const { key } of vault.list(scope)) {
      try {
        vault.get(id, scope, key);
        ok++;
      } catch (e) {
        broken.push(`${scope}/${key}: ${(e as Error).message.split("\n")[0]}`);
      }
    }
  }
  if (untrusted) info(`${red("✗")} decryption  ${dim("not attempted until the change above is accepted or undone")}`);
  else info(`${broken.length ? red("✗") : green("✓")} decryption  ${dim(`${ok} value(s) readable`)}`);
  for (const b of broken) info(`    ${red(b)}`);

  const orphaned = Object.keys(vault.data.recipients).filter((fp) => !vault.data.dek.wraps[fp]);
  info(`${orphaned.length ? yellow("!") : green("✓")} members  ${dim(`${vault.members().length} listed, ${orphaned.length} without a key wrap`)}`);

  // The other direction, and the one that matters: a key wrap nobody is listed
  // for opens every secret here while `hush team ls` shows no such member.
  const unlisted = vault.unlistedWraps();
  info(
    `${unlisted.length ? red("✗") : green("✓")} wraps  ` +
      dim(
        unlisted.length
          ? `${unlisted.length} key wrap(s) belong to no listed member — someone can decrypt this vault invisibly`
          : "every key wrap belongs to a listed member",
      ),
  );
  for (const fp of unlisted.slice(0, 10)) info(`    ${red(fp)}`);
  if (unlisted.length) info(`    ${dim("rotate to cut them out:")} hush rotate`);

  // A value left on an older generation means a rotation did not finish, so a
  // revoked member's old key still opens it. Worth failing the command over.
  const behind = vault.staleValues();
  info(
    `${behind.length ? red("✗") : green("✓")} re-seal  ` +
      dim(
        behind.length
          ? `${behind.length} value(s) still sealed under an older key — rotation did not complete`
          : `every value is on generation ${vault.data.dek.generation}`,
      ),
  );
  for (const b of behind.slice(0, 10)) info(`    ${red(`${b.env}/${b.key}`)} ${dim(`generation ${b.gen}`)}`);
  if (behind.length) info(`    ${dim("fix with:")} hush rotate`);

  audit(hushDir, {
    actor: "cli",
    action: "verify",
    ok,
    broken: broken.length,
    stale: Boolean(stale),
    behind: behind.length,
    unlisted: unlisted.length,
    untrusted,
  });
  if (broken.length || stale || behind.length || unlisted.length || untrusted) process.exitCode = 1;
}
