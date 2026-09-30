/**
 * `hush team` (ls, add, rm, accept, reject) and `hush rotate`.
 */
import { dirname, basename } from "node:path";
import { spawnSync } from "node:child_process";
import { audit, safeText } from "../vault.ts";
import { requireIdentity } from "../identity.ts";
import { pendingChanges, hasProblems, acceptPending, unacceptedMembers, describeTrustProblems } from "../integrity.ts";
import { requestApproval } from "../approval.ts";
import { ageAvailable, isAgeRecipient } from "../age.ts";
import { type Args, bool, str } from "../cli/args.ts";
import { ctx, ctxLoose, dieOnApproval, makeProjectVault, policyFor } from "../cli/context.ts";
import { bold, cyan, die, dim, green, info, red, shown, warn, yellow } from "../cli/output.ts";
import { confirm } from "../cli/prompts.ts";
import { onPath } from "../cli/programs.ts";

export async function cmdTeam(a: Args): Promise<void> {
  const sub = a._[0];

  // `team add` is the other door into a vault, alongside `--project`: a
  // folder that has only ever used library sets gets one the moment someone
  // needs to share it, exactly like `hush add K=v --project` does. Every
  // other subcommand needs a vault that already exists, so those stay on the
  // strict ctx() below, unchanged.
  if (sub === "add") {
    const loose = ctxLoose(a);
    const [name, pk] = [a._[1], a._[2]];
    if (!name || !pk) die("Usage: hush team add <name> <hush_pk_… | age1…>");
    if (isAgeRecipient(pk) && !ageAvailable()) {
      die("That is an age recipient, but the age binary is not installed.", "brew install age");
    }
    const vault = loose.vault ?? makeProjectVault(loose.hushDir, loose.root);
    const id = requireIdentity();
    const fp = vault.addRecipient(id, name, pk, str(a, "role") === "admin" ? "admin" : "member");
    vault.save();
    audit(loose.hushDir, { actor: "cli", action: "team.add", name, fingerprint: fp });
    info(`${green("✓")} ${bold(name)} can now decrypt this vault`);
    info(dim(`  commit ${loose.vaultPath} and they are in — no server, no invite email`));
    return;
  }

  const { vault, hushDir } = ctx(a);

  if (!sub || sub === "ls" || sub === "list") {
    const members = vault.members();
    // Names are free text anyone editing the file can pick; the fingerprint is
    // what this machine actually accepted.
    const unaccepted = new Set(unacceptedMembers(vault));
    info(`${bold(shown(vault.data.name))}  ${dim(`DEK generation ${vault.data.dek.generation}`)}`);
    const width = Math.max(...members.map((m) => m.name.length));
    for (const m of members) {
      const state = !m.canDecrypt ? red("revoked") : unaccepted.has(m.fingerprint) ? red("not accepted") : green("✓");
      info(
        `  ${m.name.padEnd(width)}  ${m.role === "admin" ? yellow("admin ") : dim("member")}  ` +
          `${dim(m.pk.slice(0, 20) + "…")}  ${m.kind === "age" ? cyan("age") : dim("key")}  ${state}`,
      );
    }
    if (unaccepted.size) {
      info("");
      info(dim(`  not accepted = added by someone else since this machine last looked.  hush team accept`));
    }
    return;
  }

  const id = requireIdentity();

  if (sub === "accept" || sub === "reject") {
    const view = vault.trustView(vault.dekForReview(id));
    const pending = pendingChanges(view);
    if (!hasProblems(pending)) {
      info(`${green("✓")} nothing to ${sub}: this machine has already accepted this vault as it stands`);
      return;
    }
    // Everything but the closing "if you expected this" pair, which is this command.
    for (const line of describeTrustProblems(pending).slice(0, -2)) info(line);
    const provenance = lastVaultCommit(vault.path);
    if (provenance) info(dim(`  last change to the vault file: ${provenance}`));
    info("");

    if (sub === "reject") {
      info("Nothing was accepted. To undo the change, restore the vault from before it and commit that:");
      info(`  ${cyan(`git log --oneline -- ${vault.path}`)}        find the commit before it`);
      info(`  ${cyan(`git checkout <commit> -- ${vault.path}`)}`);
      info(dim("  Then treat anything added to the vault since as exposed, and rotate it at the provider."));
      return;
    }

    // Accepting is a person's decision about who can read what is added from
    // now on. An agent with a shell can type `hush team accept --yes`; with a
    // policy in place it meets the same dialog every other gated action does.
    const policy = policyFor(hushDir);
    if (policy && policy.requireApproval.length) {
      const ap = await requestApproval(hushDir, {
        action: "trust",
        summary: `Accept changes to vault "${shown(vault.data.name)}"`,
        detail: [
          ...pending.added.map((m) => `New member:  ${shown(m.name, 64)}  (${m.fingerprint})`),
          ...(pending.replaced ? [`Replaced:  ${pending.replaced.was} → ${pending.vaultId}`] : []),
          ...(pending.keyChanged ? [`Data key changed for generation ${pending.keyChanged.generation}`] : []),
        ],
        scope: `trust:${pending.vaultId}:${pending.commit}`,
        ttlSeconds: policy.approvalTtlSeconds,
        timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
        biometry: policy.biometry,
        sessionGrant: false,
      });
      dieOnApproval(ap, "accepting the vault change");
    } else if (!bool(a, "yes")) {
      if (!process.stdin.isTTY) {
        die("Accepting a change to who can read this vault needs a person.", "Run it in a terminal, or pass --yes.");
      }
      if (!(await confirm("Have you checked this with whoever made the change? Accept it"))) return info(dim("nothing accepted"));
    }
    acceptPending(view, pending);
    audit(hushDir, {
      actor: "cli",
      action: "team.accept",
      vault: pending.vaultId,
      generation: pending.generation,
      added: pending.added.map((m) => m.fingerprint),
      replaced: Boolean(pending.replaced),
      keyChanged: Boolean(pending.keyChanged),
    });
    info(`${green("✓")} accepted${pending.added.length ? `: ${pending.added.map((m) => shown(m.name, 64)).join(", ")}` : ""}`);
    return;
  }

  if (sub === "rm" || sub === "remove") {
    const name = a._[1];
    if (!name) die("Usage: hush team rm <name>");
    const { removed, reEncrypted } = vault.removeRecipient(id, name);
    vault.save();
    audit(hushDir, { actor: "cli", action: "team.remove", name, reEncrypted });
    info(`${green("✓")} removed ${bold(removed.name)}`);
    info(`  new DEK generation ${vault.data.dek.generation}; re-sealed ${reEncrypted} value(s)`);
    info("");
    warn("They can still use any value they read before now.");
    info(dim("  Rotate those credentials at the provider (Stripe, AWS, …) — hush cannot do that for you."));
    return;
  }

  die(`Unknown: hush team ${sub}`, "Try: ls | add | rm | accept | reject");
}

/**
 * Who last touched the vault file, per git — shown next to a change someone
 * has to accept, so "who added this member?" has an answer to check against.
 * Best effort: no git, no repository, or an untracked file just means no line.
 */
function lastVaultCommit(vaultPath: string): string | null {
  const git = onPath("git");
  if (!git) return null;
  try {
    const r = spawnSync(git, ["log", "-1", "--format=%h by %an, %ar", "--", basename(vaultPath)], {
      cwd: dirname(vaultPath),
      encoding: "utf8",
      timeout: 5000,
      stdio: ["ignore", "pipe", "ignore"],
    });
    const line = (r.stdout ?? "").trim();
    return r.status === 0 && line ? safeText(line, 120) ?? null : null;
  } catch {
    return null;
  }
}

export async function cmdRotate(a: Args): Promise<void> {
  const { vault, hushDir } = ctx(a);
  const id = requireIdentity();
  const n = vault.rotate(id);
  vault.save();
  audit(hushDir, { actor: "cli", action: "rotate", generation: vault.data.dek.generation });
  info(`${green("✓")} rotated to DEK generation ${vault.data.dek.generation}, re-sealed ${n} value(s)`);
  info(dim("  This rotates the vault key, not your provider credentials."));
}
