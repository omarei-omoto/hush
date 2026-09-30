/**
 * `hush team` (ls, add, rm, accept, reject) and `hush rotate`.
 */
import { dirname, basename } from "node:path";
import { spawnSync } from "node:child_process";
import { audit, safeText } from "../vault.ts";
import { requireIdentity, signerFor } from "../identity.ts";
import { safetyNumber, decodeSpk } from "../crypto.ts";
import { pendingChanges, hasProblems, acceptPending, unacceptedMembers, describeTrustProblems } from "../integrity.ts";
import { requestApproval } from "../approval.ts";
import { ageAvailable, isAgeRecipient } from "../age.ts";
import { type Args, bool, list, str } from "../cli/args.ts";
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
    if (!name || !pk) die("Usage: hush team add <name> <hush_pk_… | age1…> [--role admin] [--sets a,b] [--spk hush_spk_…]");
    if (isAgeRecipient(pk) && !ageAvailable()) {
      die("That is an age recipient, but the age binary is not installed.", "brew install age");
    }
    const vault = loose.vault ?? makeProjectVault(loose.hushDir, loose.root);
    const id = requireIdentity();
    const sets = list(a, "sets");
    const role = str(a, "role") === "admin" ? "admin" : "member";
    const wasSigned = vault.signed;
    const fp = vault.addRecipient(id, name, pk, role, { sets, spk: str(a, "spk") });
    vault.save();
    audit(loose.hushDir, { actor: "cli", action: "team.add", name, fingerprint: fp, role, sets });
    info(`${green("✓")} ${bold(name)} can now ${sets.length ? `read ${sets.join(", ")}` : "decrypt this vault"}${role === "admin" ? " (admin)" : ""}`);
    if (!wasSigned && vault.signed) info(dim(`  the vault is now signed (hush/v3): only an admin can change who can read it`));
    if (role === "admin" && !vault.data.recipients[fp]?.spk) {
      warn(`${name} has no signing key in the vault, so they cannot sign changes yet.`);
      info(dim(`  Add them with the key \`hush id\` prints on their machine (it carries both).`));
    }
    info(dim(`  commit ${loose.vaultPath} and they are in — no server, no invite email`));
    return;
  }

  const { vault, hushDir } = ctx(a);

  if (!sub || sub === "ls" || sub === "list") {
    const members = vault.members();
    // Names are free text anyone editing the file can pick; the fingerprint is
    // what this machine actually accepted.
    const unaccepted = new Set(unacceptedMembers(vault));
    info(
      `${bold(shown(vault.data.name))}  ${dim(`key generation ${vault.data.dek.generation}`)}  ` +
        (vault.signed ? green("signed") : yellow("unsigned — an admin can run hush team sign")),
    );
    const width = Math.max(...members.map((m) => m.name.length));
    for (const m of members) {
      const state = !m.canDecrypt ? red("revoked") : unaccepted.has(m.fingerprint) ? red("not accepted") : green("✓");
      const scope = m.sets ? dim(`reads ${m.sets.join(", ") || "nothing"}`) : "";
      const role = m.ci ? cyan("ci    ") : m.role === "admin" ? yellow("admin ") : dim("member");
      info(
        `  ${m.name.padEnd(width)}  ${role}  ` +
          `${dim(m.pk.slice(0, 20) + "…")}  ${m.kind === "age" ? cyan("age") : dim("key")}  ${state}  ${scope}`.trimEnd(),
      );
    }
    if (unaccepted.size) {
      info("");
      info(dim(`  not accepted = added by someone else since this machine last looked.  hush team accept`));
    }
    return;
  }

  const id = requireIdentity();

  if (sub === "sign") {
    if (vault.signed) return info(`${green("✓")} ${shown(vault.data.name)} is already signed`);
    vault.upgradeToV3(id);
    vault.save();
    audit(hushDir, { actor: "cli", action: "team.sign", vault: vault.data.id });
    info(`${green("✓")} ${bold(shown(vault.data.name))} is now signed (hush/v3)`);
    info(dim("  Only an admin can change who can read it from now on, and every member's hush checks."));
    info(dim("  Teammates need hush 0.8 or newer to open it."));
    return;
  }

  if (sub === "verify") {
    const name = a._[1];
    if (!name) die("Usage: hush team verify <name>");
    const them = Object.entries(vault.data.recipients).find(([, r]) => r.name === name);
    if (!them) die(`No member named "${name}".`);
    if (!them[1].spk) die(`${name} has no signing key in this vault, so there is nothing to compare.`);
    const mine = signerFor(id);
    if (!mine) die("This machine has no signing key to compare with.");
    const number = safetyNumber(mine.spk, decodeSpk(them[1].spk));
    info(bold(`Safety number for you and ${shown(name, 64)}:`));
    info("");
    for (let i = 0; i < 12; i += 4) info(`  ${number.split(" ").slice(i, i + 4).join("  ")}`);
    info("");
    info(dim(`  ${shown(name, 64)} runs hush team verify <you> and reads theirs out. If every digit matches, the key`));
    info(dim("  this vault lists for them really is theirs — over a call, not over the chat the key came through."));
    return;
  }

  if (sub === "accept" || sub === "reject") {
    const view = vault.reviewView(id);
    const pending = pendingChanges(view);
    if (!hasProblems(pending)) {
      info(`${green("✓")} nothing to ${sub}: this machine has already accepted this vault as it stands`);
      return;
    }
    // Everything but the closing advice, which is this command.
    const lines = describeTrustProblems(pending);
    const advice = pending.unsigned || pending.commitMismatch || pending.downgraded ? 1 : 2;
    for (const line of lines.slice(0, -advice)) info(line);
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
          ...(pending.unknownSigner ? [`Signed by an admin not seen before:  ${shown(pending.unknownSigner.name, 64)}`] : []),
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
    if (!name) die("Usage: hush team rm <name> [--from <set>,…]");
    const from = list(a, "from");
    if (from.length) {
      const { remaining, reEncrypted } = vault.removeFromSets(id, name, from);
      vault.save();
      audit(hushDir, { actor: "cli", action: "team.remove", name, from, reEncrypted });
      info(`${green("✓")} ${bold(name)} can no longer read ${from.join(", ")}${remaining.length ? `; still reads ${remaining.join(", ")}` : " — removed from the vault"}`);
      info(`  re-sealed ${reEncrypted} value(s) under new keys`);
    } else {
      const { removed, reEncrypted, exposed } = vault.removeRecipient(id, name);
      vault.save();
      audit(hushDir, { actor: "cli", action: "team.remove", name, reEncrypted, exposed });
      info(`${green("✓")} removed ${bold(removed.name)}`);
      info(`  new key generation ${vault.data.dek.generation}; re-sealed ${reEncrypted} value(s)`);
      if (exposed) info(dim(`  ${exposed} value(s) they could read are marked exposed until you replace them: hush exposed`));
    }
    info("");
    warn("They can still use any value they read before now.");
    info(dim("  Rotate those credentials at the provider (Stripe, AWS, …) — hush cannot do that for you."));
    return;
  }

  die(`Unknown: hush team ${sub}`, "Try: ls | add | rm | accept | reject | sign | verify");
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
