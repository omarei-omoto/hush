/**
 * `hush get` — reveal one value, behind the reveal approval.
 */
import { audit } from "../vault.ts";
import { requireIdentity } from "../identity.ts";
import { checkScopes } from "../policy.ts";
import { copyToClipboard, findClipboard, clipboardNames } from "../clipboard.ts";
import { composeSets } from "../library.ts";
import { requestApproval } from "../approval.ts";
import { type Args, bool } from "../cli/args.ts";
import { ctxLoose, dieOnApproval, policyFor } from "../cli/context.ts";
import { bold, die, dim, green, info, out, warn } from "../cli/output.ts";
import { collectExtraSets } from "../cli/sets.ts";
import { confirm } from "../cli/prompts.ts";

export async function cmdGet(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  const id = requireIdentity();
  const key = a._[0];
  if (!key) die("Usage: hush get <KEY>");

  // Resolved through the same layering `hush run`/`hush export` use — a
  // library link included — not a single literal env, so a key that only a
  // used library set provides is findable at all in a vault-less folder.
  const extra = collectExtraSets(a);
  const { secrets, layers, missing, blocked } = composeSets(loose.vault, id, loose.hushDir, extra);
  if (!Object.prototype.hasOwnProperty.call(secrets, key)) {
    die(
      `No secret "${key}" in any set this project uses.`,
      blocked.length
        ? `Skipped here, because they are only for other folders: ${blocked.map((b) => `${b.name} (${b.onlyIn.join(", ")})`).join("; ")}`
        : missing.length ? `Your library is missing: ${missing.join(", ")}` : undefined,
    );
  }

  const policy = policyFor(loose.hushDir);
  if (policy) {
    checkScopes(policy, layers);
    if (policy.requireApproval.includes("reveal")) {
      const ap = await requestApproval(loose.hushDir, {
        action: "reveal",
        summary: `Reveal ${key}`,
        scope: `reveal:${layers.join("+")}/${key}`,
        ttlSeconds: policy.approvalTtlSeconds,
        timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
        biometry: policy.biometry,
        // One-shot: a grant cannot outlive this command (approval.ts sessionGrant).
        sessionGrant: false,
      });
      // --yes only skips the scrollback warning below; it never skips policy.
      dieOnApproval(ap, `revealing ${key}`);
    }
  }

  // --copy is the same reveal with less residue: the value goes to the
  // clipboard through a pipe and is never written to stdout, so it misses the
  // scrollback, the tmux buffer, and the session recording.
  if (bool(a, "copy")) {
    const found = findClipboard();
    if (!found) {
      die(
        "No clipboard tool found.",
        `Looked for: ${clipboardNames().join(", ")}. Install one, or drop --copy to print it instead.`,
      );
    }
    if (!bool(a, "yes")) {
      warn(`This puts a live credential on the clipboard, which other applications can read (via ${found.cmd}).`);
      if (!(await confirm(`Copy ${bold(key)}?`))) return info(dim("aborted"));
    }
    const copied = copyToClipboard(secrets[key]);
    if (!copied.ok) die(`Could not copy: ${copied.reason}.`);
    audit(loose.hushDir, { actor: "cli", action: "reveal", key, layers, to: `clipboard:${copied.via}` });
    // The length, never the value: enough to know the whole thing arrived.
    info(`${green("✓")} copied ${bold(key)} to the clipboard ${dim(`(${secrets[key].length} characters)`)}`);
    return;
  }

  if (!bool(a, "yes")) {
    warn("This prints a live credential to your terminal, where it stays in scrollback.");
    if (!(await confirm(`Reveal ${bold(key)}?`))) return info(dim("aborted"));
  }
  audit(loose.hushDir, { actor: "cli", action: "reveal", key, layers });
  out(secrets[key]);
}
