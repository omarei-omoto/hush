/**
 * `hush level` and `hush secure` — rendering the ladder, and climbing it.
 *
 * The rule this file follows: every failing rung must come with a command that
 * actually performs the upgrade, not a link to a doc. A nudge you cannot act on
 * in one step is just guilt.
 */
import { existsSync, readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { Vault } from "./vault.ts";
import { assess, shouldNudge, recordNudge, snooze, type Posture } from "./posture.ts";
import { loadIdentity, migrateIdentityToKeychain, publicKeyOf } from "./identity.ts";
import { ensureHelper, biometryStatus } from "./biometry.ts";
import { ageAvailable, ageIdentityPath, identityPlugin, recipientsForIdentity } from "./age.ts";
import { parseEnvFile } from "./scan.ts";
import { DEFAULT_POLICY } from "./mcp.ts";

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = c("1");
const dim = c("2");
const red = c("31");
const green = c("32");
const yellow = c("33");
const cyan = c("36");

const out = (s = ""): void => void process.stdout.write(s + "\n");

function ask(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) return Promise.resolve(false);
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((res) =>
    rl.question(`${question} ${dim("[y/N]")} `, (a) => {
      rl.close();
      res(/^y(es)?$/i.test(a.trim()));
    }),
  );
}

const meter = (rung: number): string =>
  (useColor ? green("●".repeat(rung)) : "●".repeat(rung)) + dim("○".repeat(5 - rung));

// ------------------------------------------------------------------ display

export function renderLevel(p: Posture): void {
  out();
  out(`  ${meter(p.rung)}  ${bold(`rung ${p.rung} of 5`)} ${dim("—")} ${p.name}`);
  out();
  for (const check of p.checks) {
    const mark = check.pass ? green("✓") : dim("○");
    out(`  ${mark} ${check.pass ? check.label : dim(check.label)}`);
  }

  if (p.risk.reasons.length) {
    out();
    out(`  ${p.risk.weight >= 2 ? yellow("This vault holds:") : bold("This vault holds:")}`);
    for (const r of p.risk.reasons) out(`    ${dim("·")} ${r}`);
  }

  if (p.next) {
    out();
    out(`  ${bold("Next")} ${dim("→")} ${p.next.label}`);
    if (p.next.why) out(`    ${dim(p.next.why)}`);
    out(`    ${cyan(p.next.command ?? "hush secure")}`);
  } else {
    out();
    out(`  ${green("Top rung.")} ${dim("Your key cannot be copied off this machine.")}`);
  }
  out();
}

/** Three lines, at most, printed after a command that already produced output. */
export function renderNudge(p: Posture): void {
  if (!p.next) return;
  const urgent = p.risk.weight >= 2;
  const lead = p.risk.reasons.length
    ? `${p.risk.reasons.slice(0, 2).join(", ")}, and ${p.next.gap}`
    : p.next.gap;

  process.stderr.write("\n");
  process.stderr.write(`  ${urgent ? yellow("▲") : dim("△")} ${dim("hush")} ${meter(p.rung)} ${dim(lead)}\n`);
  process.stderr.write(
    `    ${cyan("hush secure")}  ${dim("moves you up a rung")}   ${dim("· hush level  · HUSH_NO_NUDGE=1")}\n`,
  );
  recordNudge(p);
}

/** Called by commands that already print something. Never throws, never blocks. */
export function maybeNudge(vault: Vault | null, hushDir: string | null, root: string | null): void {
  try {
    const p = assess(vault, hushDir, root);
    if (shouldNudge(p)) renderNudge(p);
  } catch {
    /* a hint is never worth failing a command over */
  }
}

// ------------------------------------------------------------------ climbing

export interface SecureCtx {
  vault: Vault | null;
  hushDir: string | null;
  root: string | null;
}

function setPolicy(hushDir: string, patch: Record<string, unknown>): void {
  const p = join(hushDir, "policy.json");
  const current = existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : {};
  writeFileSync(p, JSON.stringify({ ...current, ...patch }, null, 2) + "\n");
}

export async function runSecure(ctx: SecureCtx, want?: string): Promise<void> {
  const p = assess(ctx.vault, ctx.hushDir, ctx.root);
  const target = want
    ? p.checks.find((x) => x.id === want)
    : p.next;

  if (!target) {
    renderLevel(p);
    return;
  }
  if (target.pass) {
    out(`${green("✓")} already done: ${target.label}`);
    return renderLevel(assess(ctx.vault, ctx.hushDir, ctx.root));
  }

  out();
  out(`  ${bold("Next rung")} ${dim("→")} ${target.label}`);
  if (target.why) out(`  ${dim(target.why)}`);
  out();

  switch (target.id) {
    case "vault":
      out(`  Run ${cyan("hush init")} here first.`);
      return;

    case "no-plaintext": {
      if (!ctx.root || !ctx.vault) return;
      const stray = [".env", ".env.local", ".env.production"]
        .map((f) => join(ctx.root!, f))
        .filter(existsSync);
      if (!stray.length) return;

      for (const file of stray) {
        const names = Object.keys(parseEnvFile(readFileSync(file, "utf8")));
        out(`  ${file} holds ${names.length} variable(s): ${dim(names.slice(0, 6).join(", "))}`);
        if (!(await ask(`  Import into the vault and delete the file?`))) continue;

        const id = loadIdentity();
        if (!id) return out(red("  no identity on this machine"));
        const parsed = parseEnvFile(readFileSync(file, "utf8"));
        for (const [k, v] of Object.entries(parsed)) ctx.vault.set(id, "default", k, v);
        ctx.vault.save();
        unlinkSync(file);
        out(`  ${green("✓")} imported and removed ${file}`);
      }
      break;
    }

    case "keychain": {
      const id = loadIdentity();
      if (!id) return out(red("  no identity to migrate"));
      out(`  This moves your existing key into the macOS Keychain and deletes the file.`);
      out(`  ${dim("Your public key does not change, so you stay a member of every vault.")}`);
      out(`  ${dim(publicKeyOf(id))}`);
      if (!(await ask("  Migrate now?"))) return out(dim("  left alone"));
      const r = migrateIdentityToKeychain();
      out(r.ok ? `  ${green("✓")} ${r.message}` : `  ${red("✗")} ${r.message}`);
      break;
    }

    case "approval": {
      if (!ctx.hushDir) return out(red("  no .hush directory here"));
      setPolicy(ctx.hushDir, {
        requireApproval: DEFAULT_POLICY.requireApproval,
        approvalTtlSeconds: DEFAULT_POLICY.approvalTtlSeconds,
      });
      out(`  ${green("✓")} approval is now required to run, add, or reveal`);
      out(`  ${dim("You will see a dialog naming the command, the accounts and the variables.")}`);
      break;
    }

    case "biometry": {
      if (!ctx.hushDir) return out(red("  no .hush directory here"));
      const helper = ensureHelper();
      if (!helper.ok) return out(`  ${red("✗")} ${helper.reason}`);
      const st = biometryStatus();
      if (!st.available) return out(`  ${red("✗")} ${st.reason ?? "biometry unavailable"}`);
      setPolicy(ctx.hushDir, { biometry: "required" });
      out(`  ${green("✓")} ${st.kind} is now required to approve`);
      out(`  ${dim("If biometry ever becomes unavailable, hush refuses rather than falling back.")}`);
      break;
    }

    case "hardware": {
      out(`  ${bold("This is the rung that changes the threat model.")}`);
      out(`  ${dim("Below it, anything running as you can read the vault without asking.")}`);
      out();

      if (!ageAvailable()) {
        out(`  1. ${cyan("brew install age")}`);
        out(`  2. pick a backend:`);
        out(`       YubiKey        ${cyan("brew install age-plugin-yubikey && age-plugin-yubikey")}`);
        out(`       Secure Enclave ${cyan("brew install age-plugin-se")}`);
        out(`       TPM            ${cyan("brew install age-plugin-tpm")}`);
        out(`  3. ${cyan("hush secure --hardware")} again`);
        return;
      }

      const path = ageIdentityPath();
      if (!path) {
        out(`  age is installed, but no identity was found.`);
        out(`  Create one, then run ${cyan("hush secure --hardware")} again:`);
        out(`    YubiKey        ${cyan("age-plugin-yubikey")}`);
        out(`    Secure Enclave ${cyan("age-plugin-se keygen -o ~/.hush/age-identity.txt")}`);
        return;
      }

      const plugin = identityPlugin(path);
      if (!plugin) {
        out(`  ${yellow("!")} ${path} is a software age key, not hardware.`);
        out(`  ${dim("It would not change what an attacker running as you can do.")}`);
        out(`  Use a plugin identity instead: ${cyan("age-plugin-yubikey")} or ${cyan("age-plugin-se")}.`);
        return;
      }

      const recipients = recipientsForIdentity(path);
      if (!recipients.length) return out(`  ${red("✗")} could not read a recipient from ${path}`);
      out(`  Found a ${bold(plugin)} identity: ${dim(recipients[0])}`);

      if (!ctx.vault) return out(dim("  no vault here to add it to"));
      const id = loadIdentity();
      if (!id) return out(red("  no identity on this machine"));

      const me = ctx.vault.memberName(id);
      if (!(await ask(`  Add it to vault "${ctx.vault.data.name}" as a member?`))) return;
      ctx.vault.addRecipient(id, `${me}-hw`, recipients[0], "admin");
      ctx.vault.save();
      out(`  ${green("✓")} added as ${bold(`${me}-hw`)} — your hardware key can now decrypt`);
      out();
      out(`  ${yellow("The upgrade is not finished.")} Your software key is still a member,`);
      out(`  so the vault is only as strong as that key until you retire it:`);
      out(`    ${cyan(`hush team rm ${me}`)}`);
      out("");
      out(`  ${dim(`hush refuses that unless it can see your hardware identity — otherwise it`)}`);
      out(`  ${dim(`would be locking you out. Keep it at ${path}, or set`)}`);
      out(`  ${dim("HUSH_AGE_IDENTITY, and run the command from a shell where the key works.")}`);
      out(`  ${dim("Then commit the vault.")}`);
      break;
    }
  }

  out();
  renderLevel(assess(ctx.vault, ctx.hushDir, ctx.root));
}

export { assess, snooze };
