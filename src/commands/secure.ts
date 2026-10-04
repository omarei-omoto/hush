/**
 * `hush level`, `hush secure` and `hush biometry` — the security ladder.
 */
import { existsSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { Vault, resolveVaultPath } from "../vault.ts";
import { hushHome } from "../identity.ts";
import { loadPolicy } from "../mcp.ts";
import { setLocalApprovals } from "../policy.ts";
import { consent } from "../cli/consent.ts";
import { assess } from "../posture.ts";
import { renderLevel, runSecure, snooze, parseDuration } from "../secure.ts";
import { biometryStatus, ensureHelper, authenticate } from "../biometry.ts";
import { type Args, bool, str } from "../cli/args.ts";
import { bold, die, dim, green, info, out, red } from "../cli/output.ts";

/** `hush level` — where you are on the security ladder, and what is next. */
export async function cmdLevel(a: Args): Promise<void> {
  const loc = resolveVaultPath(process.cwd());
  const vault = loc && existsSync(loc.vaultPath) ? Vault.open(loc.vaultPath) : null;
  const root = loc ? loc.hushDir.replace(/[/\\]\.hush$/, "") : null;
  const p = assess(vault, loc?.hushDir ?? null, root);
  if (bool(a, "json")) return out(JSON.stringify(p, null, 2));
  renderLevel(p);
}

/** `hush secure` — actually climb the next rung. */
export async function cmdSecure(a: Args): Promise<void> {
  if (str(a, "snooze")) {
    const days = Number(str(a, "snooze")) || 7;
    snooze(days);
    return info(dim(`reminders paused for ${days} day(s)`));
  }
  const loc = resolveVaultPath(process.cwd());
  const vault = loc && existsSync(loc.vaultPath) ? Vault.open(loc.vaultPath) : null;
  const root = loc ? loc.hushDir.replace(/[/\\]\.hush$/, "") : null;

  const explicit = ["biometry", "hardware", "approval", "keychain", "no-plaintext", "floor"]
    .find((id) => bool(a, id)) ?? a._[0];

  // Turning approvals off is this machine's choice for this project, kept in
  // ~/.hush — a repository's policy.json can add approvals, never remove them.
  // A person says so: on the terminal, or in a dialog an agent cannot answer.
  if (explicit === "approval" && bool(a, "off")) {
    if (!loc) die("No hush project here.", "Run it inside the project to stop asking in.");
    const ok = await consent(`Stop asking before hush uses a key in ${root}? (this machine only)`, {
      hushDir: loc.hushDir,
      detail: ["Runs, adds, reveals and requests here will no longer ask first."],
    });
    if (!ok) die("Nothing changed.");
    setLocalApprovals(hushHome(), loc.hushDir, []);
    const still = loadPolicy(loc.hushDir).requireApproval;
    info(`${green("✓")} approvals off for this project, on this machine`);
    if (still.length) info(dim(`  this project's policy.json still asks for: ${still.join(", ")}`));
    info(dim("  Turn them back on: hush secure approval"));
    return;
  }
  // `--for 30m` sets how long an "Allow" lasts, which is also how someone with
  // approvals already on asks for a longer window.
  const forRaw = str(a, "for");
  let ttlSeconds: number | undefined;
  if (forRaw !== undefined) {
    try {
      ttlSeconds = parseDuration(forRaw);
    } catch (e) {
      die((e as Error).message);
    }
  }
  await runSecure({ vault, hushDir: loc?.hushDir ?? null, root }, explicit, ttlSeconds);
}

/** `hush biometry` — set up, check, or try the Touch ID gate. */
export async function cmdBiometry(a: Args): Promise<void> {
  const sub = a._[0] ?? "status";

  if (sub === "setup") {
    const r = ensureHelper();
    if (!r.ok) die(`Can't set up biometry: ${r.reason}`);
    // Nothing is installed: the helper is built fresh for each process that
    // needs it, so there is no path worth naming here.
    info(`${green("✓")} the Touch ID helper builds and runs on this machine`);

    // What an older hush left in `~/.hush/bin/` is dead weight that looks
    // authoritative. Nothing reads it any more; clear it so the only copy in
    // play is one this machine built for itself.
    const stale = ["hush-touchid", "hush-touchid.stamp"]
      .map((f) => join(hushHome(), "bin", f))
      .filter((f) => existsSync(f));
    for (const f of stale) {
      try { unlinkSync(f); } catch { /* leave it: it is ignored either way */ }
    }
    if (stale.length) info(dim(`  removed the old cached copy in ~/.hush/bin (no longer used)`));
  }

  const st = biometryStatus();
  info("");
  info(`  ${st.available ? green("✓") : red("✗")} ${st.kind === "none" ? "biometry" : st.kind}` +
    (st.reason ? dim(`  ${st.reason}`) : ""));

  if (sub === "test") {
    if (!st.available) die("Biometry isn't available, so there is nothing to test.");
    info("");
    const r = await authenticate("confirm this is you — hush biometry test");
    info(r === "ok" ? `  ${green("✓")} authenticated` : `  ${red("✗")} ${r}`);
    return;
  }

  info("");
  info(bold("  What this protects, and what it doesn't"));
  info(dim("    ✓  nothing runs with your credentials unless you are physically here"));
  info(dim("    ✓  your agent cannot approve its own request"));
  info(dim("    ✗  it does NOT protect the key at rest — anything running as you"));
  info(dim("       can still read the identity from the login keychain"));
  info("");
  info(dim("  Turn it on in .hush/policy.json:  \"biometry\": \"required\""));
  info(dim("  See docs/BIOMETRY.md for the hardware-backed version."));
}
