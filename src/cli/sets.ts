/**
 * What `hush add`, `hush import` and `hush start` share when they write a set.
 */
import { basename } from "node:path";
import { Vault, slugifyEnv } from "../vault.ts";
import { setNameFor } from "../services.ts";
import { requireIdentity } from "../identity.ts";
import { MIN_REDACTABLE } from "../redact.ts";
import { openGlobal, globalVaultName, globalVaultExists } from "../library.ts";
import { requestApproval } from "../approval.ts";
import { type Args, bool, list } from "../cli/args.ts";
import { ctxLoose, dieOnApproval, makeProjectVault, policyFor } from "../cli/context.ts";
import { die, warn } from "../cli/output.ts";
import { promptLine } from "../cli/prompts.ts";

/** `--library` is honoured; otherwise a first run writes into this project. */
export const targetFor = (a: Args): "library" | "project" => (bool(a, "library") ? "library" : "project");

/**
 * Guess a set name from the filename, the same way the UI's "Save all of this
 * as one named set" bar does (src/ui.ts, `stagingPanel`'s `guess`): strip the
 * .env prefix and separators, then capitalize. `.env` alone has nothing left
 * to name it from, so it yields no guess rather than an empty label.
 */
export function guessSetName(file: string): string {
  const guess = basename(file).replace(/^\.env\.?/, "").replace(/[-_.]+/g, " ").trim();
  return guess ? guess.charAt(0).toUpperCase() + guess.slice(1) : "";
}

/**
 * Import every key from `file` into a single env, applying the same
 * `--overwrite` rule the plain import path uses. Shared so a named set behaves
 * identically whether it is brand new or already has keys in it.
 */
export function importInto(
  vault: Vault,
  id: ReturnType<typeof requireIdentity>,
  env: string,
  parsed: Record<string, string>,
  overwrite: boolean,
): { added: number; overwritten: number; skipped: number; short: string[] } {
  let added = 0;
  let overwritten = 0;
  let skipped = 0;
  const short: string[] = [];
  for (const [key, value] of Object.entries(parsed)) {
    if (vault.has(env, key) && !overwrite) {
      skipped++;
      continue;
    }
    if (vault.has(env, key)) overwritten++;
    else added++;
    if (shortValueWarning(key, value)) short.push(key);
    vault.set(id, env, key, value);
  }
  return { added, overwritten, skipped, short };
}

/**
 * Everything `hush add` and `hush import` must decide identically before a set
 * is written: which vault it lands in, and whether the policy wants the `add`
 * approval first.
 *
 * One function rather than two copies, for the same reason policy.ts exists:
 * two surfaces that each decide this for themselves drift, and the drift here
 * is either "stored somewhere the user did not expect" or "skipped the
 * approval", which is the control that matters.
 */
export async function beginSetWrite(
  loose: ReturnType<typeof ctxLoose>,
  a: Args,
  opts: {
    asLabel: string;
    count: number;
    verb: string;
    /**
     * Skip the "Where?" question by deciding up front. `hush start` uses this:
     * it already asked several questions, and a first run should not also be a
     * quiz about hush's own storage model.
     */
    target?: "library" | "project";
  },
): Promise<{ target: Vault; where: string; toLibrary: boolean }> {
  const wantLibrary = bool(a, "library") || opts.target === "library";
  const wantProject = bool(a, "project") || opts.target === "project";
  if (wantLibrary && wantProject) die("Pass only one of --library or --project.");

  const isTTY = Boolean(process.stdin.isTTY);
  // Neither flag, no vault of this folder's own, and no library to fall back
  // to: a script has nowhere sensible to land, so it fails here rather than
  // reporting success having stored nothing. A real terminal gets the prompt.
  if (!wantLibrary && !wantProject && !isTTY && !loose.vault && !globalVaultExists()) {
    die(
      "Nothing was stored: this folder has no vault yet, and you have no library either.",
      "Pass --project to make a vault here, or hush global --create to make a library.",
    );
  }

  let toLibrary: boolean;
  if (wantLibrary) toLibrary = true;
  else if (wantProject) toLibrary = false;
  else if (isTTY) {
    const def = globalVaultExists() ? "library" : "project";
    const answer = (await promptLine(`Where? [library/project] (enter for ${def}) `)).trim().toLowerCase();
    toLibrary = (answer || def) === "library";
  } else {
    toLibrary = globalVaultExists();
  }

  let target: Vault;
  let where: string;
  if (toLibrary) {
    const g = openGlobal();
    if (!g) die("You have no library yet.", "Make one: hush global --create");
    target = g;
    where = `your library (${globalVaultName()})`;
  } else {
    // Silent while a guided run is driving: see makeProjectVault's own note.
    target = loose.vault ?? makeProjectVault(loose.hushDir, loose.root, opts.target !== undefined);
    where = "this project";
  }

  const slug = slugifyEnv(opts.asLabel);
  const policy = policyFor(loose.hushDir);
  if (policy?.requireApproval.includes("add")) {
    const ap = await requestApproval(loose.hushDir, {
      action: "add",
      summary: `${opts.verb} "${opts.asLabel}" (${opts.count} key(s)) in ${where}`,
      scope: `add:${slug}`,
      ttlSeconds: policy.approvalTtlSeconds,
      timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
      biometry: policy.biometry,
      // One-shot: a grant cannot outlive this command (approval.ts sessionGrant).
      sessionGrant: false,
    });
    dieOnApproval(ap, `adding ${opts.asLabel}`);
  }

  return { target, where, toLibrary };
}

/**
 * The one thing worth saying about a value too short to mask.
 *
 * `redact.ts` refuses to track anything under MIN_REDACTABLE characters, on
 * the grounds that masking a three-character value is noise. The consequence
 * is that a short secret is injected, used, and printed in full with nothing
 * having said so — and `hush request` sharpened it, because a response that
 * reflects the value back is printed too.
 */
export function shortValueWarning(key: string, value: string): string | null {
  if (!value.length || value.length >= MIN_REDACTABLE) return null;
  return `${key} is ${value.length} character(s): hush will not mask a value that short in command output`;
}

export function warnShort(keys: string[]): void {
  if (!keys.length) return;
  warn(
    `${keys.length} value(s) are shorter than ${MIN_REDACTABLE} characters, so hush will not mask them ` +
      `in output: ${keys.join(", ")}`,
  );
}

/**
 * Extra sets for one run: `--use` (repeatable), `--with service:account`
 * (deprecated alias for `--use service/account`) and `--env` (now just
 * another set, appended like `--use`). Order among the three is fixed rather
 * than reflecting the command line, but composeSets()'s last-mention-wins
 * dedupe means that only matters when the same name appears in more than one
 * of them, which is not a case any of these flags were ever meant to express.
 */
export function collectExtraSets(a: Args): string[] {
  const extra: string[] = [...list(a, "use")];
  for (const spec of list(a, "with")) {
    const { service, account } = parseColonPair(spec);
    const name = setNameFor(service, account);
    warn(`--with ${spec} is deprecated; use --use ${name} instead.`);
    extra.push(name);
  }
  extra.push(...list(a, "env"));
  return extra;
}

/** Parse `fal:acme` / `fal=acme` from a --with flag. Not exported: services.ts's parseWith() is deprecated. */
function parseColonPair(spec: string): { service: string; account: string } {
  const m = spec.match(/^([A-Za-z0-9_.-]+)[:=]([A-Za-z0-9_.-]+)$/);
  if (!m) die(`Bad --with "${spec}". Use --with <service>:<account>, e.g. --with fal:acme`);
  return { service: m[1].toLowerCase(), account: m[2] };
}

/** Parse `fal=acme` — the pre-unification pin syntax — into the set name `fal/acme` names today. */
export function convertLegacyPin(spec: string): string {
  const m = spec.match(/^([A-Za-z0-9_.-]+)=([A-Za-z0-9_.-]+)$/);
  if (!m) return spec;
  const name = setNameFor(m[1], m[2]);
  warn(`"${spec}" is deprecated; use "${name}" instead.`);
  return name;
}
