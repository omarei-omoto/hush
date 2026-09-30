/**
 * `hush add` — every way a secret goes in: a file, KEY=value, or a known service (and the old `hush set`).
 */
import { existsSync, readFileSync } from "node:fs";
import { audit, slugifyEnv } from "../vault.ts";
import { CATALOG, knownVars, serviceLabel, setNameFor } from "../services.ts";
import { requireIdentity } from "../identity.ts";
import { parseEnvFile } from "../scan.ts";
import { preview } from "../redact.ts";
import { openGlobal, globalVaultName } from "../library.ts";
import { maybeNudge } from "../secure.ts";
import { requestApproval } from "../approval.ts";
import { type Args, bool, list, str } from "../cli/args.ts";
import { bold, cyan, die, dim, green, info, warn, yellow } from "../cli/output.ts";
import { ctxLoose, dieOnApproval, pickVault, policyFor, resolveSetName, useHere } from "../cli/context.ts";
import { beginSetWrite, guessSetName, importInto, shortValueWarning, warnShort } from "../cli/sets.ts";
import { promptLine, promptSecret } from "../cli/prompts.ts";

/**
 * `hush set` is the pre-unification name for storing one KEY=value. It is now
 * a thin alias for `hush add KEY=value`: same target-resolution rule (--to,
 * falling back to --env for old scripts, falling back to "default"), no
 * prompt and no --to tip, because a script that already types `hush set` was
 * never going to see either.
 */
export async function cmdSet(a: Args): Promise<void> {
  warn("`hush set` is deprecated; use `hush add KEY=value` instead.");
  const key = a._[0];
  if (!key) die("Usage: hush set <KEY> [--env <env>] [--note <text>]");
  const to = str(a, "to") ?? str(a, "env") ?? "default";
  // An alias keeps the old behaviour, and `hush set K --env prod` never made
  // the project use "prod" — that was `hush run --env prod`, run by run.
  return cmdAddKeyValue({ _: [key], rest: [], flags: { ...a.flags, to, "no-use": true } });
}

/**
 * `hush add <file>` — the file-shaped input of `hush add`. Asks (on a TTY)
 * what to call the set and whether it belongs in the library or the project;
 * off a TTY it needs `--as`, because a run that stores nothing must not look
 * like one that did.
 */
export async function cmdAddFile(a: Args, file: string): Promise<void> {
  const loose = ctxLoose(a);
  let project = loose.vault;
  const id = requireIdentity();
  if (!existsSync(file)) die(`No such file: ${file}`);

  const parsed = parseEnvFile(readFileSync(file, "utf8"));
  const names = Object.keys(parsed);
  if (!names.length) die(`No variables found in ${file}.`);

  const isTTY = Boolean(process.stdin.isTTY);
  let asLabel = str(a, "as");
  if (!asLabel) {
    if (!isTTY) {
      die(
        `Nothing was stored from ${file}: no name given for the set.`,
        `Pass one:  hush add ${file} --as "Name"`,
      );
    }
    const guess = guessSetName(file);
    const answer = await promptLine(`Name this set?${guess ? ` (e.g. "${guess}")` : ""} `);
    asLabel = answer || guess;
    if (!asLabel) die(`Nothing was stored from ${file}: no name given for the set.`);
  }

  const { target, where, toLibrary } = await beginSetWrite(loose, a, {
    asLabel,
    count: names.length,
    verb: "Add set",
  });
  project = toLibrary ? project : target;
  const slug = slugifyEnv(asLabel);

  const { added, skipped, short } = importInto(target, id, slug, parsed, bool(a, "overwrite"));
  // A second import into the same named set is someone adding to the set they
  // already named, not re-describing it — leaving out --description here must
  // not blank out the description the first import set.
  const meta: Parameters<typeof target.describeEnv>[1] = { label: asLabel, source: file };
  const description = str(a, "description");
  const when = str(a, "when");
  if (description !== undefined) meta.description = description;
  if (when !== undefined) meta.whenToUse = when;
  if (!added) target.ensureEnvExists(slug); // describeEnv requires the env to exist
  target.describeEnv(slug, meta);
  target.save();
  audit(loose.hushDir, { actor: "cli", action: "add", kind: "file", env: slug, as: asLabel, file, added, skipped, where: toLibrary ? "library" : "project" });

  info(`${green("✓")} stored ${bold(String(added))} secret(s) as ${bold(asLabel)} ${dim(`(${slug})`)} in ${where}`);
  if (skipped) info(dim(`  ${skipped} already present (pass --overwrite to replace)`));
  warnShort(short);
  useHere(loose.hushDir, slug, a);
  info("");
  info(yellow(`  Now delete ${file} — or at least make sure it is gitignored.`));
  maybeNudge(project, loose.hushDir, loose.root);
}

// -------------------------------------------------------------------- add

function cmdAddUsage(): void {
  info(bold("Usage:"));
  info("  hush add <file> [--as <name>] [--library|--project]");
  info("  hush add KEY=value [KEY=value…] [--to <set>]");
  info("  hush add <service> [--as <name>]      " + dim("e.g. hush add fal"));
  info("");
  info(dim("  known services: " + Object.keys(CATALOG).sort().join(", ")));
}

/**
 * `hush add` — the one way to put secrets in, however they arrive: a file, a
 * KEY=value on the command line, or a known service prompted one variable at
 * a time. Dispatch order matters: `--account`/`--vars` force the service
 * form even for a name outside CATALOG (the pre-unification `hush add` took
 * any service name at all, and this keeps that working), a bare "=" forces
 * key/value, and only then does an existing path win — so a CATALOG name
 * never has to also collide with a file to be recognised as a service.
 */
export async function cmdAdd(a: Args): Promise<void> {
  const first = a._[0];
  if (!first) return void cmdAddUsage();

  if (a._.some((x) => x.includes("="))) return cmdAddKeyValue(a);

  const service = first.toLowerCase();
  if (CATALOG[service] || str(a, "account") !== undefined || list(a, "vars").length) {
    return cmdAddService(a, service);
  }

  if (existsSync(first)) return cmdAddFile(a, first);

  // Not a file, not a known service: the same shape `hush set <KEY>` always
  // had — a bare key name, prompted for its value.
  return cmdAddKeyValue(a);
}

/** `hush add KEY=value [KEY=value…] [--to <set>]` — the direct-value form. */
async function cmdAddKeyValue(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  const id = requireIdentity();
  const pairs = a._;
  if (!pairs.length) die("Usage: hush add <KEY>[=value] [<KEY>=value…] [--to <set>]");

  let to = str(a, "to");
  if (!to) {
    if (process.stdin.isTTY) {
      const answer = await promptLine(`Which set? (enter for ${dim("default")}) `);
      to = answer || "default";
    } else {
      to = "default";
      info(dim(`  Tip: hush add ${pairs[0]} --to <set> keeps this out of "default".`));
    }
  }
  const slug = resolveSetName(to, [loose.vault, openGlobal()]);
  const { vault, where } = pickVault(loose, a, slug);
  const isNew = !vault.hasSet(slug);
  const policy = policyFor(loose.hushDir);

  for (const spec of pairs) {
    let key = spec;
    let value: string;
    const eq = spec.indexOf("=");
    if (eq > 0) {
      key = spec.slice(0, eq);
      value = spec.slice(eq + 1);
      warn("Value passed on the command line — it is now in your shell history.");
    } else {
      value = await promptSecret(`value for ${bold(key)}`, true);
    }
    if (!value) die("Empty value, nothing written.");

    if (policy?.requireApproval.includes("add")) {
      const ap = await requestApproval(loose.hushDir, {
        action: "add",
        summary: `Set ${key} (${slug})`,
        scope: `add:${slug}/${key}`,
        ttlSeconds: policy.approvalTtlSeconds,
        timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
        biometry: policy.biometry,
        // One-shot: a grant cannot outlive this command (approval.ts sessionGrant).
        sessionGrant: false,
      });
      dieOnApproval(ap, `setting ${key}`);
    }

    const existed = vault.has(slug, key);
    vault.set(id, slug, key, value, str(a, "note"));
    vault.save();
    const short = shortValueWarning(key, value);
    if (short) warn(short);
    audit(loose.hushDir, { actor: "cli", action: existed ? "update" : "create", env: slug, key, where });
    info(`${green("✓")} ${existed ? "updated" : "added"} ${bold(key)} in ${cyan(slug)}  ${dim(preview(value))}`);
  }
  if (isNew) useHere(loose.hushDir, slug, a);
  if (where === "library") info(dim(`  in your library (${globalVaultName()}) — never in the repo`));
  else info(dim(`  commit ${loose.vaultPath} to share it with the team`));
  maybeNudge(where === "project" ? vault : loose.vault, loose.hushDir, loose.root);
}

/**
 * `hush add <service>` — prompt for a known service's variables one at a
 * time, into a set named by `--as` or by prompt. `--account <x>` is the
 * deprecated alias for `--as "<service>/<x>"`.
 */
async function cmdAddService(a: Args, service: string): Promise<void> {
  const loose = ctxLoose(a);
  const id = requireIdentity();

  const accountAlias = str(a, "account");
  let asLabel = str(a, "as");
  let slug: string;
  if (accountAlias !== undefined) {
    const aliasName = setNameFor(service, accountAlias);
    warn(`--account is deprecated; use --as "${aliasName}" instead.`);
    slug = aliasName;
    asLabel ??= aliasName;
  } else if (asLabel) {
    slug = slugifyEnv(asLabel);
  } else if (process.stdin.isTTY) {
    const answer = await promptLine(`Name this set? e.g. "Personal ${serviceLabel(service)}" `);
    if (!answer) die(`Nothing was stored for ${service}: no name given for the set.`);
    asLabel = answer;
    slug = slugifyEnv(asLabel);
  } else {
    die(
      `Nothing was stored for ${service}: no name given for the set.`,
      `Pass one:  hush add ${service} --as "Personal ${serviceLabel(service)}"`,
    );
  }

  const { vault, where } = pickVault(loose, a, slug);
  const vars = list(a, "vars").length ? list(a, "vars") : knownVars(service);
  if (!vars.length) {
    die(
      `"${service}" is not a known service, so hush doesn't know which variables it needs.`,
      `Tell it: hush add ${service} --as "${asLabel}" --vars API_KEY,API_SECRET`,
    );
  }

  const policy = policyFor(loose.hushDir);
  if (policy?.requireApproval.includes("add")) {
    const ap = await requestApproval(loose.hushDir, {
      action: "add",
      summary: `Add ${serviceLabel(service)} set "${asLabel}" (${vars.join(", ")})`,
      scope: `add:${slug}`,
      ttlSeconds: policy.approvalTtlSeconds,
      timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
      biometry: policy.biometry,
      // One-shot: a grant cannot outlive this command (approval.ts sessionGrant).
      sessionGrant: false,
    });
    dieOnApproval(ap, `adding ${slug}`);
  }

  info(`${bold(serviceLabel(service))} ${dim("/")} ${bold(asLabel!)}`);
  info(dim(`  ${vars.length} variable(s). Leave blank to skip one.`));
  info("");

  let stored = 0;
  const skipped: string[] = [];
  const short: string[] = [];
  for (const v of vars) {
    const had = vault.has(slug, v);
    const value = await promptSecret(`  ${v}${had ? dim(" (set — enter to keep)") : ""}`);
    if (!value) {
      skipped.push(v);
      continue;
    }
    vault.set(id, slug, v, value);
    if (shortValueWarning(v, value)) short.push(v);
    stored++;
  }

  if (!stored) {
    // Skipping every prompt is a real choice when a human is at the keyboard.
    // With no terminal there were no prompts to skip: something piped in one
    // value fewer than expected, or nothing at all — and reporting success for
    // that told a CI job the credential was stored when the vault was untouched.
    if (!process.stdin.isTTY) {
      die(
        `Nothing was stored for ${slug}: no value arrived on stdin.`,
        `Pipe one line per variable (${vars.join(", ")}):  ` +
          `printf '%s\\n' "$KEY" | hush add ${service} --as "${asLabel}"`,
      );
    }
    return info(dim("nothing entered, nothing changed"));
  }

  // A partial write is not a failure, but it must not look like a complete one.
  if (skipped.length) {
    warn(`Left unset: ${skipped.join(", ")}${process.stdin.isTTY ? "" : " (stdin ran out of lines)"}`);
  }
  warnShort(short);

  if (!accountAlias) vault.describeEnv(slug, { label: asLabel });
  vault.save();
  audit(loose.hushDir, { actor: "cli", action: "add", kind: "service", service, env: slug, stored, where });
  info("");
  info(`${green("✓")} stored ${stored} value(s) for ${bold(slug)}`);
  // The --account alias promises the old behaviour, and the old behaviour
  // was "stored, not pinned" — scripts then ran `hush use` themselves.
  if (accountAlias === undefined) useHere(loose.hushDir, slug, a);
  info("");
  info("Use it:");
  info(`  ${cyan("hush npm run dev")}  ${dim("← or any command; the set is injected")}`);
  info(`  ${cyan(`hush run --use ${slug} -- <cmd>`)}  ${dim("← from a project that does not use it")}`);
  if (where === "library") info(dim(`  in your library (${globalVaultName()}) — never in the repo`));
  else info(dim(`  commit ${loose.vaultPath} to share it`));
}
