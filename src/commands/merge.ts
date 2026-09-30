/**
 * `hush merge-driver` (git's merge driver, and `--install` to use it here),
 * `hush merge` (finish a merge git left conflicted), and `hush merge pick` /
 * `hush merge status` (choose a side for each key both branches changed).
 *
 * The committed `.hush/.gitattributes` says `vault.json -merge`, and stays
 * that way: git falls back to a plain text merge when a named driver is not
 * configured, and a text merge can combine a rotation on one branch with a
 * value added on the other into a vault that quietly loses the value. The
 * driver is switched on per clone instead — in `.git/info/attributes` and git
 * config, neither of which is committed — so a teammate without it gets the
 * safe conflict and `hush merge`, never a silent text merge.
 */
import { existsSync, readFileSync, writeFileSync, unlinkSync, appendFileSync, mkdirSync } from "node:fs";
import { join, dirname, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { Vault, safeText, locateProject, audit, type VaultFile, type SecretEntry } from "../vault.ts";
import { loadIdentity } from "../identity.ts";
import { mergeVaults, type MergeConflict, type MergeResult } from "../merge.ts";
import { type Args, bool, str } from "../cli/args.ts";
import { bold, cyan, die, dim, green, info, red, yellow } from "../cli/output.ts";
import { onPath, selfCommand } from "../cli/programs.ts";

/** Where the choices a merge left open are kept, beside the vault. Never a value. */
export const conflictFile = (vaultPath: string): string => join(dirname(vaultPath), "merge-conflicts.json");

interface ConflictRecord {
  vault: string;
  at: string;
  conflicts: MergeConflict[];
}

function git(args: string[], cwd: string): { ok: boolean; out: string } {
  const bin = onPath("git");
  if (!bin) return { ok: false, out: "" };
  const r = spawnSync(bin, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 15_000 });
  return { ok: r.status === 0, out: (r.stdout ?? "").trimEnd() };
}

const parseVault = (text: string, label: string): VaultFile | null => {
  if (!text.trim()) return null;
  try {
    return JSON.parse(text) as VaultFile;
  } catch {
    throw new Error(`the ${label} side of the vault is not valid JSON`);
  }
};

/** One line per conflict, for a person: set, key, who and when on each side. */
function describeConflict(c: MergeConflict): string {
  const side = (s: MergeConflict["ours"]) =>
    s.deleted ? "deleted it" : `${safeText(s.updatedBy, 40) ?? "someone"} at ${safeText(s.updatedAt, 24) ?? "?"}`;
  return `${c.set}/${c.key}   this branch: ${side(c.ours)}   other branch: ${side(c.theirs)}`;
}

function report(r: MergeResult, pathForHumans: string): void {
  const err = (s: string) => process.stderr.write(s + "\n");
  if (r.structural) {
    err(red(`✗ hush could not merge ${pathForHumans}: ${r.structural}.`));
    return;
  }
  if (r.rewrapped.length) err(dim(`hush: gave the newer vault key to ${r.rewrapped.join(", ")} (added on the other branch)`));
  if (r.resealed) err(dim(`hush: re-sealed ${r.resealed} value(s) under the newer vault key`));
  for (const n of r.notes) err(yellow(`! ${n}`));
  if (r.conflicts.length) {
    err(yellow(`! ${r.conflicts.length} key(s) were changed on both branches; this branch's value is kept for now:`));
    for (const c of r.conflicts) err(`    ${describeConflict(c)}`);
    err(dim(`  Choose for each:  hush merge pick <KEY> --ours | --theirs   (hush merge status lists them)`));
  } else {
    err(green(`✓ hush merged ${pathForHumans}`));
  }
}

function writeConflicts(vaultPath: string, r: MergeResult, displayPath: string): void {
  const file = conflictFile(vaultPath);
  if (!r.conflicts.length) {
    if (existsSync(file)) unlinkSync(file);
    return;
  }
  const record: ConflictRecord = { vault: displayPath, at: new Date().toISOString(), conflicts: r.conflicts };
  writeFileSync(file, JSON.stringify(record, null, 2) + "\n", { mode: 0o600 });
}

/**
 * `hush merge-driver %O %A %B %P` — what git runs. Writes the merge into %A and
 * exits 0 when nothing is left to decide, 1 otherwise (git then reports a
 * conflict and the file holds a working vault with this branch's side).
 */
export async function cmdMergeDriver(a: Args): Promise<void> {
  if (bool(a, "install") || bool(a, "uninstall")) return installDriver(a);
  const [basePath, oursPath, theirsPath, realPath] = a._;
  if (!basePath || !oursPath || !theirsPath) {
    die("Usage: hush merge-driver %O %A %B %P   (git runs this; to switch it on: hush merge-driver --install)");
  }
  const display = realPath ?? ".hush/vault.json";
  let r: MergeResult;
  try {
    const base = existsSync(basePath) ? parseVault(readFileSync(basePath, "utf8"), "common ancestor") : null;
    const ours = parseVault(readFileSync(oursPath, "utf8"), "this branch's");
    const theirs = parseVault(readFileSync(theirsPath, "utf8"), "other branch's");
    if (!ours || !theirs) {
      // One side deleted the vault: not something to merge by key.
      process.stderr.write(red(`✗ one branch deleted ${display}; keep or delete it by hand`) + "\n");
      process.exit(1);
    }
    r = mergeVaults(base, ours, theirs, loadIdentity());
  } catch (e) {
    process.stderr.write(red(`✗ hush could not merge ${display}: ${(e as Error).message}`) + "\n");
    process.exit(1);
  }
  report(r, display);
  if (r.structural || !r.data) process.exit(1);
  writeFileSync(oursPath, JSON.stringify(r.data, null, 2) + "\n");
  // git runs the driver from the top of the work tree, and %P is relative to it.
  writeConflicts(resolve(display), r, display);
  process.exit(r.conflicts.length ? 1 : 0);
}

/**
 * Switch the driver on (or off) for this clone only: a line in
 * `.git/info/attributes` — which outranks the committed `.gitattributes` — and
 * the driver's command in this clone's git config.
 */
function installDriver(a: Args): void {
  const cwd = process.cwd();
  const inRepo = git(["rev-parse", "--show-toplevel"], cwd);
  if (!inRepo.ok) die("This is not inside a git repository.", "The merge driver is for vaults committed to git.");
  const attrs = git(["rev-parse", "--git-path", "info/attributes"], cwd);
  const attrsPath = resolve(cwd, attrs.out);
  const line = "**/.hush/vault.json merge=hush";
  const current = existsSync(attrsPath) ? readFileSync(attrsPath, "utf8") : "";

  if (bool(a, "uninstall")) {
    if (current.includes(line)) {
      writeFileSync(attrsPath, current.split("\n").filter((l) => l.trim() !== line).join("\n"));
    }
    git(["config", "--local", "--unset", "merge.hush.driver"], cwd);
    git(["config", "--local", "--unset", "merge.hush.name"], cwd);
    info(`${green("✓")} the hush merge driver is off for this clone; vault merges conflict as before`);
    return;
  }

  const { command, args } = selfCommand(["merge-driver"]);
  const quoted = [command, ...args].map((s) => (/^[\w./@:-]+$/.test(s) ? s : `'${s.replace(/'/g, "'\\''")}'`)).join(" ");
  const driver = `${quoted} %O %A %B %P`;
  const setName = git(["config", "--local", "merge.hush.name", "hush vault merge"], cwd);
  const setDriver = git(["config", "--local", "merge.hush.driver", driver], cwd);
  if (!setName.ok || !setDriver.ok) die("git config refused the merge driver.");
  if (!current.split("\n").some((l) => l.trim() === line)) {
    mkdirSync(dirname(attrsPath), { recursive: true });
    appendFileSync(attrsPath, (current && !current.endsWith("\n") ? "\n" : "") + line + "\n");
  }
  info(`${green("✓")} vault merges in this clone now go through hush`);
  info(dim(`  ${attrsPath}: ${line}`));
  info(dim(`  git config merge.hush.driver: ${driver}`));
  info(dim("  Only this clone: teammates run the same command once. Undo: hush merge-driver --uninstall"));
}

/** Whether this clone routes vault merges through hush — for `hush doctor`. */
export function driverInstalled(cwd: string): boolean | null {
  const top = git(["rev-parse", "--show-toplevel"], cwd);
  if (!top.ok) return null;
  const driver = git(["config", "--get", "merge.hush.driver"], cwd);
  const attrs = git(["rev-parse", "--git-path", "info/attributes"], cwd);
  const path = resolve(cwd, attrs.out);
  const has = existsSync(path) && readFileSync(path, "utf8").split("\n").some((l) => l.trim() === "**/.hush/vault.json merge=hush");
  return driver.ok && Boolean(driver.out) && has;
}

/**
 * `hush merge` — finish a merge git stopped on. Reads the three versions git
 * kept in the index, merges them, and writes the vault. `hush merge status`
 * and `hush merge pick` handle what is left to choose.
 */
export async function cmdMerge(a: Args): Promise<void> {
  const sub = a._[0];
  const loc = locateProject(process.cwd());
  if (!loc || !loc.hasVault) die("No project vault here to merge.");
  const vaultPath = loc.vaultPath;

  if (sub === "status") return mergeStatus(vaultPath);
  if (sub === "pick") return mergePick(a, vaultPath);
  if (sub) die(`Unknown: hush merge ${sub}`, "Try: hush merge, hush merge status, hush merge pick <KEY> --ours|--theirs");

  const top = git(["rev-parse", "--show-toplevel"], dirname(vaultPath));
  if (!top.ok) die("This vault is not in a git repository, so there is no merge to finish.");
  const rel = relative(top.out, vaultPath).split("\\").join("/");
  const stage = (n: number) => git(["show", `:${n}:${rel}`], top.out);
  const ours = stage(2);
  const theirs = stage(3);
  if (!ours.ok || !theirs.ok) {
    die(`git has no merge in progress for ${rel}.`, "Run this after a git merge, pull or rebase stops on the vault.");
  }
  const base = stage(1);
  const r = mergeVaults(
    base.ok ? parseVault(base.out, "common ancestor") : null,
    parseVault(ours.out, "this branch's")!,
    parseVault(theirs.out, "other branch's")!,
    loadIdentity(),
  );
  report(r, rel);
  if (r.structural || !r.data) {
    process.exitCode = 1;
    return;
  }
  writeFileSync(vaultPath, JSON.stringify(r.data, null, 2) + "\n");
  writeConflicts(vaultPath, r, rel);
  audit(loc.hushDir, { actor: "cli", action: "merge", conflicts: r.conflicts.length, resealed: r.resealed });
  if (!r.conflicts.length) info(`  ${dim("then:")} ${cyan(`git add ${rel}`)} ${dim("and finish the merge as usual")}`);
}

function readConflicts(vaultPath: string): ConflictRecord | null {
  const file = conflictFile(vaultPath);
  if (!existsSync(file)) return null;
  try {
    return JSON.parse(readFileSync(file, "utf8")) as ConflictRecord;
  } catch {
    die(`${file} is not readable. Delete it and run hush merge again.`);
  }
}

function mergeStatus(vaultPath: string): void {
  const record = readConflicts(vaultPath);
  if (!record || !record.conflicts.length) return info(`${green("✓")} nothing left to choose in this vault's merge`);
  info(bold(`${record.conflicts.length} key(s) to choose:`));
  for (const c of record.conflicts) info(`  ${describeConflict(c)}`);
  info(dim(`  hush merge pick <KEY> --ours | --theirs   (--set <set> when the key is in more than one)`));
}

function mergePick(a: Args, vaultPath: string): void {
  const key = a._[1];
  const wantOurs = bool(a, "ours");
  const wantTheirs = bool(a, "theirs");
  if (!key || wantOurs === wantTheirs) die("Usage: hush merge pick <KEY> --ours | --theirs [--set <set>]");
  const record = readConflicts(vaultPath);
  if (!record) die("There is no merge in progress with keys to choose.", "hush merge status");
  const set = str(a, "set");
  const matches = record.conflicts.filter((c) => c.key === key && (!set || c.set === set));
  if (!matches.length) die(`"${key}" is not one of the keys left to choose.`, "hush merge status");
  if (matches.length > 1) die(`"${key}" is left to choose in ${matches.map((c) => c.set).join(" and ")}.`, "Say which with --set <set>.");
  const c = matches[0];
  const side = wantOurs ? c.ours : c.theirs;

  const vault = Vault.open(vaultPath);
  if (side.deleted) {
    vault.delete(c.set, c.key);
  } else {
    const entry = side.entry as SecretEntry;
    // The recorded entry was sealed under this vault's key at merge time. If
    // the vault has moved on since, it no longer fits: merge again.
    if (entry.gen !== vault.data.dek.generation) {
      die("The vault's key changed since this merge was recorded.", "Run hush merge again, then pick.");
    }
    vault.data.envs[c.set] ??= {};
    vault.data.envs[c.set][c.key] = entry;
    vault.markStructural();
  }
  vault.save();
  const rest = record.conflicts.filter((x) => x !== c);
  if (rest.length) {
    writeFileSync(conflictFile(vaultPath), JSON.stringify({ ...record, conflicts: rest }, null, 2) + "\n", { mode: 0o600 });
  } else {
    unlinkSync(conflictFile(vaultPath));
  }
  info(`${green("✓")} ${c.set}/${c.key}: kept ${wantOurs ? "this branch's" : "the other branch's"} ${side.deleted ? "deletion" : "value"}`);
  if (rest.length) info(dim(`  ${rest.length} left: hush merge status`));
  else info(`  ${dim("all chosen — now:")} ${cyan(`git add ${relative(process.cwd(), vaultPath)}`)}`);
}
