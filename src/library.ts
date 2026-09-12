/**
 * The global library, and what a project takes from it.
 *
 * Two levels, because people keep secrets at two levels:
 *
 *   - **Global.** Your own named env sets — "Acme Production", "Personal /
 *     fal" — in one vault under ~/.hush. They live in exactly one place, so
 *     rotating a key is one edit rather than one edit per project.
 *   - **Project.** The repo's own vault, committed and shared with the team,
 *     plus a list naming which global sets this project uses.
 *
 * A project *links* a global set rather than copying it. The keys never enter
 * the repo, so a teammate who clones it does not get them — which is the point:
 * the repo says "this project needs a set called acme-production" and each
 * person supplies their own. Copying would also mean two copies that drift, and
 * a rotation that silently only half-applied.
 *
 * Resolution order is least specific first: global links, then the project's
 * own environment, then any service accounts chosen for the run. The project
 * wins over the library, and an explicit `--with` wins over both.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Vault, namedVaultPath, ValidationError, loadUse, type EnvMeta } from "./vault.ts";
import { hushHome } from "./identity.ts";
import type { Opener } from "./crypto.ts";
import { setNameFor } from "./services.ts";

// ------------------------------------------------------------------- config

interface Config {
  /** Which named vault under ~/.hush/vaults is the global library. */
  globalVault?: string;
}

const configPath = (): string => join(hushHome(), "config.json");

export function loadConfig(): Config {
  try {
    return JSON.parse(readFileSync(configPath(), "utf8")) as Config;
  } catch {
    return {};
  }
}

export function saveConfig(patch: Config): void {
  mkdirSync(hushHome(), { recursive: true, mode: 0o700 });
  writeFileSync(configPath(), JSON.stringify({ ...loadConfig(), ...patch }, null, 2) + "\n");
}

/**
 * The library's vault name. HUSH_GLOBAL_VAULT wins, then the config file, then
 * "global" — so someone who already keeps everything in a vault called
 * "personal" can adopt it rather than start again.
 */
export const globalVaultName = (): string =>
  process.env.HUSH_GLOBAL_VAULT || loadConfig().globalVault || "global";

export const globalVaultPath = (): string => namedVaultPath(globalVaultName());

export const globalVaultExists = (): boolean => existsSync(globalVaultPath());

/** Named vaults that already exist, so a first run can offer them. */
export function namedVaults(): string[] {
  const dir = join(hushHome(), "vaults");
  if (!existsSync(dir)) return [];
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && existsSync(join(dir, e.name, "vault.json")))
      .map((e) => e.name)
      .sort();
  } catch {
    return [];
  }
}

export function openGlobal(): Vault | null {
  return globalVaultExists() ? Vault.open(globalVaultPath()) : null;
}

// ------------------------------------------------------------- project links

/**
 * `.hush/envs.json` — which global sets this project uses.
 *
 * Kept apart from `use.json` deliberately. That file maps a service to an
 * account and is read as a flat object in half a dozen places; quietly giving
 * it a second shape would have meant an `envs` key showing up as if it were a
 * service named "envs".
 */
export interface LinkedEnvs {
  use: string[];
}

const linksPath = (hushDir: string): string => join(hushDir, "envs.json");

export function loadLinks(hushDir: string): string[] {
  try {
    const raw = JSON.parse(readFileSync(linksPath(hushDir), "utf8")) as LinkedEnvs;
    return Array.isArray(raw?.use) ? raw.use.filter((x) => typeof x === "string") : [];
  } catch {
    return [];
  }
}

/**
 * Dedupe keeping each name's *last* position. Sets are layered later-wins,
 * so when a name is listed twice the later mention is the one that counts —
 * "`--use a`" on a set the project already uses means "and let a win now".
 */
function lastMentionWins(names: string[]): string[] {
  return [...new Set([...names].reverse())].reverse();
}

export function saveLinks(hushDir: string, use: string[]): void {
  mkdirSync(hushDir, { recursive: true });
  // Order is precedence (later wins), so the file keeps the order it was
  // given — never sorted — and mentioning a set again moves it to the end,
  // which is how "hush use <set>" on an already-used set makes it win.
  writeFileSync(linksPath(hushDir), JSON.stringify({ use: lastMentionWins(use) }, null, 2) + "\n");
}

/**
 * The ordered list of set names this project uses, floor first: "default",
 * then linked sets in the order they were added, then old (service, account)
 * pins for compatibility. Later wins, so the project's own "default" is the
 * baseline every set the person chose to use layers on top of — naming it in
 * envs.json is the one way to move it (and so to make it win).
 *
 * The use.json read is compatibility only, for a project set up before sets
 * were unified — nothing writes that file from here (loadUse's own
 * @deprecated note says the same). It can be deleted once no vault on earth
 * still has one.
 */
export function usedSets(hushDir: string | null): string[] {
  const names: string[] = [];
  if (hushDir) {
    names.push(...loadLinks(hushDir));
    for (const [service, account] of Object.entries(loadUse(hushDir))) {
      names.push(setNameFor(service, account));
    }
  }
  if (!names.includes("default")) names.unshift("default");
  return lastMentionWins(names);
}

// -------------------------------------------------------------- composition

export interface Composed {
  secrets: Record<string, string>;
  /** Every layer that contributed, in the order it was applied. */
  layers: string[];
  /** Linked sets this project names but the library does not have. */
  missing: string[];
}

/**
 * Everything a command should run with: the sets this project uses (see
 * usedSets(): "default" as the floor, then links, then old pins) with `extra`
 * (a `--use` flag) layered last, later wins.
 *
 * For each name, the project wins over a library set of the same name; a
 * *linked* name neither vault has is reported in `missing` rather than
 * thrown on — the expected state for a teammate who cloned the repo and has
 * not made their own copy of a global set yet, and failing the command
 * outright would tell them far less than naming what is missing. A name in
 * `extra` is different: the person just typed it, so silence about it would
 * be a lie — except "default", which an empty project simply does not have,
 * and that is not something to report either.
 */
export function composeSets(
  project: Vault | null,
  id: Opener,
  hushDir: string | null,
  extra: string[] = [],
): Composed {
  const secrets: Record<string, string> = {};
  const layers: string[] = [];
  const missing: string[] = [];

  const library = openGlobal();
  const typed = new Set(extra);
  // Position is precedence: a name the project already uses, named again in
  // `extra`, moves to the end so it wins for this run.
  const names = lastMentionWins([...usedSets(hushDir), ...extra]);

  for (const name of names) {
    if (project?.hasSet(name)) {
      Object.assign(secrets, project.materialize(id, name));
      layers.push(name);
    } else if (library?.hasSet(name)) {
      Object.assign(secrets, library.materialize(id, name));
      layers.push(`${globalVaultName()}:${name}`);
    } else if (name === "default") {
      // Every vault is born with one; an empty project simply has none.
      continue;
    } else if (typed.has(name)) {
      // Plain names, because that is what `--use` accepts — a "main:work-fal"
      // in this list would be a name the person cannot type back.
      const known = [
        ...new Set([...(project ? project.envNames() : []), ...(library ? library.envNames() : [])]),
      ];
      throw new ValidationError(
        `No set called "${name}". You have: ${known.length ? known.join(", ") : "none yet"}.`,
      );
    } else {
      missing.push(name);
    }
  }

  return { secrets, layers, missing };
}

/** One line per set, for `hush env` and the UI. */
export interface LibrarySet {
  name: string;
  label: string;
  description?: string;
  whenToUse?: string;
  source?: string;
  keys: string[];
}

// `hushDir` is part of the call-site shape shared with usedSets()/composeSets()
// (cli.ts, mcp.ts and ui.ts all pass it here without checking whether this
// particular function still needs it) — kept unused rather than dropped, since
// removing the parameter would break every one of those call sites.
export function librarySets(_hushDir: string | null): LibrarySet[] {
  const library = openGlobal();
  if (!library) return [];
  return library
    .sets()
    // Every vault is born with an empty "default". In a project that is the
    // environment you work in; in the library it is an entry nobody created,
    // with no name and nothing in it, sitting at the top of a list of things
    // you did create. It appears the moment it has anything in it. (A set
    // with a "/" in its name — an old "service account" — is listed like any
    // other; it was never anything but a name someone chose.)
    .filter((s) => !(s.name === "default" && s.keys.length === 0 && !s.description && !s.whenToUse))
    .map((s) => ({
      name: s.name,
      label: s.label,
      description: s.description,
      whenToUse: s.whenToUse,
      source: s.source,
      keys: s.keys,
    }));
}

export type { EnvMeta };
