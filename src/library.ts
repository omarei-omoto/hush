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
import { Vault, namedVaultPath, ValidationError, type EnvMeta } from "./vault.ts";
import { hushHome } from "./identity.ts";
import type { Opener } from "./crypto.ts";
import { scopeOf } from "./services.ts";

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

export function saveLinks(hushDir: string, use: string[]): void {
  mkdirSync(hushDir, { recursive: true });
  // Deduplicated and ordered, so the file is stable in git and the resolution
  // order is the one shown in the UI rather than insertion order.
  const unique = [...new Set(use)].sort();
  writeFileSync(linksPath(hushDir), JSON.stringify({ use: unique }, null, 2) + "\n");
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
 * Everything a command should run with: the library sets this project links,
 * then the project's own environment, then the chosen service accounts.
 *
 * A linked set the library does not have is reported rather than thrown on. It
 * is the expected state for a teammate who cloned the repo and has not made
 * their own copy yet, and failing the command outright would tell them far less
 * than naming what is missing.
 */
export function compose(
  project: Vault | null,
  id: Opener,
  hushDir: string | null,
  baseEnv: string,
  choices: { service: string; account: string }[] = [],
): Composed {
  const secrets: Record<string, string> = {};
  const layers: string[] = [];
  const missing: string[] = [];

  const links = hushDir ? loadLinks(hushDir) : [];
  if (links.length) {
    const library = openGlobal();
    for (const name of links) {
      if (!library || !library.data.envs[name]) {
        missing.push(name);
        continue;
      }
      Object.assign(secrets, library.materialize(id, name));
      layers.push(`${globalVaultName()}:${name}`);
    }
  }

  if (project) {
    const resolved = project.resolve(id, baseEnv, choices);
    Object.assign(secrets, resolved.secrets);
    layers.push(...resolved.layers);
  } else if (choices.length) {
    throw new ValidationError(
      `No project vault here, so there is no account to use for ${choices
        .map((c) => scopeOf(c.service, c.account))
        .join(", ")}.`,
    );
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
  /** True when the project in hand links this set. */
  linked: boolean;
}

export function librarySets(hushDir: string | null): LibrarySet[] {
  const library = openGlobal();
  if (!library) return [];
  const linked = new Set(hushDir ? loadLinks(hushDir) : []);
  return library
    .envSets()
    // Every vault is born with an empty "default". In a project that is the
    // environment you work in; in the library it is an entry nobody created,
    // with no name and nothing in it, sitting at the top of a list of things
    // you did create. It appears the moment it has anything in it.
    .filter((s) => !s.isAccount)
    .filter((s) => !(s.name === "default" && s.keys.length === 0 && !s.description && !s.whenToUse))
    .map((s) => ({
      name: s.name,
      label: s.label,
      description: s.description,
      whenToUse: s.whenToUse,
      source: s.source,
      keys: s.keys,
      linked: linked.has(s.name),
    }));
}

export type { EnvMeta };
