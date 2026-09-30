/**
 * What the app's page is told: the folder, its sets and keys (masked), the team, the
 * agent, the ladder. `/api/state` returns this, and so does every write.
 */
import { existsSync, readFileSync } from "node:fs";
import { join, basename } from "node:path";
import { scanRepo } from "./scan.ts";
import { loadPolicy, DEFAULT_POLICY } from "./mcp.ts";
import { approvalPromptAvailable } from "./approval.ts";
import { readPolicyFile } from "./policy.ts";
import { assess } from "./posture.ts";
import { biometryStatus } from "./biometry.ts";
import { AGENTS, mcpRegistrations } from "./agents.ts";
import { Vault, ValidationError } from "./vault.ts";
import { librarySets, openGlobal, usedSets, globalVaultName, globalVaultExists, namedVaults, ensureProjectVault, suggestSets, LIBRARY_DEFAULT, linkNameFor } from "./library.ts";
import { requireIdentity, publicKeyOf, hushHome, type ResolvedIdentity } from "./identity.ts";
import { CATALOG } from "./services.ts";
import { preview } from "./redact.ts";
import { isTrustError } from "./integrity.ts";

export interface UiCtx {
  /**
   * The project's own vault file. May not exist on disk yet — a links-only or
   * brand-new folder has none until something writes into it — so every use
   * of this must check existsSync() first rather than assume Vault.open() is
   * safe to call.
   */
  vaultPath: string;
  hushDir: string;
  /** The folder hush is serving: where a scan for env-var usage looks, and the name a first project vault takes. */
  root: string;
  defaultEnv: string;
}

/**
 * Which of the three states this folder is in, checked fresh from disk each
 * time rather than cached on ctx: a request can create the vault mid-flight
 * (see projectVault()), and the state() call at the end of that same request
 * has to see the result.
 */
function folderState(ctx: UiCtx): "unset" | "links-only" | "vault" {
  if (existsSync(ctx.vaultPath)) return "vault";
  // Any marker findHushDir() itself accepts means the folder was set up, even
  // before it earns a vault of its own.
  if (existsSync(join(ctx.hushDir, "envs.json")) || existsSync(join(ctx.hushDir, "link.json"))) return "links-only";
  return "unset";
}

/** The project's vault, only if this folder already has one — never Vault.open() on a path that may not exist. */
export function openProjectVault(ctx: UiCtx): Vault | null {
  return existsSync(ctx.vaultPath) ? Vault.open(ctx.vaultPath) : null;
}

/**
 * The project's vault, required. Used by every endpoint that operates on an
 * existing project secret and has no business creating one on the caller's
 * behalf (reveal, move, tag, renaming a set) — the 400 names the state rather
 * than crashing on Vault.open(missing file).
 */
export function requireProjectVault(ctx: UiCtx): Vault {
  const v = openProjectVault(ctx);
  if (v) return v;
  throw new ValidationError(
    folderState(ctx) === "unset"
      ? "This folder isn't set up for hush yet — use the panel on the page to pick sets for it first."
      : "This folder has no vault of its own yet — add a project secret or a teammate to make one.",
  );
}

/** The founding-member shape Vault.create()/ensureProjectVault() want, built the same way `hush init` builds it. */
function memberOf(id: ResolvedIdentity): Parameters<typeof Vault.create>[2] {
  const name = process.env.USER || "me";
  return id.pub ? { name, pub: id.pub, priv: id.priv } : { name, ageRecipient: id.age!.recipients[0] };
}

/**
 * Open this project's vault, making one the moment something actually needs
 * to write into it — a links-only folder has no business carrying key
 * material before that. Every write path allowed to create the vault funnels
 * through here, so "made on first write, toast once" is one behavior rather
 * than four near-duplicates that could drift apart.
 */
export function projectVault(ctx: UiCtx, id: ResolvedIdentity): { vault: Vault; created: boolean } {
  return ensureProjectVault(ctx.hushDir, memberOf(id), basename(ctx.root));
}

/**
 * What an agent's presence looks like on disk — the same four facts `hush
 * doctor` checks (cli.ts), read the same way, so the page and the CLI never
 * disagree about whether an agent is wired up here.
 */
function agentStatus(ctx: UiCtx): {
  mcpRegistered: boolean;
  skillInstalled: boolean;
  policyFilePresent: boolean;
  policyFloorPresent: boolean;
} {
  // Every agent hush knows, not only Claude Code's files — as `hush doctor` does.
  const read = (p: string): string | null => {
    try {
      return readFileSync(p, "utf8");
    } catch {
      return null;
    }
  };
  const skills = AGENTS.flatMap((g) => [g.skill.project(ctx.root), g.skill.global?.(process.env)]);
  return {
    mcpRegistered: mcpRegistrations(ctx.root, process.env, read).length > 0,
    skillInstalled: skills.some((p) => !!p && existsSync(p)),
    policyFilePresent: existsSync(join(ctx.hushDir, "policy.json")),
    policyFloorPresent: existsSync(join(hushHome(), "policy.json")),
  };
}

interface ResolutionLine {
  /**
   * Index into `used` — the entry this line belongs to, so up/down and "stop
   * using" act on the right one even when "default" prints two lines (see
   * below: it is two floors, not one).
   */
  usedIndex: number;
  /** Only the first line for a usedIndex carries the reorder/remove controls. */
  first: boolean;
  name: string;
  label: string;
  note: string;
  removable: boolean;
}

/**
 * What a run actually gets, without decrypting anything — the same branching
 * composeSets() (library.ts) uses to build the real layers, reading only set
 * metadata (Vault#sets/#hasSet) rather than Vault#materialize(). /api/state
 * has to stay value-blind, and composeSets() is not: it decrypts every layer
 * to build the run's environment, which would make rendering this list alone
 * enough to prompt a hardware key.
 */
function resolutionLines(vault: Vault | null, libraryVault: Vault | null, used: string[]): ResolutionLine[] {
  const lines: ResolutionLine[] = [];
  used.forEach((name, usedIndex) => {
    let first = true;
    const push = (label: string, note: string, removable: boolean) => {
      lines.push({ usedIndex, first, name, label, note, removable });
      first = false;
    };
    if (name === "default") {
      push("default", vault?.hasSet("default") ? "(this folder)" : "(this folder, once you add one)", false);
      return;
    }
    if (name === LIBRARY_DEFAULT) {
      push("default", libraryVault?.hasSet("default") ? "(library)" : "(not found)", true);
      return;
    }
    const projSet = vault?.sets().find((s) => s.name === name);
    if (projSet) { push(projSet.label, "(this folder)", true); return; }
    const libSet = libraryVault?.sets().find((s) => s.name === name);
    if (libSet) { push(libSet.label, "(library)", true); return; }
    push(name, "(not found)", true);
  });
  return lines;
}

/**
 * What this folder's code reads from the environment, for the page's "your
 * code needs" panel. Names and file paths only — scanning never looks at a
 * value. Cached briefly because state() runs after every click and a large
 * repo is not worth walking that often; a few seconds stale is invisible.
 */
const SCAN_TTL_MS = 10_000;
let scanCache: { root: string; at: number; needs: { name: string; sites: string[]; declared: boolean }[] } | null = null;
function codeNeeds(root: string): { name: string; sites: string[]; declared: boolean }[] {
  if (scanCache && scanCache.root === root && Date.now() - scanCache.at < SCAN_TTL_MS) return scanCache.needs;
  let needs: { name: string; sites: string[]; declared: boolean }[] = [];
  try {
    needs = scanRepo(root).slice(0, 300).map((u) => ({ name: u.name, sites: u.sites.slice(0, 3), declared: u.declared }));
  } catch {
    /* an unreadable tree is not a reason for the page to fail */
  }
  scanCache = { root, at: Date.now(), needs };
  return needs;
}

export function state(ctx: UiCtx) {
  const id = requireIdentity();
  const fState = folderState(ctx);
  // Never Vault.open() a project vault that does not exist yet — that is
  // exactly the crash a links-only or brand-new folder used to hit.
  const vault = fState === "vault" ? Vault.open(ctx.vaultPath) : null;

  // "default" is the floor, then linked sets in the order they were added —
  // this is the one order the whole page agrees on: which sets a run actually
  // gets, and in what precedence. A card's position in it is what "used ·
  // 2nd" means; a set not in the list at all gets no position.
  const used = usedSets(ctx.hushDir);
  const positionOf = (name: string): number | null => {
    const i = used.indexOf(name);
    return i === -1 ? null : i;
  };

  // A vault whose membership or key changed without anyone here accepting it
  // is not decrypted — not even for a masked preview (V-1). The page still
  // loads, with the previews blank and the reason at the top, because the
  // answer is a terminal command a person runs, not a button an agent that
  // can see this page's URL could press.
  let trust: string[] | null = null;
  const describe = (v: Vault, scope: string) => {
    try {
      return v.list(scope).map((i) => ({
        key: i.key,
        preview: preview(v.get(id, scope, i.key)),
        updatedBy: i.updatedBy,
        updatedAt: i.updatedAt,
        note: i.note ?? "",
      }));
    } catch (e) {
      if (!isTrustError(e)) throw e;
      trust ??= e.message.split("\n").map((l) => l.trim()).filter(Boolean);
      return [];
    }
  };

  const projectSets = vault
    ? vault.sets().map((s) => ({
        where: "project" as const,
        name: s.name,
        label: s.label,
        description: s.description ?? "",
        whenToUse: s.whenToUse ?? "",
        source: s.source ?? "",
        keys: s.keys,
        secrets: describe(vault, s.name),
        used: used.includes(s.name),
        position: positionOf(s.name),
      }))
    : [];

  // The library is a second vault, and it may not exist yet or may not be
  // readable by this identity. Neither is a reason for the whole page to fail,
  // so it degrades to an empty list with a note rather than a 500.
  let library: ReturnType<typeof librarySets> = [];
  let libraryError = "";
  let libraryVault: Vault | null = null;
  try {
    library = librarySets();
    libraryVault = openGlobal();
  } catch (e) {
    libraryError = (e as Error).message.split("\n")[0];
  }

  const librarySetsOut = library.map((s) => ({
    where: "library" as const,
    name: s.name,
    label: s.label,
    description: s.description ?? "",
    whenToUse: s.whenToUse ?? "",
    source: s.source ?? "",
    keys: s.keys,
    secrets: libraryVault ? describe(libraryVault, s.name) : [],
    // What the page sends to /api/link: the library's default is recorded as
    // library:default, because a plain "default" means this folder's own.
    link: linkNameFor("library", s.name),
    used: used.includes(linkNameFor("library", s.name)),
    position: positionOf(linkNameFor("library", s.name)),
  }));

  // A folder with no marker at all gets offered a one-click setup: what its
  // code references, and which library sets already cover that. Only worth
  // computing once there is no project yet — a linked or vaulted project has
  // already made this choice.
  const needs = codeNeeds(ctx.root);
  const suggestion = fState === "unset" ? (() => {
    const needed = needs.map((u) => u.name);
    const files = new Set<string>();
    for (const u of needs) for (const site of u.sites) files.add(site);
    return {
      needed,
      files: files.size,
      ...suggestSets(needed, library.map((s) => ({ name: s.name, keys: s.keys }))),
    };
  })() : undefined;

  // No project vault to name you in: fall back to the library's membership,
  // then to what a first vault would call you, rather than crashing on
  // vault.memberName() with no vault to ask.
  const meName = vault ? vault.memberName(id) : libraryVault ? libraryVault.memberName(id) : (process.env.USER || "me");

  // The repo's own requireApproval, read raw rather than through the merged
  // floor+repo+base policy: the switches on the page are asking "what does
  // .hush/policy.json say", not "what does the floor force" — a floor
  // requirement the repo cannot turn off regardless of what the switch shows.
  const repoPolicy = readPolicyFile(join(ctx.hushDir, "policy.json"));
  const effectivePolicy = loadPolicy(ctx.hushDir);
  const posture = assess(vault, ctx.hushDir, ctx.root);

  return {
    vault: vault ? vault.data.name : null,
    // hush/v3: only an admin can change who can read it, and every member checks.
    signed: vault ? vault.signed : null,
    trust,
    me: { name: meName, pk: publicKeyOf(id) },
    defaultEnv: ctx.defaultEnv,
    folder: { root: ctx.root, state: fState, hushDir: ctx.hushDir },
    // Derived for one release: this used to be the only signal for "no
    // project to show"; folder.state is now the real source of truth and the
    // page reads that instead. Kept in case anything else still reads it.
    standalone: fState === "unset",
    ...(suggestion ? { suggestion } : {}),
    global: {
      name: globalVaultName(),
      exists: globalVaultExists(),
      others: namedVaults().filter((v) => v !== globalVaultName()),
      error: libraryError,
    },
    // Every named set in your library, and whether this project uses it. The
    // masked previews come too: without them you could see a library set but
    // not work on the keys inside it, and the state everyone starts in is one
    // big unnamed pile that needs carving up.
    library: librarySetsOut,
    // Fed to the "for a service…" hint on the new-set form, so naming a set
    // for a known service (e.g. twilio) can prefill its variable names.
    catalog: Object.entries(CATALOG).map(([id2, d]) => ({ id: id2, label: d.label, vars: d.vars })),
    project: projectSets,
    used,
    // What a run actually gets, in precedence order — the numbered list on
    // the "This folder" section. Value-blind: see resolutionLines().
    resolution: resolutionLines(vault, libraryVault, used),
    policy: {
      requireApproval: repoPolicy.requireApproval ?? DEFAULT_POLICY.requireApproval,
      // The repo's own value when it has one, so the page shows the number the
      // dialog's button is actually built from.
      approvalTtlSeconds: repoPolicy.approvalTtlSeconds ?? DEFAULT_POLICY.approvalTtlSeconds,
      biometry: effectivePolicy.biometry,
      // So the page does not offer "preferred" fingerprint approval on a
      // machine that has no fingerprint reader to prefer.
      biometryAvailable: biometryStatus().available,
      // Whether anything here can put an approval in front of a person. When
      // nothing can, every gated action is refused, and the page says so.
      promptAvailable: approvalPromptAvailable(),
    },
    // Names only: which variables this folder's code reads, and where.
    needs,
    agent: agentStatus(ctx),
    posture: {
      rung: posture.rung,
      name: posture.name,
      next: posture.next ? { label: posture.next.label, command: posture.next.command ?? "", why: posture.next.why ?? "" } : null,
    },
    members: vault
      ? vault.members().map((m) => ({
          name: m.name,
          role: m.role,
          pk: m.pk,
          fingerprint: m.fingerprint,
          kind: m.kind === "age" ? "hardware" : "key",
          canDecrypt: m.canDecrypt,
          // hush/v3: a scoped member reads only these; a CI identity is a machine.
          sets: m.sets ?? null,
          ci: m.ci === true,
        }))
      : [],
  };
}
