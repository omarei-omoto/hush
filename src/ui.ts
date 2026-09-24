/**
 * `hush ui` — a local web app for managing the vault.
 *
 * Security posture, because this thing holds every key you own:
 *   - binds 127.0.0.1 only, never 0.0.0.0
 *   - a random per-session token is required on every /api call
 *   - the Host header must be loopback, which blocks DNS-rebinding
 *   - values are sent to the browser as masked previews; revealing one is an
 *     explicit click that gets written to the audit log
 *   - no CDN, no external fonts, no third-party JS. Everything is inline.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { dirname, join, basename } from "node:path";
import { scanRepo, parseEnvFile } from "./scan.ts";
import { loadPolicy, DEFAULT_POLICY } from "./mcp.ts";

/**
 * Never let a repo-supplied symlink redirect a write hush performs.
 *
 * `.hush/policy.json` is a committed file, so a clone can make that path a
 * symlink (git stores them) pointing at the user's own `~/.hush/policy.json`
 * floor. `writeFileSync` follows it, so one ordinary settings change in the
 * page would rewrite the floor — the control SECURITY.md names as the
 * mitigation against repo-controlled policy. The class has to hold at every
 * path hush writes into a repository, not one.
 *
 * Returns an error message, or null when the path is safe to write.
 */
function symlinkRefusal(path: string): string | null {
  const st = lstatSync(path, { throwIfNoEntry: false });
  if (st && !st.isFile()) {
    return `${path} is not a regular file — it is a link or a device. Remove it and try again.`;
  }
  return null;
}
import { requestApproval, approvalPromptAvailable } from "./approval.ts";
import { readPolicyFile } from "./policy.ts";
import { assess } from "./posture.ts";
import { biometryStatus } from "./biometry.ts";
import { PAGE } from "./ui-page.ts";
import { AGENTS, mcpRegistrations } from "./agents.ts";
import {
  Vault, locateProject, namedVaultPath, audit,
  isValidationError, ValidationError, slugifyEnv,
  assertProjectHushDir,
} from "./vault.ts";
import {
  librarySets, loadLinks, saveLinks, openGlobal, usedSets,
  globalVaultName, globalVaultExists, namedVaults, saveConfig,
  writeProjectDotfiles, ensureProjectVault, suggestSets, LIBRARY_DEFAULT, linkNameFor,
} from "./library.ts";
import { requireIdentity, publicKeyOf, hushHome, type ResolvedIdentity } from "./identity.ts";
import { CATALOG, serviceForVar } from "./services.ts";
import { preview } from "./redact.ts";

const TOKEN = randomBytes(24).toString("base64url");

/** Compare against the session token without leaking its prefix through timing. */
function tokenOk(given: unknown): boolean {
  if (typeof given !== "string") return false;
  const a = Buffer.from(given);
  const b = Buffer.from(TOKEN);
  // Length is not secret (it is fixed), but timingSafeEqual requires a match.
  return a.length === b.length && timingSafeEqual(a, b);
}

interface UiCtx {
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
function openProjectVault(ctx: UiCtx): Vault | null {
  return existsSync(ctx.vaultPath) ? Vault.open(ctx.vaultPath) : null;
}

/**
 * The project's vault, required. Used by every endpoint that operates on an
 * existing project secret and has no business creating one on the caller's
 * behalf (reveal, move, tag, renaming a set) — the 400 names the state rather
 * than crashing on Vault.open(missing file).
 */
function requireProjectVault(ctx: UiCtx): Vault {
  const v = openProjectVault(ctx);
  if (v) return v;
  throw new ValidationError(
    folderState(ctx) === "unset"
      ? "This folder isn't set up for hush yet — use the panel on the page to pick sets for it first."
      : "This folder has no vault of its own yet — add a project secret or a teammate to make one.",
  );
}

/** The founding-member shape Vault.create()/ensureProjectVault() want, built the same way `hush init` builds it. */
function memberOf(id: ResolvedIdentity): { name: string; pub?: Buffer; ageRecipient?: string } {
  const name = process.env.USER || "me";
  return id.pub ? { name, pub: id.pub } : { name, ageRecipient: id.age!.recipients[0] };
}

/**
 * Open this project's vault, making one the moment something actually needs
 * to write into it — a links-only folder has no business carrying key
 * material before that. Every write path allowed to create the vault funnels
 * through here, so "made on first write, toast once" is one behavior rather
 * than four near-duplicates that could drift apart.
 */
function projectVault(ctx: UiCtx, id: ResolvedIdentity): { vault: Vault; created: boolean } {
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
 * Hard ceiling on a request body.
 *
 * This has to sit above the largest thing the API legitimately accepts — a
 * staged .env, capped at 2 MB — or that check becomes unreachable and an
 * oversized drop surfaces as a connection reset instead of a clear message.
 */
const MAX_BODY_BYTES = 4 * 1024 * 1024;

function readBody(req: IncomingMessage): Promise<any> {
  return new Promise((res, rej) => {
    let data = "";
    req.on("data", (c) => {
      data += c;
      if (data.length > MAX_BODY_BYTES) {
        // Reject *and* stop reading: settling the promise alone left the socket
        // streaming into a string nobody would ever look at.
        req.destroy();
        rej(new Error("body too large"));
      }
    });
    req.on("end", () => {
      try {
        res(data ? JSON.parse(data) : {});
      } catch {
        rej(new Error("invalid JSON"));
      }
    });
  });
}

const json = (res: ServerResponse, code: number, body: unknown) => {
  const s = JSON.stringify(body);
  res.writeHead(code, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(s),
    "cache-control": "no-store",
  });
  res.end(s);
};

/** Reject anything that isn't a loopback Host — stops DNS-rebinding attacks. */
function hostIsLocal(req: IncomingMessage): boolean {
  const host = (req.headers.host ?? "").split(":")[0];
  return host === "127.0.0.1" || host === "localhost" || host === "[::1]" || host === "::1";
}

/**
 * A dropped .env, parsed and held server-side until it is imported or expires.
 *
 * The values deliberately do not travel back to the browser: staging returns
 * names, masked previews and suggestions only. The page already holds the file
 * it just read, but there is no reason to also put every secret into an API
 * response, the network panel, and any proxy in between.
 */
interface Stage {
  at: number;
  file: string;
  values: Record<string, string>;
}

const stages = new Map<string, Stage>();
/**
 * How long a dropped file waits to be reviewed before its plaintext is dropped.
 *
 * Overridable only downwards, and only within this process. Fifteen minutes of
 * real time is not something a test can wait for, and a sweep that is never
 * exercised is a sweep that can quietly stop happening — which is exactly what
 * mutation testing found. Raising it is refused rather than honoured: the point
 * of the cap is that plaintext does not sit in memory indefinitely, and an
 * environment variable should not be able to undo that.
 */
export const DEFAULT_STAGE_TTL_MS = 15 * 60_000;

/** Exported so the clamp can be checked without waiting fifteen minutes. */
export const resolveStageTtl = (raw: unknown, dflt = DEFAULT_STAGE_TTL_MS): number => {
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 && n < dflt ? n : dflt;
};

const STAGE_TTL_MS = resolveStageTtl(process.env.HUSH_UI_STAGE_TTL_MS);

/**
 * Staging holds plaintext, so it is bounded on both axes. Without a cap, a page
 * left open dropping files could pin an unlimited amount of secret material in
 * the server's memory for the whole TTL.
 */
const MAX_STAGES = 20;
const MAX_STAGED_BYTES = 8 * 1024 * 1024;

function sweepStages(): void {
  const now = Date.now();
  for (const [id, s] of stages) if (now - s.at > STAGE_TTL_MS) stages.delete(id);
}

const stagedBytes = (): number => {
  let total = 0;
  for (const s of stages.values()) {
    for (const [k, v] of Object.entries(s.values)) total += k.length + v.length;
  }
  return total;
};

/** Forget a stage's plaintext the moment it is no longer needed. */
function dropStages(ids: unknown): number {
  let n = 0;
  for (const id of Array.isArray(ids) ? ids : []) {
    if (stages.delete(String(id))) n++;
  }
  return n;
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

function state(ctx: UiCtx) {
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

  const describe = (v: Vault, scope: string) =>
    v.list(scope).map((i) => ({
      key: i.key,
      preview: preview(v.get(id, scope, i.key)),
      updatedBy: i.updatedBy,
      updatedAt: i.updatedAt,
      note: i.note ?? "",
    }));

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
        }))
      : [],
  };
}

async function handleApi(ctx: UiCtx, req: IncomingMessage, res: ServerResponse, path: string) {
  // Throws a 400-shaped message naming the folder's state rather than
  // crashing on Vault.open() of a project vault that does not exist yet.
  const vault = () => requireProjectVault(ctx);
  const id = requireIdentity();

  if (path === "/api/state" && req.method === "GET") {
    return json(res, 200, state(ctx));
  }

  const body = await readBody(req);

  switch (path) {
    case "/api/secret": {
      const { scope, key, value, note, where } = body;
      if (!scope || !key) return json(res, 400, { error: "scope and key are required" });
      const inLibrary = where === "library";
      let v: Vault;
      let vaultCreated = false;
      if (inLibrary) {
        const g = openGlobal();
        if (!g) return json(res, 400, { error: "you have no library vault yet" });
        v = g;
      } else {
        // A project secret is exactly the moment a links-only folder earns a
        // vault of its own — not before.
        const opened = projectVault(ctx, id);
        v = opened.vault;
        vaultCreated = opened.created;
      }
      if (value === null) {
        v.delete(scope, key);
        audit(ctx.hushDir, { actor: "ui", action: "delete", scope, key, where });
      } else {
        if (typeof value !== "string" || !value) return json(res, 400, { error: "empty value" });
        v.set(id, scope, key, value, typeof note === "string" && note ? note : undefined);
        audit(ctx.hushDir, { actor: "ui", action: "set", scope, key, where });
      }
      v.save();
      return json(res, 200, { ...state(ctx), ...(vaultCreated ? { vaultCreated: true } : {}) });
    }

    /**
     * Change a secret's tag without touching its value.
     *
     * The note lives beside the ciphertext rather than inside it, so this never
     * unseals anything — relabelling must not make a hardware key prompt.
     */
    /**
     * Name an env set, describe it, rename it, or throw it away.
     *
     * `where` says which vault: "library" for the global one, "project" for this
     * repo's. Renaming is the only operation here that touches ciphertext — the
     * set's name is bound into every value's AAD, so the values are re-sealed.
     */
    case "/api/env": {
      const { action, where, name, label, description, whenToUse, service } = body;
      const inLibrary = where !== "project";
      const id = requireIdentity();

      // Naming the first set a links-only folder gets is a write to the
      // project vault same as any other, so it is the one non-create path
      // allowed to make one; renaming/describing/deleting need a set that
      // already exists, which means the vault already does too.
      let vaultCreated = false;
      const open = (): Vault => {
        if (!inLibrary) {
          if (action === "create") {
            const opened = projectVault(ctx, id);
            vaultCreated = opened.created;
            return opened.vault;
          }
          return vault();
        }
        const g = openGlobal();
        if (!g) throw new ValidationError("You have no library vault yet.");
        return g;
      };

      if (action === "create") {
        const spelling = String(label ?? name ?? "").trim();
        if (!spelling) return json(res, 400, { error: "give it a name" });
        const v = open();
        const slug = slugifyEnv(spelling);
        if (v.data.envs[slug]) return json(res, 409, { error: '"' + spelling + '" already exists' });
        v.ensureEnvExists(slug);
        v.describeEnv(slug, {
          label: spelling,
          description: typeof description === "string" ? description : undefined,
          whenToUse: typeof whenToUse === "string" ? whenToUse : undefined,
        });
        v.save();
        audit(ctx.hushDir, { actor: "ui", action: "env.create", where, name: slug });
        // "for a service…" only hints at which variables to prompt for — it
        // never stores a value itself, so a known service still goes through
        // /api/secret per row like any other key.
        const vars = typeof service === "string" ? (CATALOG[service.toLowerCase()]?.vars ?? []) : [];
        return json(res, 200, { ...state(ctx), created: slug, vars, ...(vaultCreated ? { vaultCreated: true } : {}) });
      }

      if (!name) return json(res, 400, { error: "name is required" });
      const v = open();
      if (!v.data.envs[String(name)]) return json(res, 404, { error: "no such env set" });

      if (action === "rename") {
        const spelling = String(label ?? "").trim();
        if (!spelling) return json(res, 400, { error: "give it a name" });
        const next = slugifyEnv(spelling);
        if (next !== String(name)) {
          v.renameEnv(id, String(name), next);
          // Anything pinned to the old name follows it, or the rename quietly
          // breaks every project that was using it.
          const links = loadLinks(ctx.hushDir);
          if (inLibrary && links.includes(String(name))) {
            saveLinks(ctx.hushDir, links.map((l) => (l === String(name) ? next : l)));
          }
        }
        v.describeEnv(next, { label: spelling });
        v.save();
        audit(ctx.hushDir, { actor: "ui", action: "env.rename", where, from: name, to: next });
        return json(res, 200, { ...state(ctx), renamed: next });
      }

      if (action === "describe") {
        v.describeEnv(String(name), {
          ...(typeof label === "string" ? { label } : {}),
          ...(typeof description === "string" ? { description } : {}),
          ...(typeof whenToUse === "string" ? { whenToUse } : {}),
        });
        v.save();
        audit(ctx.hushDir, { actor: "ui", action: "env.describe", where, name });
        return json(res, 200, state(ctx));
      }

      if (action === "delete") {
        const keys = Object.keys(v.data.envs[String(name)] ?? {});
        delete v.data.envs[String(name)];
        if (v.data.meta) delete v.data.meta[String(name)];
        v.markStructural();
        v.save();
        if (inLibrary) {
          saveLinks(ctx.hushDir, loadLinks(ctx.hushDir).filter((l) => l !== String(name)));
        }
        audit(ctx.hushDir, { actor: "ui", action: "env.delete", where, name, keys: keys.length });
        return json(res, 200, state(ctx));
      }

      return json(res, 400, { error: "unknown action" });
    }

    /**
     * Whether this project uses a set — library or project, either can be
     * switched on or off the same way. `order` replaces the whole list at
     * once, which is what a drag-to-reorder does; position in that list is
     * precedence, so this is also how resolution order changes.
     */
    case "/api/link": {
      const { name, use, order } = body;
      if (Array.isArray(order)) {
        saveLinks(ctx.hushDir, order.map(String));
        audit(ctx.hushDir, { actor: "ui", action: "env.order", order });
        return json(res, 200, state(ctx));
      }
      if (!name) return json(res, 400, { error: "name is required" });
      const links = loadLinks(ctx.hushDir);
      const next = use === false
        ? links.filter((l) => l !== String(name))
        : [...links, String(name)];
      saveLinks(ctx.hushDir, next);
      audit(ctx.hushDir, { actor: "ui", action: use === false ? "env.drop" : "env.use", name });
      return json(res, 200, state(ctx));
    }

    /** Pick which vault is your library, or make one. */
    case "/api/global": {
      const { name, create } = body;
      const id = requireIdentity();
      if (create) {
        const target = String(name || globalVaultName());
        const path = namedVaultPath(target);
        if (existsSync(path)) return json(res, 409, { error: 'a vault called "' + target + '" already exists' });
        mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
        Vault.create(path, target, {
          name: "me",
          pub: id.pub,
          ageRecipient: id.age?.recipients[0],
        });
        saveConfig({ globalVault: target });
        audit(ctx.hushDir, { actor: "ui", action: "global.create", name: target });
        return json(res, 200, state(ctx));
      }
      if (!name) return json(res, 400, { error: "name is required" });
      if (!existsSync(namedVaultPath(String(name)))) {
        return json(res, 404, { error: 'no vault called "' + name + '"' });
      }
      saveConfig({ globalVault: String(name) });
      audit(ctx.hushDir, { actor: "ui", action: "global.adopt", name });
      return json(res, 200, state(ctx));
    }

    /** Move a key from one named set to another. Re-seals it under its new name. */
    case "/api/move": {
      const { where, key, from, to } = body;
      if (!key || !from || !to) return json(res, 400, { error: "key, from and to are required" });
      const id = requireIdentity();
      const inLibrary = where !== "project";
      let v: Vault;
      if (inLibrary) {
        const g = openGlobal();
        if (!g) return json(res, 400, { error: "you have no library vault yet" });
        v = g;
      } else {
        v = vault();
      }
      v.moveSecret(id, String(key), String(from), String(to));
      v.save();
      audit(ctx.hushDir, { actor: "ui", action: "move", where, key, from, to });
      return json(res, 200, state(ctx));
    }

    case "/api/tag": {
      const { scope, key, note } = body;
      if (!scope || !key) return json(res, 400, { error: "scope and key are required" });
      const v = vault();
      if (!v.has(String(scope), String(key))) return json(res, 404, { error: "no such secret" });
      const label = typeof note === "string" ? note : "";
      v.retag(String(scope), String(key), label);
      v.save();
      audit(ctx.hushDir, { actor: "ui", action: "tag", scope, key, tagged: Boolean(label) });
      return json(res, 200, state(ctx));
    }

    /**
     * Parse a dropped .env and hold it for review. Returns metadata only —
     * names, masked previews, a suggested destination, and where each key
     * already exists — so nothing has to be committed sight unseen.
     */
    case "/api/stage": {
      sweepStages();
      const { text, filename } = body;
      if (typeof text !== "string") return json(res, 400, { error: "text is required" });
      if (text.length > 2_000_000) {
        return json(res, 400, { error: "that file is too large to be a .env (2 MB limit)" });
      }

      if (stages.size >= MAX_STAGES || stagedBytes() + text.length > MAX_STAGED_BYTES) {
        return json(res, 429, {
          error: "too many uploads waiting for review — import or discard the ones on screen first",
        });
      }

      const parsed = parseEnvFile(text);
      // Staging never writes anywhere, so it must not require a project vault
      // that does not exist yet — an unset or links-only folder just sees no
      // existing project scopes to flag a conflict against.
      const v = openProjectVault(ctx);
      const used = usedSets(ctx.hushDir);

      // Names the parser refused. Derived from its own output, so the two can
      // never disagree about what counts as a usable variable name.
      const rejected: string[] = [];
      for (const raw of text.split(/\r?\n/)) {
        const line = raw.trim();
        if (!line || line.startsWith("#")) continue;
        const eq = line.indexOf("=");
        if (eq < 1) continue;
        const name = line.slice(0, eq).replace(/^export\s+/, "").trim();
        if (!(name in parsed) && !rejected.includes(name)) rejected.push(name);
      }

      const scopes = v ? v.envNames() : [];
      const entries = Object.entries(parsed).map(([key, value]) => {
        const service = serviceForVar(key);
        // Prefer a set this project already uses that is named for the
        // service ("fal/acme"); otherwise any existing set named for it —
        // the "/" is just a naming convention here, not a special lookup.
        const pinned = service ? used.find((n) => n.startsWith(service + "/")) : undefined;
        const anyForService = service ? scopes.filter((s) => s.startsWith(service + "/")) : [];
        return {
          key,
          preview: preview(value),
          length: value.length,
          multiline: value.includes("\n"),
          service,
          suggestedScope: pinned ?? anyForService[0] ?? ctx.defaultEnv,
          existsIn: v ? scopes.filter((s) => v!.has(s, key)) : [],
        };
      });

      const stageId = randomBytes(12).toString("base64url");
      stages.set(stageId, {
        at: Date.now(),
        file: typeof filename === "string" && filename ? filename.slice(0, 80) : ".env",
        values: parsed,
      });
      audit(ctx.hushDir, { actor: "ui", action: "stage", file: filename, keys: entries.length });

      return json(res, 200, { stageId, file: stages.get(stageId)!.file, entries, rejected });
    }

    /**
     * Throw away staged uploads. The page's Discard button used to drop only its
     * own reference, leaving the plaintext in server memory until the TTL.
     */
    case "/api/discard": {
      const dropped = dropStages(body?.stageIds);
      audit(ctx.hushDir, { actor: "ui", action: "discard", stages: dropped });
      return json(res, 200, { discarded: dropped });
    }

    /** Commit a reviewed stage: each key to the scope and tag chosen for it. */
    case "/api/import": {
      sweepStages();
      const { stages: batches, overwrite, where } = body as {
        stages?: { stageId: string; assignments: Record<string, { scope: string; note?: string }> }[];
        overwrite?: boolean;
        where?: string;
      };
      if (!Array.isArray(batches) || batches.length === 0) {
        return json(res, 400, { error: "nothing to import" });
      }

      // A dropped .env usually belongs in the library — it is yours, and you
      // want it from every project — so the importer can target either vault.
      const intoLibrary = where === "library";
      let v: Vault;
      let vaultCreated = false;
      if (intoLibrary) {
        const g = openGlobal();
        if (!g) return json(res, 400, { error: "you have no library vault yet" });
        v = g;
      } else {
        // Importing into the project is a write to it, so it is one of the
        // moments a links-only folder earns a vault of its own.
        const opened = projectVault(ctx, id);
        v = opened.vault;
        vaultCreated = opened.created;
      }
      const imported: string[] = [];
      const skipped: { key: string; why: string }[] = [];

      for (const batch of batches) {
        const stage = stages.get(String(batch.stageId));
        if (!stage) {
          skipped.push({ key: "(whole file)", why: "this upload expired — drop it again" });
          continue;
        }
        for (const [key, choice] of Object.entries(batch.assignments ?? {})) {
          const value = stage.values[key];
          if (value === undefined) {
            skipped.push({ key, why: "not part of that upload" });
            continue;
          }
          const scope = String(choice?.scope ?? "");
          try {
            if (v.has(scope, key) && !overwrite) {
              skipped.push({ key, why: `already in ${scope}` });
              continue;
            }
            const note = typeof choice.note === "string" && choice.note.trim() ? choice.note.trim() : undefined;
            v.set(id, scope, key, value, note);
            imported.push(`${scope}/${key}`);
          } catch (e) {
            skipped.push({ key, why: (e as Error).message.split("\n")[0] });
          }
        }
      }

      if (imported.length) v.save();
      for (const batch of batches) stages.delete(String(batch.stageId));
      audit(ctx.hushDir, {
        actor: "ui",
        action: "import",
        imported: imported.length,
        skipped: skipped.length,
      });

      // Filing a key into a service-named set this project does not use means
      // `hush run` will not hand it to the app — and nothing else would say so.
      const used = usedSets(ctx.hushDir);
      const unpinned: { service: string; account: string; scope: string; keys: number }[] = [];
      for (const entry of imported) {
        const scope = entry.slice(0, entry.lastIndexOf("/"));
        const sep = scope.indexOf("/");
        if (sep < 1) continue; // not shaped like "<service>/<account>" — nothing to warn about
        if (used.includes(scope)) continue; // already used by this project
        const service = scope.slice(0, sep);
        const account = scope.slice(sep + 1);
        const seen = unpinned.find((u) => u.scope === scope);
        if (seen) seen.keys++;
        else unpinned.push({ service, account, scope, keys: 1 });
      }

      return json(res, 200, { ...state(ctx), imported, skipped, unpinned, ...(vaultCreated ? { vaultCreated: true } : {}) });
    }

    /**
     * The old "service accounts" vocabulary. An account was always just a set
     * named "service/account"; naming one is now /api/env `create` with an
     * optional `service` hint, so this endpoint is gone rather than kept as a
     * second way to make the same thing.
     */
    case "/api/use":
      return json(res, 410, {
        error: "/api/use is gone — use /api/link to choose which sets this project uses.",
      });

    case "/api/reveal": {
      const { scope, key, where } = body;
      if (!scope || !key) return json(res, 400, { error: "scope and key are required" });

      // Handing back plaintext is the most dangerous thing this server does, so
      // it goes through the same approval policy as everything else rather than
      // being trusted because it came from localhost.
      const policy = loadPolicy(ctx.hushDir);
      if (policy.requireApproval.includes("reveal")) {
        const ap = await requestApproval(ctx.hushDir, {
          action: "reveal",
          summary: `Reveal the value of ${key}`,
          detail: [`Scope:  ${scope}`, "It will be shown in your browser."],
          // Deliberately not cached with the run scope: revealing is its own act.
          scope: `reveal:${scope}:${key}`,
          ttlSeconds: 0,
          biometry: policy.biometry,
        });
        audit(ctx.hushDir, { actor: "ui", action: "approval", on: "reveal", scope, key, decision: ap.decision, via: ap.via });
        if (ap.decision === "deny" || ap.decision === "timeout") {
          return json(res, 403, { error: ap.note ?? `Not approved (${ap.decision}).` });
        }
      }

      // Same vault the key was written to: a library card's reveal used to
      // look in the project vault, and either 404 or show a same-named
      // project key as if it were the library one.
      const source = where === "library" ? openGlobal() : vault();
      if (!source) return json(res, 400, { error: "you have no library vault yet" });
      const value = source.get(id, scope, key);
      audit(ctx.hushDir, { actor: "ui", action: "reveal", scope, key, where });
      return json(res, 200, { value });
    }

    case "/api/team": {
      const { action, name, pk } = body;
      // Adding or removing a teammate only makes sense against a real vault,
      // and giving someone access is exactly the kind of write a links-only
      // folder should earn one for.
      const { vault: v, created: vaultCreated } = projectVault(ctx, id);
      if (action === "remove") {
        const r = v.removeRecipient(id, name);
        v.save();
        audit(ctx.hushDir, { actor: "ui", action: "team.remove", name });
        return json(res, 200, {
          ...state(ctx),
          notice: `Removed ${name}; re-sealed ${r.reEncrypted} value(s).`,
          ...(vaultCreated ? { vaultCreated: true } : {}),
        });
      }
      v.addRecipient(id, name, pk);
      v.save();
      audit(ctx.hushDir, { actor: "ui", action: "team.add", name });
      return json(res, 200, { ...state(ctx), ...(vaultCreated ? { vaultCreated: true } : {}) });
    }

    /**
     * "Set this folder up" — a links-only project is born here: which library
     * (or, if this project already has a vault, project) sets it uses, and
     * optionally the approval floor a coding agent gets pointed at it.
     *
     * Deliberately makes no vault: a folder that only uses library sets has
     * no business carrying key material until it actually needs to (see
     * projectVault()).
     */
    case "/api/setup": {
      const { use, agent } = body;
      if (!Array.isArray(use) || use.some((u: unknown) => typeof u !== "string")) {
        return json(res, 400, { error: "use must be a list of set names" });
      }
      const existing = openProjectVault(ctx);
      const known = new Set([...librarySets().map((s) => s.name), ...(existing ? existing.envNames() : [])]);
      const unknown = (use as string[]).find((u) => !known.has(u));
      if (unknown) {
        return json(res, 400, {
          error: `No set called "${unknown}". You have: ${known.size ? [...known].join(", ") : "none yet"}.`,
        });
      }

      writeProjectDotfiles(ctx.hushDir);
      saveLinks(ctx.hushDir, (use as string[]).map((u) => (existing?.hasSet(u) ? u : linkNameFor("library", u))));

      let policyKept = false;
      if (agent) {
        const policyPath = join(ctx.hushDir, "policy.json");
        if (existsSync(policyPath)) {
          // Never clobber a policy someone already tuned — the whole point of
          // "kept" is that a second setup run cannot silently loosen it back
          // to the floor, or tighten one they deliberately relaxed.
          policyKept = true;
        } else {
          assertProjectHushDir(ctx.hushDir);
          const bad = symlinkRefusal(policyPath);
          if (bad) return json(res, 400, { error: bad });
          writeFileSync(policyPath, JSON.stringify({ requireApproval: DEFAULT_POLICY.requireApproval }, null, 2) + "\n");
        }
      }

      audit(ctx.hushDir, { actor: "ui", action: "setup", use, agent: Boolean(agent) });
      return json(res, 200, { ...state(ctx), ...(policyKept ? { policyKept: true } : {}) });
    }

    /**
     * The three switches on the Agent section: what needs your say-so before
     * it happens. Only requireApproval — never any other field — and a repo
     * file that fails to parse is refused rather than silently overwritten,
     * because whatever tightened it (possibly the floor's own advice) would
     * be lost the moment this endpoint guessed at the rest of the file.
     */
    case "/api/policy": {
      const { requireApproval, approvalTtlSeconds } = body;
      const allowed = new Set(["run", "add", "reveal", "request"]);
      if (
        !Array.isArray(requireApproval) ||
        requireApproval.some((a: unknown) => typeof a !== "string" || !allowed.has(a))
      ) {
        return json(res, 400, { error: 'requireApproval must be a list drawn from "run", "add", "reveal", "request"' });
      }
      // How long an "Allow" lasts. Bounded rather than free: under a minute is
      // a dialog per call, and over a day is "off" with extra steps.
      if (approvalTtlSeconds !== undefined) {
        if (
          typeof approvalTtlSeconds !== "number" ||
          !Number.isInteger(approvalTtlSeconds) ||
          approvalTtlSeconds < 60 ||
          approvalTtlSeconds > 86_400
        ) {
          return json(res, 400, { error: "approvalTtlSeconds must be a whole number of seconds, from 60 to 86400" });
        }
      }
      const policyPath = join(ctx.hushDir, "policy.json");
      let existing: Record<string, unknown> = {};
      if (existsSync(policyPath)) {
        try {
          existing = JSON.parse(readFileSync(policyPath, "utf8"));
        } catch {
          return json(res, 400, {
            error: ".hush/policy.json is not valid JSON — fix it by hand before the page can change it",
          });
        }
      }
      assertProjectHushDir(ctx.hushDir);
      mkdirSync(ctx.hushDir, { recursive: true });
      const badPolicyPath = symlinkRefusal(policyPath);
      if (badPolicyPath) return json(res, 400, { error: badPolicyPath });
      writeFileSync(
        policyPath,
        JSON.stringify(
          {
            ...existing,
            requireApproval: [...new Set(requireApproval)],
            // Only when the page sent one, so a caller that knows nothing about
            // this field cannot reset it by leaving it out.
            ...(approvalTtlSeconds === undefined ? {} : { approvalTtlSeconds }),
          },
          null,
          2,
        ) + "\n",
      );
      audit(ctx.hushDir, {
        actor: "ui",
        action: "policy.update",
        requireApproval,
        ...(approvalTtlSeconds === undefined ? {} : { approvalTtlSeconds }),
      });
      return json(res, 200, state(ctx));
    }

    /** The Activity section: the last 100 lines of the local access log, newest first. */
    case "/api/audit": {
      const path = join(ctx.hushDir, "audit.log");
      const lines = existsSync(path) ? readFileSync(path, "utf8").split("\n").filter(Boolean) : [];
      const entries = lines
        .slice(-100)
        .reverse()
        .map((line) => {
          try {
            const parsed = JSON.parse(line) as Record<string, unknown>;
            // Never render a field named "value" — belt and suspenders on top
            // of audit() itself never writing one (see the red-team test).
            const { value: _drop, ...rest } = parsed;
            return rest;
          } catch {
            return null;
          }
        })
        .filter((e): e is Record<string, unknown> => e !== null);
      return json(res, 200, { entries });
    }

    default:
      return json(res, 404, { error: "not found" });
  }
}

export function serveUi(opts: { port?: number; open?: boolean } = {}): void {
  const proj = locateProject(process.cwd());

  // Three states of "this folder": no .hush anywhere above it (a brand-new
  // folder — the setup panel on the page is how it gets one), one that only
  // links library sets (.hush/envs.json, no vault.json yet), and one with a
  // vault of its own. The first two used to be unreachable here at all: no
  // project meant a hard error unless a library existed, and a links-only
  // project meant Vault.open() throwing on a file that was never supposed to
  // exist yet — the crash this whole feature exists to fix.
  let ctx: UiCtx;
  if (proj) {
    ctx = { vaultPath: proj.vaultPath, hushDir: proj.hushDir, root: dirname(proj.hushDir), defaultEnv: proj.env || "default" };
  } else {
    const root = process.cwd();
    const hushDir = join(root, ".hush");
    ctx = { vaultPath: join(hushDir, "vault.json"), hushDir, root, defaultEnv: "default" };
  }

  // Fail fast rather than after the browser opens — but only against a vault
  // that actually exists; a links-only or brand-new folder has none yet, and
  // that is no longer a reason to refuse to start.
  const id = requireIdentity();
  const existing = openProjectVault(ctx);
  if (existing && !existing.canRead(id)) {
    throw new Error(`Your key is not a recipient of vault "${existing.data.name}".`);
  }

  const server = createServer(async (req, res) => {
    try {
      if (!hostIsLocal(req)) {
        return json(res, 403, { error: "loopback only" });
      }
      const url = new URL(req.url ?? "/", "http://127.0.0.1");

      if (url.pathname === "/") {
        if (!tokenOk(url.searchParams.get("t"))) {
          res.writeHead(403, { "content-type": "text/plain" });
          return res.end("Bad or missing token. Start the UI with `hush ui`.");
        }
        const html = PAGE.replace("__TOKEN__", TOKEN);
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
          "content-security-policy":
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
          "referrer-policy": "no-referrer",
        });
        return res.end(html);
      }

      if (url.pathname.startsWith("/api/")) {
        if (!tokenOk(req.headers["x-hush-token"])) return json(res, 403, { error: "bad token" });
        try {
          return await handleApi(ctx, req, res, url.pathname);
        } catch (err) {
          // Rejected input is the caller's problem (400); anything else is ours.
          const message = err instanceof Error ? err.message : String(err);
          if (isValidationError(err) || /body too large|invalid JSON/.test(message)) {
            return json(res, 400, { error: message.split("\n")[0] });
          }
          throw err;
        }
      }

      return json(res, 404, { error: "not found" });
    } catch (err) {
      return json(res, 500, { error: err instanceof Error ? err.message : String(err) });
    }
  });

  const port = opts.port ?? 0;
  server.listen(port, "127.0.0.1", () => {
    const addr = server.address();
    const actual = typeof addr === "object" && addr ? addr.port : port;
    const link = `http://127.0.0.1:${actual}/?t=${TOKEN}`;
    const vaultLine = existing ? `vault: ${existing.data.name}` : "no vault here yet — set this folder up in the browser";
    process.stdout.write(`\n  hush ui  →  ${link}\n\n  ${vaultLine}\n  Ctrl-C to stop.\n\n`);
    if (opts.open !== false) {
      import("node:child_process").then(({ spawn }) => {
        const cmd = process.platform === "darwin" ? "open" : "xdg-open";
        // A server, a container or an SSH session has no xdg-open. spawn()
        // reports that as an 'error' event, and an unhandled one took the
        // whole server down a moment after it printed the link.
        const child = spawn(cmd, [link], { stdio: "ignore", detached: true });
        child.on("error", () => {
          process.stdout.write(`  (could not open a browser here — open the link above yourself)\n\n`);
        });
        child.unref();
      });
    }
  });
}
