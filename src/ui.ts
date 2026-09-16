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
import { requestApproval } from "./approval.ts";
import { readPolicyFile } from "./policy.ts";
import { assess } from "./posture.ts";
import {
  Vault, locateProject, namedVaultPath, audit,
  isValidationError, ValidationError, slugifyEnv,
} from "./vault.ts";
import {
  librarySets, loadLinks, saveLinks, openGlobal, usedSets,
  globalVaultName, globalVaultExists, namedVaults, saveConfig,
  writeProjectDotfiles, ensureProjectVault, suggestSets,
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
  const skillPath = join(ctx.root, ".claude", "skills", "hush", "SKILL.md");
  const globalSkillPath = join(process.env.HOME ?? "", ".claude", "skills", "hush", "SKILL.md");
  return {
    mcpRegistered: existsSync(join(ctx.root, ".mcp.json")),
    skillInstalled: existsSync(skillPath) || existsSync(globalSkillPath),
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
      const libDefault = libraryVault?.sets().find((s) => s.name === "default" && s.keys.length);
      const projDefault = vault?.hasSet("default");
      if (libDefault) push("default", "— your global environment", false);
      if (projDefault) push("default", "(this folder)", false);
      if (!libDefault && !projDefault) push("default", "(this folder, once you add one)", false);
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
    used: used.includes(s.name),
    position: positionOf(s.name),
  }));

  // A folder with no marker at all gets offered a one-click setup: what its
  // code references, and which library sets already cover that. Only worth
  // computing once there is no project yet — a linked or vaulted project has
  // already made this choice.
  const suggestion = fState === "unset" ? (() => {
    const usages = scanRepo(ctx.root);
    const needed = usages.map((u) => u.name);
    const files = new Set<string>();
    for (const u of usages) for (const site of u.sites) files.add(site);
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
    },
    agent: agentStatus(ctx),
    posture: { rung: posture.rung, name: posture.name },
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
      saveLinks(ctx.hushDir, use as string[]);

      let policyKept = false;
      if (agent) {
        const policyPath = join(ctx.hushDir, "policy.json");
        if (existsSync(policyPath)) {
          // Never clobber a policy someone already tuned — the whole point of
          // "kept" is that a second setup run cannot silently loosen it back
          // to the floor, or tighten one they deliberately relaxed.
          policyKept = true;
        } else {
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
        const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
        spawn(cmd, [link], { stdio: "ignore", detached: true }).unref();
      });
    }
  });
}

// ----------------------------------------------------------------- the page
//
// Paper, ink, and redaction. The page is a real application shell — a
// sidebar of five sections and a content column — not a stack of cards.
// The one memorable element is the redaction bar over every secret value:
// solid ink carrying only a masked preview, until Reveal lifts it for 15s.

const PAGE = String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>hush</title>
<style>
:root{
  --paper:#EEF1F4; --panel:#FFFFFF; --ink:#14213D; --ink-muted:#5B6478;
  --line:#D5DAE2; --used:#0F6E56; --wax:#9B1B30;
  --serif:"Iowan Old Style","Palatino Linotype",Palatino,"Book Antiqua",Georgia,serif;
  --sans:-apple-system,"Segoe UI",system-ui,sans-serif;
  --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
}
@media (prefers-color-scheme:dark){:root{
  --paper:#161B26; --panel:#1E2430; --ink:#E6E9EF; --ink-muted:#9AA3B5;
  --line:#2E3644; --used:#3DBE8B; --wax:#E0526A;
}}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 var(--sans)}
button,input,select{font-family:inherit}
a{color:inherit}
.shell{display:flex;min-height:100vh}

/* ---------------------------------------------------------------- sidebar */
.sidebar{width:220px;flex:0 0 220px;background:var(--paper);border-right:1px solid var(--line);
  display:flex;flex-direction:column;padding:20px 16px;gap:22px}
.brand{display:flex;align-items:center;gap:8px;color:var(--ink)}
.brand svg{flex:0 0 auto}
.brand .wordmark{font:600 18px/1 var(--serif);letter-spacing:-.01em}
.navlist{list-style:none;margin:0;padding:0;display:flex;flex-direction:column}
.navlist li{margin:0}
.navlist a{display:flex;align-items:center;justify-content:space-between;gap:8px;
  padding:8px 10px;border-left:2px solid transparent;color:var(--ink-muted);
  text-decoration:none;font-size:15px;border-radius:0 4px 4px 0}
.navlist a:hover{color:var(--ink)}
.navlist a.active{border-left-color:var(--ink);color:var(--ink);font-weight:600}
.navlist .count{font-size:13px;color:var(--ink-muted)}
.navlist .count.used{color:var(--used)}
.sidefoot{margin-top:auto;padding-top:16px;border-top:1px solid var(--line);
  display:flex;flex-direction:column;gap:10px;font-size:13px;color:var(--ink-muted)}
.drophint{background:none;border:0;padding:0;margin:0;text-align:left;color:var(--ink-muted);
  font-size:13px;line-height:1.4;cursor:pointer}
.drophint:hover{color:var(--ink)}
.rung{color:var(--ink-muted);text-decoration:none;font-size:13px}
.rung:hover{color:var(--ink);text-decoration:underline}

/* ---------------------------------------------------------------- content */
.content{flex:1;min-width:0;padding:32px;max-width:944px}
.pageheader{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:28px}
.pageheader h1{font:600 24px/1.2 var(--serif);letter-spacing:-.01em;margin:0}
.pageheader .state{font:15px/1.4 var(--sans);color:var(--ink-muted)}
.sectiontitle{font:600 18px/1.3 var(--serif);letter-spacing:-.01em;margin:0 0 4px}
.subtitle{font:600 15px/1.3 var(--sans);color:var(--ink);margin:24px 0 8px}
.intro{color:var(--ink-muted);font-size:15px;margin:0 0 20px;max-width:64ch}
.content p{margin:0 0 10px}
.muted{color:var(--ink-muted)}
.mono{font-family:var(--mono)}
.serif{font-family:var(--serif)}
.k{font-family:var(--mono);font-size:13px}

/* ------------------------------------------------------------------ ledger */
.ledger{border-top:1px solid var(--line)}
.ledgerrow{border-bottom:1px solid var(--line)}
.rowmain{display:flex;align-items:center;gap:12px;padding:12px 4px}
.chevron{background:none;border:0;padding:2px 4px;cursor:pointer;color:var(--ink-muted);
  font-size:15px;line-height:1;flex:0 0 auto}
.chevron:hover{color:var(--ink)}
.rowname{flex:1;min-width:0}
input[type=text].nameinput{font:600 15px var(--serif);background:transparent;border:1px solid transparent;
  border-radius:4px;padding:2px 4px;margin:-2px 0 0 -4px;width:100%;color:var(--ink)}
input[type=text].nameinput:hover{border-color:var(--line)}
input[type=text].nameinput:focus{border-color:var(--line);background:var(--panel)}
.rowdesc{font-size:13px;color:var(--ink-muted);margin-top:2px}
.rowcount{flex:0 0 auto;font-size:13px;color:var(--ink-muted);white-space:nowrap}
.rowuse{flex:0 0 auto}
.quiet{background:none;border:0;padding:4px 6px;cursor:pointer;color:var(--ink-muted);font-size:13px;border-radius:4px}
.quiet:hover{color:var(--ink);text-decoration:underline}
.quiet.on{color:var(--used)}
.quiet.wax{color:var(--wax)}
.quiet.wax:hover{color:var(--wax)}
.quiet:disabled{cursor:default;text-decoration:none}
/* A single one-line control, not a stray span the name is edited with — click
   turns it into an input; Enter/blur saves through /api/env describe, Escape
   reverts. No separate boxed field duplicates it below the row. */
.editrow{margin-top:2px}
.editspan{cursor:pointer;display:inline-block;max-width:100%;border-bottom:1px dotted transparent}
.editspan:hover{border-bottom-color:var(--ink-muted)}
.editspan.placeholder{font-style:italic}
/* An unset "when to use it" is an invitation, not information: offer it only once the row is open. */
.ledgerrow:not(.open) .editrow.empty[data-field=whenToUse]{display:none}
input[type=text].editinput{background:var(--panel);border:1px solid var(--line);border-radius:4px;
  padding:2px 6px;margin:-2px 0 0 -6px;font-size:13px;color:var(--ink);width:100%;max-width:60ch}
input[type=text].editinput:focus{border-color:var(--ink);outline:none}
.rowdetail{padding:0 4px 16px 32px}
/* Dimming is only for the boundary-disabled reorder arrows — an informational
   label like "always used" must keep full-strength colour, or the "used" green
   drops below the 4.5:1 contrast floor (measured: 1.68:1 at 35% opacity). */
.resline .updown button:disabled{opacity:.35}

/* --------------------------------------------------------------- redrows */
.redrow{display:flex;align-items:center;gap:10px;padding:6px 0}
.redkey{font-family:var(--mono);font-size:13px;min-width:170px;flex:0 0 auto;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.redbar{position:relative;flex:1;min-width:0;height:30px;border-radius:4px;overflow:hidden}
.redbar .layer{position:absolute;inset:0;display:flex;align-items:center;
  padding:0 10px;font-family:var(--mono);font-size:13px;white-space:nowrap;overflow:hidden}
.redbar .value{background:var(--panel);color:var(--ink);border:1px solid var(--line)}
.redbar .masked{background:var(--ink);color:var(--paper);transition:transform .16s ease}
.redbar.open .masked{transform:translateY(-100%)}
@media (prefers-reduced-motion:reduce){.redbar .masked{transition:none}}
.redactions{flex:0 0 auto;display:flex;gap:2px;align-items:center;flex-wrap:wrap}
/* One word-button, not a native select with a floating arrow: the select
   itself carries the "Move to…" label, appearance:none removes the native
   arrow, and .moveto draws a single small chevron of its own over it. */
.moveto{position:relative;display:inline-flex;align-items:center}
select.moveselect{appearance:none;-webkit-appearance:none;-moz-appearance:none;
  background:none;border:0;color:var(--ink-muted);font-size:13px;font-family:inherit;
  padding:4px 16px 4px 6px;border-radius:4px;cursor:pointer;max-width:150px}
select.moveselect:hover{color:var(--ink)}
.moveto::after{content:"⌄";position:absolute;right:5px;top:50%;transform:translateY(-52%);
  pointer-events:none;color:var(--ink-muted);font-size:11px}
.moveto:hover::after{color:var(--ink)}
.addrow{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap;align-items:center}
.addrow input{flex:1;min-width:120px}
.addrow button{flex:0 0 auto}
.addrow .deleteset{margin-left:auto}

/* ----------------------------------------------------------------- forms */
button.primary{background:var(--ink);color:var(--paper);border:1px solid var(--ink);
  border-radius:4px;padding:7px 14px;font-size:14px;cursor:pointer}
button.primary:hover{opacity:.9}
input[type=text],input[type=password],select.plain{
  font-size:14px;padding:7px 9px;border:1px solid var(--line);border-radius:4px;
  background:var(--panel);color:var(--ink)}
input:focus,select:focus,button:focus,a:focus{outline:2px solid var(--ink);outline-offset:2px}
input:focus-visible,select:focus-visible,button:focus-visible,a:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
input[type=checkbox],input[type=radio]{accent-color:var(--ink)}

/* ----------------------------------------------------------- empty state */
.empty{color:var(--ink-muted);padding:24px 4px;border-top:1px dashed var(--line);font-size:14px}

/* A section's intro/subtitle line with its "New set" action on the same
   line, right-aligned — so the button reads as an action next to what it
   acts on, not a stray label floating in the ledger. */
.sectionhead{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;
  flex-wrap:wrap;margin:0 0 8px}
.sectionhead .intro,.sectionhead .subtitle{margin:0}
.newbtn{background:none;border:1px solid var(--line);color:var(--ink);border-radius:4px;
  font-size:13px;padding:4px 10px;cursor:pointer;flex:0 0 auto;white-space:nowrap}
.newbtn:hover{border-color:var(--ink-muted)}
.newbtn[aria-expanded=true]{border-color:var(--ink)}

/* -------------------------------------------------------------- setup box */
.panelbox{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px 18px;margin:0 0 20px}
.panelbox h3{font:600 15px var(--sans);margin:0 0 8px}
.checkline{display:flex;align-items:center;gap:7px;margin:12px 0}
.gorow{margin-top:16px}

/* --------------------------------------------------------- resolution list */
.resolution{margin:0 0 8px;padding:0;border-top:1px solid var(--line)}
.resline{display:flex;align-items:center;gap:10px;padding:8px 4px;border-bottom:1px solid var(--line);font-size:14px}
.resline .num{font-family:var(--mono);color:var(--ink-muted);flex:0 0 20px}
.resline .reslabel{flex:1;font-family:var(--serif)}
.resline .updown{display:flex;gap:4px;flex:0 0 auto}
.resline .updown button{width:24px;height:24px;padding:0;font-size:13px;line-height:1;
  border:1px solid transparent;border-radius:4px}
.resline .updown button:hover:not(:disabled),.resline .updown button:focus-visible{border-color:var(--line)}
.rule{color:var(--ink-muted);font-size:13px;margin:10px 0 24px}

/* ------------------------------------------------------------- team rows */
.teamrow{display:flex;align-items:center;gap:16px;padding:10px 4px;flex-wrap:wrap}
.teamrow .rowname{flex:1;min-width:120px}
.teamrow .rowmeta{flex:0 0 auto;font-size:13px;color:var(--ink-muted);min-width:70px}

/* ------------------------------------------------------------- agent rows */
.statusrow{display:flex;align-items:center;gap:10px;padding:8px 4px;border-bottom:1px solid var(--line)}
.statusdot{width:8px;height:8px;border-radius:50%;flex:0 0 auto;background:var(--ink-muted)}
.statusdot.ok{background:var(--used)}
.statuslabel{flex:1;font-size:14px}
.statusfix{font-family:var(--mono);font-size:12.5px;color:var(--ink-muted)}
.switchrow{display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:8px 4px;border-bottom:1px solid var(--line);max-width:60ch}
.switch{position:relative;display:inline-block;width:36px;height:20px;flex:0 0 auto}
.switch input{opacity:0;width:100%;height:100%;margin:0;position:absolute;inset:0;cursor:pointer;z-index:1}
.switch .track{position:absolute;inset:0;background:var(--line);border-radius:10px;pointer-events:none}
.switch .knob{position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;
  background:var(--panel);pointer-events:none;transition:none}
.switch input:checked ~ .track{background:var(--ink)}
.switch input:checked ~ .knob{left:18px}
.switch input:focus-visible ~ .track{outline:2px solid var(--ink);outline-offset:2px}

/* -------------------------------------------------------------- activity */
.auditrow{display:flex;align-items:baseline;gap:14px;padding:7px 4px;border-bottom:1px solid var(--line);font-size:13.5px}
.auditrow .when{flex:0 0 84px;color:var(--ink-muted)}
.auditrow .who{flex:0 0 48px;color:var(--ink-muted);font-family:var(--mono)}
.auditrow .what{flex:1}

/* --------------------------------------------------------------- dropzone */
.dropzone{position:fixed;inset:12px;border:3px dashed var(--ink);border-radius:8px;
  background:var(--panel);display:none;align-items:center;justify-content:center;
  z-index:50;font:600 17px var(--serif);color:var(--ink);pointer-events:none;text-align:center}
.dropzone.on{display:flex}
.modalback{position:fixed;inset:0;background:rgba(20,33,61,.4);display:flex;
  align-items:flex-start;justify-content:center;padding:40px 16px;overflow:auto;z-index:40}
.modalback[hidden]{display:none}
.modalpanel{background:var(--panel);border:1px solid var(--line);border-radius:8px;
  padding:20px 22px;max-width:760px;width:100%}
.bulk{display:flex;gap:9px;margin:12px 0;flex-wrap:wrap}
.bulk input,.bulk select{flex:1;min-width:160px}
.namer{border:1px solid var(--line);border-radius:4px;padding:12px 14px;margin:12px 0}
.file{font-size:12px;color:var(--ink-muted);margin:16px 0 4px;font-weight:600}
.stagerow{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:6px 0;border-top:1px solid var(--line)}
.stagerow .k{min-width:150px;flex:0 0 auto}
.stagerow select{max-width:180px}
.warn{font-size:12px;color:var(--wax)}
.hint{font-size:12px;color:var(--used)}
.stagefoot{display:flex;gap:12px;align-items:center;margin-top:16px;flex-wrap:wrap}
.stagefoot label{font-size:13px;color:var(--ink-muted);display:flex;align-items:center;gap:6px}

/* ------------------------------------------------------------------ toast */
.toast{position:fixed;left:50%;transform:translateX(-50%);bottom:22px;background:var(--ink);
  color:var(--paper);padding:9px 16px;border-radius:4px;font-size:13px;opacity:0;
  transition:opacity .16s;pointer-events:none;max-width:90vw}
.toast.on{opacity:1}
@media (prefers-reduced-motion:reduce){.toast{transition:none}}

/* -------------------------------------------------------------- responsive */
@media (max-width:800px){
  .shell{flex-direction:column}
  /* flex-wrap so the sidefoot (drop hint + rung) is forced onto its own row
     below brand+nav via flex-basis:100%, rather than competing with the tabs
     for width in the same row and squeezing "Library" down to "Li…". */
  .sidebar{width:auto;flex:0 0 auto;flex-direction:row;flex-wrap:wrap;align-items:center;
    padding:12px 16px;gap:4px 16px}
  .brand{flex:0 0 auto}
  /* The tab row scrolls on its own axis rather than shrinking its labels —
     min-width:0 lets a flex child shrink below its content size at all, which
     is what makes its own overflow-x take over instead of wrapping text. */
  .navlist{flex-direction:row;gap:4px;flex-wrap:nowrap;flex:1 1 auto;min-width:0;
    overflow-x:auto;overflow-y:hidden;padding-right:24px;
    -ms-overflow-style:none;scrollbar-width:none}
  .navlist::-webkit-scrollbar{display:none}
  .navlist li{flex:0 0 auto}
  .navlist a{border-left:0;border-bottom:2px solid transparent;padding:6px 8px;
    border-radius:4px 4px 0 0;white-space:nowrap}
  .navlist a.active{border-left-color:transparent;border-bottom-color:var(--ink)}
  .sidefoot{flex:1 1 100%;order:3;margin-top:4px;padding-top:10px;border-top:1px solid var(--line);
    flex-direction:row;gap:14px;flex-wrap:wrap}
  .content{padding:20px}
}
@media (max-width:480px){
  .navlist .count{display:none}
}
@media (max-width:400px){
  .content{padding:14px}
  .redkey{min-width:100px}
  .teamrow{flex-wrap:wrap}
  .pageheader{gap:6px}
}
</style></head><body>
<div class="shell">
<nav class="sidebar" aria-label="Sections">
  <div class="brand"><svg viewBox="0 0 64 64" width="28" height="28" aria-hidden="true"><rect x="10" y="6" width="44" height="52" rx="6" fill="none" stroke="currentColor" stroke-width="4"/><rect x="20" y="18" width="24" height="3" rx="1.5" fill="currentColor" opacity="0.45"/><rect x="18" y="28" width="28" height="9" rx="2" fill="currentColor"/><rect x="20" y="45" width="16" height="3" rx="1.5" fill="currentColor" opacity="0.45"/></svg><span class="wordmark">hush</span></div>
  <ul class="navlist" id="navlist"></ul>
  <div class="sidefoot">
    <div id="drophint-holder"></div>
    <a href="#agent" class="rung" id="runglink"></a>
  </div>
</nav>
<main class="content">
  <header class="pageheader">
    <h1 id="foldername"></h1>
    <div class="state" id="folderstate"></div>
  </header>
  <div id="sectionbody"></div>
</main>
</div>
<div class="modalback" id="modalback" hidden><div class="modalpanel" id="modalpanel"></div></div>
<div class="dropzone" id="drop">Drop .env files to bring them in</div>
<input type="file" id="picker" multiple hidden>
<div class="toast" id="toast"></div>
<script>
const T="__TOKEN__";
let S=null;
const $=(h)=>{const d=document.createElement("div");d.innerHTML=h.trim();return d.firstChild};
const esc=(s)=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

function toast(msg){const t=document.getElementById("toast");t.textContent=msg;t.classList.add("on");
  clearTimeout(t._x);t._x=setTimeout(()=>t.classList.remove("on"),2600)}

async function api(path,body){
  const r=await fetch(path,{method:body?"POST":"GET",headers:{"x-hush-token":T,"content-type":"application/json"},
    body:body?JSON.stringify(body):undefined});
  const j=await r.json();
  if(!r.ok){toast(j.error||"failed");throw new Error(j.error)}
  return j;
}
async function refresh(next){S=next||await api("/api/state");render()}

/** 1st, 2nd, 3rd, 4th, … — how a set's place in the resolution order is shown. */
function ordinal(n){
  if(n%10===1&&n%100!==11)return n+"st";
  if(n%10===2&&n%100!==12)return n+"nd";
  if(n%10===3&&n%100!==13)return n+"rd";
  return n+"th";
}

async function retag(scope,key,note){
  await refresh(await api("/api/tag",{scope,key,note}));
  toast(note?"tagged "+key:"tag cleared");
}
async function setSecret(scope,key,value,where){
  const r=await api("/api/secret",{scope,key,value,where});
  await refresh(r);
  toast(r.vaultCreated?"made this folder's own vault — commit .hush/vault.json":(value===null?"deleted":"saved"));
}
async function reveal(scope,key,barEl,valueEl,where){
  const {value}=await api("/api/reveal",{scope,key,where});
  valueEl.textContent=value;
  barEl.classList.add("open");
  clearTimeout(barEl._hideTimer);
  barEl._hideTimer=setTimeout(function(){barEl.classList.remove("open");valueEl.textContent=""},15000);
}

/* ------------------------------------------------------- redaction rows -- */

function redactionRow(scope,s,where){
  const row=$('<div class="redrow"></div>');
  row.append($('<div class="redkey">'+esc(s.key)+'</div>'));

  const bar=document.createElement("div");
  bar.className="redbar";
  const valueLayer=$('<div class="layer value"></div>');
  const maskedLayer=$('<div class="layer masked">'+esc(s.preview)+'</div>');
  bar.append(valueLayer,maskedLayer);
  row.append(bar);

  const actions=$('<div class="redactions"></div>');

  const rv=$('<button type="button" class="quiet wax">Reveal</button>');
  rv.setAttribute("aria-label","Reveal "+s.key);
  rv.onclick=()=>reveal(scope,s.key,bar,valueLayer,where).catch(()=>{});
  actions.append(rv);

  const rep=$('<button type="button" class="quiet">Replace</button>');
  rep.setAttribute("aria-label","Replace "+s.key);
  rep.onclick=()=>{const nv=prompt("New value for "+s.key);if(nv)setSecret(scope,s.key,nv,where)};
  actions.append(rep);

  const here=where||"project";
  const dests=(here==="library"?S.library:S.project).map(function(x){return {name:x.name,label:x.label}})
    .filter(function(x){return x.name!==scope});
  if(dests.length){
    // One control, not a select sitting loose next to a floating native arrow:
    // .moveto draws its own chevron over an appearance:none select, so the
    // whole thing reads as a single word-button like Replace beside it.
    const mvWrap=document.createElement("span");
    mvWrap.className="moveto";
    const mv=document.createElement("select");
    mv.className="moveselect";
    mv.setAttribute("aria-label","Move "+s.key+" to another set");
    mv.append($('<option value="">Move to…</option>'));
    dests.forEach(function(d){mv.append($('<option value="'+esc(d.name)+'">'+esc(d.label)+'</option>'))});
    mv.onchange=async function(){
      if(!mv.value)return;
      const to=mv.value;mv.value="";
      try{await refresh(await api("/api/move",{where:here,key:s.key,from:scope,to:to}));toast("moved "+s.key)}
      catch(e){toast(e.message)}
    };
    mvWrap.append(mv);
    actions.append(mvWrap);
  }

  const del=$('<button type="button" class="quiet wax">Delete</button>');
  del.setAttribute("aria-label","Delete "+s.key);
  del.onclick=()=>{if(confirm("Delete "+s.key+"?"))setSecret(scope,s.key,null,where)};
  actions.append(del);

  row.append(actions);
  return row;
}

/* ------------------------------------------------------------ ledger rows */

/**
 * A muted line that becomes a text input on click — the description and
 * when-to-use line under a set's name. Exactly one representation: no
 * permanently-visible boxed field duplicates the same text below the row.
 */
function editableRow(set,where,field,value,placeholder,ariaLabel){
  const holder=document.createElement("div");
  holder.className="rowdesc editrow";
  holder.setAttribute("data-field",field);
  let current=value||"";

  const span=document.createElement("span");
  span.className="editspan";
  span.tabIndex=0;
  span.setAttribute("role","button");

  const showSpan=()=>{
    holder.innerHTML="";
    span.textContent=current||placeholder;
    span.classList.toggle("placeholder",!current);
    holder.classList.toggle("empty",!current);
    span.setAttribute("aria-label","Edit "+ariaLabel);
    holder.append(span);
  };

  const showInput=()=>{
    const input=document.createElement("input");
    input.type="text";input.className="editinput";input.value=current;input.placeholder=placeholder;
    input.setAttribute("aria-label",ariaLabel);
    holder.innerHTML="";holder.append(input);
    input.focus();input.select();
    let settled=false;
    const save=async()=>{
      if(settled)return;settled=true;
      const next=input.value.trim();
      if(next===current){showSpan();return}
      const patch={action:"describe",where:where,name:set.name};patch[field]=next;
      try{current=next;await refresh(await api("/api/env",patch))}
      catch(e){toast(e.message);showSpan()}
    };
    input.onblur=save;
    input.onkeydown=(ev)=>{
      if(ev.key==="Enter"){input.blur()}
      else if(ev.key==="Escape"){settled=true;showSpan()}
    };
  };

  span.onclick=showInput;
  span.onkeydown=(ev)=>{if(ev.key==="Enter"){ev.preventDefault();showInput()}};
  showSpan();
  return holder;
}

function setRow(set,where){
  const row=document.createElement("div");
  row.className="ledgerrow";
  const detailId="detail-"+where+"-"+set.name.replace(/[^a-zA-Z0-9]/g,"_");

  const main=$('<div class="rowmain"></div>');

  const chev=$('<button type="button" class="chevron" aria-expanded="false">›</button>');
  chev.setAttribute("aria-controls",detailId);
  chev.setAttribute("aria-label","Show keys for "+set.label);
  main.append(chev);

  const nameWrap=$('<div class="rowname"></div>');
  const nm=document.createElement("input");
  nm.type="text";nm.className="nameinput";nm.value=set.label;nm.placeholder="name this set";
  nm.setAttribute("aria-label","Rename "+set.label);
  let lastName=set.label;
  nm.onblur=async()=>{
    const next=nm.value.trim();
    if(!next||next===lastName){nm.value=lastName;return}
    try{
      const r=await api("/api/env",{action:"rename",where:where,name:set.name,label:next});
      lastName=next;await refresh(r);
      toast("renamed to "+next);
    }catch(e){nm.value=lastName;toast(e.message)}
  };
  nm.onkeydown=(ev)=>{if(ev.key==="Enter")nm.blur();if(ev.key==="Escape"){nm.value=lastName;nm.blur()}};
  nameWrap.append(nm);

  const descFallback=(where==="library"&&set.name==="default")
    ?"your global environment — under everything, in every folder":"what is this for?";
  nameWrap.append(editableRow(set,where,"description",set.description,descFallback,"description for "+set.label));
  nameWrap.append(editableRow(set,where,"whenToUse",set.whenToUse,"When to use it","when to use "+set.label));
  main.append(nameWrap);

  const keyWord=set.keys.length===1?" key":" keys";
  main.append($('<div class="rowcount">'+set.keys.length+esc(keyWord)+'</div>'));

  const useWrap=$('<div class="rowuse"></div>');
  if(where==="project"&&set.name==="default"){
    const floor=$('<button type="button" class="quiet on" disabled>● always used · '+ordinal((set.position||0)+1)+'</button>');
    floor.title="The default set of this project is always used, underneath everything else";
    useWrap.append(floor);
  }else{
    const useLabel=set.used?("● Used here · "+ordinal(set.position+1)):"Use in this folder";
    const use=$('<button type="button" class="quiet'+(set.used?" on":"")+'">'+esc(useLabel)+'</button>');
    use.title=set.used?"Stop using it in this folder":"Use it in this folder";
    use.onclick=async()=>{
      const r=await api("/api/link",{name:set.name,use:!set.used});
      await refresh(r);toast(set.used?"dropped "+set.name:"this project now uses "+set.name);
    };
    useWrap.append(use);
  }
  main.append(useWrap);
  row.append(main);

  const detail=document.createElement("div");
  detail.className="rowdetail";detail.id=detailId;detail.hidden=true;

  chev.onclick=()=>{
    const open=chev.getAttribute("aria-expanded")==="true";
    chev.setAttribute("aria-expanded",open?"false":"true");
    chev.textContent=open?"›":"‹";
    detail.hidden=open;
    row.classList.toggle("open",!open);
  };

  if(set.secrets&&set.secrets.length){
    set.secrets.forEach(function(sec){detail.append(redactionRow(set.name,sec,where))});
  }

  // The last line of the expanded row: the add-key fields on the left, and
  // Delete this set at the far right of the very same line, not centered
  // underneath it on a line of its own.
  const addRow=document.createElement("form");addRow.className="addrow";
  const ak=document.createElement("input");ak.type="text";ak.placeholder="KEY";ak.setAttribute("aria-label","New key name");
  const av=document.createElement("input");av.type="password";av.placeholder="value";av.autocomplete="new-password";
  av.setAttribute("aria-label","New key value");
  addRow.append(ak,av);
  const addBtn=document.createElement("button");addBtn.type="submit";addBtn.textContent="Add";
  addRow.append(addBtn);
  addRow.onsubmit=async(ev)=>{
    ev.preventDefault();
    if(!ak.value||!av.value)return;
    await setSecret(set.name,ak.value.trim(),av.value,where);
  };
  const delBtn=$('<button type="button" class="quiet wax deleteset">Delete this set</button>');
  delBtn.onclick=async()=>{
    if(!confirm('Delete "'+set.label+'" and its '+set.keys.length+' key(s)? This cannot be undone.'))return;
    await refresh(await api("/api/env",{action:"delete",where:where,name:set.name}));toast("deleted");
  };
  addRow.append(delBtn);
  detail.append(addRow);

  if(set.source)detail.append($('<div class="muted">from '+esc(set.source)+'</div>'));

  row.append(detail);
  return row;
}

/* ------------------------------------------------------------ new-set form */

function promptForVars(where,scope,serviceLabel,vars){
  const back=document.getElementById("sectionbody");
  const box=document.createElement("div");box.className="panelbox";
  box.append($('<h3>Fill in '+esc(serviceLabel)+'</h3>'));
  const inputs=vars.map(function(name){
    const row=$('<div class="redrow"></div>');
    row.append($('<div class="redkey">'+esc(name)+'</div>'));
    const vi=document.createElement("input");vi.type="password";vi.placeholder="value";vi.autocomplete="new-password";
    row.append(vi);
    box.append(row);
    return {key:name,input:vi};
  });
  const save=$('<button type="button" class="primary">Save these values</button>');
  save.onclick=async()=>{
    let n=0;
    for(const it of inputs){
      if(!it.input.value)continue;
      await api("/api/secret",{where:where,scope:scope,key:it.key,value:it.input.value});
      n++;
    }
    await refresh(await api("/api/state"));
    toast("saved "+n+" value(s)");
  };
  box.append(save);
  back.insertBefore(box,back.firstChild);
}

function newSetForm(where,onDone){
  const box=document.createElement("div");box.className="panelbox";
  const f=document.createElement("form");f.className="addrow";
  const nm=document.createElement("input");nm.type="text";nm.placeholder="name it — e.g. Acme Production";
  const ds=document.createElement("input");ds.type="text";ds.placeholder="what is it for? (optional)";
  f.append(nm,ds);
  const svc=document.createElement("select");svc.className="plain";
  svc.append($('<option value="">for a service… (optional)</option>'));
  S.catalog.forEach(function(c){svc.append($('<option value="'+esc(c.id)+'">'+esc(c.label)+'</option>'))});
  f.append(svc);
  const submit=document.createElement("button");submit.type="submit";submit.className="primary";submit.textContent="Add set";
  f.append(submit);
  f.onsubmit=async(ev)=>{
    ev.preventDefault();
    if(!nm.value.trim())return;
    const serviceLabel=svc.options[svc.selectedIndex].text;
    try{
      if(where==="library"&&!S.global.exists)await api("/api/global",{create:true});
      const r=await api("/api/env",{action:"create",where:where,label:nm.value.trim(),description:ds.value,service:svc.value||undefined});
      const created=r.created;
      await refresh(r);
      toast(r.vaultCreated?"made this folder's own vault — commit .hush/vault.json":"created "+nm.value.trim());
      if(onDone)onDone();
      if(created&&r.vars&&r.vars.length)promptForVars(where,created,serviceLabel,r.vars);
    }catch(e){toast(e.message)}
  };
  box.append(f);
  return box;
}

/**
 * The "New set" / "New set here" action — a bordered button that sits beside
 * a section's own intro or subtitle line (see .sectionhead), toggling a
 * full-width form panel in the caller-supplied holder below that line.
 */
function newSetButton(where,buttonLabel,holder){
  const btn=$('<button type="button" class="newbtn">'+esc(buttonLabel)+'</button>');
  btn.setAttribute("aria-expanded","false");
  btn.onclick=()=>{
    if(holder.childNodes.length){holder.innerHTML="";btn.setAttribute("aria-expanded","false");return}
    holder.append(newSetForm(where,function(){holder.innerHTML="";btn.setAttribute("aria-expanded","false")}));
    btn.setAttribute("aria-expanded","true");
  };
  return btn;
}

function librarySetup(){
  const box=document.createElement("div");box.className="panelbox";
  box.append($("<h3>You have no library yet</h3>"));
  box.append($('<p class="muted">A library holds your named env sets in one place, so a key lives in exactly one vault and every project points at it.</p>'));
  const row=document.createElement("div");
  const make=$('<button type="button" class="primary">Create one</button>');
  make.onclick=async()=>{await refresh(await api("/api/global",{create:true}));toast("library created")};
  row.append(make);
  (S.global.others||[]).forEach(function(v){
    const b=$('<button type="button" class="quiet">use my "'+esc(v)+'" vault</button>');
    b.onclick=async()=>{await refresh(await api("/api/global",{name:v}));toast("library is now "+v)};
    row.append(b);
  });
  box.append(row);
  return box;
}

/**
 * "Set this folder up" — shown above the library when folder.state is
 * "unset". Nothing is written until the button: checkboxes and radios only
 * build up the list of names the click sends to /api/setup.
 */
function setupPanel(){
  const sug=S.suggestion||{needed:[],files:0,picks:[],ambiguous:[],uncovered:[],provider:{}};
  const box=document.createElement("div");box.className="panelbox";
  box.append($("<h3>This folder isn't set up for hush yet</h3>"));

  if(sug.needed.length){
    const word=sug.files===1?"file":"files";
    box.append($('<p class="muted">Its code references '+esc(sug.needed.join(", "))+' ('+sug.files+' '+word+').</p>'));
  }else{
    box.append($('<p class="muted">No env-var references were found here — pick sets from your library below, or add one.</p>'));
  }

  if(!S.global.exists||!S.library.length){
    box.append($('<p class="muted">Your library has nothing to offer yet — set it up below, then come back here.</p>'));
  }

  const checks={};
  if(S.library.length){
    if(sug.picks.length)box.append($('<p class="muted">Your library covers them:</p>'));
    S.library.forEach(function(set){
      const picked=sug.picks.indexOf(set.name)>-1;
      const row=$('<div class="stagerow"></div>');
      const cb=document.createElement("input");
      cb.type="checkbox";cb.checked=picked;
      cb.setAttribute("aria-label","Use "+set.label+" here");
      checks[set.name]=cb;
      row.append(cb);
      row.append($('<div class="serif">'+esc(set.label)+'</div>'));
      const covered=Object.keys(sug.provider).filter(function(k){return sug.provider[k]===set.name});
      row.append($('<div class="muted mono">'+esc((covered.length?covered:set.keys).join(", "))+'</div>'));
      box.append(row);
    });
  }

  const radios={};
  sug.ambiguous.forEach(function(a){
    const row=$('<div class="stagerow"></div>');
    row.append($('<div class="k">'+esc(a.key)+'</div>'));
    row.append($('<div class="muted">is in more than one set</div>'));
    const group=document.createElement("div");
    radios[a.key]=group;
    a.options.forEach(function(optName){
      const set=S.library.find(function(x){return x.name===optName});
      const label=document.createElement("label");
      label.style.marginRight="12px";
      const r=document.createElement("input");
      r.type="radio";r.name="amb-"+a.key;r.value=optName;
      label.append(r,document.createTextNode(" "+(set?set.label:optName)));
      group.append(label);
    });
    row.append(group);
    box.append(row);
  });

  if(sug.uncovered.length){
    box.append($('<p class="muted">Not in your library: '+esc(sug.uncovered.join(", "))+' — add it to a set later</p>'));
  }

  const agentRow=document.createElement("label");
  agentRow.className="muted checkline";
  const agentCb=document.createElement("input");
  agentCb.type="checkbox";
  agentRow.append(agentCb,document.createTextNode(" An AI agent will use secrets here (turn approvals on)"));
  box.append(agentRow);

  const go=$('<button type="button" class="primary">Use these here</button>');
  go.onclick=async function(){
    const use=[];
    Object.keys(checks).forEach(function(name){if(checks[name].checked)use.push(name)});
    Object.keys(radios).forEach(function(key){
      const chosen=radios[key].querySelector("input[type=radio]:checked");
      if(chosen&&use.indexOf(chosen.value)<0)use.push(chosen.value);
    });
    try{
      await refresh(await api("/api/setup",{use:use,agent:agentCb.checked}));
      toast("this folder now uses "+use.length+" set(s)");
    }catch(e){toast(e.message)}
  };
  const goRow=document.createElement("div");
  goRow.className="gorow";
  goRow.append(go);
  box.append(goRow);
  return box;
}

/* ---------------------------------------------------------------- library */

function renderLibrary(){
  const wrap=document.createElement("div");

  if(S.global.error){
    wrap.append($('<p class="intro">Yours alone, never in a repo. Any folder can use these.</p>'));
    wrap.append($('<div class="empty">'+esc(S.global.error)+'</div>'));
    return wrap;
  }
  if(!S.global.exists){
    wrap.append($('<p class="intro">Yours alone, never in a repo. Any folder can use these.</p>'));
    wrap.append(librarySetup());
    return wrap;
  }

  const holder=document.createElement("div");
  const head=$('<div class="sectionhead"></div>');
  head.append($('<p class="intro">Yours alone, never in a repo. Any folder can use these.</p>'));
  head.append(newSetButton("library","New set",holder));
  wrap.append(head);
  wrap.append(holder);

  if(!S.library.length){
    wrap.append($('<div class="empty">Nothing here yet. Drop a .env anywhere on this page, or make a set.</div>'));
    return wrap;
  }

  const ledger=document.createElement("div");ledger.className="ledger";
  S.library.forEach(function(set){ledger.append(setRow(set,"library"))});
  wrap.append(ledger);
  return wrap;
}

/* ------------------------------------------------------------ this folder */

function renderFolder(){
  const wrap=document.createElement("div");
  const fstate=S.folder.state;

  if(fstate==="unset"){
    wrap.append(setupPanel());
    return wrap;
  }

  wrap.append($('<h3 class="subtitle">What a run gets</h3>'));
  const list=document.createElement("div");list.className="resolution";
  (S.resolution||[]).forEach(function(line,idx){
    const li=$('<div class="resline"></div>');
    li.append($('<div class="num">'+(idx+1)+'</div>'));
    li.append($('<div class="reslabel">'+esc(line.label)+' '+esc(line.note)+'</div>'));
    if(line.first){
      const controls=$('<div class="updown"></div>');
      const up=$('<button type="button" class="quiet" aria-label="Move '+esc(line.label)+' earlier in the order">▴</button>');
      const down=$('<button type="button" class="quiet" aria-label="Move '+esc(line.label)+' later in the order">▾</button>');
      up.disabled=line.usedIndex===0;
      down.disabled=line.usedIndex===S.used.length-1;
      up.onclick=async()=>{
        const order=S.used.slice();
        const i=line.usedIndex;
        const t=order[i-1];order[i-1]=order[i];order[i]=t;
        await refresh(await api("/api/link",{order:order}));
      };
      down.onclick=async()=>{
        const order=S.used.slice();
        const i=line.usedIndex;
        const t=order[i+1];order[i+1]=order[i];order[i]=t;
        await refresh(await api("/api/link",{order:order}));
      };
      controls.append(up,down);
      li.append(controls);
      if(line.removable){
        const stop=$('<button type="button" class="quiet">Stop using</button>');
        stop.onclick=async()=>{
          await refresh(await api("/api/link",{name:line.name,use:false}));
          toast("dropped "+line.name);
        };
        li.append(stop);
      }
    }
    list.append(li);
  });
  wrap.append(list);
  wrap.append($('<p class="rule">Later wins on a shared key.</p>'));

  const ownHolder=document.createElement("div");
  const ownHead=$('<div class="sectionhead"></div>');
  ownHead.append($("<h3 class=\"subtitle\">This folder's own sets</h3>"));
  ownHead.append(newSetButton("project","New set here",ownHolder));
  wrap.append(ownHead);
  wrap.append(ownHolder);
  if(fstate==="links-only"){
    wrap.append($("<p class=\"muted\">No vault of its own yet — one is made the first time you add a secret here or a teammate.</p>"));
  }else{
    if(!S.project.length){
      wrap.append($('<div class="empty">Nothing here yet. Drop a .env anywhere on this page, or make a set.</div>'));
    }else{
      const ledger=document.createElement("div");ledger.className="ledger";
      S.project.forEach(function(set){ledger.append(setRow(set,"project"))});
      wrap.append(ledger);
    }
  }
  return wrap;
}

/* ------------------------------------------------------------------- team */

function renderTeam(){
  const wrap=document.createElement("div");
  wrap.append($("<p class=\"intro\">People who can decrypt this folder's vault. Give someone access with the key they send you; removing them re-encrypts everything so their old copy decrypts nothing new.</p>"));

  if(S.folder.state!=="vault"){
    wrap.append($('<p class="muted">This folder has no vault yet. Adding a teammate makes one.</p>'));
  }

  if(S.members.length){
    const ledger=document.createElement("div");ledger.className="ledger";
    S.members.forEach(function(member){
      const kindLabel=member.kind==="hardware"?"hardware":"key";
      const row=$('<div class="ledgerrow teamrow"></div>');
      row.append($('<div class="rowname serif">'+esc(member.name)+'</div>'));
      row.append($('<div class="rowmeta">'+esc(member.role)+'</div>'));
      row.append($('<div class="rowmeta mono">'+esc((member.fingerprint||"").slice(0,12))+'…</div>'));
      row.append($('<div class="rowmeta">'+esc(kindLabel)+'</div>'));
      if(member.name!==S.me.name){
        const rm=$('<button type="button" class="quiet wax">Remove</button>');
        rm.setAttribute("aria-label","Remove "+member.name);
        rm.onclick=async()=>{
          if(!confirm("Remove "+member.name+"? Removing them re-encrypts everything so their old copy decrypts nothing new."))return;
          const r=await api("/api/team",{action:"remove",name:member.name});await refresh(r);
          toast(r.vaultCreated?"made this folder's own vault — commit .hush/vault.json":(r.notice||"removed"));
        };
        row.append(rm);
      }
      ledger.append(row);
    });
    wrap.append(ledger);
  }

  const f=document.createElement("form");f.className="addrow";
  const nm=document.createElement("input");nm.type="text";nm.placeholder="their name";
  const pk=document.createElement("input");pk.type="text";pk.placeholder="hush_pk_…  (they run: hush id --create)";
  f.append(nm,pk);
  const submit=document.createElement("button");submit.type="submit";submit.className="primary";submit.textContent="Give them access";
  f.append(submit);
  f.onsubmit=async(ev)=>{
    ev.preventDefault();
    if(!nm.value||!pk.value)return;
    const res=await api("/api/team",{name:nm.value.trim(),pk:pk.value.trim()});
    await refresh(res);
    toast(res.vaultCreated?"made this folder's own vault — commit .hush/vault.json":"added "+nm.value);
    f.reset();
  };
  wrap.append(f);
  return wrap;
}

/* ------------------------------------------------------------------ agent */

function renderAgent(){
  const wrap=document.createElement("div");
  wrap.append($('<p class="intro">What an AI coding agent may do with these secrets, and what it must ask you for.</p>'));

  const statusItems=[
    {label:"MCP registered",ok:S.agent.mcpRegistered,fix:"hush install-mcp"},
    {label:"Skill installed",ok:S.agent.skillInstalled,fix:"hush install-skill"},
    {label:"Policy file present",ok:S.agent.policyFilePresent,fix:"hush install-mcp"},
    {label:"Policy floor present",ok:S.agent.policyFloorPresent,fix:"create ~/.hush/policy.json"},
  ];
  statusItems.forEach(function(item){
    const row=$('<div class="statusrow"></div>');
    const dot=document.createElement("span");
    dot.className="statusdot"+(item.ok?" ok":"");
    row.append(dot);
    row.append($('<div class="statuslabel">'+esc(item.label)+'</div>'));
    if(!item.ok)row.append($('<div class="statusfix">'+esc(item.fix)+'</div>'));
    wrap.append(row);
  });

  wrap.append($('<h3 class="subtitle">Asks first</h3>'));
  const ACTIONS=[["run","Running a command with secrets injected"],["add","Adding a new secret"],["reveal","Revealing a value"],["request","Sending a secret to an API"]];
  ACTIONS.forEach(function(pair){
    const action=pair[0],label=pair[1];
    const row=$('<div class="switchrow"></div>');
    row.append($('<div>'+esc(label)+'</div>'));
    const sw=document.createElement("label");sw.className="switch";
    const cb=document.createElement("input");cb.type="checkbox";
    cb.checked=S.policy.requireApproval.indexOf(action)>-1;
    cb.setAttribute("aria-label","Ask before: "+label);
    const track=document.createElement("span");track.className="track";
    const knob=document.createElement("span");knob.className="knob";
    sw.append(cb,track,knob);
    cb.onchange=async()=>{
      const chosen=new Set(S.policy.requireApproval);
      if(cb.checked)chosen.add(action);else chosen.delete(action);
      try{
        S=await api("/api/policy",{requireApproval:Array.from(chosen)});
        render();
        toast("updated");
      }catch(e){cb.checked=!cb.checked}
    };
    row.append(sw);
    wrap.append(row);
  });

  // How long an "Allow" lasts, in plain words rather than seconds. The number
  // is what the dialog's own button says, so it is the same choice seen twice.
  const TTL_CHOICES=[[900,"15 minutes"],[1800,"30 minutes"],[3600,"1 hour"],[14400,"4 hours"],[86400,"all day"]];
  const ttlRow=$('<div class="switchrow"></div>');
  ttlRow.append($('<div>An \u201Callow\u201D lasts</div>'));
  const ttlSel=document.createElement("select");ttlSel.className="plain";
  ttlSel.setAttribute("aria-label","How long an allow lasts");
  TTL_CHOICES.forEach(function(pair){
    const o=document.createElement("option");o.value=String(pair[0]);o.textContent=String(pair[1]);
    if(S.policy.approvalTtlSeconds===pair[0])o.selected=true;
    ttlSel.append(o);
  });
  // A value set by hand that is not one of the choices must not be silently
  // rewritten by simply opening this page, so it gets its own option.
  if(!TTL_CHOICES.some(function(p){return p[0]===S.policy.approvalTtlSeconds})){
    const o=document.createElement("option");
    o.value=String(S.policy.approvalTtlSeconds);
    o.textContent=Math.round(S.policy.approvalTtlSeconds/60)+" minutes (set by hand)";
    o.selected=true;
    ttlSel.append(o);
  }
  ttlSel.onchange=async()=>{
    try{
      S=await api("/api/policy",{requireApproval:S.policy.requireApproval,approvalTtlSeconds:Number(ttlSel.value)});
      render();
      toast("updated");
    }catch(e){toast(String(e.message||e))}
  };
  ttlRow.append(ttlSel);
  wrap.append(ttlRow);

  const bioRow=$('<div class="switchrow"></div>');
  bioRow.append($('<div>Approval by fingerprint</div>'));
  bioRow.append($('<div class="statusfix">'+esc(S.policy.biometry)+' — change with hush secure</div>'));
  wrap.append(bioRow);

  return wrap;
}

/* --------------------------------------------------------------- activity */

function relTime(iso){
  const t=new Date(iso).getTime();
  if(isNaN(t))return "";
  const diff=Math.max(0,Math.round((Date.now()-t)/1000));
  if(diff<60)return diff+"s ago";
  const mins=Math.round(diff/60);
  if(mins<60)return mins+" min ago";
  const hrs=Math.round(mins/60);
  if(hrs<24)return hrs+" hr ago";
  const days=Math.round(hrs/24);
  return days+" day"+(days===1?"":"s")+" ago";
}

function describeEvent(entry){
  const skip={at:1,actor:1,action:1};
  const parts=[];
  Object.keys(entry).forEach(function(k){
    if(skip[k])return;
    const v=entry[k];
    if(v===undefined||v===null||v==="")return;
    parts.push(k+": "+(Array.isArray(v)?v.join(", "):String(v)));
  });
  return parts.join(", ");
}

let AUDIT=[];

function renderAuditBox(){
  const box=document.getElementById("auditbox");
  if(!box)return;
  box.innerHTML="";
  if(!AUDIT.length){box.append($('<p class="muted">Nothing yet.</p>'));return}
  AUDIT.forEach(function(entry){
    const row=$('<div class="auditrow"></div>');
    row.append($('<div class="when">'+esc(relTime(entry.at))+'</div>'));
    row.append($('<div class="who">'+esc(entry.actor||"")+'</div>'));
    const detail=describeEvent(entry);
    const what=esc(entry.action||"")+(detail?" — "+esc(detail):"");
    row.append($('<div class="what">'+what+'</div>'));
    box.append(row);
  });
}

async function loadAudit(){
  try{
    const r=await api("/api/audit",{});
    AUDIT=r.entries||[];
  }catch(e){/* api() already reported it */}
  renderAuditBox();
}

function renderActivity(){
  const wrap=document.createElement("div");
  const box=document.createElement("div");box.id="auditbox";
  wrap.append(box);
  loadAudit();
  return wrap;
}

/* --------------------------------------------------------- staging modal -- */

let STAGES=[];        // [{stageId,file,entries,rejected}]
let CHOICE={};        // stageId|key -> {scope,note,include}   (per row, not per name)
let EXTRA=[];         // scopes typed during review
let OVERWRITE=false;
let countBtn=null;
let importing=false;

/* Two dropped files may each define the same variable; keep their rows apart. */
function ck(stageId,key){return stageId+"|"+key}

function allScopes(){
  const out=[];
  (S.project||[]).forEach(function(e){out.push(e.name)});
  (S.library||[]).forEach(function(s){if(out.indexOf(s.name)<0)out.push(s.name)});
  EXTRA.forEach(function(x){if(out.indexOf(x)<0)out.push(x)});
  return out;
}

function stagedCount(){return Object.keys(CHOICE).filter(function(k){return CHOICE[k].include}).length}

function refreshCount(){
  if(countBtn)countBtn.textContent="Import "+stagedCount()+" secret(s)";
}

/* Matches the server's limits, so an impossible file is refused before the tab
   tries to hold it in memory rather than after. */
const MAX_DROP_BYTES=2*1024*1024;
const MAX_DROP_FILES=20;

async function ingestFiles(files){
  let list=[].slice.call(files);
  if(!list.length)return;
  if(list.length>MAX_DROP_FILES){
    toast("taking the first "+MAX_DROP_FILES+" files");
    list=list.slice(0,MAX_DROP_FILES);
  }
  let added=0;
  for(const f of list){
    if(f.size>MAX_DROP_BYTES){toast(f.name+" is too large to be a .env");continue}
    let text;
    try{text=await f.text()}catch(err){toast("could not read "+f.name);continue}
    try{
      const st=await api("/api/stage",{text:text,filename:f.name});
      if(!st.entries.length&&!st.rejected.length){toast("no variables in "+f.name);continue}
      STAGES.push(st);
      // Pre-tag with the service hush recognised, so the common case is one click.
      st.entries.forEach(function(e){CHOICE[ck(st.stageId,e.key)]={scope:e.suggestedScope,note:e.service||"",include:true}});
      added++;
    }catch(err){/* api() already reported it */}
  }
  if(added)render();
}

function scopeSelect(cid){
  const sel=document.createElement("select");
  allScopes().forEach(function(sc){
    const o=document.createElement("option");
    o.value=sc;o.textContent=sc;
    if(CHOICE[cid].scope===sc)o.selected=true;
    sel.append(o);
  });
  sel.onchange=function(){CHOICE[cid].scope=sel.value};
  return sel;
}

function dropCard(){
  const c=document.createElement("button");
  c.type="button";c.className="drophint";
  c.textContent="Drop a .env anywhere on the page";
  c.onclick=function(){document.getElementById("picker").click()};
  return c;
}

function stagingPanel(){
  const c=document.createElement("div");
  let total=0;STAGES.forEach(function(st){total+=st.entries.length});
  c.append($('<h3>Review '+total+' variable(s)</h3>'));
  c.append($('<p class="muted">Nothing is saved until you import. Values stay on this machine.</p>'));

  const namer=document.createElement("div");namer.className="namer";
  namer.append($("<p><b>Save all of this as one named set</b></p>"));
  const nrow=document.createElement("div");nrow.className="bulk";
  const setName=document.createElement("input");
  setName.type="text";
  const guess=STAGES.length===1?(STAGES[0].file||"").replace(/^\.env\.?/,"").replace(/[-_.]+/g," ").trim():"";
  setName.placeholder="name it — e.g. Acme Production";
  setName.value=guess?guess.charAt(0).toUpperCase()+guess.slice(1):"";
  const setDesc=document.createElement("input");
  setDesc.type="text";setDesc.placeholder="what is it for? (optional)";
  const dest=document.createElement("select");dest.className="plain";
  dest.append($('<option value="library">in my library — every project can use it</option>'));
  dest.append($('<option value="project">in this project — shared with the team</option>'));
  if(!S.global.exists)dest.value="project";
  nrow.append(setName,setDesc);
  namer.append(nrow);
  const drow=document.createElement("div");drow.className="bulk";
  drow.append(dest);
  const go=document.createElement("button");go.type="button";go.className="primary";go.textContent="Save as a named set";
  go.onclick=async function(){
    const label=setName.value.trim();
    if(!label){toast("give it a name first");return}
    if(importing)return;importing=true;
    try{
      const where=dest.value;
      if(where==="library"&&!S.global.exists){
        await api("/api/global",{create:true});
      }
      const created=await api("/api/env",{action:"create",where:where,label:label,description:setDesc.value});
      const scope=created.created;
      if(!scope)throw new Error("could not create the set");
      const batches=STAGES.map(function(st){
        const assignments={};
        st.entries.forEach(function(e){
          const c2=CHOICE[ck(st.stageId,e.key)];
          if(c2&&c2.include!==false)assignments[e.key]={scope:scope,note:(c2&&c2.note)||""};
        });
        return {stageId:st.stageId,assignments:assignments};
      }).filter(function(b){return Object.keys(b.assignments).length});
      const r=await api("/api/import",{stages:batches,where:where,overwrite:true});
      if(where==="library")await api("/api/link",{name:scope,use:true});
      STAGES=[];CHOICE={};EXTRA=[];countBtn=null;
      await refresh(await api("/api/state"));
      toast("saved "+label+(where==="library"?" — this project now uses it":""));
    }catch(e){toast(e.message)}
    finally{importing=false}
  };
  drow.append(go);
  namer.append(drow);
  namer.append($('<p class="muted">Or file them one by one below.</p>'));
  c.append(namer);

  const bar=document.createElement("div");bar.className="bulk";
  const setAll=document.createElement("select");setAll.className="plain";
  setAll.append($('<option value="">move all to…</option>'));
  allScopes().forEach(function(sc){setAll.append($('<option value="'+esc(sc)+'">'+esc(sc)+'</option>'))});
  setAll.onchange=function(){
    if(!setAll.value)return;
    Object.keys(CHOICE).forEach(function(k){CHOICE[k].scope=setAll.value});
    renderModal();
  };
  const mk=document.createElement("input");
  mk.type="text";
  mk.placeholder="or a new scope, e.g. fal/acme — press enter";
  mk.onkeydown=function(ev){
    if(ev.key!=="Enter")return;
    const v=mk.value.trim();
    if(!v)return;
    if(EXTRA.indexOf(v)<0)EXTRA.push(v);
    Object.keys(CHOICE).forEach(function(k){CHOICE[k].scope=v});
    mk.value="";renderModal();
  };
  bar.append(setAll,mk);
  c.append(bar);

  STAGES.forEach(function(st){
    c.append($('<div class="file">'+esc(st.file)+'</div>'));
    st.rejected.forEach(function(n){c.append($('<div class="muted">skipped '+esc(n)+' — not a usable variable name</div>'))});
    st.entries.forEach(function(e){
      const cid=ck(st.stageId,e.key);
      const row=$('<div class="stagerow"></div>');
      const cb=document.createElement("input");
      cb.type="checkbox";cb.checked=CHOICE[cid].include;
      cb.onchange=function(){CHOICE[cid].include=cb.checked;refreshCount()};
      row.append(cb);
      row.append($('<div class="k">'+esc(e.key)+'</div>'));
      row.append($('<div class="muted">'+esc(e.preview)+(e.multiline?" · multi-line":"")+'</div>'));
      if(e.existsIn.length)row.append($('<span class="warn">already in '+esc(e.existsIn.join(", "))+'</span>'));
      else if(e.service)row.append($('<span class="hint">'+esc(e.service)+'</span>'));
      row.append(scopeSelect(cid));
      const tag=document.createElement("input");
      tag.type="text";tag.placeholder="tag";tag.value=CHOICE[cid].note;
      tag.oninput=function(){CHOICE[cid].note=tag.value};
      row.append(tag);
      c.append(row);
    });
  });

  const foot=document.createElement("div");foot.className="stagefoot";
  countBtn=document.createElement("button");countBtn.type="button";
  countBtn.className="primary";
  countBtn.onclick=doImport;
  const ow=document.createElement("label");
  const owc=document.createElement("input");
  owc.type="checkbox";owc.checked=OVERWRITE;
  owc.onchange=function(){OVERWRITE=owc.checked};
  ow.append(owc,document.createTextNode("overwrite keys that already exist"));
  const cancel=document.createElement("button");cancel.type="button";
  cancel.className="quiet";
  cancel.textContent="Discard";
  cancel.onclick=async function(){
    const ids=STAGES.map(function(st){return st.stageId});
    STAGES=[];CHOICE={};EXTRA=[];countBtn=null;renderModal();
    try{await api("/api/discard",{stageIds:ids})}catch(err){}
    toast("discarded");
  };
  foot.append(countBtn,ow,cancel);
  c.append(foot);
  refreshCount();
  return c;
}

async function doImport(){
  if(importing)return;                       // a double click would re-send spent stages
  if(!stagedCount()){toast("nothing selected");return}
  importing=true;
  if(countBtn){countBtn.disabled=true;countBtn.textContent="Importing…"}
  try{
    await runImport();
  }catch(err){
    // Leave the review on screen so the work is not lost, and let them retry.
    if(countBtn){countBtn.disabled=false}
    refreshCount();
  }finally{
    importing=false;
  }
}

async function runImport(){
  const batches=STAGES.map(function(st){
    const assignments={};
    st.entries.forEach(function(e){
      const cid=ck(st.stageId,e.key);
      if(!CHOICE[cid].include)return;
      assignments[e.key]={scope:CHOICE[cid].scope,note:CHOICE[cid].note};
    });
    return {stageId:st.stageId,assignments:assignments};
  });
  const res=await api("/api/import",{stages:batches,overwrite:OVERWRITE});
  STAGES=[];CHOICE={};EXTRA=[];countBtn=null;
  await refresh(res);
  let msg="imported "+res.imported.length;
  if(res.skipped.length)msg+=", skipped "+res.skipped.length;
  if(res.vaultCreated)msg+=" — made this folder's own vault, commit .hush/vault.json";
  toast(msg);
  if(res.unpinned&&res.unpinned.length){
    const body=document.getElementById("sectionbody");
    const box=document.createElement("div");box.className="panelbox";
    box.append($("<h3>Not in use here yet</h3>"));
    res.unpinned.forEach(function(u){
      const row=$('<div class="redrow"></div>');
      row.append($('<div class="redkey">'+esc(u.scope)+'</div>'));
      row.append($('<div class="muted">'+u.keys+' key(s) — this project does not use this account, so hush run will not inject them</div>'));
      const b=document.createElement("button");b.type="button";b.className="primary";b.textContent="Use it here";
      b.onclick=async function(){await refresh(await api("/api/link",{name:u.scope,use:true}));toast("using "+u.scope+" here")};
      row.append(b);
      box.append(row);
    });
    body.insertBefore(box,body.firstChild);
  }
  if(res.skipped.length){
    const body=document.getElementById("sectionbody");
    const box=document.createElement("div");box.className="panelbox";
    box.append($('<h3>Skipped '+res.skipped.length+'</h3>'));
    res.skipped.forEach(function(sk){box.append($('<div class="redrow"><div class="redkey">'+esc(sk.key)+'</div><div class="muted">'+esc(sk.why)+'</div></div>'))});
    body.insertBefore(box,body.firstChild);
  }
}

function renderModal(){
  const back=document.getElementById("modalback");
  const panel=document.getElementById("modalpanel");
  if(!STAGES.length){back.hidden=true;panel.innerHTML="";return}
  panel.innerHTML="";
  panel.append(stagingPanel());
  back.hidden=false;
}

/* Drag anywhere on the window, not just onto a small target. */
let dragDepth=0;
function dz(){return document.getElementById("drop")}
window.addEventListener("dragenter",function(ev){ev.preventDefault();dragDepth++;dz().classList.add("on")});
window.addEventListener("dragover",function(ev){ev.preventDefault()});
window.addEventListener("dragleave",function(ev){ev.preventDefault();if(--dragDepth<=0){dragDepth=0;dz().classList.remove("on")}});
window.addEventListener("drop",function(ev){
  ev.preventDefault();dragDepth=0;dz().classList.remove("on");
  if(ev.dataTransfer&&ev.dataTransfer.files&&ev.dataTransfer.files.length)ingestFiles(ev.dataTransfer.files);
});
document.getElementById("picker").addEventListener("change",function(ev){
  if(ev.target.files&&ev.target.files.length)ingestFiles(ev.target.files);
  ev.target.value="";
});
document.getElementById("drophint-holder").append(dropCard());

/* -------------------------------------------------------------- the shell */

const SECTIONS=["library","folder","team","agent","activity"];
const SECTION_TITLES={library:"Library",folder:"This folder",team:"Team",agent:"Agent",activity:"Activity"};

function currentSection(){
  const h=(location.hash||"").replace("#","");
  return SECTIONS.indexOf(h)>-1?h:"library";
}

function sectionHeading(text){
  return $('<h2 class="sectiontitle">'+esc(text)+'</h2>');
}

function renderNav(){
  const nav=document.getElementById("navlist");
  nav.innerHTML="";
  const active=currentSection();
  const libUsed=(S.library||[]).filter(function(x){return x.used}).length;
  const folderUsed=(S.project||[]).filter(function(x){return x.used}).length;
  const items=[
    {id:"library",label:"Library",count:libUsed,bullet:true},
    {id:"folder",label:"This folder",count:folderUsed,bullet:true},
    {id:"team",label:"Team",count:S.members.length,bullet:false},
    {id:"agent",label:"Agent",count:0},
    {id:"activity",label:"Activity",count:0},
  ];
  items.forEach(function(it){
    const li=document.createElement("li");
    const a=document.createElement("a");
    a.href="#"+it.id;
    a.textContent=it.label;
    if(it.id===active){a.className="active";a.setAttribute("aria-current","page")}
    if(it.count>0){
      const c=document.createElement("span");
      c.className="count"+(it.bullet?" used":"");
      c.textContent=(it.bullet?"●":"")+it.count;
      a.append(c);
    }
    li.append(a);
    nav.append(li);
  });
}

function renderHeader(){
  const name=S.folder.root.replace(/[\\/]+$/,"").split(/[\\/]/).pop()||S.folder.root;
  document.getElementById("foldername").textContent=name;
  const stateText=S.folder.state==="unset"?"not set up"
    :S.folder.state==="links-only"?"no vault yet — uses library sets only"
    :"vault committed to the repo";
  document.getElementById("folderstate").textContent=stateText;
}

function renderSidefoot(){
  document.getElementById("runglink").textContent="rung "+S.posture.rung+" of 5";
}

function render(){
  renderHeader();
  renderNav();
  renderSidefoot();

  const body=document.getElementById("sectionbody");
  body.innerHTML="";
  const sec=currentSection();
  body.append(sectionHeading(SECTION_TITLES[sec]));
  if(sec==="library")body.append(renderLibrary());
  else if(sec==="folder")body.append(renderFolder());
  else if(sec==="team")body.append(renderTeam());
  else if(sec==="agent")body.append(renderAgent());
  else if(sec==="activity")body.append(renderActivity());

  renderModal();
}
window.addEventListener("hashchange",render);

refresh().catch(function(e){document.getElementById("sectionbody").innerHTML='<div class="empty">'+esc(e.message)+'</div>'});
</script></body></html>`;
