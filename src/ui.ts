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
import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { parseEnvFile } from "./scan.ts";
import { loadPolicy } from "./mcp.ts";
import { requestApproval } from "./approval.ts";
import {
  Vault, resolveVaultPath, namedVaultPath, audit,
  isValidationError, ValidationError, slugifyEnv,
} from "./vault.ts";
import {
  librarySets, loadLinks, saveLinks, openGlobal, usedSets,
  globalVaultName, globalVaultExists, globalVaultPath, namedVaults, saveConfig,
} from "./library.ts";
import { requireIdentity, publicKeyOf } from "./identity.ts";
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
  vaultPath: string;
  hushDir: string;
  defaultEnv: string;
  /** True when the app was opened outside any project, on the library alone. */
  standalone?: boolean;
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
  const vault = Vault.open(ctx.vaultPath);
  const id = requireIdentity();

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

  const projectSets = vault.sets().map((s) => ({
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
  }));

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

  return {
    vault: vault.data.name,
    me: { name: vault.memberName(id), pk: publicKeyOf(id) },
    defaultEnv: ctx.defaultEnv,
    standalone: Boolean(ctx.standalone),
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
    members: vault.members().map((m) => ({
      name: m.name,
      role: m.role,
      pk: m.pk,
      canDecrypt: m.canDecrypt,
    })),
  };
}

async function handleApi(ctx: UiCtx, req: IncomingMessage, res: ServerResponse, path: string) {
  const vault = () => Vault.open(ctx.vaultPath);
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
      if (inLibrary) {
        const g = openGlobal();
        if (!g) return json(res, 400, { error: "you have no library vault yet" });
        v = g;
      } else {
        v = vault();
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
      return json(res, 200, state(ctx));
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

      const open = (): Vault => {
        if (!inLibrary) return vault();
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
        return json(res, 200, { ...state(ctx), created: slug, vars });
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
      const v = vault();
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

      const scopes = v.envNames();
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
          existsIn: scopes.filter((s) => v.has(s, key)),
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
      if (intoLibrary) {
        const g = openGlobal();
        if (!g) return json(res, 400, { error: "you have no library vault yet" });
        v = g;
      } else {
        v = vault();
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

      return json(res, 200, { ...state(ctx), imported, skipped, unpinned });
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
      const v = vault();
      if (action === "remove") {
        const r = v.removeRecipient(id, name);
        v.save();
        audit(ctx.hushDir, { actor: "ui", action: "team.remove", name });
        return json(res, 200, { ...state(ctx), notice: `Removed ${name}; re-sealed ${r.reEncrypted} value(s).` });
      }
      v.addRecipient(id, name, pk);
      v.save();
      audit(ctx.hushDir, { actor: "ui", action: "team.add", name });
      return json(res, 200, state(ctx));
    }

    default:
      return json(res, 404, { error: "not found" });
  }
}

export function serveUi(opts: { port?: number; open?: boolean } = {}): void {
  const loc = resolveVaultPath(process.cwd());

  // Your library is yours wherever you are standing, so the app opens on it
  // alone when there is no project here. Requiring a repo to look at your own
  // keys is the kind of thing that makes a tool annoying, and the library is
  // the level most of this is managed at anyway.
  let ctx: UiCtx;
  if (loc) {
    ctx = { vaultPath: loc.vaultPath, hushDir: loc.hushDir, defaultEnv: loc.env || "default" };
  } else if (globalVaultExists()) {
    ctx = {
      vaultPath: globalVaultPath(),
      hushDir: dirname(globalVaultPath()),
      defaultEnv: "default",
      standalone: true,
    };
  } else {
    throw new Error(
      "No vault here and no library yet.\n" +
        "  Start a project:  hush init\n" +
        "  Or make a library: hush global --create",
    );
  }
  // Fail fast rather than after the browser opens.
  const v = Vault.open(ctx.vaultPath);
  const id = requireIdentity();
  if (!v.canRead(id)) throw new Error(`Your key is not a recipient of vault "${v.data.name}".`);

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
    process.stdout.write(`\n  hush ui  →  ${link}\n\n  vault: ${v.data.name}\n  Ctrl-C to stop.\n\n`);
    if (opts.open !== false) {
      import("node:child_process").then(({ spawn }) => {
        const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
        spawn(cmd, [link], { stdio: "ignore", detached: true }).unref();
      });
    }
  });
}

// ----------------------------------------------------------------- the page

const PAGE = String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>hush</title>
<style>
:root{
  --bg:#fbfbfa; --panel:#fff; --line:#e6e4e0; --ink:#1c1b19; --dim:#78746e;
  --accent:#2f6f4f; --accent-soft:#e8f2ec; --danger:#a8342a; --radius:10px;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#141413; --panel:#1c1b1a; --line:#302e2b; --ink:#eeece7; --dim:#948f88;
  --accent:#6fb894; --accent-soft:#1d2b24; --danger:#e0705f;
}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:14px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:920px;margin:0 auto;padding:28px 20px 80px}
header{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:6px}
h1{font-size:19px;margin:0;letter-spacing:-.2px}
h1 span{color:var(--dim);font-weight:400}
.sub{color:var(--dim);font-size:12.5px;margin-bottom:26px}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.9px;color:var(--dim);
  margin:34px 0 12px;font-weight:600}
h2 .h2note{text-transform:none;letter-spacing:0;font-weight:400;color:var(--dim);
  opacity:.75;margin-left:10px;font-size:11.5px}
.namer{border:1px solid var(--accent);background:var(--accent-soft);border-radius:9px;
  padding:12px 14px;margin:12px 0 14px}
.namerlead{margin-bottom:9px;font-size:13.5px}
.namer .bulk{margin:0 0 8px}
.namer .muted{margin-top:2px}
.card.set{padding-bottom:12px}
.sethead{display:flex;align-items:flex-start;gap:12px;justify-content:space-between}
.setname{flex:1;min-width:0}
.nameinput{font-size:15px;font-weight:600;background:transparent;border:1px solid transparent;
  border-radius:7px;padding:3px 7px;margin:-3px 0 0 -7px;width:100%;color:var(--ink);
  font-family:inherit}
.nameinput:hover{border-color:var(--line)}
.nameinput:focus{border-color:var(--accent);background:var(--bg);outline:none}
.slug{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;color:var(--dim);padding-left:1px;margin-top:2px}
.setactions{display:flex;align-items:center;gap:14px;flex-shrink:0;padding-top:4px}
.setactions .link.on{color:var(--accent)}
.setfields{display:flex;flex-direction:column;gap:6px;margin-top:10px}
.setfield{background:transparent;border:1px solid transparent;border-radius:7px;
  padding:4px 7px;margin-left:-7px;width:100%;color:var(--ink);font-family:inherit;font-size:12.5px}
.setfield::placeholder{color:var(--dim);opacity:.6}
.setfield:hover{border-color:var(--line)}
.setfield:focus{border-color:var(--accent);background:var(--bg);outline:none}
.moveto{background:transparent;border:1px solid var(--line);border-radius:6px;color:var(--dim);
  font-family:inherit;font-size:11.5px;padding:2px 5px;max-width:130px}
.setkeys{display:flex;flex-wrap:wrap;gap:5px;margin-top:11px}
.chip{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;padding:2px 7px;border-radius:5px;
  background:var(--accent-soft);color:var(--dim)}
.setsecrets{margin-top:12px;border-top:1px solid var(--line);padding-top:6px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  padding:14px 16px;margin-bottom:10px}
.svc{display:flex;align-items:center;gap:9px;margin-bottom:4px}
.svc b{font-size:14.5px}
.tag{font-size:11px;padding:2px 7px;border-radius:20px;background:var(--accent-soft);
  color:var(--accent);font-weight:600;letter-spacing:.2px}
.row{display:flex;align-items:center;gap:10px;padding:7px 0;border-top:1px solid var(--line)}
.row:first-of-type{border-top:0}
.k{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;min-width:190px}
.v{color:var(--dim);font-family:ui-monospace,Menlo,monospace;font-size:12.5px;flex:1;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.spacer{flex:1}
button{font:inherit;font-size:12.5px;padding:5px 11px;border-radius:7px;cursor:pointer;
  border:1px solid var(--line);background:transparent;color:var(--ink)}
button:hover{border-color:var(--dim)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.primary:hover{opacity:.9}
button.link{border:0;padding:4px 6px;color:var(--dim);text-decoration:underline}
button.link:hover{color:var(--ink)}
button.danger{color:var(--danger);border-color:transparent}
input,select{font:inherit;font-size:13px;padding:7px 10px;border:1px solid var(--line);
  border-radius:7px;background:var(--bg);color:var(--ink);width:100%}
input:focus,select:focus{outline:2px solid var(--accent);outline-offset:-1px;border-color:transparent}
form.add{display:grid;gap:9px;margin-top:12px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:9px}
@media(max-width:560px){.grid2{grid-template-columns:1fr}.k{min-width:0}}
.muted{color:var(--dim);font-size:12.5px}
.empty{color:var(--dim);padding:18px;text-align:center;border:1px dashed var(--line);
  border-radius:var(--radius)}
.toast{position:fixed;left:50%;transform:translateX(-50%);bottom:22px;background:var(--ink);
  color:var(--bg);padding:9px 16px;border-radius:8px;font-size:13px;opacity:0;
  transition:opacity .18s;pointer-events:none;max-width:90vw}
.toast.on{opacity:1}
details summary{cursor:pointer;color:var(--dim);font-size:12.5px;padding:4px 0}
code{font-family:ui-monospace,Menlo,monospace;font-size:12px;background:var(--accent-soft);
  padding:1px 5px;border-radius:4px}

/* --- dropzone and staging --- */
.dropzone{position:fixed;inset:12px;border:3px dashed var(--accent);border-radius:16px;
  background:var(--accent-soft);display:none;align-items:center;justify-content:center;
  z-index:50;font-size:17px;color:var(--accent);font-weight:600;pointer-events:none;text-align:center}
.dropzone.on{display:flex}
.dropcard{border:1.5px dashed var(--line);border-radius:var(--radius);padding:20px;text-align:center;
  color:var(--dim);cursor:pointer;margin-bottom:12px;background:var(--panel);font-size:13px}
.dropcard:hover{border-color:var(--accent);color:var(--accent)}
.dropcard b{display:block;color:var(--ink);font-size:14px;margin-bottom:3px}
.stage{border-color:var(--accent)}
.bulk{display:flex;gap:9px;margin:12px 0 4px;flex-wrap:wrap}
.bulk select,.bulk input{flex:1;min-width:160px}
.file{font-size:11px;color:var(--dim);margin:16px 0 2px;font-weight:600;letter-spacing:.7px;
  text-transform:uppercase}
.stagerow{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.stagerow .k{min-width:150px;flex:0 0 auto}
.stagerow select{max-width:180px;flex:0 0 auto}
.stagerow .tag{max-width:120px;flex:0 0 auto}
.row .tag{max-width:110px;flex:0 0 auto;font-size:12px;padding:3px 7px;
  border-color:transparent;background:transparent;color:var(--dim)}
.row .tag:hover{border-color:var(--line)}
.row .tag:focus{background:var(--bg);color:var(--ink)}
.stagerow input[type=checkbox]{width:auto;flex:0 0 auto;accent-color:var(--accent)}
.warn{font-size:11px;color:var(--danger);white-space:nowrap}
.hint{font-size:11px;color:var(--accent);white-space:nowrap}
.stagefoot{display:flex;gap:12px;align-items:center;margin-top:16px;flex-wrap:wrap}
.stagefoot label{font-size:12.5px;color:var(--dim);display:flex;align-items:center;gap:6px}
.stagefoot label input{width:auto;accent-color:var(--accent)}
@media(max-width:600px){.stagerow .k{min-width:0;width:100%}.stagerow select,.stagerow .tag{max-width:none;flex:1}}
</style></head><body><div class="wrap">
<header><h1>hush <span id="vname"></span></h1></header>
<div class="sub" id="who"></div>
<div id="app"></div>
</div>
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

async function retag(scope,key,note){
  await refresh(await api("/api/tag",{scope,key,note}));
  toast(note?"tagged "+key:"tag cleared");
}
async function setSecret(scope,key,value,where){await refresh(await api("/api/secret",{scope,key,value,where}));toast(value===null?"deleted":"saved")}
async function reveal(scope,key,el,where){
  const {value}=await api("/api/reveal",{scope,key,where});
  el.textContent=value; el.style.color="var(--ink)";
  setTimeout(()=>{el.textContent="•••••••• (hidden again)";el.style.color="";},15000);
}

function secretRow(scope,s,where){
  const row=$('<div class="row"></div>');
  row.append($('<div class="k">'+esc(s.key)+'</div>'));
  const v=$('<div class="v">'+esc(s.preview)+'</div>');row.append(v);
  // The tag is editable in place: click it, type, blur to save.
  const tag=document.createElement("input");
  tag.type="text";tag.className="tag";tag.placeholder="tag";tag.value=s.note||"";
  tag.onblur=()=>{if((s.note||"")!==tag.value)retag(scope,s.key,tag.value)};
  tag.onkeydown=(ev)=>{if(ev.key==="Enter")tag.blur()};
  row.append(tag);

  // Moving a key is how one big pile under "default" becomes named sets, so it
  // belongs on the row rather than behind a separate screen.
  const here=where||"project";
  const dests=(here==="library"?S.library.map(function(x){return {name:x.name,label:x.label}}):
                                S.project.map(function(x){return {name:x.name,label:x.label}}))
              .filter(function(x){return x.name!==scope});
  if(dests.length){
    const mv=document.createElement("select");
    mv.className="moveto";
    mv.append($('<option value="">move to…</option>'));
    dests.forEach(function(d){mv.append($('<option value="'+esc(d.name)+'">'+esc(d.label)+'</option>'))});
    mv.onchange=async function(){
      if(!mv.value)return;
      const to=mv.value;mv.value="";
      try{
        await refresh(await api("/api/move",{where:here,key:s.key,from:scope,to:to}));
        toast("moved "+s.key);
      }catch(e){toast(e.message)}
    };
    row.append(mv);
  }

  const rv=$('<button class="link">reveal</button>');
  rv.onclick=()=>reveal(scope,s.key,v,where).catch(()=>{});
  const ed=$('<button class="link">replace</button>');
  ed.onclick=()=>{const nv=prompt("New value for "+s.key);if(nv)setSecret(scope,s.key,nv,where)};
  const rm=$('<button class="link danger">delete</button>');
  rm.onclick=()=>{if(confirm("Delete "+s.key+"?"))setSecret(scope,s.key,null,where)};
  row.append(rv,ed,rm);
  return row;
}

/* ---------------- dropzone: bring a .env in, then say where each key goes -------- */

let STAGES=[];        // [{stageId,file,entries,rejected}]
let CHOICE={};        // stageId|key -> {scope,note,include}   (per row, not per name)
let EXTRA=[];         // scopes typed during review
let OVERWRITE=false;
let countBtn=null;

/* Two dropped files may each define the same variable; keep their rows apart. */
function ck(stageId,key){return stageId+"|"+key}

function allScopes(){
  const out=[];
  (S.project||[]).forEach(e=>out.push(e.name));
  (S.library||[]).forEach(s=>{if(out.indexOf(s.name)<0)out.push(s.name)});
  EXTRA.forEach(x=>{if(out.indexOf(x)<0)out.push(x)});
  return out;
}

function stagedCount(){return Object.keys(CHOICE).filter(k=>CHOICE[k].include).length}

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
      const st=await api("/api/stage",{text,filename:f.name});
      if(!st.entries.length&&!st.rejected.length){toast("no variables in "+f.name);continue}
      STAGES.push(st);
      // Pre-tag with the service hush recognised, so the common case is one click.
      st.entries.forEach(e=>{CHOICE[ck(st.stageId,e.key)]={scope:e.suggestedScope,note:e.service||"",include:true}});
      added++;
    }catch(err){/* api() already reported it */}
  }
  if(added)render();
}

function scopeSelect(cid){
  const sel=document.createElement("select");
  allScopes().forEach(sc=>{
    const o=document.createElement("option");
    o.value=sc;o.textContent=sc;
    if(CHOICE[cid].scope===sc)o.selected=true;
    sel.append(o);
  });
  sel.onchange=()=>{CHOICE[cid].scope=sel.value};
  return sel;
}

function dropCard(){
  const c=$('<div class="dropcard"><b>Drop a .env file here</b>or click to choose one — you pick where each key goes before anything is saved</div>');
  c.onclick=()=>document.getElementById("picker").click();
  return c;
}

function stagingPanel(){
  const c=$('<div class="card stage"></div>');
  let total=0;STAGES.forEach(st=>{total+=st.entries.length});
  c.append($('<div class="svc"><b>Review '+total+' variable(s)</b></div>'));
  c.append($('<div class="muted">Nothing is saved until you import. Values stay on this machine.</div>'));

  // The thing people actually want when they drop a .env: give the whole file a
  // name, and have it become one entry in a list rather than twenty loose keys
  // filed under "default".
  const namer=$('<div class="namer"></div>');
  namer.append($('<div class="namerlead"><b>Save all of this as one named set</b></div>'));
  const nrow=$('<div class="bulk"></div>');
  const setName=document.createElement("input");
  setName.type="text";
  const guess=STAGES.length===1?(STAGES[0].file||"").replace(/^\.env\.?/,"").replace(/[-_.]+/g," ").trim():"";
  setName.placeholder="name it — e.g. Acme Production";
  setName.value=guess?guess.charAt(0).toUpperCase()+guess.slice(1):"";
  const setDesc=document.createElement("input");
  setDesc.type="text";setDesc.placeholder="what is it for? (optional)";
  const dest=document.createElement("select");
  dest.append($('<option value="library">in my library — every project can use it</option>'));
  dest.append($('<option value="project">in this project — shared with the team</option>'));
  if(!S.global.exists)dest.value="project";
  nrow.append(setName,setDesc);
  namer.append(nrow);
  const drow=$('<div class="bulk"></div>');
  drow.append(dest);
  const go=$('<button type="button">Save as a named set</button>');
  go.onclick=async()=>{
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
      const batches=STAGES.map(st=>{
        const assignments={};
        st.entries.forEach(e=>{
          const c=CHOICE[ck(st.stageId,e.key)];
          if(c&&c.include!==false)assignments[e.key]={scope:scope,note:(c&&c.note)||""};
        });
        return {stageId:st.stageId,assignments:assignments};
      }).filter(b=>Object.keys(b.assignments).length);
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
  namer.append($('<div class="muted">Or file them one by one below.</div>'));
  c.append(namer);

  const bar=$('<div class="bulk"></div>');
  const setAll=document.createElement("select");
  setAll.append($('<option value="">move all to…</option>'));
  allScopes().forEach(sc=>setAll.append($('<option value="'+esc(sc)+'">'+esc(sc)+'</option>')));
  setAll.onchange=()=>{
    if(!setAll.value)return;
    Object.keys(CHOICE).forEach(k=>{CHOICE[k].scope=setAll.value});
    render();
  };
  const mk=document.createElement("input");
  mk.type="text";
  mk.placeholder="or a new scope, e.g. fal/acme — press enter";
  mk.onkeydown=(ev)=>{
    if(ev.key!=="Enter")return;
    const v=mk.value.trim();
    if(!v)return;
    if(EXTRA.indexOf(v)<0)EXTRA.push(v);
    Object.keys(CHOICE).forEach(k=>{CHOICE[k].scope=v});
    mk.value="";render();
  };
  bar.append(setAll,mk);
  c.append(bar);

  STAGES.forEach(st=>{
    c.append($('<div class="file">'+esc(st.file)+'</div>'));
    st.rejected.forEach(n=>c.append($('<div class="row"><span class="muted">skipped '+esc(n)+' — not a usable variable name</span></div>')));
    st.entries.forEach(e=>{
      const cid=ck(st.stageId,e.key);
      const row=$('<div class="row stagerow"></div>');
      const cb=document.createElement("input");
      cb.type="checkbox";cb.checked=CHOICE[cid].include;
      cb.onchange=()=>{CHOICE[cid].include=cb.checked;refreshCount()};
      row.append(cb);
      row.append($('<div class="k">'+esc(e.key)+'</div>'));
      row.append($('<div class="v">'+esc(e.preview)+(e.multiline?" · multi-line":"")+'</div>'));
      if(e.existsIn.length)row.append($('<span class="warn">already in '+esc(e.existsIn.join(", "))+'</span>'));
      else if(e.service)row.append($('<span class="hint">'+esc(e.service)+'</span>'));
      row.append(scopeSelect(cid));
      const tag=document.createElement("input");
      tag.type="text";tag.className="tag";tag.placeholder="tag";tag.value=CHOICE[cid].note;
      tag.oninput=()=>{CHOICE[cid].note=tag.value};
      row.append(tag);
      c.append(row);
    });
  });

  const foot=$('<div class="stagefoot"></div>');
  countBtn=document.createElement("button");
  countBtn.className="primary";
  countBtn.onclick=doImport;
  const ow=document.createElement("label");
  const owc=document.createElement("input");
  owc.type="checkbox";owc.checked=OVERWRITE;
  owc.onchange=()=>{OVERWRITE=owc.checked};
  ow.append(owc,document.createTextNode("overwrite keys that already exist"));
  const cancel=document.createElement("button");
  cancel.textContent="Discard";
  cancel.onclick=async()=>{
    const ids=STAGES.map(st=>st.stageId);
    STAGES=[];CHOICE={};EXTRA=[];countBtn=null;render();
    try{await api("/api/discard",{stageIds:ids})}catch(err){}
    toast("discarded");
  };
  foot.append(countBtn,ow,$('<div class="spacer"></div>'),cancel);
  c.append(foot);
  refreshCount();
  return c;
}

let importing=false;

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
  const batches=STAGES.map(st=>{
    const assignments={};
    st.entries.forEach(e=>{
      const cid=ck(st.stageId,e.key);
      if(!CHOICE[cid].include)return;
      assignments[e.key]={scope:CHOICE[cid].scope,note:CHOICE[cid].note};
    });
    return {stageId:st.stageId,assignments};
  });
  const res=await api("/api/import",{stages:batches,overwrite:OVERWRITE});
  STAGES=[];CHOICE={};EXTRA=[];countBtn=null;
  await refresh(res);
  let msg="imported "+res.imported.length;
  if(res.skipped.length)msg+=", skipped "+res.skipped.length;
  toast(msg);
  if(res.unpinned&&res.unpinned.length){
    const app=document.getElementById("app");
    const box=$('<div class="card"></div>');
    box.append($('<div class="svc"><b>Not in use here yet</b></div>'));
    res.unpinned.forEach(u=>{
      const row=$('<div class="row"></div>');
      row.append($('<div class="k">'+esc(u.scope)+'</div>'));
      row.append($('<div class="v">'+u.keys+' key(s) — this project does not use this account, so hush run will not inject them</div>'));
      const b=$('<button class="primary">Use it here</button>');
      b.onclick=async()=>{await refresh(await api("/api/link",{name:u.scope,use:true}));toast("using "+u.scope+" here")};
      row.append(b);
      box.append(row);
    });
    app.insertBefore(box,app.firstChild);
  }
  if(res.skipped.length){
    const app=document.getElementById("app");
    const box=$('<div class="card"></div>');
    box.append($('<div class="svc"><b>Skipped '+res.skipped.length+'</b></div>'));
    res.skipped.forEach(sk=>box.append($('<div class="row"><div class="k">'+esc(sk.key)+'</div><div class="v">'+esc(sk.why)+'</div></div>')));
    app.insertBefore(box,app.firstChild);
  }
}

/* Drag anywhere on the window, not just onto a small target. */
let dragDepth=0;
function dz(){return document.getElementById("drop")}
window.addEventListener("dragenter",ev=>{ev.preventDefault();dragDepth++;dz().classList.add("on")});
window.addEventListener("dragover",ev=>{ev.preventDefault()});
window.addEventListener("dragleave",ev=>{ev.preventDefault();if(--dragDepth<=0){dragDepth=0;dz().classList.remove("on")}});
window.addEventListener("drop",ev=>{
  ev.preventDefault();dragDepth=0;dz().classList.remove("on");
  if(ev.dataTransfer&&ev.dataTransfer.files&&ev.dataTransfer.files.length)ingestFiles(ev.dataTransfer.files);
});
document.getElementById("picker").addEventListener("change",ev=>{
  if(ev.target.files&&ev.target.files.length)ingestFiles(ev.target.files);
  ev.target.value="";
});

/** 1st, 2nd, 3rd, 4th, … — how a set's place in the resolution order is shown. */
function ordinal(n){
  if(n%10===1&&n%100!==11)return n+"st";
  if(n%10===2&&n%100!==12)return n+"nd";
  if(n%10===3&&n%100!==13)return n+"rd";
  return n+"th";
}

/**
 * One named set, as an editable row.
 *
 * The name, the description and the note about when to use it are all edited in
 * place: an env set is a thing you name and explain, not a bare map key, and
 * asking someone to go to a different screen to rename it defeats the point.
 * Every field is optional, including the description. A library set and a
 * project set are the same card with the same toggle — the only difference is
 * which vault "where" points the writes at.
 */
function envSetCard(set,where){
  const c=$('<div class="card set"></div>');
  const head=$('<div class="sethead"></div>');

  const nameWrap=$('<div class="setname"></div>');
  const nm=document.createElement("input");
  nm.className="nameinput";nm.value=set.label;nm.placeholder="name this set";
  nm.title="Rename. The command-line name follows what you type.";
  let lastName=set.label;
  nm.onblur=async()=>{
    const next=nm.value.trim();
    if(!next||next===lastName){nm.value=lastName;return}
    try{
      const r=await api("/api/env",{action:"rename",where:where,name:set.name,label:next});
      lastName=next;await refresh(r);
      toast("renamed to "+next+(r.renamed?" ("+r.renamed+")":""));
    }catch(e){nm.value=lastName;toast(e.message)}
  };
  nm.onkeydown=(ev)=>{if(ev.key==="Enter")nm.blur();if(ev.key==="Escape"){nm.value=lastName;nm.blur()}};
  nameWrap.append(nm);
  nameWrap.append($('<div class="slug" title="hush use '+esc(set.name)+'">'+esc(set.name)+' · '+set.keys.length+' key'+(set.keys.length===1?'':'s')+'</div>'));
  head.append(nameWrap);

  // A library set and a project set are both just sets a run can use, so both
  // get the same toggle — "used" shows where it lands in resolution order,
  // since that is the number that decides which value wins a clash.
  const actions=$('<div class="setactions"></div>');
  if(where==="project"&&set.name==="default"){
    // The project's own default set is the floor of every run and cannot be
    // switched off, so a toggle here would promise something a click cannot
    // do. Say what it is instead.
    const floor=$('<button class="link on" disabled title="The default set of this project is always used, underneath everything else">● always used · '+ordinal((set.position||0)+1)+'</button>');
    actions.append(floor);
  }else{
    const useLabel=set.used?("● used · "+ordinal(set.position+1)):"use in this project";
    const use=$('<button class="'+(set.used?"link on":"link")+'">'+useLabel+'</button>');
    use.title=set.used?"Stop using it in this project":"Use it in this project";
    use.onclick=async()=>{
      const r=await api("/api/link",{name:set.name,use:!set.used});
      await refresh(r);toast(set.used?"dropped "+set.name:"this project now uses "+set.name);
    };
    actions.append(use);
  }
  const del=$('<button class="link danger">delete</button>');
  del.onclick=async()=>{
    if(!confirm('Delete "'+set.label+'" and its '+set.keys.length+' key(s)? This cannot be undone.'))return;
    await refresh(await api("/api/env",{action:"delete",where:where,name:set.name}));toast("deleted");
  };
  actions.append(del);
  head.append(actions);
  c.append(head);

  const fields=$('<div class="setfields"></div>');
  const mk=(value,placeholder,field,hint)=>{
    const i=document.createElement("input");
    i.className="setfield";i.value=value||"";i.placeholder=placeholder;i.title=hint;
    let last=value||"";
    i.onblur=async()=>{
      if(i.value===last)return;
      const patch={action:"describe",where:where,name:set.name};patch[field]=i.value;
      try{last=i.value;await refresh(await api("/api/env",patch));}
      catch(e){i.value=last;toast(e.message)}
    };
    i.onkeydown=(ev)=>{if(ev.key==="Enter")i.blur()};
    return i;
  };
  fields.append(mk(set.description,"what is this for?  (optional)","description","A short description. Optional."));
  fields.append(mk(set.whenToUse,"when should you use it?  (optional)","whenToUse","e.g. deploys only, local dev. Optional."));
  c.append(fields);

  if(set.secrets&&set.secrets.length){
    const detail=$('<div class="setsecrets"></div>');
    set.secrets.forEach(s=>detail.append(secretRow(set.name,s,where)));
    c.append(detail);
  }else if(set.keys.length){
    const keys=$('<div class="setkeys"></div>');
    set.keys.forEach(k=>keys.append($('<span class="chip">'+esc(k)+'</span>')));
    c.append(keys);
  }else{
    c.append($('<div class="muted">no keys in it yet</div>'));
  }
  if(set.source)c.append($('<div class="muted">from '+esc(set.source)+'</div>'));

  // Every card can grow, not just project ones — a library set used to need
  // the CLI for this, which defeats naming it here in the first place.
  const addRow=document.createElement("form");addRow.className="add";
  const ag=$('<div class="grid2"></div>');
  const ak=document.createElement("input");ak.placeholder="KEY";
  const av=document.createElement("input");av.placeholder="value";av.type="password";av.autocomplete="new-password";
  ag.append(ak,av);addRow.append(ag);
  addRow.append($('<button type="submit">Add</button>'));
  addRow.onsubmit=async(ev)=>{
    ev.preventDefault();
    if(!ak.value||!av.value)return;
    await setSecret(set.name,ak.value.trim(),av.value,where);
  };
  c.append(addRow);
  return c;
}

/** The first-run panel: you have no library, here is how to get one. */
function librarySetup(){
  const c=$('<div class="card"></div>');
  c.append($('<div class="svc"><b>You have no library yet</b></div>'));
  c.append($('<div class="muted">A library holds your named env sets in one place, so a key lives in exactly one vault and every project points at it.</div>'));
  const row=$('<div class="setactions"></div>');
  const make=$('<button type="button">Create one</button>');
  make.onclick=async()=>{await refresh(await api("/api/global",{create:true}));toast("library created")};
  row.append(make);
  (S.global.others||[]).forEach(v=>{
    const b=$('<button type="button" class="link">use my "'+esc(v)+'" vault</button>');
    b.onclick=async()=>{await refresh(await api("/api/global",{name:v}));toast("library is now "+v)};
    row.append(b);
  });
  c.append(row);
  return c;
}

/**
 * "Name this set" — the one way a new one is made by hand, at either level.
 * This replaces the old per-service account form: picking a service here is
 * just a hint that pre-fills the variable names it needs, one plain row each,
 * so they can be filled in like any other key rather than through a second
 * flow.
 */
function newSetForm(){
  const c=$('<div class="card"></div>');
  const f=document.createElement("form");f.className="add";
  const g=$('<div class="grid2"></div>');
  const nm=document.createElement("input");nm.placeholder="name a new set — e.g. Acme Production";
  const ds=document.createElement("input");ds.placeholder="what is it for? (optional)";
  g.append(nm,ds);f.append(g);

  const g2=$('<div class="grid2"></div>');
  const dest=document.createElement("select");
  dest.append($('<option value="library">in my library</option>'));
  if(!S.standalone)dest.append($('<option value="project">in this project</option>'));
  if(!S.global.exists)dest.value="project";
  const svc=document.createElement("select");
  svc.append($('<option value="">for a service… (optional)</option>'));
  S.catalog.forEach(function(s){svc.append($('<option value="'+esc(s.id)+'">'+esc(s.label)+'</option>'))});
  g2.append(dest,svc);f.append(g2);
  f.append($('<button type="submit">Add set</button>'));

  f.onsubmit=async(ev)=>{
    ev.preventDefault();
    if(!nm.value.trim())return;
    const where=dest.value;
    const serviceLabel=svc.options[svc.selectedIndex].text;
    try{
      if(where==="library"&&!S.global.exists)await api("/api/global",{create:true});
      const r=await api("/api/env",{
        action:"create",where:where,label:nm.value.trim(),description:ds.value,
        service:svc.value||undefined,
      });
      const created=r.created;
      await refresh(r);
      toast("created "+nm.value.trim());
      f.reset();
      if(created&&r.vars&&r.vars.length)promptForVars(where,created,serviceLabel,r.vars);
    }catch(e){toast(e.message)}
  };
  c.append(f);
  return c;
}

/**
 * The empty rows a "for a service…" pick offers: the set already exists with
 * nothing in it, so this is only ever a convenience, never the only way in —
 * the card's own add-key row reaches the same values.
 */
function promptForVars(where,scope,serviceLabel,vars){
  const app=document.getElementById("app");
  const box=$('<div class="card"></div>');
  box.append($('<div class="svc"><b>Fill in '+esc(serviceLabel)+'</b></div>'));
  const inputs=vars.map(function(name){
    const row=$('<div class="row"></div>');
    row.append($('<div class="k">'+esc(name)+'</div>'));
    const vi=document.createElement("input");vi.type="password";vi.placeholder="value";vi.autocomplete="new-password";
    row.append(vi);
    box.append(row);
    return {key:name,input:vi};
  });
  const save=$('<button class="primary">Save these values</button>');
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
  app.insertBefore(box,app.firstChild);
}

function render(){
  document.getElementById("vname").textContent="/ "+S.vault;
  document.getElementById("who").textContent="you are "+S.me.name+" · "+S.members.length+" member(s) · this file is safe to commit";
  const app=document.getElementById("app");app.innerHTML="";

  app.append(STAGES.length?stagingPanel():dropCard());

  // One list of sets, at two levels — the point of the screen, so it comes
  // first. Library and project cards are the same shape with the same toggle;
  // only the vault the writes land in differs.
  app.append($('<h2>Your library <span class="h2note">every project can use these · they stay in '+esc(S.global.name)+', never in the repo</span></h2>'));
  if(S.global.error){
    app.append($('<div class="empty">'+esc(S.global.error)+'</div>'));
  }else if(!S.global.exists){
    app.append(librarySetup());
  }else{
    if(!S.library.length)app.append($('<div class="empty">Drop a .env above, or make a set below.</div>'));
    S.library.forEach(set=>app.append(envSetCard(set,"library")));
  }

  if(S.standalone){
    app.append($('<h2>This project</h2>'));
    app.append($('<div class="empty">You opened hush outside a project, so there is nothing here.<br>Run <b>hush init</b> in a repo, then <b>hush ui</b> there, to use a set in it.</div>'));
  }else{
    app.append($('<h2>This project <span class="h2note">committed with the repo · your team gets these</span></h2>'));
    if(!S.project.length)app.append($('<div class="empty">Drop a .env above, or make a set below.</div>'));
    S.project.forEach(set=>app.append(envSetCard(set,"project")));
  }

  app.append($('<h2>New set</h2>'));
  app.append(newSetForm());

  app.append($('<h2>Team</h2>'));
  const tc=$('<div class="card"></div>');
  S.members.forEach(m=>{
    const r=$('<div class="row"></div>');
    r.append($('<div class="k">'+esc(m.name)+'</div>'));
    r.append($('<div class="v">'+esc(m.role)+' · '+esc(m.pk.slice(0,22))+'…</div>'));
    if(m.name!==S.me.name){
      const rm=$('<button class="link danger">remove</button>');
      rm.onclick=async()=>{if(!confirm("Remove "+m.name+"? Every value is re-encrypted and they lose access."))return;
        const r2=await api("/api/team",{action:"remove",name:m.name});await refresh(r2);toast(r2.notice||"removed")};
      r.append(rm);
    }
    tc.append(r);
  });
  const tf=document.createElement("form");tf.className="add";
  const g2=$('<div class="grid2"></div>');
  const nm=document.createElement("input");nm.placeholder="their name";
  const pk=document.createElement("input");pk.placeholder="hush_pk_…  (they run: hush id --create)";
  g2.append(nm,pk);tf.append(g2);
  tf.append($('<button type="submit">Give them access</button>'));
  tf.onsubmit=async(e)=>{e.preventDefault();if(!nm.value||!pk.value)return;
    await refresh(await api("/api/team",{name:nm.value.trim(),pk:pk.value.trim()}));
    toast("added "+nm.value);tf.reset()};
  tc.append(tf);app.append(tc);
}

refresh().catch(e=>{document.getElementById("app").innerHTML='<div class="empty">'+esc(e.message)+'</div>'});
</script></body></html>`;
