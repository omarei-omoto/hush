/**
 * The app's endpoints, and the staging area for a dropped .env (values stay here, never
 * in the browser, until they are imported or discarded).
 */
import { type IncomingMessage, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { parseEnvFile } from "./scan.ts";
import { loadPolicy, DEFAULT_POLICY } from "./mcp.ts";
import { requestApproval } from "./approval.ts";
import { Vault, namedVaultPath, audit, ValidationError, slugifyEnv, assertProjectHushDir } from "./vault.ts";
import { librarySets, loadLinks, saveLinks, openGlobal, usedSets, globalVaultName, saveConfig, writeProjectDotfiles, linkNameFor } from "./library.ts";
import { requireIdentity } from "./identity.ts";
import { CATALOG, serviceForVar } from "./services.ts";
import { preview } from "./redact.ts";
import { withoutChain } from "./audit.ts";
import { type UiCtx, openProjectVault, projectVault, requireProjectVault, state } from "./ui-state.ts";

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

export const json = (res: ServerResponse, code: number, body: unknown) => {
  const s = JSON.stringify(body);
  res.writeHead(code, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(s),
    "cache-control": "no-store",
  });
  res.end(s);
};

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

export async function handleApi(ctx: UiCtx, req: IncomingMessage, res: ServerResponse, path: string) {
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
        v.removeSet(id, String(name));
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
          priv: id.priv,
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
      const { sets, role } = body;
      if (sets !== undefined && (!Array.isArray(sets) || sets.some((x: unknown) => typeof x !== "string"))) {
        return json(res, 400, { error: "sets must be a list of set names" });
      }
      v.addRecipient(id, name, pk, role === "admin" ? "admin" : "member", { sets: (sets as string[] | undefined) ?? [] });
      v.save();
      audit(ctx.hushDir, { actor: "ui", action: "team.add", name, sets: sets ?? [] });
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
            return withoutChain(rest);
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
