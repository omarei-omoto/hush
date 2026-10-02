/**
 * What each of the MCP server's tools does (mcp.ts has the protocol, the tool
 * list and the policy defaults). The contract is the server's: a tool may say
 * a secret exists and may use it, and none of them returns one.
 */
import { resolve as resolvePath, sep } from "node:path";
import { realpathSync } from "node:fs";
import { resolveVaultPath, Vault, audit, ValidationError, withoutControls } from "./vault.ts";
import { serviceLabel, knownVars, setNameFor, serviceForTool } from "./services.ts";
import { type Composed, composeSets, usedSets, librarySets, globalVaultName, openGlobal, linkNameFor, placeOf, allowedAt } from "./library.ts";
import { requestApproval, promptForSecretNatively, nativeDialogsAvailable } from "./approval.ts";
import {
  checkEnv, checkScopes, checkCommand, checkHost, runScope, requestScope,
  approvalCoverageLine, requestCoverageLine,
} from "./policy.ts";
import {
  isHeaderName, assertHeaderValue, requestWithSecrets, renderRequest,
  requestSummary, requestSecretNames, prepare, type RequestInput,
} from "./request.ts";
import { loadSchema, validate, unsensitiveForOutput, describeProblems } from "./schema.ts";
import { requireIdentity } from "./identity.ts";
import { scanTree, reconcile } from "./scan.ts";
import { runWithSecrets } from "./run.ts";
import { preview } from "./redact.ts";
import { loadPolicy, type Policy } from "./mcp.ts";


/** A required string argument. Without this, a missing `command` reached spawn as "undefined". */
function requireArg(args: Record<string, unknown>, name: string, tool: string): string {
  const v = args?.[name];
  if (typeof v !== "string" || v.trim() === "") {
    throw new Error(`${tool} needs a non-empty "${name}" argument.`);
  }
  return v;
}

const text = (s: string) => ({ content: [{ type: "text", text: s }] });
/** An error for the agent. Scrubbed like the terminal's: some of it came from the vault file. */
export const errText = (s: string) => ({ content: [{ type: "text", text: withoutControls(s) }], isError: true });

// ------------------------------------------------------------------ server

export interface Ctx {
  vault: Vault;
  hushDir: string;
  defaultEnv: string;
  policy: Policy;
  identity: ReturnType<typeof requireIdentity>;
  root: string;
  /**
   * Set only by the tailnet broker (broker.ts). Which tools may be called at
   * all; which sets a call may draw from, in place of this project's own; and
   * who asked, for the approval prompt and the audit log.
   */
  tools?: ReadonlySet<string>;
  compose?: (extra: string[]) => Composed;
  caller?: string;
  /** The caller's tailnet login, when it is a person (a tagged device has none). */
  callerLogin?: string;
}

function loadCtx(): Ctx {
  const loc = resolveVaultPath(process.cwd());
  if (!loc) throw new Error("No hush vault found from this directory. Run `hush init`.");
  const vault = Vault.open(loc.vaultPath);
  const identity = requireIdentity();
  if (!vault.canRead(identity)) {
    throw new Error(`This machine's key is not a recipient of vault "${vault.data.name}".`);
  }
  const policy = loadPolicy(loc.hushDir);
  return {
    vault,
    hushDir: loc.hushDir,
    defaultEnv: loc.env || "default",
    policy,
    identity,
    // Both separators: forward-slash only gave the wrong project root on Windows.
    root: loc.hushDir.replace(/[/\\]\.hush$/, ""),
  };
}

/**
 * The directory hush_check_repo may scan: the project, or somewhere inside it.
 *
 * It only ever reports variable *names*, never file contents or values, but
 * its description says "the current codebase" and an agent pointing it at
 * `/etc` or a sibling checkout got an answer (docs/RED-TEAM.md). Real paths on
 * both sides, so a symlink inside the project that leads out of it is outside.
 * A monorepo is covered: the root is the repository's, not the package's.
 */
export function confinedScanRoot(requested: unknown, root: string): string {
  if (requested === undefined || requested === null || requested === "") return root;
  if (typeof requested !== "string") throw new ValidationError(`"path" must be a string.`);
  const real = (p: string): string | null => {
    try {
      return realpathSync(p);
    } catch {
      return null;
    }
  };
  const base = real(root) ?? resolvePath(root);
  const target = real(resolvePath(root, requested));
  if (!target) throw new ValidationError(`No such directory in this project: ${requested.slice(0, 200)}`);
  if (target !== base && !target.startsWith(base + sep)) {
    throw new ValidationError(
      `"${requested.slice(0, 200)}" is outside this project (${root}). hush_check_repo scans the project hush was started in.`,
    );
  }
  return target;
}

interface ListedSet {
  name: string;
  label: string;
  description?: string;
  whenToUse?: string;
  onlyIn?: string[];
  keys: string[];
  where: "library" | "project";
  used: boolean;
}

/**
 * Every set the agent could use, library and project side by side.
 *
 * Listed separately rather than merged: a name can exist in both places at
 * once (the project one wins when a run actually resolves it — see
 * composeSets() — but an agent deciding which to ask for needs to see both).
 * Neither sets() nor librarySets() decrypts anything; both read plaintext
 * metadata, so this never touches a data key.
 */
function listSets(ctx: Ctx): ListedSet[] {
  const used = new Set(usedSets(ctx.hushDir));
  const project: ListedSet[] = ctx.vault.sets().map((s) => ({
    name: s.name,
    label: s.label,
    description: s.description,
    whenToUse: s.whenToUse,
    onlyIn: s.onlyIn,
    keys: s.keys,
    where: "project",
    used: used.has(s.name),
  }));
  const library: ListedSet[] = librarySets().map((s) => ({
    name: s.name,
    label: s.label,
    description: s.description,
    whenToUse: s.whenToUse,
    onlyIn: s.onlyIn,
    keys: s.keys,
    where: "library",
    used: used.has(linkNameFor("library", s.name)),
  }));
  return [...project, ...library].sort((a, b) => a.label.localeCompare(b.label));
}

export async function callTool(name: string, args: any, injected?: Ctx): Promise<unknown> {
  const ctx = injected ?? loadCtx();
  if (ctx.tools && !ctx.tools.has(name)) return errText(`${name} is not offered here.`);

  switch (name) {
    case "hush_list_secrets": {
      const set = String(args?.set || args?.env || ctx.defaultEnv);
      checkEnv(ctx.policy, set);
      const items = ctx.vault.list(set);
      audit(ctx.hushDir, { actor: "mcp", action: "list", set, count: items.length });
      if (!items.length) return text(`No secrets in set "${set}".`);
      const body = items
        .map((i) => `  ${i.key}${i.note ? `  — ${i.note}` : ""}   (set by ${i.updatedBy}, ${i.updatedAt.slice(0, 10)})`)
        .join("\n");
      return text(
        `${items.length} secret(s) in set "${set}" of vault "${ctx.vault.data.name}":\n${body}\n\n` +
          `Values are not available to you. Use hush_run to execute a command with these injected.`,
      );
    }

    case "hush_describe_secret": {
      const set = String(args?.set || args?.env || ctx.defaultEnv);
      checkEnv(ctx.policy, set);
      const key = requireArg(args, "key", "hush_describe_secret");
      if (!ctx.vault.has(set, key)) {
        return text(`"${key}" is NOT set in set "${set}". Use hush_add_secret to have the human add it.`);
      }
      const value = ctx.vault.get(ctx.identity, set, key);
      const meta = ctx.vault.list(set).find((i) => i.key === key)!;
      audit(ctx.hushDir, { actor: "mcp", action: "describe", set, key });
      return text(
        `${key} is set in set "${set}".\n` +
          `  preview:   ${preview(value)}\n` +
          `  length:    ${value.length}\n` +
          `  last set:  ${meta.updatedBy} on ${meta.updatedAt.slice(0, 10)}\n` +
          (meta.note ? `  note:      ${meta.note}\n` : ""),
      );
    }

    case "hush_list_sets":
    case "hush_list_accounts": {
      const all = listSets(ctx);
      if (!all.length) return text("No sets in this vault or library yet.");
      const lines = all.map((s) => {
        const flags = [s.where, s.used ? "used by this project" : null].filter(Boolean).join(", ");
        const label = s.label === s.name ? s.name : `${s.label} (${s.name})`;
        const limit = s.onlyIn
          ? allowedAt(s.onlyIn, placeOf(ctx.hushDir))
            ? `only in: ${s.onlyIn.join(", ")}`
            : `only in: ${s.onlyIn.join(", ")} — NOT usable in this project; hush will refuse it here`
          : null;
        const notes = [s.description, s.whenToUse ? `when: ${s.whenToUse}` : null, limit].filter(Boolean).join("  —  ");
        return (
          `  ${label}   [${flags}]   keys: ${s.keys.join(", ") || "(none)"}` + (notes ? `\n      ${notes}` : "")
        );
      });
      const footer =
        name === "hush_list_accounts"
          ? "\n\n(hush_list_accounts is deprecated and will be removed in hush 2.0; use hush_list_sets — this is the same list.)"
          : "";
      return text(
        `${all.length} set(s) available:\n${lines.join("\n")}\n\n` +
          `Pass one to hush_run as sets: ["<name>"].` +
          footer,
      );
    }

    case "hush_check_repo": {
      const env = args?.env || ctx.defaultEnv;
      checkEnv(ctx.policy, env);
      const root = confinedScanRoot(args?.path, ctx.root);
      const { usages, truncated } = scanTree(root);
      const r = reconcile(usages, ctx.vault.list(env).map((i) => i.key));
      audit(ctx.hushDir, { actor: "mcp", action: "check", env, missing: r.missing.length });
      const lines = [
        `Scanned ${root}`,
        `  referenced by code: ${r.needed.length}`,
        `  satisfied by vault: ${r.satisfied.length}`,
        `  MISSING:            ${r.missing.length}`,
        ...(truncated ? ["  (stopped early: the folder is too big to read in full — pass path: the project folder)"] : []),
      ];
      if (r.missing.length) {
        lines.push("", "Missing:");
        for (const m of r.missing.slice(0, 40)) {
          lines.push(`  ${m.name}   (used in ${m.sites.slice(0, 2).join(", ")})`);
        }
        lines.push("", "Add them with hush_add_secret — the human types each value on their own screen.");
      }
      if (r.unused.length) {
        lines.push("", `In vault but unreferenced: ${r.unused.join(", ")}`);
      }
      return text(lines.join("\n"));
    }

    case "hush_request": {
      const url = requireArg(args, "url", "hush_request");

      let parsedUrl: URL;
      try {
        parsedUrl = new URL(url);
      } catch {
        return errText(`hush_request got something that is not a URL: ${JSON.stringify(url)}`);
      }

      // Names and values arrive as separate arguments here, so they are
      // validated separately: joining them into "Name: value" and re-parsing
      // would let a name containing a colon become a second header.
      const headers: [string, string][] = [];
      const rawHeaders = args.headers;
      if (rawHeaders !== undefined && rawHeaders !== null) {
        if (typeof rawHeaders !== "object" || Array.isArray(rawHeaders)) {
          return errText('hush_request: "headers" must be an object of name -> value.');
        }
        for (const [name, value] of Object.entries(rawHeaders as Record<string, unknown>)) {
          if (typeof value !== "string") {
            return errText(`hush_request: header ${JSON.stringify(name)} must have a string value.`);
          }
          if (!isHeaderName(name)) {
            return errText(`hush_request: ${JSON.stringify(name)} is not a valid header name.`);
          }
          try {
            assertHeaderValue(name, value);
          } catch (e) {
            return errText(`hush_request: ${(e as Error).message}`);
          }
          headers.push([name, value]);
        }
      }

      const extraSets: string[] = Array.isArray(args.sets) ? args.sets.map(String) : [];
      const resolved = ctx.compose ? ctx.compose(extraSets) : composeSets(ctx.vault, ctx.identity, ctx.hushDir, extraSets);
      checkScopes(ctx.policy, resolved.layers);
      // The host takes the place of checkCommand's command: hush is the client
      // here, so the destination is the thing the caller actually chooses, and
      // it is the only control that decides where a credential may be sent.
      checkHost(ctx.policy, parsedUrl);

      const secrets = resolved.secrets;
      for (const k of ctx.policy.denyKeys) delete secrets[k];

      const input: RequestInput = {
        url,
        method: typeof args.method === "string" ? args.method : undefined,
        headers,
        body: typeof args.body === "string" ? args.body : undefined,
        secrets,
        substitute: Array.isArray(args.substitute) ? args.substitute.map(String) : [],
        timeoutMs: ctx.policy.maxRunMs,
        // A model's context is the scarce resource here, so a tool result is
        // capped tighter than the CLI's own default.
        maxBytes: 64 * 1024,
      };

      // Same schema gate as the CLI. No override here on purpose: a human may
      // overrule their own schema, an agent should not be able to talk past it.
      const requestSchema = loadSchema(ctx.root);
      if (requestSchema) {
        const problems = validate(secrets, requestSchema.rules, Object.keys(secrets));
        if (problems.length) {
          return errText(
            `.env.schema rejected ${problems.length} value(s), so nothing was sent:\n` +
              describeProblems(problems).map((l) => `  ${l}`).join("\n"),
          );
        }
        // Only the user's floor can grant an unmask; see unsensitiveForOutput.
        input.redactOmit = unsensitiveForOutput(requestSchema.rules, ctx.policy.unmaskKeys).omit;
      }

      // Validate before asking anyone to approve: a request that cannot be
      // built (an unresolvable $NAME, a secret in the path, cleartext) should
      // fail on its own, not after a human has been dragged into a dialog for
      // something that was never going to be sent.
      prepare(input);

      if (ctx.policy.requireApproval.includes("request")) {
        const ap = await requestApproval(ctx.hushDir, {
          action: "request",
          summary: `Request:  ${requestSummary(input, secrets)}`,
          detail: [
            `Sends:  ${requestSecretNames(input, secrets).join(", ") || "(no secret)"}`,
            `Using sets:  ${resolved.layers.join(", ") || "(none)"}`,
            ctx.caller ? `From:  ${ctx.caller}` : `Directory:  ${ctx.root}`,
            requestCoverageLine(ctx.policy, parsedUrl.host, resolved.layers),
          ],
          // Naming the host, so a grant for one destination cannot authorise
          // the same sets being sent somewhere else — and on a broker, naming
          // the caller, so one person's "Allow 15 min" is not everyone's.
          scope: requestScope(ctx.policy, parsedUrl.host, resolved.layers) + (ctx.caller ? `#from=${ctx.caller}` : ""),
          ...(ctx.callerLogin ? { approverFor: ctx.callerLogin } : {}),
          ttlSeconds: ctx.policy.approvalTtlSeconds,
          timeoutMs: Math.max(1, ctx.policy.approvalTimeoutSeconds) * 1000,
          biometry: ctx.policy.biometry,
        });
        audit(ctx.hushDir, {
          actor: "mcp", action: "approval", on: "request", decision: ap.decision, via: ap.via, code: ap.code,
          ...(ctx.caller ? { caller: ctx.caller } : {}),
        });
        if (ap.decision === "deny") {
          return errText(ap.note ?? `The user denied this (code ${ap.code}, via ${ap.via}).`);
        }
        if (ap.decision === "timeout") {
          return errText(
            `No answer to the approval prompt (code ${ap.code}). Ask the user to check their screen, then retry.`,
          );
        }
      }

      let result;
      try {
        result = await requestWithSecrets(input);
      } catch (e) {
        return errText((e as Error).message);
      }

      audit(ctx.hushDir, {
        actor: "mcp",
        action: "request",
        url: result.url,
        method: result.method,
        status: result.status,
        layers: resolved.layers,
        sent: result.used,
        redactions: result.redactions,
        ...(ctx.caller ? { caller: ctx.caller } : {}),
      });

      // A non-2xx is a real answer the model needs to see rather than a tool
      // failure: returning it as text lets it read the error body and adapt,
      // where an isError result would just look like the call went wrong.
      const skipped = resolved.blocked.map((b) => `Note: skipped set "${b.name}": it is only for ${b.onlyIn.join(", ")}, not this project.`);
      return text([renderRequest(result, { includeHeaders: true }), ...skipped].join("\n"));
    }

    case "hush_run": {
      const command = requireArg(args, "command", "hush_run");
      checkCommand(ctx.policy, command);
      const cmdArgs: string[] = Array.isArray(args.args) ? args.args.map(String) : [];

      // `sets` is the surface; `accounts` folds each pair into the set name
      // setNameFor() would have built, so a skill file written before sets
      // existed keeps working unmodified.
      // `env` was the base environment before sets existed. As an alias it is
      // the first extra set, so it still sits under `sets` and `accounts` —
      // the order it always had — rather than being ignored without a word.
      const extraSets: string[] = [
        ...(args.env ? [String(args.env)] : []),
        ...(Array.isArray(args.sets) ? args.sets.map(String) : []),
      ];
      for (const [service, account] of Object.entries(args.accounts ?? {})) {
        extraSets.push(setNameFor(String(service).toLowerCase(), String(account)));
      }

      // The project's usual sets (its "default" floor, then whatever it links)
      // with the extras layered last — later wins. Any name in `extraSets`
      // that resolves nowhere throws, naming it and every set that does exist.
      const resolved = composeSets(ctx.vault, ctx.identity, ctx.hushDir, extraSets);
      checkScopes(ctx.policy, resolved.layers);
      const secrets = resolved.secrets;
      for (const k of ctx.policy.denyKeys) delete secrets[k];

      // Same schema gate as the CLI, and no way to skip it from here.
      const runSchema = loadSchema(ctx.root);
      // Only the user's floor can grant an unmask; see unsensitiveForOutput.
      const redactOmit = runSchema ? unsensitiveForOutput(runSchema.rules, ctx.policy.unmaskKeys).omit : [];
      if (runSchema) {
        const problems = validate(secrets, runSchema.rules, Object.keys(secrets));
        if (problems.length) {
          return errText(
            `.env.schema rejected ${problems.length} value(s), so nothing was run:\n` +
              describeProblems(problems).map((l) => `  ${l}`).join("\n"),
          );
        }
      }

      if (ctx.policy.requireApproval.includes("run")) {
        const ap = await requestApproval(ctx.hushDir, {
          action: "run",
          summary: `Run:  ${command} ${cmdArgs.join(" ")}`.trim(),
          detail: [
            `Using sets:  ${resolved.layers.join(", ") || "(none)"}`,
            `Injects:  ${Object.keys(secrets).join(", ") || "(nothing)"}`,
            `Directory:  ${args.cwd || ctx.root}`,
            approvalCoverageLine(ctx.policy, command, resolved.layers),
          ],
          // Built by runScope(), not by hand: under the default
          // approvalScope: "command" this names the command too, not only the
          // sets, so "Allow 15 min" for one command no longer silently covers
          // every other command sharing those sets. A grant cached under the
          // old, sets-only shape will not match this one — one re-prompt, then
          // it is cached under the new shape like anything else.
          scope: runScope(ctx.policy, command, resolved.layers),
          ttlSeconds: ctx.policy.approvalTtlSeconds,
          timeoutMs: Math.max(1, ctx.policy.approvalTimeoutSeconds) * 1000,
          biometry: ctx.policy.biometry,
        });
        audit(ctx.hushDir, { actor: "mcp", action: "approval", on: "run", decision: ap.decision, via: ap.via, code: ap.code });
        if (ap.decision === "deny") {
          return errText(
            ap.note ?? `The user denied this (code ${ap.code}, via ${ap.via}).`,
          );
        }
        if (ap.decision === "timeout") {
          return errText(
            `No answer to the approval prompt (code ${ap.code}). Ask the user to check their screen, then retry.`,
          );
        }
      }

      const result = await runWithSecrets(command, cmdArgs, {
        cwd: args.cwd || ctx.root,
        secrets,
        redact: true,
        capture: true,
        timeoutMs: ctx.policy.maxRunMs,
        redactOmit,
      });
      audit(ctx.hushDir, {
        actor: "mcp",
        action: "run",
        command,
        args: cmdArgs,
        exit: result.code,
        injected: Object.keys(secrets).length,
        layers: resolved.layers,
      });

      const parts = [
        `exit ${result.code}${result.timedOut ? " (timed out)" : ""}  ` +
          `· using ${resolved.layers.join(", ") || "(none)"} ` +
          `· injected ${Object.keys(secrets).length} secret(s) · ${result.redactions} value(s) masked in output`,
      ];
      for (const b of resolved.blocked) {
        parts.push(`Note:  skipped set "${b.name}": it is only for ${b.onlyIn.join(", ")}, not this project. Do not try to use it here.`);
      }
      if (resolved.missing.length) {
        parts.push(`Note:  this project uses ${resolved.missing.join(", ")}, which your library does not have.`);
      }
      if (result.stdout.trim()) parts.push(`--- stdout ---\n${result.stdout.trimEnd()}`);
      if (result.stderr.trim()) parts.push(`--- stderr ---\n${result.stderr.trimEnd()}`);
      return result.code === 0 ? text(parts.join("\n\n")) : errText(parts.join("\n\n"));
    }

    case "hush_add_secret": {
      const service = args.service ? String(args.service).toLowerCase() : null;
      const account = args.account ? String(args.account) : null;
      if (service && !account) return errText(`Which account for "${service}"? Pass account, e.g. "personal".`);

      const where: "library" | "project" = args.where === "library" ? "library" : "project";
      const set = args.set
        ? String(args.set)
        : service && account
          ? setNameFor(service, account)
          : args.env
            ? String(args.env) // the pre-sets name for the same argument
            : ctx.defaultEnv;

      // Policy first, capability second. The other order meant that on any host
      // without native dialogs a set the policy forbids was never refused.
      // Worse, the fallback message handed the agent the exact command to run
      // in the terminal to get the forbidden set anyway.
      checkScopes(ctx.policy, [set]);

      if (!nativeDialogsAvailable()) {
        return text(
          "Secure on-screen entry isn't available here (macOS, or a Linux desktop with zenity " +
            "or kdialog, is needed). Ask the user to run:\n\n" +
            (service && account
              ? `    hush add ${service} --account ${account}`
              : service
                ? `    hush add ${service} --as "${set}"`
                : `    hush add ${args.key ?? "<KEY>"} --to ${set}`),
        );
      }

      const vars: string[] = service
        ? (knownVars(service).length ? knownVars(service) : args.key ? [String(args.key)] : [])
        : args.key
          ? [String(args.key)]
          : [];
      if (!vars.length) {
        return errText(
          `Don't know which variables "${service ?? "that"}" needs. Pass key explicitly, e.g. key: "MYAPI_TOKEN".`,
        );
      }

      let target: { vault: Vault; save: () => void; label: string };
      if (where === "library") {
        const lib = openGlobal();
        if (!lib) {
          return errText(
            `There is no library vault yet (looked for "${globalVaultName()}"). ` +
              `Ask the user to run:  hush global --create`,
          );
        }
        target = { vault: lib, save: () => lib.save(), label: `your library (${globalVaultName()})` };
      } else {
        target = { vault: ctx.vault, save: () => ctx.vault.save(), label: "this project" };
      }

      const why = args.why ? String(args.why) : "requested by your coding agent";
      const stored: string[] = [];
      const skipped: string[] = [];
      for (const v of vars) {
        const res = await promptForSecretNatively(v, [
          why,
          "",
          service ? `Service:  ${serviceLabel(service)}` : `Set:  ${set}`,
          ...(account ? [`Account:  ${account}`] : []),
          // Name the destination vault: the CLI's add approval already does,
          // and the agent is the one choosing library vs project.
          `Stored in:  ${target.label}`,
          target.vault.has(set, v) ? "This will REPLACE the existing value." : "",
        ].filter(Boolean));
        if (res.value) {
          target.vault.set(ctx.identity, set, v, res.value);
          stored.push(v);
        } else {
          skipped.push(v);
        }
      }

      if (!stored.length) {
        audit(ctx.hushDir, { actor: "mcp", action: "add.cancelled", set, vars });
        return errText("The user cancelled — nothing was stored.");
      }
      target.save();
      audit(ctx.hushDir, { actor: "mcp", action: "add", set, where, stored });

      return text(
        `Stored ${stored.join(", ")} in "${set}" (${target.label}). The value never entered this conversation.` +
          (skipped.length ? `\nSkipped (left blank): ${skipped.join(", ")}` : "") +
          `\n\nUse it:  hush_run with sets: ["${set}"]`,
      );
    }

    case "hush_provision": {
      const tool = requireArg(args, "tool", "hush_provision");
      const service = args.service ? String(args.service).toLowerCase() : serviceForTool(tool);
      if (!service) {
        return text(
          `Don't know which service "${tool}" authenticates with.\n` +
            `Either pass service explicitly, or call hush_check_repo to see what the code needs.`,
        );
      }

      const need = knownVars(service);
      if (!need.length) {
        return text(
          `Don't know which variables ${serviceLabel(service)} needs.\n` +
            `Call hush_check_repo to see what the code actually references.`,
        );
      }

      // No explicit `set`: check this project's own used sets (its "default"
      // floor plus whatever it links) — exactly what hush_run would resolve
      // with no extra sets. An explicit `set` is layered on top of those, same
      // as `sets` would be for a real run, so the answer matches what running
      // it for real would actually inject.
      const requestedSet = args.set ? String(args.set) : null;
      const resolved = composeSets(ctx.vault, ctx.identity, ctx.hushDir, requestedSet ? [requestedSet] : []);

      // Which set actually supplies each needed variable, later layer wins —
      // read from sets()/librarySets()'s plaintext key-name metadata, so this
      // never decrypts anything to answer "is it configured".
      // Layers say where a value came from ("main:work-fal" for the library);
      // what the agent passes back to hush_run, and what the user types after
      // `hush use`, is the plain set name.
      const prefix = `${globalVaultName()}:`;
      const plain = (layer: string): string => (layer.startsWith(prefix) ? layer.slice(prefix.length) : layer);
      const keysOf = (layer: string): string[] => {
        if (layer.startsWith(prefix)) {
          return librarySets().find((s) => s.name === layer.slice(prefix.length))?.keys ?? [];
        }
        return ctx.vault.sets().find((s) => s.name === layer)?.keys ?? [];
      };
      const providerOf = new Map<string, string>();
      for (const layer of resolved.layers) {
        const keys = keysOf(layer);
        for (const v of need) if (keys.includes(v)) providerOf.set(v, layer);
      }
      const missing = need.filter((v) => !providerOf.has(v));

      if (missing.length === need.length) {
        const limited = resolved.blocked.map((b) => `"${b.name}" (only for ${b.onlyIn.join(", ")})`);
        if (limited.length) {
          return text(
            `"${tool}" needs ${serviceLabel(service)} (${need.join(", ")}). This project cannot use ` +
              `${limited.join(", ")}: ${limited.length > 1 ? "those sets are" : "that set is"} kept for other folders. ` +
              `Do not work around that; ask the user which key this project should use.`,
          );
        }
        return text(
          `"${tool}" needs ${serviceLabel(service)} (${need.join(", ")}), but none of this project's ` +
            `used sets have ${need.length > 1 ? "them" : "it"} yet.\n\n` +
            `Call hush_add_secret with service "${service}"${requestedSet ? `, set "${requestedSet}"` : ""} ` +
            `to have the user fill it in (ask what to call the set — e.g. "personal", "work-${service}").`,
        );
      }
      if (missing.length) {
        return text(
          `${serviceLabel(service)} is missing: ${missing.join(", ")}.\n` +
            `Call hush_add_secret with service "${service}"${requestedSet ? `, set "${requestedSet}"` : ""} ` +
            `to have the user fill it in.`,
        );
      }

      const usingSets = [...new Set(need.map((v) => plain(providerOf.get(v)!)))];
      audit(ctx.hushDir, { actor: "mcp", action: "provision", tool, service, sets: usingSets });
      return text(
        `Ready. "${tool}" will get ${need.join(", ")} from ${usingSets.length > 1 ? "sets" : "set"} ${usingSets.join(", ")}.\n\n` +
          `Run it with hush_run:\n` +
          `  command: "${tool}", sets: [${usingSets.map((s) => `"${s}"`).join(", ")}]\n\n` +
          `The user can make this permanent with:  hush use ${usingSets.join(" ")}`,
      );
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}
