/**
 * hush MCP server — agent-facing, value-blind.
 *
 * The contract with the agent is: you may learn that a secret EXISTS, you may
 * USE it by running a command, you may not READ it. Every tool here is built
 * around that line.
 *
 * Zero dependencies: MCP is JSON-RPC 2.0 over newline-delimited stdio, which is
 * short enough to implement here rather than take an SDK for.
 */
import { createInterface } from "node:readline";
import { join } from "node:path";
import { resolveVaultPath, Vault, audit } from "./vault.ts";
import { serviceLabel, knownVars, setNameFor, serviceForTool } from "./services.ts";
import { composeSets, usedSets, librarySets, globalVaultName, openGlobal } from "./library.ts";
import { requestApproval, promptForSecretNatively, nativeDialogsAvailable } from "./approval.ts";
import {
  checkEnv, checkScopes, checkCommand, checkHost, runScope, requestScope,
  approvalCoverageLine, requestCoverageLine, readPolicyFile, mergePolicies,
} from "./policy.ts";
import {
  isHeaderName, assertHeaderValue, requestWithSecrets, renderRequest,
  requestSummary, requestSecretNames, prepare, type RequestInput,
} from "./request.ts";
import { loadSchema, validate, unsensitiveForOutput, describeProblems } from "./schema.ts";
import { requireIdentity, hushHome } from "./identity.ts";
import { scanRepo, reconcile } from "./scan.ts";
import { runWithSecrets } from "./run.ts";
import { preview } from "./redact.ts";
import { VERSION } from "./version.ts";

const PROTOCOL = "2025-06-18";

export interface Policy {
  /**
   * If non-empty, only these argv[0] values may be run. This is the only
   * command control that actually holds — prefer it for anything sensitive.
   */
  allowCommands: string[];
  /**
   * Refused outright. Treat this as a speed bump, never as a boundary: any
   * interpreter, build script or package.json entry can read the environment
   * and write it to a file, which output redaction cannot see. The controls
   * that hold are allowCommands and human approval.
   *
   * Entries in policy.json are ADDED to the built-in list, never substituted
   * for it, so an old config cannot hold you below the current floor.
   */
  denyCommands: string[];
  /**
   * Removes commands from the built-in deny list. Named to be off-putting on
   * purpose: allowing `node` or `bash` here means an agent can read every
   * injected secret and write it anywhere it likes.
   */
  unsafeAllowCommands: string[];
  /** Environments the agent may touch. */
  allowEnvs: string[];
  /**
   * Hosts `hush_request` may reach. Empty means "any host over https".
   * Entries are a bare host (`api.stripe.com`), a host with a port
   * (`localhost:3000`), or a subdomain glob (`*.example.com`). The list only
   * ever narrows — it is the one control that decides *where* a credential
   * may be sent, which no command or set rule can express.
   */
  allowHosts: string[];
  /** Keys the agent may never inject, even into an allowed command. */
  denyKeys: string[];
  maxRunMs: number;
  /**
   * Actions that need a human to approve on screen: "run", "add", "reveal",
   * "request".
   *
   * "request" is here by default for the same reason "run" is: it is a way to
   * *use* a credential. It is arguably the one that needs it most, since a run
   * keeps the value on this machine while a request puts it on the wire to a
   * host the agent chose.
   */
  requireApproval: string[];
  /** How long an "Allow 15 min" approval lasts. */
  approvalTtlSeconds: number;
  /**
   * How long to wait for the human before giving up on an approval.
   *
   * A blocked tool call is a blocked agent, so this is a real knob and not only
   * a test seam: two minutes of silence is a long time to sit there, and on a
   * headless box where no dialog can ever appear it is two minutes of nothing.
   */
  approvalTimeoutSeconds: number;
  /** "off" | "preferred" | "required" — gate approvals behind Touch ID. */
  biometry: "off" | "preferred" | "required";
  /**
   * What an "Allow 15 min" grant covers. "command" (the default) scopes it to
   * the command's basename plus the sets in use; "sets" is the pre-existing,
   * wider shape that covers any command using those sets. See runScope() in
   * policy.ts — both surfaces build the scope string through it.
   */
  approvalScope: "command" | "sets";
  /**
   * Keys the *user* has allowed to appear unmasked in output even though a
   * project `.env.schema` also asks for it, e.g. `["APP_ENV"]`.
   *
   * This is deliberately floor-only: `mergePolicies` takes it from
   * `~/.hush/policy.json` and ignores the repo file entirely, because a
   * repository that can grant itself an unmask can read a value it was only
   * ever supposed to use. Empty (the default) means "honour no repo request".
   */
  unmaskKeys: string[];
}

export const DEFAULT_POLICY: Policy = {
  allowCommands: [],
  denyCommands: [
    // dump the environment
    "env", "printenv", "set", "export", "cat", "less", "more", "head", "tail",
    // re-encode it past the redactor
    "base64", "base64url", "xxd", "od", "strings", "openssl", "gzip", "tar",
    // send it somewhere
    "curl", "wget", "nc", "ncat", "socat", "ssh", "scp", "rsync", "ftp", "telnet",
    // shells
    "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh", "xargs", "eval",
    // interpreters: one-liners defeat output redaction entirely
    "node", "deno", "bun", "python", "python2", "python3", "ruby", "perl",
    "php", "irb", "osascript", "awk", "gawk", "tclsh", "lua",
  ],
  allowEnvs: [],
  // See the interface above for the entry shapes.
  allowHosts: [],
  denyKeys: [],
  maxRunMs: 120_000,
  unsafeAllowCommands: [],
  requireApproval: ["run", "add", "reveal", "request"],
  approvalTtlSeconds: 900,
  approvalTimeoutSeconds: 120,
  biometry: "preferred",
  approvalScope: "command",
  unmaskKeys: [],
};

/**
 * The deny list is a floor, not a setting — and now there are two floors.
 *
 * A plain object merge let an on-disk policy.json *replace* denyCommands, so a
 * file written by an older version silently kept its shorter list and missed
 * every protection added since. Security defaults that apply only to fresh
 * installs are not defaults. Entries in the repo file are therefore unioned
 * with the built-ins, and going below that takes the deliberately unattractive
 * `unsafeAllowCommands` — which itself now needs the *user's* ~/.hush/policy.json
 * to agree, because the repo file is something an agent with write access to
 * the project can edit, and the whole point of a floor is that it cannot.
 * mergePolicies() in policy.ts has the actual per-field rules.
 */
export function loadPolicy(hushDir: string): Policy {
  const floor = readPolicyFile(join(hushHome(), "policy.json"));
  const repo = readPolicyFile(join(hushDir, "policy.json"));
  return mergePolicies(DEFAULT_POLICY, floor, repo);
}

// --------------------------------------------------------------- JSON-RPC

interface Req {
  jsonrpc: "2.0";
  id?: number | string;
  method: string;
  params?: any;
}

const send = (msg: unknown) => process.stdout.write(JSON.stringify(msg) + "\n");
const ok = (id: Req["id"], result: unknown) => send({ jsonrpc: "2.0", id, result });
const fail = (id: Req["id"], code: number, message: string) =>
  send({ jsonrpc: "2.0", id, error: { code, message } });

/** A required string argument. Without this, a missing `command` reached spawn as "undefined". */
function requireArg(args: Record<string, unknown>, name: string, tool: string): string {
  const v = args?.[name];
  if (typeof v !== "string" || v.trim() === "") {
    throw new Error(`${tool} needs a non-empty "${name}" argument.`);
  }
  return v;
}

const text = (s: string) => ({ content: [{ type: "text", text: s }] });
const errText = (s: string) => ({ content: [{ type: "text", text: s }], isError: true });

// ------------------------------------------------------------------ tools

const TOOLS = [
  {
    name: "hush_list_secrets",
    description:
      "List the NAMES of secrets available in one named set of the current project's vault. " +
      "Returns names, which set they live in, and when they were last changed. " +
      "Never returns secret values — use hush_run to actually use a secret.",
    inputSchema: {
      type: "object",
      properties: {
        set: { type: "string", description: "Which set to list (default: the project's default set)." },
        env: { type: "string", description: "Deprecated alias for \"set\", kept for one release." },
      },
    },
  },
  {
    name: "hush_list_sets",
    description:
      "List every named set the agent could use with this project: sets in the user's own " +
      "library (global, e.g. 'Personal fal', 'Work fal') and sets in the project's own vault. " +
      "Each entry says where it lives (library or project), whether this project already uses " +
      "it, and its key names. Call this when the user names a set loosely (\"use my acme fal " +
      "key\", \"the work fal account\") so you can pass the right name to hush_run. Returns " +
      "names only, never values.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "hush_list_accounts",
    description:
      "Deprecated, use hush_list_sets — this returns exactly the same thing. Kept registered " +
      "so a skill file written before sets replaced accounts still works.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "hush_check_repo",
    description:
      "Scan the current codebase for the environment variables it references, and report which " +
      "are present in the vault and which are missing. Use this before running or building a " +
      "project to find out whether its configuration is complete.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Directory to scan (default: project root)." },
        env: { type: "string" },
      },
    },
  },
  {
    name: "hush_run",
    description:
      "Run a shell command with the project's secrets injected as environment variables. " +
      "The command sees real credentials; you only see its output, with any secret values " +
      "masked. This is the correct way to perform a task that needs a credential " +
      "(migrations, deploys, authenticated API calls) without the credential entering this " +
      "conversation.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string", description: "Executable to run, e.g. 'npm'." },
        args: { type: "array", items: { type: "string" }, description: "Arguments, e.g. ['run','build']." },
        cwd: { type: "string" },
        sets: {
          type: "array",
          items: { type: "string" },
          description:
            "Extra named sets to layer on top of this project's usual ones, for this run only, " +
            "e.g. [\"work-fal\"]. Later entries win over earlier ones on a shared key name. " +
            "Use hush_list_sets to see the options. Omit to use this project's usual sets.",
        },
        accounts: {
          type: "object",
          additionalProperties: { type: "string" },
          description:
            "Deprecated alias for sets: {\"fal\":\"acme\"} means the set named \"fal/acme\". Prefer sets.",
        },
        env: { type: "string", description: "Deprecated: the base set for this run, layered under sets. Prefer sets." },
      },
      required: ["command"],
    },
  },
  {
    name: "hush_request",
    description:
      "Make an authenticated HTTP request without the credential ever entering this " +
      "conversation. Write $NAME where a secret belongs and hush substitutes it from the " +
      "vault inside its own process; you get back the response with any secret values " +
      "masked as [redacted:NAME]. Use this for any API call that needs a key, instead of " +
      "trying to run curl/wget (denied) or building an Authorization header yourself. " +
      "Secrets go into HEADER VALUES only unless you also list 'body' or 'query' in " +
      "substitute. https only; the host must be one the policy allows.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Full URL, e.g. \"https://api.stripe.com/v1/refunds\".",
        },
        method: {
          type: "string",
          description: "HTTP method. Default GET, or POST when a body is given.",
        },
        headers: {
          type: "object",
          additionalProperties: { type: "string" },
          description:
            "Header name to value. Put the secret placeholder in the value, e.g. " +
            "{\"Authorization\": \"Bearer $STRIPE_KEY\"}. The value is substituted inside " +
            "hush and never returned to you.",
        },
        body: { type: "string", description: "Request body. Substituted only if \"body\" is in substitute." },
        substitute: {
          type: "array",
          items: { type: "string", enum: ["body", "query"] },
          description:
            "Extra places, besides header values, where $NAME may be replaced. Omit for " +
            "header values only, which is the safe default.",
        },
        sets: {
          type: "array",
          items: { type: "string" },
          description:
            "Extra named sets to layer on top of this project's usual ones, for this call " +
            "only, e.g. [\"work-stripe\"]. Later entries win on a shared key name. Use " +
            "hush_list_sets to see the options.",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "hush_add_secret",
    description:
      "Add a credential to the vault WITHOUT it passing through this conversation. " +
      "A secure input box opens on the user's screen; they paste the value there and it is " +
      "encrypted straight into the vault. You get back only a confirmation. " +
      "ALWAYS use this instead of asking the user to paste a key into the chat. " +
      "Give a set name (created if it doesn't already exist) and either a known service " +
      "(hush knows which variables it needs, e.g. 'fal') or a bare key.",
    inputSchema: {
      type: "object",
      properties: {
        set: {
          type: "string",
          description: "The set to add this to, e.g. 'work-fal'. Created if absent. Default: the project's default set.",
        },
        where: {
          type: "string",
          enum: ["project", "library"],
          description: "Where to create a new set: this project's vault (default) or the user's own library.",
        },
        service: { type: "string", description: "Deprecated alias: e.g. 'fal'. hush knows which variables it needs." },
        account: { type: "string", description: "Deprecated, used with service — together they mean set \"service/account\"." },
        key: { type: "string", description: "A single variable name, if this isn't a known service." },
        env: { type: "string", description: "Deprecated alias for \"set\", kept for one release." },
        why: { type: "string", description: "Shown to the user so they know what they are approving." },
      },
    },
  },
  {
    name: "hush_provision",
    description:
      "Prepare a CLI or codebase to run with the right credentials. Give it a tool name " +
      "(e.g. 'wrangler') and optionally which set to use. It works out which service the tool " +
      "authenticates with, checks which of this project's used sets already provide it, prompts " +
      "the user to add it if missing, and tells you the exact hush_run call to make. Use this " +
      "when the user says something like 'set up wrangler with my personal Cloudflare set'.",
    inputSchema: {
      type: "object",
      properties: {
        tool: { type: "string", description: "The command that needs credentials, e.g. 'wrangler'." },
        service: { type: "string", description: "Override the detected service." },
        set: { type: "string", description: "Which set to check, e.g. 'work-fal'. Default: whichever of this project's used sets already provide it." },
      },
      required: ["tool"],
    },
  },
  {
    name: "hush_describe_secret",
    description:
      "Describe one secret without revealing it: whether it exists, its length, a masked " +
      "preview, who last set it and when. Use this to confirm a credential is configured.",
    inputSchema: {
      type: "object",
      properties: {
        key: { type: "string" },
        set: { type: "string" },
        env: { type: "string", description: "Deprecated alias for \"set\", kept for one release." },
      },
      required: ["key"],
    },
  },
];

// ------------------------------------------------------------------ server

interface Ctx {
  vault: Vault;
  hushDir: string;
  defaultEnv: string;
  policy: Policy;
  identity: ReturnType<typeof requireIdentity>;
  root: string;
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

interface ListedSet {
  name: string;
  label: string;
  description?: string;
  whenToUse?: string;
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
    keys: s.keys,
    where: "project",
    used: used.has(s.name),
  }));
  const library: ListedSet[] = librarySets().map((s) => ({
    name: s.name,
    label: s.label,
    description: s.description,
    whenToUse: s.whenToUse,
    keys: s.keys,
    where: "library",
    used: used.has(s.name),
  }));
  return [...project, ...library].sort((a, b) => a.label.localeCompare(b.label));
}

async function callTool(name: string, args: any): Promise<unknown> {
  const ctx = loadCtx();

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
        return text(`"${key}" is NOT set in set "${set}". Use hush_request_secret to ask for it.`);
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
        const notes = [s.description, s.whenToUse ? `when: ${s.whenToUse}` : null].filter(Boolean).join("  —  ");
        return (
          `  ${label}   [${flags}]   keys: ${s.keys.join(", ") || "(none)"}` + (notes ? `\n      ${notes}` : "")
        );
      });
      const footer =
        name === "hush_list_accounts"
          ? "\n\n(hush_list_accounts is deprecated, use hush_list_sets — this is the same list.)"
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
      const root = args?.path || ctx.root;
      const usages = scanRepo(root);
      const r = reconcile(usages, ctx.vault.list(env).map((i) => i.key));
      audit(ctx.hushDir, { actor: "mcp", action: "check", env, missing: r.missing.length });
      const lines = [
        `Scanned ${root}`,
        `  referenced by code: ${r.needed.length}`,
        `  satisfied by vault: ${r.satisfied.length}`,
        `  MISSING:            ${r.missing.length}`,
      ];
      if (r.missing.length) {
        lines.push("", "Missing:");
        for (const m of r.missing.slice(0, 40)) {
          lines.push(`  ${m.name}   (used in ${m.sites.slice(0, 2).join(", ")})`);
        }
        lines.push("", "Ask the human to add these with hush_request_secret.");
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
      const resolved = composeSets(ctx.vault, ctx.identity, ctx.hushDir, extraSets);
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
            `Directory:  ${ctx.root}`,
            requestCoverageLine(ctx.policy, parsedUrl.host, resolved.layers),
          ],
          // Naming the host, so a grant for one destination cannot authorise
          // the same sets being sent somewhere else.
          scope: requestScope(ctx.policy, parsedUrl.host, resolved.layers),
          ttlSeconds: ctx.policy.approvalTtlSeconds,
          timeoutMs: Math.max(1, ctx.policy.approvalTimeoutSeconds) * 1000,
          biometry: ctx.policy.biometry,
        });
        audit(ctx.hushDir, { actor: "mcp", action: "approval", on: "request", decision: ap.decision, via: ap.via, code: ap.code });
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
      });

      // A non-2xx is a real answer the model needs to see rather than a tool
      // failure: returning it as text lets it read the error body and adapt,
      // where an isError result would just look like the call went wrong.
      return text(renderRequest(result, { includeHeaders: true }));
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

/** A single JSON-RPC line larger than this is treated as junk rather than buffered. */
const MAX_LINE_BYTES = 4 * 1024 * 1024;

export function serveMcp(): void {
  const rl = createInterface({ input: process.stdin, terminal: false });

  // A tool call can legitimately run for minutes (a build, an approval dialog).
  // Exiting the moment stdin closes killed those mid-flight, losing the reply
  // and orphaning the child process.
  const inFlight = new Set<Promise<unknown>>();
  const track = <T>(p: Promise<T>): Promise<T> => {
    inFlight.add(p);
    // `p.finally(fn)` returns a NEW promise that rejects when p does. Nothing
    // awaits that one, so every tool error became an unhandled rejection and
    // took the whole server down mid-session. `then(done, done)` settles.
    const done = (): void => void inFlight.delete(p);
    p.then(done, done);
    return p;
  };

  rl.on("line", async (line) => {
    if (line.length > MAX_LINE_BYTES) {
      // Never buffer or parse an unbounded blob; it is not a real request.
      return send({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32600, message: "request line too large" },
      });
    }
    const trimmed = line.trim();
    if (!trimmed) return;
    let req: Req;
    try {
      req = JSON.parse(trimmed);
    } catch {
      return;
    }

    try {
      switch (req.method) {
        case "initialize":
          return ok(req.id, {
            protocolVersion: req.params?.protocolVersion ?? PROTOCOL,
            capabilities: { tools: {} },
            serverInfo: { name: "hush", version: VERSION },
            instructions:
              "hush holds this project's secrets. You can see which secrets exist and run " +
              "commands with them injected, but you can never read their values — that is " +
              "deliberate, and there is no flag that changes it. If a task needs a credential, " +
              "call hush_run rather than asking the user to paste one.",
          });

        case "notifications/initialized":
        case "notifications/cancelled":
          return;

        case "ping":
          return ok(req.id, {});

        case "tools/list":
          return ok(req.id, { tools: TOOLS });

        case "tools/call": {
          const result = await track(callTool(req.params?.name, req.params?.arguments ?? {}));
          return ok(req.id, result);
        }

        default:
          if (req.id === undefined) return;
          return fail(req.id, -32601, `Method not found: ${req.method}`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (req.id === undefined) return;
      if (req.method === "tools/call") return ok(req.id, errText(message));
      return fail(req.id, -32603, message);
    }
  });

  rl.on("close", () => {
    if (inFlight.size === 0) return process.exit(0);
    // Let running calls finish and reply, but do not hang forever on a wedged one.
    const giveUp = setTimeout(() => process.exit(0), 130_000);
    void Promise.allSettled([...inFlight]).then(() => {
      clearTimeout(giveUp);
      process.exit(0);
    });
  });
}
