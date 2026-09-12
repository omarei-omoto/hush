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
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { resolveVaultPath, Vault, audit, loadUse } from "./vault.ts";
import { serviceLabel, knownVars, scopeOf, serviceForTool } from "./services.ts";
import { requestApproval, promptForSecretNatively, nativeDialogsAvailable } from "./approval.ts";
import { checkEnv, checkScopes, checkCommand } from "./policy.ts";
import { requireIdentity } from "./identity.ts";
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
  /** Keys the agent may never inject, even into an allowed command. */
  denyKeys: string[];
  maxRunMs: number;
  /** Actions that need a human to approve on screen: "run", "add", "reveal". */
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
  denyKeys: [],
  maxRunMs: 120_000,
  unsafeAllowCommands: [],
  requireApproval: ["run", "add", "reveal"],
  approvalTtlSeconds: 900,
  approvalTimeoutSeconds: 120,
  biometry: "preferred",
};

/**
 * The deny list is a floor, not a setting.
 *
 * A plain object merge let an on-disk policy.json *replace* denyCommands, so a
 * file written by an older version silently kept its shorter list and missed
 * every protection added since. Security defaults that apply only to fresh
 * installs are not defaults. Entries in the file are therefore unioned with the
 * built-ins, and going below the floor takes the deliberately unattractive
 * `unsafeAllowCommands`.
 */
export function loadPolicy(hushDir: string): Policy {
  const p = join(hushDir, "policy.json");
  if (!existsSync(p)) return DEFAULT_POLICY;

  let raw: Partial<Policy>;
  try {
    raw = JSON.parse(readFileSync(p, "utf8")) as Partial<Policy>;
  } catch {
    return DEFAULT_POLICY;
  }

  const unsafeAllow = new Set((raw.unsafeAllowCommands ?? []).map(String));
  const denyCommands = [
    ...new Set([...DEFAULT_POLICY.denyCommands, ...(raw.denyCommands ?? [])]),
  ].filter((cmd) => !unsafeAllow.has(cmd));

  return { ...DEFAULT_POLICY, ...raw, denyCommands, unsafeAllowCommands: [...unsafeAllow] };
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
      "List the NAMES of secrets available in the current project's vault. " +
      "Returns names, which environment they live in, and when they were last changed. " +
      "Never returns secret values — use hush_run to actually use a secret.",
    inputSchema: {
      type: "object",
      properties: {
        env: { type: "string", description: "Environment to list (default: the project's linked env)." },
      },
    },
  },
  {
    name: "hush_list_accounts",
    description:
      "List the service accounts in this vault — e.g. fal has 'personal', 'acme' and 'client'; " +
      "gemini has 'team'. Also shows which account this project uses by default. " +
      "Call this when the user names an account ('use my acme fal key') so you can pass the " +
      "right one to hush_run. Returns account names only, never key values.",
    inputSchema: {
      type: "object",
      properties: { service: { type: "string", description: "Filter to one service, e.g. 'fal'." } },
    },
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
        env: { type: "string", description: "Which environment's secrets to inject." },
        accounts: {
          type: "object",
          additionalProperties: { type: "string" },
          description:
            "Which account to use per service, e.g. {\"fal\":\"acme\",\"gemini\":\"team\"}. " +
            "Omit to use this project's pinned defaults. Use hush_list_accounts to see the options.",
        },
      },
      required: ["command"],
    },
  },
  {
    name: "hush_add_secret",
    description:
      "Add a credential to the vault WITHOUT it passing through this conversation. " +
      "A secure input box opens on the user's screen; they paste the value there and it is " +
      "encrypted straight into the vault. You get back only a confirmation. " +
      "ALWAYS use this instead of asking the user to paste a key into the chat. " +
      "Give either (service + account) — e.g. service 'fal', account 'personal' — or (key + env).",
    inputSchema: {
      type: "object",
      properties: {
        service: { type: "string", description: "e.g. 'fal'. hush knows which variables it needs." },
        account: { type: "string", description: "e.g. 'personal', 'acme'. Required with service." },
        key: { type: "string", description: "A single variable name, if this isn't a known service." },
        env: { type: "string", description: "Environment for a bare key. Default: the project's." },
        why: { type: "string", description: "Shown to the user so they know what they are approving." },
      },
    },
  },
  {
    name: "hush_provision",
    description:
      "Prepare a CLI or codebase to run with the right credentials. Give it a tool name " +
      "(e.g. 'wrangler') and optionally which account to use. It works out which service the " +
      "tool authenticates with, checks the vault has it, prompts the user to add it if missing, " +
      "and tells you the exact hush_run call to make. Use this when the user says something " +
      "like 'set up wrangler with my personal Cloudflare account'.",
    inputSchema: {
      type: "object",
      properties: {
        tool: { type: "string", description: "The command that needs credentials, e.g. 'wrangler'." },
        service: { type: "string", description: "Override the detected service." },
        account: { type: "string", description: "Which account to use, e.g. 'personal'." },
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
        env: { type: "string" },
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

async function callTool(name: string, args: any): Promise<unknown> {
  const ctx = loadCtx();
  const env = args?.env || ctx.defaultEnv;

  switch (name) {
    case "hush_list_secrets": {
      checkEnv(ctx.policy, env);
      const items = ctx.vault.list(env);
      audit(ctx.hushDir, { actor: "mcp", action: "list", env, count: items.length });
      if (!items.length) return text(`No secrets in env "${env}".`);
      const body = items
        .map((i) => `  ${i.key}${i.note ? `  — ${i.note}` : ""}   (set by ${i.updatedBy}, ${i.updatedAt.slice(0, 10)})`)
        .join("\n");
      return text(
        `${items.length} secret(s) in env "${env}" of vault "${ctx.vault.data.name}":\n${body}\n\n` +
          `Values are not available to you. Use hush_run to execute a command with these injected.`,
      );
    }

    case "hush_describe_secret": {
      checkEnv(ctx.policy, env);
      const key = requireArg(args, "key", "hush_describe_secret");
      if (!ctx.vault.has(env, key)) {
        return text(`"${key}" is NOT set in env "${env}". Use hush_request_secret to ask for it.`);
      }
      const value = ctx.vault.get(ctx.identity, env, key);
      const meta = ctx.vault.list(env).find((i) => i.key === key)!;
      audit(ctx.hushDir, { actor: "mcp", action: "describe", env, key });
      return text(
        `${key} is set in env "${env}".\n` +
          `  preview:   ${preview(value)}\n` +
          `  length:    ${value.length}\n` +
          `  last set:  ${meta.updatedBy} on ${meta.updatedAt.slice(0, 10)}\n` +
          (meta.note ? `  note:      ${meta.note}\n` : ""),
      );
    }

    case "hush_list_accounts": {
      const filter = args?.service ? String(args.service).toLowerCase() : "";
      const all = ctx.vault.accounts().filter((x) => !filter || x.service === filter);
      const pinned = loadUse(ctx.hushDir);
      if (!all.length) {
        return text(filter ? `No accounts for "${filter}".` : "No service accounts in this vault yet.");
      }
      const lines: string[] = [];
      let cur = "";
      for (const a of all) {
        if (a.service !== cur) {
          cur = a.service;
          lines.push(`${serviceLabel(a.service)} (${a.service}):`);
        }
        const isDefault = pinned[a.service] === a.account;
        lines.push(`  ${a.account}${isDefault ? "  [project default]" : ""}   sets: ${a.vars.join(", ")}`);
      }
      lines.push("", 'Pass one to hush_run as accounts, e.g. {"fal":"acme"}.');
      return text(lines.join("\n"));
    }

    case "hush_check_repo": {
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

    case "hush_run": {
      checkEnv(ctx.policy, env);
      const command = requireArg(args, "command", "hush_run");
      checkCommand(ctx.policy, command);
      const cmdArgs: string[] = Array.isArray(args.args) ? args.args.map(String) : [];

      // Project defaults first, then whatever the caller explicitly asked for.
      const chosen = new Map<string, string>(Object.entries(loadUse(ctx.hushDir)));
      for (const [service, account] of Object.entries(args.accounts ?? {})) {
        chosen.set(String(service).toLowerCase(), String(account));
      }
      const choices = [...chosen].map(([service, account]) => ({ service, account }));
      const resolved = ctx.vault.resolve(ctx.identity, env, choices);
      checkScopes(ctx.policy, resolved.layers);
      const secrets = resolved.secrets;
      for (const k of ctx.policy.denyKeys) delete secrets[k];

      if (ctx.policy.requireApproval.includes("run")) {
        const using = choices.length ? choices.map((c) => `${c.service}:${c.account}`).join(", ") : env;
        const ap = await requestApproval(ctx.hushDir, {
          action: "run",
          summary: `Run:  ${command} ${cmdArgs.join(" ")}`.trim(),
          detail: [
            `Using accounts:  ${using}`,
            `Injects:  ${Object.keys(secrets).join(", ") || "(nothing)"}`,
            `Directory:  ${args.cwd || ctx.root}`,
          ],
          scope: `run:${resolved.layers.join("+")}`,
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
      });
      audit(ctx.hushDir, {
        actor: "mcp",
        action: "run",
        env,
        command,
        args: cmdArgs,
        exit: result.code,
        injected: Object.keys(secrets).length,
        layers: resolved.layers,
      });

      const parts = [
        `exit ${result.code}${result.timedOut ? " (timed out)" : ""}  ` +
          `· using ${choices.length ? choices.map((c) => `${c.service}:${c.account}`).join(", ") : env} ` +
          `· injected ${Object.keys(secrets).length} secret(s) · ${result.redactions} value(s) masked in output`,
      ];
      if (result.stdout.trim()) parts.push(`--- stdout ---\n${result.stdout.trimEnd()}`);
      if (result.stderr.trim()) parts.push(`--- stderr ---\n${result.stderr.trimEnd()}`);
      return result.code === 0 ? text(parts.join("\n\n")) : errText(parts.join("\n\n"));
    }

    case "hush_add_secret": {
      checkEnv(ctx.policy, env);

      const service = args.service ? String(args.service).toLowerCase() : null;
      const account = args.account ? String(args.account) : null;
      if (service && !account) return errText(`Which account for "${service}"? Pass account, e.g. "personal".`);

      const scope = service && account ? scopeOf(service, account) : env;
      // Policy first, capability second. The other order meant that on any host
      // without native dialogs — every Linux box, and macOS with
      // HUSH_APPROVAL_MODE=file — a scope the policy forbids was never refused.
      // Worse, the fallback message handed the agent the exact command to run in
      // the terminal to get the forbidden account anyway.
      checkScopes(ctx.policy, [scope]);

      if (!nativeDialogsAvailable()) {
        return text(
          "Secure on-screen entry isn't available on this platform. Ask the user to run:\n\n" +
            (service && account
              ? `    hush add ${service} --account ${account}`
              : `    hush set ${args.key ?? "<KEY>"} --env ${env}`),
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

      const why = args.why ? String(args.why) : "requested by your coding agent";
      const stored: string[] = [];
      const skipped: string[] = [];
      for (const v of vars) {
        const res = await promptForSecretNatively(v, [
          why,
          "",
          service ? `Service:  ${serviceLabel(service)}` : `Environment:  ${env}`,
          ...(account ? [`Account:  ${account}`] : []),
          ctx.vault.has(scope, v) ? "This will REPLACE the existing value." : "",
        ].filter(Boolean));
        if (res.value) {
          ctx.vault.set(ctx.identity, scope, v, res.value);
          stored.push(v);
        } else {
          skipped.push(v);
        }
      }

      if (!stored.length) {
        audit(ctx.hushDir, { actor: "mcp", action: "add.cancelled", scope, vars });
        return errText("The user cancelled — nothing was stored.");
      }
      ctx.vault.save();
      audit(ctx.hushDir, { actor: "mcp", action: "add", scope, stored });

      return text(
        `Stored ${stored.join(", ")} in ${scope}. The value never entered this conversation.` +
          (skipped.length ? `\nSkipped (left blank): ${skipped.join(", ")}` : "") +
          (service && account
            ? `\n\nUse it:  hush_run with accounts { "${service}": "${account}" }`
            : ""),
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

      const available = ctx.vault.accountsFor(service);
      const account = args.account ? String(args.account) : (loadUse(ctx.hushDir)[service] ?? available[0]);

      if (!account) {
        return text(
          `"${tool}" needs ${serviceLabel(service)} (${knownVars(service).join(", ") || "unknown vars"}), ` +
            `but there are no ${service} accounts in the vault yet.\n\n` +
            `Call hush_add_secret with service "${service}" and an account name ` +
            `(ask the user what to call it — e.g. "personal").`,
        );
      }
      if (!available.includes(account)) {
        return errText(
          `No "${account}" account for ${service}. Available: ${available.join(", ") || "none"}.`,
        );
      }

      const scope = scopeOf(service, account);
      const need = knownVars(service).length ? knownVars(service) : Object.keys(ctx.vault.data.envs[scope] ?? {});
      const missing = need.filter((v) => !ctx.vault.has(scope, v));

      if (missing.length) {
        return text(
          `${serviceLabel(service)} account "${account}" is missing: ${missing.join(", ")}.\n` +
            `Call hush_add_secret with service "${service}", account "${account}" to have the user fill it in.`,
        );
      }

      audit(ctx.hushDir, { actor: "mcp", action: "provision", tool, service, account });
      return text(
        `Ready. "${tool}" will get ${need.join(", ")} from the ${serviceLabel(service)} "${account}" account.\n\n` +
          `Run it with hush_run:\n` +
          `  command: "${tool}", accounts: { "${service}": "${account}" }\n\n` +
          `The user can make this the project default with:  hush use ${service}=${account}`,
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
