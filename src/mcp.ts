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
import { readPolicyFile, mergePolicies } from "./policy.ts";
import { hushHome } from "./identity.ts";
import { VERSION } from "./version.ts";
import { callTool, errText } from "./mcp-tools.ts";


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
  /**
   * How many days a value may go without being replaced before `hush level`,
   * `hush doctor` and `hush ls --age` call it overdue (F-6). A number for every
   * set, or an object from set name to days with "*" for the rest. Unset means
   * no reminders. A reminder, not a gate: nothing is refused over it.
   */
  rotateAfterDays?: number | Record<string, number>;
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

// ------------------------------------------------------------------ tools

export const TOOLS = [
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
        env: { type: "string", description: "Deprecated alias for \"set\", removed in hush 2.0." },
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
      "Deprecated (removed in hush 2.0), use hush_list_sets — this returns exactly the same thing. Kept registered " +
      "so a skill file written before sets replaced accounts still works.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "hush_setup_status",
    description:
      "What is set up for hush on this machine and in this project, and what is next. Each step has a " +
      "status, the exact command that does it, and a kind: auto (run it), choice (ask the user which " +
      "option, then run it), or person (run it and wait: it asks the user on their screen, and you must " +
      "never answer it or add --yes). Call this when the user asks you to set up hush, or when another " +
      "hush tool says hush is not set up here. It never shows a secret.",
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
            "Deprecated alias for sets (removed in hush 2.0): {\"fal\":\"acme\"} means the set named \"fal/acme\". Prefer sets.",
        },
        env: { type: "string", description: "Deprecated (removed in hush 2.0): the base set for this run, layered under sets. Prefer sets." },
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
        service: { type: "string", description: "Deprecated alias (removed in hush 2.0): e.g. 'fal'. hush knows which variables it needs." },
        account: { type: "string", description: "Deprecated (removed in hush 2.0), used with service — together they mean set \"service/account\"." },
        key: { type: "string", description: "A single variable name, if this isn't a known service." },
        env: { type: "string", description: "Deprecated alias for \"set\", removed in hush 2.0." },
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
        env: { type: "string", description: "Deprecated alias for \"set\", removed in hush 2.0." },
      },
      required: ["key"],
    },
  },
];

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
              "call hush_run rather than asking the user to paste one. If hush is not set up in this project, " +
              "call hush_setup_status and follow it.",
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
