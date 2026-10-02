/**
 * Plaintext credentials in coding agents' own config files.
 *
 * The way most people give an MCP server its API key is to paste the key into
 * the agent's config: `"env": { "GITHUB_TOKEN": "ghp_…" }` in
 * claude_desktop_config.json, `~/.cursor/mcp.json`, `~/.codex/config.toml`.
 * Those files are plaintext, readable by every process running as you
 * (including the agents themselves), and sometimes committed. This module
 * finds them — names, places and a masked preview only; the CLI decides what
 * to print and never prints a value.
 *
 * Everything here is pure over (path, text) so the detection is testable
 * without anyone's real home folder. Finding the files is the one part that
 * touches the filesystem, and it only reads.
 */
import { join } from "node:path";
import { platform as osPlatform } from "node:os";
import { stripJsonc } from "./agents.ts";

export type ConfigFormat = "json" | "jsonc" | "toml" | "yaml";

export interface AgentConfigFile {
  agent: string;
  path: string;
  format: ConfigFormat;
  /** `user` files apply to every project; `project` files may be committed. */
  scope: "user" | "project";
}

const home = (env: NodeJS.ProcessEnv): string => env.HOME ?? env.USERPROFILE ?? "~";
const xdgConfig = (env: NodeJS.ProcessEnv): string => env.XDG_CONFIG_HOME || join(home(env), ".config");
/** Where a desktop app keeps its settings on each platform. */
const appData = (env: NodeJS.ProcessEnv, plat: string, name: string): string =>
  plat === "darwin"
    ? join(home(env), "Library", "Application Support", name)
    : plat === "win32"
      ? join(env.APPDATA ?? join(home(env), "AppData", "Roaming"), name)
      : join(xdgConfig(env), name);

/**
 * Every file an agent on this machine may keep MCP servers or API keys in.
 * Broader than agents.ts's list, which is where hush *writes* its own entry:
 * reading is safe, so this also covers user-wide files and the settings
 * files with an `env` block (Claude Code's settings.json takes one).
 */
export function agentConfigFiles(root: string, env: NodeJS.ProcessEnv, plat: string = osPlatform()): AgentConfigFile[] {
  const h = home(env);
  const code = appData(env, plat, "Code");
  const list: AgentConfigFile[] = [
    { agent: "Claude Code", path: join(h, ".claude.json"), format: "json", scope: "user" },
    { agent: "Claude Code", path: join(h, ".claude", "settings.json"), format: "json", scope: "user" },
    { agent: "Claude Code", path: join(root, ".mcp.json"), format: "json", scope: "project" },
    { agent: "Claude Code", path: join(root, ".claude", "settings.json"), format: "json", scope: "project" },
    { agent: "Claude Code", path: join(root, ".claude", "settings.local.json"), format: "json", scope: "project" },
    { agent: "Claude Desktop", path: join(appData(env, plat, "Claude"), "claude_desktop_config.json"), format: "json", scope: "user" },
    { agent: "Cursor", path: join(h, ".cursor", "mcp.json"), format: "json", scope: "user" },
    { agent: "Cursor", path: join(root, ".cursor", "mcp.json"), format: "json", scope: "project" },
    { agent: "Windsurf", path: join(h, ".codeium", "windsurf", "mcp_config.json"), format: "json", scope: "user" },
    { agent: "Windsurf", path: join(xdgConfig(env), "devin", "mcp_config.json"), format: "json", scope: "user" },
    { agent: "Gemini CLI", path: join(h, ".gemini", "settings.json"), format: "json", scope: "user" },
    { agent: "Gemini CLI", path: join(root, ".gemini", "settings.json"), format: "json", scope: "project" },
    { agent: "VS Code", path: join(code, "User", "mcp.json"), format: "jsonc", scope: "user" },
    { agent: "VS Code", path: join(code, "User", "settings.json"), format: "jsonc", scope: "user" },
    { agent: "VS Code", path: join(root, ".vscode", "mcp.json"), format: "jsonc", scope: "project" },
    { agent: "Cline", path: join(h, ".cline", "mcp.json"), format: "json", scope: "user" },
    {
      agent: "Cline",
      path: join(code, "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
      format: "json",
      scope: "user",
    },
    { agent: "Zed", path: join(xdgConfig(env), "zed", "settings.json"), format: "jsonc", scope: "user" },
    { agent: "Codex", path: join(h, ".codex", "config.toml"), format: "toml", scope: "user" },
    { agent: "Continue", path: join(h, ".continue", "config.json"), format: "json", scope: "user" },
    { agent: "Continue", path: join(h, ".continue", "config.yaml"), format: "yaml", scope: "user" },
  ];
  // The project and the home folder can be the same place; report a file once.
  const seen = new Set<string>();
  return list.filter((f) => (seen.has(f.path) ? false : (seen.add(f.path), true)));
}

// ------------------------------------------------------------------ detection

/**
 * Prefixes providers put on their keys. A match is a credential whatever the
 * field is called. Order matters where one prefix contains another: the
 * Anthropic and OpenRouter forms both start with OpenAI's `sk-`.
 */
const TOKEN_PATTERNS: [service: string, pattern: RegExp][] = [
  // Not preceded by a letter or digit: Context7's `ctx7sk-…` is not an OpenAI key.
  ["anthropic", /(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}/],
  ["openrouter", /(?<![A-Za-z0-9])sk-or-v1-[A-Za-z0-9]{32,}/],
  ["openai", /(?<![A-Za-z0-9])sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/],
  ["stripe", /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/],
  ["github", /\bgh[pousr]_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}/],
  ["gitlab", /\bglpat-[A-Za-z0-9_-]{20,}/],
  ["slack", /\bxox[abposr]-[A-Za-z0-9-]{10,}/],
  ["aws", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ["google", /\bAIza[0-9A-Za-z_-]{35}/],
  ["huggingface", /\bhf_[A-Za-z0-9]{30,}/],
  ["replicate", /\br8_[A-Za-z0-9]{30,}/],
  ["groq", /\bgsk_[A-Za-z0-9]{40,}/],
  ["linear", /\blin_api_[A-Za-z0-9]{30,}/],
  ["notion", /\b(?:ntn|secret)_[A-Za-z0-9]{40,}/],
  ["figma", /\bfigd_[A-Za-z0-9_-]{30,}/],
  ["sendgrid", /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/],
  ["npm", /\bnpm_[A-Za-z0-9]{36}\b/],
  ["private key", /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
];

export function serviceOf(value: string): string | null {
  for (const [service, pattern] of TOKEN_PATTERNS) if (pattern.test(value)) return service;
  return null;
}

/** Words that make a field name a credential's name, after splitting camelCase and separators. */
const SECRET_WORDS = new Set([
  "KEY", "APIKEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PWD", "CREDENTIAL", "CREDENTIALS", "PAT", "AUTH",
  "AUTHORIZATION", "BEARER", "PRIVATEKEY", "ACCESSKEY", "CLIENTSECRET",
]);

export function secretName(name: string): boolean {
  const words = name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toUpperCase()
    .split(/[^A-Z0-9]+/)
    .filter(Boolean);
  if (words.some((w) => SECRET_WORDS.has(w))) return true;
  // apiKey → API_KEY is handled above; "x-api-key" splits into X, API, KEY.
  return false;
}

/** Stand-ins people leave in config: references, templates, and the example values. */
const PLACEHOLDER = /^\$|\$\{|\{\{|<[^>]*>|^(?:your|my)[-_ ]|x{4,}|changeme|example|placeholder|replace[-_ ]?me|dummy|\[redacted|\*{3,}|\.{3}|^(?:true|false|null|none|undefined)$/i;

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER.test(value.trim());
}

/**
 * Whether a value under a credential-ish name is a real credential and not a
 * setting that happens to share the word: `MAX_TOKENS=4096`,
 * `SSH_KEY_PATH=~/.ssh/id_ed25519`, `AUTH_MODE=oauth` are all left alone.
 */
export function looksLikeCredential(value: string): boolean {
  const v = value.trim();
  if (v.length < 12 || /\s/.test(v) || isPlaceholder(v)) return false;
  if (/^[~./\\]/.test(v) || /^[A-Za-z]:\\/.test(v)) return false; // a path
  if (/^https?:\/\//i.test(v)) return false; // a URL is checked on its own terms
  // Dates and times: `claudeCodeFirstTokenDate` has "Token" in it and a value
  // with digits and capitals, and is still not a key.
  if (/^\d{4}-\d{2}-\d{2}(?:[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)?$/.test(v)) return false;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((r) => r.test(v)).length;
  return classes >= 2;
}

export type FindingKind = "env" | "header" | "arg" | "url" | "field";

export interface Finding {
  /** The MCP server the value belongs to, when it sits inside one. */
  server: string | null;
  /** Where in the file, for a person: `mcpServers.github.env.GITHUB_TOKEN`. */
  where: string;
  /** The variable, header or field name. */
  name: string;
  value: string;
  kind: FindingKind;
  /** A provider recognised from the value itself. */
  service: string | null;
  /**
   * The JSON path of the server entry, when this is an `env` value of a server
   * that is started as a command — the case `--fix` can move into hush.
   */
  entryPath: string[] | null;
}

/** Keys under which agents list their MCP servers. */
const SERVER_MAPS = new Set(["mcpServers", "servers", "context_servers", "mcp_servers"]);

function judgeUrl(value: string): boolean {
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return false;
  }
  if (u.password && !isPlaceholder(decodeURIComponent(u.password))) return true;
  for (const [k, v] of u.searchParams) if (secretName(k) && v.length >= 12 && !isPlaceholder(v)) return true;
  return false;
}

/** One candidate value, judged by what it is called and what it looks like. */
function judge(name: string, value: string, kind: FindingKind): { secret: boolean; service: string | null } {
  // A URL is judged by its secret parts only: "example" or "your" in a host
  // name says nothing about the token in its query string.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    const service = serviceOf(value);
    return { secret: judgeUrl(value) || service !== null, service };
  }
  if (isPlaceholder(value)) return { secret: false, service: null };
  const service = serviceOf(value);
  if (service) return { secret: true, service };
  if (kind === "header" && /^authorization$/i.test(name)) {
    const m = /^(?:bearer|basic|token)\s+(\S+)$/i.exec(value.trim());
    return { secret: !!m && m[1].length >= 12 && !isPlaceholder(m[1]), service: null };
  }
  return { secret: secretName(name) && looksLikeCredential(value), service: null };
}

/** `--api-key=sk-…`, or `--token` followed by the value as the next argument. */
function judgeArgs(args: unknown[]): { index: number; name: string; value: string; service: string | null }[] {
  const hits: { index: number; name: string; value: string; service: string | null }[] = [];
  args.forEach((arg, i) => {
    if (typeof arg !== "string") return;
    const eq = /^--?([A-Za-z0-9_-]+)=(.+)$/.exec(arg);
    if (eq) {
      const j = judge(eq[1], eq[2], "arg");
      if (j.secret) hits.push({ index: i, name: eq[1], value: eq[2], service: j.service });
      return;
    }
    const prev = i > 0 ? args[i - 1] : null;
    const flag = typeof prev === "string" ? /^--?([A-Za-z0-9_-]+)$/.exec(prev) : null;
    const service = serviceOf(arg);
    if (service || (flag && secretName(flag[1]) && looksLikeCredential(arg))) {
      hits.push({ index: i, name: flag ? flag[1] : `args[${i}]`, value: arg, service });
    }
  });
  return hits;
}

/** Walk a parsed JSON document. */
function walkJson(node: unknown, path: string[], server: { name: string; path: string[] } | null, out: Finding[]): void {
  if (Array.isArray(node)) {
    node.forEach((v, i) => walkJson(v, [...path, String(i)], server, out));
    return;
  }
  if (!node || typeof node !== "object") return;
  const obj = node as Record<string, unknown>;
  const startsAsCommand = server !== null && typeof obj.command === "string";
  for (const [k, v] of Object.entries(obj)) {
    const here = [...path, k];
    if (SERVER_MAPS.has(k) && v && typeof v === "object" && !Array.isArray(v)) {
      for (const [name, entry] of Object.entries(v as Record<string, unknown>)) {
        walkJson(entry, [...here, name], { name, path: [...here, name] }, out);
      }
      continue;
    }
    if ((k === "env" || k === "environment") && v && typeof v === "object" && !Array.isArray(v)) {
      for (const [name, value] of Object.entries(v as Record<string, unknown>)) {
        if (typeof value !== "string") continue;
        const j = judge(name, value, "env");
        if (j.secret) {
          out.push({
            server: server?.name ?? null,
            where: [...here, name].join("."),
            name,
            value,
            kind: "env",
            service: j.service,
            entryPath: startsAsCommand && server ? server.path : null,
          });
        }
      }
      continue;
    }
    if (k === "headers" && v && typeof v === "object" && !Array.isArray(v)) {
      for (const [name, value] of Object.entries(v as Record<string, unknown>)) {
        if (typeof value !== "string") continue;
        const j = judge(name, value, "header");
        if (j.secret) {
          out.push({ server: server?.name ?? null, where: [...here, name].join("."), name, value, kind: "header", service: j.service, entryPath: null });
        }
      }
      continue;
    }
    if (k === "args" && Array.isArray(v)) {
      for (const hit of judgeArgs(v)) {
        out.push({
          server: server?.name ?? null,
          where: `${here.join(".")}[${hit.index}]`,
          name: hit.name,
          value: hit.value,
          kind: "arg",
          service: hit.service,
          entryPath: null,
        });
      }
      continue;
    }
    if (typeof v === "string") {
      const kind: FindingKind = /^(url|serverUrl|uri|endpoint)$/i.test(k) ? "url" : "field";
      const j = judge(k, v, kind);
      if (j.secret) out.push({ server: server?.name ?? null, where: here.join("."), name: k, value: v, kind, service: j.service, entryPath: null });
      continue;
    }
    walkJson(v, here, server, out);
  }
}

const unquote = (s: string): string => {
  const t = s.trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    return t.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, "\\");
  }
  return t;
};

/**
 * Codex's config.toml, read line by line: `[mcp_servers.x.env]` tables,
 * inline `env = { K = "v" }`, `args = [ … ]`, and plain `key = "value"`.
 * Not a TOML parser — just enough of one to find a string where it sits.
 */
function scanToml(text: string, out: Finding[]): void {
  let table: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/^\s+/, "");
    if (!line || line.startsWith("#")) continue;
    const header = /^\[{1,2}([^\]]+)\]{1,2}/.exec(line);
    if (header) {
      table = header[1].split(".").map((p) => unquote(p));
      continue;
    }
    const kv = /^([A-Za-z0-9_"'.-]+)\s*=\s*(.+)$/.exec(line);
    if (!kv) continue;
    const key = unquote(kv[1]);
    const rhs = kv[2].trim();
    const server = table[0] === "mcp_servers" && table[1] ? table[1] : null;
    const inEnv = table[2] === "env";
    // http_headers and env_http_headers (Codex's remote servers) hold headers.
    const inHeaders = /headers$/.test(table[2] ?? "");
    if (rhs.startsWith("{")) {
      for (const m of rhs.matchAll(/([A-Za-z0-9_"'-]+)\s*=\s*("(?:[^"\\]|\\.)*"|'[^']*')/g)) {
        const name = unquote(m[1]);
        const value = unquote(m[2]);
        const kind: FindingKind = key === "env" ? "env" : /headers$/.test(key) ? "header" : "field";
        const j = judge(name, value, kind);
        if (j.secret) out.push({ server, where: [...table, key, name].join("."), name, value, kind, service: j.service, entryPath: null });
      }
      continue;
    }
    if (rhs.startsWith("[")) {
      const items = [...rhs.matchAll(/"(?:[^"\\]|\\.)*"|'[^']*'/g)].map((m) => unquote(m[0]));
      for (const hit of judgeArgs(items)) {
        out.push({ server, where: `${[...table, key].join(".")}[${hit.index}]`, name: hit.name, value: hit.value, kind: "arg", service: hit.service, entryPath: null });
      }
      continue;
    }
    if (!/^["']/.test(rhs)) continue;
    const value = unquote(rhs.replace(/\s+#.*$/, ""));
    const kind: FindingKind = inEnv ? "env" : inHeaders ? "header" : /^(url|bearer_token)$/.test(key) ? "url" : "field";
    const j = judge(key, value, kind);
    if (j.secret) out.push({ server, where: [...table, key].join("."), name: key, value, kind, service: j.service, entryPath: null });
  }
}

/** YAML (Continue's config.yaml), line by line: `name: value` pairs. */
function scanYaml(text: string, out: Finding[]): void {
  for (const raw of text.split(/\r?\n/)) {
    const m = /^\s*(?:-\s+)?([A-Za-z_][\w-]*)\s*:\s*(.+?)\s*$/.exec(raw);
    if (!m || m[2].startsWith("#")) continue;
    const value = unquote(m[2].replace(/\s+#.*$/, ""));
    const j = judge(m[1], value, "field");
    if (j.secret) out.push({ server: null, where: m[1], name: m[1], value, kind: "field", service: j.service, entryPath: null });
  }
}

export interface FileScan {
  findings: Finding[];
  /** The file could not be read as its format; nothing was judged. */
  unreadable?: string;
}

export function findSecrets(text: string, format: ConfigFormat): FileScan {
  const out: Finding[] = [];
  if (format === "toml") {
    scanToml(text, out);
    return { findings: out };
  }
  if (format === "yaml") {
    scanYaml(text, out);
    return { findings: out };
  }
  let doc: unknown;
  try {
    doc = JSON.parse(format === "jsonc" ? stripJsonc(text) : text);
  } catch {
    try {
      doc = JSON.parse(stripJsonc(text));
    } catch (e) {
      return { findings: [], unreadable: (e as Error).message };
    }
  }
  walkJson(doc, [], null, out);
  return { findings: out };
}

// ------------------------------------------------------------------ moving them

/** One MCP server whose `env` credentials can move into a hush set. */
export interface WrapPlan {
  server: string;
  /** JSON path of the server's entry in its file. */
  entryPath: string[];
  /** Variable name → value, exactly as the file holds them now. */
  keys: Record<string, string>;
}

/** The env credentials of servers that are started as a command, one plan per server. */
export function planWraps(findings: Finding[]): WrapPlan[] {
  const byEntry = new Map<string, WrapPlan>();
  for (const f of findings) {
    if (f.kind !== "env" || !f.entryPath || !f.server) continue;
    const id = JSON.stringify(f.entryPath);
    const plan = byEntry.get(id) ?? { server: f.server, entryPath: f.entryPath, keys: {} };
    plan.keys[f.name] = f.value;
    byEntry.set(id, plan);
  }
  return [...byEntry.values()];
}

function entryAt(doc: unknown, path: string[]): Record<string, unknown> | null {
  let node: unknown = doc;
  for (const p of path) {
    if (!node || typeof node !== "object") return null;
    node = (node as Record<string, unknown>)[p];
  }
  return node && typeof node === "object" && !Array.isArray(node) ? (node as Record<string, unknown>) : null;
}

/**
 * Rewrite one server entry so the agent starts it through `hush run`, with the
 * moved variables injected from a set instead of written in the file. `launch`
 * is everything up to and including `--`; the old command and args follow it:
 *
 *   { "command": "npx", "args": ["-y", "@x/server"], "env": { "X_TOKEN": "…", "LOG": "debug" } }
 *   →
 *   { "command": <hush>, "args": [<hush's args>, "run", …, "--use", "mcp-x", "--", "npx", "-y", "@x/server"],
 *     "env": { "LOG": "debug" } }
 *
 * Refuses (returns a reason) rather than guessing when the entry is no longer
 * the one that was planned — the file changed in between, or a value differs.
 */
export function applyWrap(
  doc: unknown,
  plan: WrapPlan,
  launch: { command: string; args: string[] },
): { ok: true } | { ok: false; reason: string } {
  const entry = entryAt(doc, plan.entryPath);
  if (!entry || typeof entry.command !== "string") return { ok: false, reason: "the server entry is no longer there" };
  const env = entry.env as Record<string, unknown> | undefined;
  for (const [k, v] of Object.entries(plan.keys)) {
    if (!env || env[k] !== v) return { ok: false, reason: `${k} changed since it was read` };
  }
  const args = Array.isArray(entry.args) ? entry.args.filter((a): a is string => typeof a === "string") : [];
  if (Array.isArray(entry.args) && args.length !== entry.args.length) return { ok: false, reason: "its args are not all strings" };
  entry.args = [...launch.args, entry.command, ...args];
  entry.command = launch.command;
  for (const k of Object.keys(plan.keys)) delete env![k];
  if (Object.keys(env!).length === 0) delete entry.env;
  return { ok: true };
}

/** A server entry that already starts through hush. */
export function alreadyWrapped(entry: { command?: unknown; args?: unknown }): boolean {
  const args = Array.isArray(entry.args) ? entry.args : [];
  const runs = args.indexOf("run");
  const viaHush = typeof entry.command === "string" && /(?:^|[/\\])hush(?:\.exe)?$/.test(entry.command);
  const viaNode = args.some((a) => typeof a === "string" && /(?:^|[/\\])(?:cli\.(?:ts|js)|hush\.js)$/.test(a));
  return runs !== -1 && (viaHush || viaNode) && args.includes("--use");
}

/** The indentation a JSON file already uses, so a rewrite keeps its shape. */
export function indentOf(text: string): string | number {
  const m = /^\{\r?\n([ \t]+)"/.exec(text);
  return m ? (m[1].includes("\t") ? "\t" : m[1].length) : 2;
}
