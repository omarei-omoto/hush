/**
 * Telling a coding agent about hush.
 *
 * `hush install-mcp` used to write one file — `.mcp.json` — and print a tick.
 * That file is Claude Code's. Running it in a Codex or Cursor session printed
 * the same tick and changed nothing the agent would ever read, which is the
 * worst kind of setup step: it looks done and is not.
 *
 * So the details of each agent live here as data: where it reads its MCP
 * servers from, which format that file is in, where it keeps skills, how to
 * tell whether it is on this machine at all, and what to print for a human to
 * paste when hush cannot write the file safely. The command in cli.ts does the
 * asking and the printing; this file knows the layouts and the merge rules,
 * which is also what makes them testable without a filesystem.
 */
import { join } from "node:path";
import { onPath } from "./which.ts";

export type AgentId =
  | "codex" | "claude-code" | "cursor" | "windsurf" | "gemini" | "vscode" | "zed" | "cline" | "continue";

export interface McpEntry {
  command: string;
  args: string[];
}

/**
 * How a config file represents "here is a server called hush".
 *
 * - `json`: `{ "mcpServers": { "hush": { command, args } } }` — most agents.
 * - `toml`: Codex's `[mcp_servers.hush]`.
 * - `vscode`: VS Code's `{ "servers": { "hush": { "type": "stdio", … } } }`.
 * - `zed`: Zed's settings file, `{ "context_servers": { "hush": … } }`, which
 *   is JSON with comments — so it is edited in place, never re-serialised.
 */
export type McpFormat = "json" | "toml" | "vscode" | "zed";

export interface AgentSpec {
  id: AgentId;
  name: string;
  /** Cheap, read-only "is this agent used on this machine" check. */
  present: (root: string, env: NodeJS.ProcessEnv, exists: (p: string) => boolean) => boolean;
  mcp: {
    /** Absolute path of the file to write. */
    path: (root: string, env: NodeJS.ProcessEnv) => string;
    format: McpFormat;
  };
  /**
   * Where a skill goes. `project` is inside the repository (committable),
   * `global` is this machine only. Null when the agent has no such place.
   */
  skill: {
    project: (root: string) => string;
    global: ((env: NodeJS.ProcessEnv) => string) | null;
    /** Cursor wants a rule file with its own frontmatter; the others take SKILL.md as-is. */
    transform?: (skillMarkdown: string, description: string) => string;
  };
  /**
   * The line to print when hush cannot write the config itself. Takes the entry
   * hush would have written, or a bare path to cli.ts/cli.js (run with node).
   */
  manual: (entry: McpEntry | string, root: string) => string;
}

const asEntry = (e: McpEntry | string): McpEntry => (typeof e === "string" ? { command: "node", args: [e, "mcp"] } : e);

/** `node "/path/cli.js" mcp` or `hush mcp`, for a shell line. */
const shellLine = (e: McpEntry | string): string => {
  const { command, args } = asEntry(e);
  return [command, ...args.map((a) => (/^[\w./-]+$/.test(a) ? a : JSON.stringify(a)))].join(" ");
};

/** The JSON `mcpServers` document, on one line, for a paste. */
const jsonLine = (e: McpEntry | string): string => {
  const { command, args } = asEntry(e);
  const list = args.map((a) => JSON.stringify(a)).join(", ");
  return `{ "mcpServers": { "hush": { "command": ${JSON.stringify(command)}, "args": [${list}] } } }`;
};

const home = (env: NodeJS.ProcessEnv): string => env.HOME ?? env.USERPROFILE ?? "~";

/** A rule file that needs its own frontmatter in place of SKILL.md's. */
const withFrontmatter = (lines: string[]) => (markdown: string, description: string): string =>
  `---\n${lines.map((l) => l.replace("$DESCRIPTION", description)).join("\n")}\n---\n\n${stripFrontmatter(markdown)}`;

/** $XDG_CONFIG_HOME, or ~/.config — where Windsurf (Devin) and Zed keep settings. */
const xdgConfig = (env: NodeJS.ProcessEnv): string => env.XDG_CONFIG_HOME || join(home(env), ".config");

/** macOS keeps app support outside the home dotfiles; both are worth checking. */
const appSupport = (env: NodeJS.ProcessEnv, name: string): string =>
  join(home(env), "Library", "Application Support", name);

/**
 * The agents hush knows. Order is the order they are reported in.
 *
 * Every path here is documented by the tool that reads it, never guessed: a
 * wrong path would put a tick on screen for a file nobody opens, which is the
 * bug this module exists to fix. Codex reads MCP servers from
 * `~/.codex/config.toml` and skills from `~/.agents/skills`; Claude Code reads
 * `.mcp.json` and `.claude/skills`; Cursor reads `.cursor/mcp.json` and
 * `.cursor/rules`. The rest name their source beside their entry, checked
 * against each tool's documentation on 2026-09-30.
 */
export const AGENTS: AgentSpec[] = [
  {
    id: "codex",
    name: "Codex",
    present: (root, env, exists) =>
      exists(join(home(env), ".codex")) || exists(join(root, ".codex")) || onPath("codex", env.PATH) !== null,
    mcp: {
      path: (_root, env) => join(home(env), ".codex", "config.toml"),
      format: "toml",
    },
    skill: {
      project: (root) => join(root, ".agents", "skills", "hush", "SKILL.md"),
      global: (env) => join(home(env), ".agents", "skills", "hush", "SKILL.md"),
    },
    manual: (entry) => `codex mcp add hush -- ${shellLine(entry)}`,
  },
  {
    id: "claude-code",
    name: "Claude Code",
    present: (root, env, exists) =>
      exists(join(root, ".claude")) ||
      exists(join(root, ".mcp.json")) ||
      exists(join(home(env), ".claude")) ||
      exists(join(home(env), ".claude.json")) ||
      onPath("claude", env.PATH) !== null,
    mcp: {
      path: (root) => join(root, ".mcp.json"),
      format: "json",
    },
    skill: {
      project: (root) => join(root, ".claude", "skills", "hush", "SKILL.md"),
      global: (env) => join(home(env), ".claude", "skills", "hush", "SKILL.md"),
    },
    manual: (entry, root) => `write ${join(root, ".mcp.json")}:\n    ${jsonLine(entry)}`,
  },
  {
    id: "cursor",
    name: "Cursor",
    present: (root, env, exists) =>
      exists(join(root, ".cursor")) ||
      exists(join(home(env), ".cursor")) ||
      exists(appSupport(env, "Cursor")) ||
      onPath("cursor", env.PATH) !== null,
    mcp: {
      path: (root) => join(root, ".cursor", "mcp.json"),
      format: "json",
    },
    skill: {
      project: (root) => join(root, ".cursor", "rules", "hush.mdc"),
      global: null,
      // Cursor rules carry their own frontmatter; the skill's own is replaced.
      transform: (markdown, description) =>
        `---\ndescription: ${description}\nalwaysApply: false\n---\n\n${stripFrontmatter(markdown)}`,
    },
    manual: (entry, root) => `write ${join(root, ".cursor", "mcp.json")}:\n    ${jsonLine(entry)}`,
  },
  {
    // Windsurf's Cascade agent: docs.windsurf.com/windsurf/cascade/mcp gives
    // ~/.config/devin/mcp_config.json (or $XDG_CONFIG_HOME/devin/…); workspace
    // rules live in .windsurf/rules/, with a `trigger` in their frontmatter.
    id: "windsurf",
    name: "Windsurf",
    present: (root, env, exists) =>
      exists(join(root, ".windsurf")) ||
      exists(join(home(env), ".codeium", "windsurf")) ||
      exists(join(xdgConfig(env), "devin")) ||
      exists(appSupport(env, "Windsurf")) ||
      onPath("windsurf", env.PATH) !== null,
    mcp: {
      path: (_root, env) => join(xdgConfig(env), "devin", "mcp_config.json"),
      format: "json",
    },
    skill: {
      project: (root) => join(root, ".windsurf", "rules", "hush.md"),
      global: null,
      // model_decision: only the description sits in the prompt until it is needed.
      transform: withFrontmatter(["trigger: model_decision", "description: $DESCRIPTION"]),
    },
    manual: (entry, _root) => `add to ~/.config/devin/mcp_config.json:\n    ${jsonLine(entry)}`,
  },
  {
    // Gemini CLI: `gemini mcp add` writes .gemini/settings.json (project scope
    // is its default); skills are read from .agents/skills/ like Codex's.
    id: "gemini",
    name: "Gemini CLI",
    present: (root, env, exists) =>
      exists(join(root, ".gemini")) || exists(join(home(env), ".gemini")) || onPath("gemini", env.PATH) !== null,
    mcp: {
      path: (root) => join(root, ".gemini", "settings.json"),
      format: "json",
    },
    skill: {
      project: (root) => join(root, ".agents", "skills", "hush", "SKILL.md"),
      global: (env) => join(home(env), ".agents", "skills", "hush", "SKILL.md"),
    },
    manual: (entry) => `gemini mcp add hush ${shellLine(entry)}`,
  },
  {
    // VS Code (Copilot agent mode): .vscode/mcp.json with a top-level
    // `servers` object; instructions in .github/instructions/*.instructions.md.
    id: "vscode",
    name: "VS Code",
    present: (root, env, exists) =>
      exists(join(root, ".vscode")) ||
      exists(appSupport(env, "Code")) ||
      exists(join(xdgConfig(env), "Code")) ||
      onPath("code", env.PATH) !== null,
    mcp: {
      path: (root) => join(root, ".vscode", "mcp.json"),
      format: "vscode",
    },
    skill: {
      project: (root) => join(root, ".github", "instructions", "hush.instructions.md"),
      global: null,
      transform: withFrontmatter(["description: $DESCRIPTION"]),
    },
    manual: (entry, root) => {
      const { command, args } = asEntry(entry);
      return `write ${join(root, ".vscode", "mcp.json")}:\n    { "servers": { "hush": { "type": "stdio", "command": ${JSON.stringify(command)}, "args": [${args.map((a) => JSON.stringify(a)).join(", ")}] } } }`;
    },
  },
  {
    // Zed: `context_servers` in the settings file (zed: open settings file),
    // ~/.config/zed/settings.json; skills from .agents/skills/ (zed.dev/docs/ai/skills).
    id: "zed",
    name: "Zed",
    present: (root, env, exists) =>
      exists(join(root, ".zed")) ||
      exists(join(xdgConfig(env), "zed")) ||
      exists(appSupport(env, "Zed")) ||
      onPath("zed", env.PATH) !== null,
    mcp: {
      path: (_root, env) => join(xdgConfig(env), "zed", "settings.json"),
      format: "zed",
    },
    skill: {
      project: (root) => join(root, ".agents", "skills", "hush", "SKILL.md"),
      global: (env) => join(home(env), ".agents", "skills", "hush", "SKILL.md"),
    },
    manual: (entry) => {
      const { command, args } = asEntry(entry);
      return `add to your Zed settings (zed: open settings file):\n    "context_servers": { "hush": { "command": ${JSON.stringify(command)}, "args": [${args.map((a) => JSON.stringify(a)).join(", ")}], "env": {} } }`;
    },
  },
  {
    // Cline: the CLI reads ~/.cline/mcp.json; the editor extension keeps its
    // own file behind "Configure MCP Servers", so that one is a paste.
    // Workspace rules: .clinerules/ (docs.cline.bot/customization/cline-rules).
    id: "cline",
    name: "Cline",
    present: (root, env, exists) =>
      exists(join(root, ".clinerules")) || exists(join(home(env), ".cline")) || onPath("cline", env.PATH) !== null,
    mcp: {
      path: (_root, env) => join(home(env), ".cline", "mcp.json"),
      format: "json",
    },
    skill: {
      project: (root) => join(root, ".clinerules", "hush.md"),
      global: null,
      transform: (markdown) => stripFrontmatter(markdown),
    },
    manual: (entry) =>
      `Cline panel → MCP Servers → Configure → Configure MCP Servers, then add:\n    ${jsonLine(entry)}`,
  },
  {
    // Continue: JSON files in .continue/mcpServers/ are read as-is, and rules
    // are .md files with frontmatter in .continue/rules/ (docs.continue.dev).
    id: "continue",
    name: "Continue",
    present: (root, env, exists) => exists(join(root, ".continue")) || exists(join(home(env), ".continue")),
    mcp: {
      path: (root) => join(root, ".continue", "mcpServers", "hush.json"),
      format: "json",
    },
    skill: {
      project: (root) => join(root, ".continue", "rules", "hush.md"),
      global: null,
      transform: withFrontmatter(["name: hush", "description: $DESCRIPTION", "alwaysApply: false"]),
    },
    manual: (entry, root) => `write ${join(root, ".continue", "mcpServers", "hush.json")}:\n    ${jsonLine(entry)}`,
  },
];

/** SKILL.md opens with its own YAML frontmatter; Cursor wants its own. */
export function stripFrontmatter(markdown: string): string {
  if (!markdown.startsWith("---\n")) return markdown;
  const end = markdown.indexOf("\n---", 4);
  if (end === -1) return markdown;
  return markdown.slice(end + 4).replace(/^\s*\n/, "");
}

/** The `description:` line of a SKILL.md, for a file that needs its own frontmatter. */
export function skillDescription(markdown: string): string {
  const m = /^---\n[\s\S]*?\ndescription:\s*(.+)$/m.exec(markdown);
  return m ? m[1].trim() : "hush — use credentials without ever seeing them";
}

/**
 * Add hush to an `mcpServers` JSON document.
 *
 * Refuses to replace an entry that is already there: it may be one the user
 * wrote deliberately (a different path, extra env), and silently rewriting it
 * would be worse than saying it is already registered.
 */
export function mergeMcpJson(
  existing: string | null,
  name: string,
  entry: McpEntry,
): { ok: true; text: string; changed: boolean } | { ok: false; reason: string } {
  let doc: Record<string, unknown> = {};
  if (existing && existing.trim()) {
    try {
      doc = JSON.parse(existing) as Record<string, unknown>;
    } catch {
      return { ok: false, reason: "it is not valid JSON" };
    }
  }
  const servers = (doc.mcpServers ??= {}) as Record<string, unknown>;
  if (servers[name]) return { ok: true, text: existing ?? "", changed: false };
  servers[name] = entry;
  return { ok: true, text: JSON.stringify(doc, null, 2) + "\n", changed: true };
}

/**
 * Add hush to a `config.toml` that uses `[mcp_servers.<name>]`.
 *
 * Appending a new table header at the end of a TOML file is always valid, which
 * is why this does not try to parse and rewrite the whole document: a
 * zero-dependency parse-and-rewrite of someone's config is a much bigger risk
 * than an append. An existing `hush` table wins, for the same reason as above.
 */
export function mergeMcpToml(
  existing: string | null,
  name: string,
  entry: McpEntry,
): { ok: true; text: string; changed: boolean } {
  const text = existing ?? "";
  const header = `[mcp_servers.${name}]`;
  const already = text.split("\n").some((line) => line.trim() === header);
  if (already) return { ok: true, text, changed: false };

  const args = entry.args.map((a) => JSON.stringify(a)).join(", ");
  const block = `${header}\ncommand = ${JSON.stringify(entry.command)}\nargs = [${args}]\n`;
  const sep = !text || text.endsWith("\n\n") ? "" : text.endsWith("\n") ? "\n" : "\n\n";
  return { ok: true, text: text + sep + block, changed: true };
}

/**
 * Add hush to VS Code's `.vscode/mcp.json`, whose servers live under
 * `servers` and name their transport.
 */
export function mergeMcpVscode(
  existing: string | null,
  name: string,
  entry: McpEntry,
): { ok: true; text: string; changed: boolean } | { ok: false; reason: string } {
  let doc: Record<string, unknown> = {};
  if (existing && existing.trim()) {
    try {
      doc = JSON.parse(stripJsonc(existing)) as Record<string, unknown>;
    } catch {
      return { ok: false, reason: "it is not valid JSON" };
    }
    // VS Code allows comments here; re-serialising would drop them.
    if (stripJsonc(existing) !== existing) {
      const servers = (doc.servers ?? {}) as Record<string, unknown>;
      if (servers[name]) return { ok: true, text: existing, changed: false };
      return { ok: false, reason: "it has comments, which rewriting it would lose" };
    }
  }
  const servers = (doc.servers ??= {}) as Record<string, unknown>;
  if (servers[name]) return { ok: true, text: existing ?? "", changed: false };
  servers[name] = { type: "stdio", command: entry.command, args: entry.args };
  return { ok: true, text: JSON.stringify(doc, null, 2) + "\n", changed: true };
}

/**
 * JSON with comments and trailing commas, reduced to JSON. Strings are kept
 * byte for byte, including any "//" inside them.
 */
export function stripJsonc(text: string): string {
  let out = "";
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (ch === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
    } else if (ch === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end === -1 ? text.length : end + 2;
    } else {
      out += ch;
      i++;
    }
  }
  return out.replace(/,(\s*[}\]])/g, "$1");
}

/**
 * Where, in a JSONC document, a top-level key's object value opens — the index
 * just past its `{` — or null. Scanned rather than parsed, so comments and
 * formatting around it are untouched when something is inserted there.
 */
function topLevelObjectStart(text: string, key: string): { rootOpen: number; keyOpen: number | null } | null {
  let depth = 0;
  let rootOpen = -1;
  let pendingKey: string | null = null;
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const str = text.slice(i + 1, j);
      if (depth === 1) pendingKey = str;
      i = j + 1;
      continue;
    }
    if (ch === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      continue;
    }
    if (ch === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end === -1 ? text.length : end + 2;
      continue;
    }
    if (ch === "{" || ch === "[") {
      if (ch === "{" && depth === 0 && rootOpen === -1) rootOpen = i + 1;
      else if (ch === "{" && depth === 1 && pendingKey === key) return { rootOpen, keyOpen: i + 1 };
      depth++;
    } else if (ch === "}" || ch === "]") {
      depth--;
    } else if (ch === "," && depth === 1) {
      pendingKey = null;
    }
    i++;
  }
  return rootOpen === -1 ? null : { rootOpen, keyOpen: null };
}

/** Whether the next thing after `at` (skipping space and comments) closes the object. */
function emptyAfter(text: string, at: number): boolean {
  return /^\s*}/.test(stripJsonc(text.slice(at)));
}

/**
 * Add hush to Zed's settings file under `context_servers`.
 *
 * That file is JSON with comments — Zed's own default one opens with a
 * comment — so re-serialising it would throw the user's comments away. The
 * entry is inserted as text at the right place instead, and the result is
 * parsed back to make sure it says what was meant before anything is written.
 */
export function mergeMcpZed(
  existing: string | null,
  name: string,
  entry: McpEntry,
): { ok: true; text: string; changed: boolean } | { ok: false; reason: string } {
  const value = { command: entry.command, args: entry.args, env: {} };
  if (!existing || !existing.trim()) {
    return { ok: true, text: JSON.stringify({ context_servers: { [name]: value } }, null, 2) + "\n", changed: true };
  }
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(stripJsonc(existing)) as Record<string, unknown>;
  } catch {
    return { ok: false, reason: "it is not valid JSON" };
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) return { ok: false, reason: "it is not a settings object" };
  const servers = doc.context_servers as Record<string, unknown> | undefined;
  if (servers && typeof servers === "object" && servers[name]) return { ok: true, text: existing, changed: false };

  const at = topLevelObjectStart(existing, "context_servers");
  if (!at) return { ok: false, reason: "hush could not find where its settings begin" };
  const body = `${JSON.stringify(name)}: ${JSON.stringify(value)}`;
  let text: string;
  if (at.keyOpen !== null) {
    text = existing.slice(0, at.keyOpen) + `\n    ${body}${emptyAfter(existing, at.keyOpen) ? "" : ","}` + existing.slice(at.keyOpen);
  } else {
    const block = `\n  "context_servers": {\n    ${body}\n  }${emptyAfter(existing, at.rootOpen) ? "" : ","}`;
    text = existing.slice(0, at.rootOpen) + block + existing.slice(at.rootOpen);
  }
  try {
    const check = JSON.parse(stripJsonc(text)) as { context_servers?: Record<string, unknown> };
    if (JSON.stringify(check.context_servers?.[name]) !== JSON.stringify(value)) throw new Error("mismatch");
  } catch {
    return { ok: false, reason: "hush could not add to it without risking its contents" };
  }
  return { ok: true, text, changed: true };
}

/** The merge for whichever shape the target file takes. */
export function renderMcp(
  format: McpFormat,
  existing: string | null,
  name: string,
  entry: McpEntry,
): { ok: true; text: string; changed: boolean } | { ok: false; reason: string } {
  switch (format) {
    case "toml":
      return mergeMcpToml(existing, name, entry);
    case "vscode":
      return mergeMcpVscode(existing, name, entry);
    case "zed":
      return mergeMcpZed(existing, name, entry);
    default:
      return mergeMcpJson(existing, name, entry);
  }
}

/**
 * The agents whose config file actually has a `hush` server in it. Shared by
 * `hush doctor` and the app so the two never disagree — and a file merely
 * existing is not a registration: most Codex users have a config.toml.
 */
export function mcpRegistrations(
  root: string,
  env: NodeJS.ProcessEnv,
  read: (path: string) => string | null,
): { agent: AgentSpec; file: string }[] {
  return AGENTS.flatMap((agent) => {
    const file = agent.mcp.path(root, env);
    const text = read(file);
    if (text === null) return [];
    const merged = renderMcp(agent.mcp.format, text, "hush", { command: "hush", args: ["mcp"] });
    return merged.ok && !merged.changed ? [{ agent, file }] : [];
  });
}
