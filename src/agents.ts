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

export type AgentId = "codex" | "claude-code" | "cursor";

export interface McpEntry {
  command: string;
  args: string[];
}

/** How a config file represents "here is a server called hush". */
export type McpFormat = "json" | "toml";

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
 * `.cursor/rules`.
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

/** The merge for whichever shape the target file takes. */
export function renderMcp(
  format: McpFormat,
  existing: string | null,
  name: string,
  entry: McpEntry,
): { ok: true; text: string; changed: boolean } | { ok: false; reason: string } {
  return format === "toml" ? mergeMcpToml(existing, name, entry) : mergeMcpJson(existing, name, entry);
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
