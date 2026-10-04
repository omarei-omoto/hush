# Connecting your agent

```bash
hush install-mcp
```

It looks for the coding agents on this machine and registers hush with each one
it finds, in the file that agent actually reads:

| Agent | MCP config | Skill / rule |
|---|---|---|
| **Claude Code** | `.mcp.json` | `.claude/skills/hush/SKILL.md` |
| **Codex** | `~/.codex/config.toml` | `.agents/skills/hush/SKILL.md` |
| **Cursor** | `.cursor/mcp.json` | `.cursor/rules/hush.mdc` |
| **Gemini CLI** | `.gemini/settings.json` | `.agents/skills/hush/SKILL.md` |
| **VS Code** (Copilot) | `.vscode/mcp.json` | `.github/instructions/hush.instructions.md` |
| **Windsurf** | `~/.config/devin/mcp_config.json` | `.windsurf/rules/hush.md` |
| **Zed** | `~/.config/zed/settings.json` (comments kept) | `.agents/skills/hush/SKILL.md` |
| **Cline** | `~/.cline/mcp.json` (CLI); the extension gets a line to paste | `.clinerules/hush.md` |
| **Continue** | `.continue/mcpServers/hush.json` | `.continue/rules/hush.md` |

On a terminal it lists the files first and asks
(`pick` to choose per agent; `--yes` skips the question). It never rewrites an
entry you already have, and when it cannot write one it prints the line to
paste instead of a tick that means nothing. The entry is a plain `hush mcp`
when the `hush` on your PATH is this install, so the committed file works on
your teammates' machines too.

If hush cannot see your agent (a fresh machine, an unusual setup):

```bash
hush install-mcp --for codex        # or: claude-code, cursor, gemini, vscode, windsurf, zed, cline, continue
```

An existing entry is left alone; to point it at a different hush, edit that
file yourself.
