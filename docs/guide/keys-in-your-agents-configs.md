# Keys in your agents' configs

The usual way to give an MCP server its API key is to paste it into the
agent's config file:

```json
{ "mcpServers": { "github": { "command": "npx", "args": ["-y", "github-mcp"],
  "env": { "GITHUB_TOKEN": "ghp_…" } } } }
```

That file is plaintext. Every process running as you can read it, including
the agents, and some of these files sit in a repository. `hush scan --agents`
finds them:

```
$ hush scan --agents

  Claude Desktop  ~/Library/Application Support/Claude/claude_desktop_config.json
    ✗ github  GITHUB_TOKEN  GitHub · ghp…AB (40 chars)  can move
  Cursor  ~/.cursor/mcp.json
    ✗ figma   FIGMA_API_KEY  Figma · fig…Vq (45 chars)  can move

  2 plaintext credential(s) in 2 file(s). Anything running as you can read them.
  Move the 2 hush can into your library:  hush scan --agents --fix
```

It reads Claude Code (`~/.claude.json`, settings, `.mcp.json`), Claude Desktop,
Cursor, Windsurf, Gemini CLI, VS Code, Cline, Zed, Codex and Continue, in your
home folder and in the current project. It shows a masked preview, never a
value. A value is a credential if a provider's prefix says so (`ghp_`,
`sk-ant-`, `AKIA…`) or if its name does and it looks like one: `MAX_TOKENS=4096`,
a path, a date or a `${VAR}` reference are left alone.

## Moving them

```bash
hush scan --agents --fix
```

For each server that the agent starts as a command, hush:

1. stores its keys in your library as a set named `mcp-<server>` (the same key
   used by two agents goes into one set);
2. reads them back from disk, and stops without touching any config file if
   it cannot;
3. rewrites the server entry to start through hush, keeping everything else:

```json
{ "command": "/opt/homebrew/bin/node",
  "args": [".../hush/dist/cli.js", "run", "--vault", "global", "--quiet",
           "--use", "mcp-github", "--", "npx", "-y", "github-mcp"] }
```

The server gets the same variable as before. Its output passes through the
redactor, so a server that echoes its key prints `[redacted:GITHUB_TOKEN]`. A
user-wide file gets hush's absolute path, because desktop apps start servers
without your shell's PATH. A project file gets a bare `hush`, because it may be
committed. A file that changed while this ran is left alone. Restart the agent
afterwards.

If approvals are on, starting the server asks you like any other `hush run`.

## What it cannot move

- **A header, or a key in the server's URL.** Remote servers often take one of
  these. hush cannot inject either, so the file stays a secret. Use the
  server's env-variable option if it has one.
- **A setting the app hands its extension** (Zed's `settings`) or keeps for
  itself. Keep the file private.
- **A file with comments** (VS Code, Zed) **or TOML** (Codex). A rewrite would
  lose the comments, so move these by hand: `hush add`, then start the server
  with `hush run --use <set> -- <command>`.

The old values were in plaintext. If one of those files was ever synced,
backed up or shared, replace the key at the provider: moving it into hush
protects it from now on, not before.
