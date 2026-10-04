# What the agent may run

```bash
hush install-skill            # this project
hush install-skill --global   # every project
```

Installs a skill telling your agent never to ask for a pasted key, to use
`hush_run` rather than reading values, and how to pick a set when you name
one. It goes where each agent looks for instructions — the right-hand column
of the table in [Connecting your agent](connecting-your-agent.md). Codex, Gemini CLI and Zed share `.agents/skills/` (and
`~/.agents/skills/` for `--global`), so one file serves all three. Without it the tools still work — the tool
descriptions explain themselves — you just have to say so each time.

`.hush/policy.json` controls what it may run — through the MCP tools *and*
through the CLI, so an agent that shells out to `hush run` or `hush export`
meets the same approval prompt. For the agent's tools, anything that exists to
dump or re-encode the environment is denied outright — shells, `env`, `base64`,
`curl`, and every interpreter, because `node -e` can write the whole environment
to a file that output redaction never sees. In your terminal the same commands
are not refused: `hush node server.js` goes to the approval prompt with a
warning line, the way `op run` asks rather than blocks. `allowCommands` still
narrows both:

```json
{
  "allowCommands": [],
  "denyCommands": ["your-own-additions"],
  "unsafeAllowCommands": [],
  "allowEnvs": ["default", "work-fal"],
  "allowHosts": ["api.stripe.com", "*.github.com"],
  "denyKeys": ["STRIPE_LIVE_KEY"],
  "maxRunMs": 120000,
  "approvalScope": "command"
}
```

- **`denyCommands`** is *added* to the built-in list, never substituted for it —
  an old config cannot hold you below the current floor.
- **`unsafeAllowCommands`** is the only way below that floor. Named to be
  off-putting: allowing `node` or `bash` lets an agent read every injected
  secret and write it anywhere.
- **`allowEnvs`** names the sets an agent may use — by the name you gave them,
  wherever they live — so `["default", "work-fal"]` keeps an agent out of
  `client-fal`.
- **`allowHosts`** bounds where `hush request` and `hush_request` may send a
  credential. Empty means any host over https. Entries are a bare host
  (`api.stripe.com`), a host with a port (`localhost:3000`), or a subdomain
  glob (`*.example.com`, which does not match the apex). It is the one control
  that decides *where* a secret goes, which no command or set rule can express:
  without it, a set allowed for `api.stripe.com` is equally allowed for an
  attacker's collector.
- **`allowCommands`**, if non-empty, is an allowlist — the only command control
  that actually holds. Prefer it for anything sensitive.
- **`requireApproval`** lists what a human must approve on screen: `run`, `add`,
  `reveal`, and `request` — all four by default. A repository's file can add to
  them, not remove any: turning one off is your choice on your machine
  (`hush secure approval --off`, or the app's Agent section). `--materialize` is
  gated by `reveal`, not `run`, because it writes plaintext to a path the caller
  chose.
- **`approvalScope`** is what "Allow 15 min" covers: `"command"` (the default)
  means that command with those sets; `"sets"` means any allowed command with
  those sets, if you find the prompts too frequent.
- **`approvalTtlSeconds`** is how long an "Allow" lasts (default 900 = 15
  minutes), counted inside the process that asked — the MCP server and the app
  keep it, a one-shot `hush` command does not. Change it in the app's Agent
  section, or with
  `hush secure approval --for 30m`, rather than by hand.

**Your floor.** `policy.json` is a file in the repo, so an agent with write
access can edit it. `~/.hush/policy.json` — same shape, outside every repo —
is your floor: a repo's policy can only *tighten* relative to it. Where your
floor says nothing about approvals, fingerprints or what an "Allow" covers, the
defaults are the floor — an empty file is not "no opinion". `allowCommands`,
`allowEnvs` and `allowHosts` can only narrow, `requireApproval` and `denyKeys`
can only grow, `biometry` and `approvalScope` can only get stricter, and
`unsafeAllowCommands` only takes effect when your floor lists the same command
— the repo asks, you permit. `unmaskKeys` is floor-only as well: it is the list
of keys you have allowed to print unmasked, and a repository cannot add to it.
`hush doctor` shows every place a repo policy tried to go below your floor.

An allow list your floor sets keeps applying even when a repo's `policy.json`
does not mention it. A repo file that omits `allowCommands` inherits your floor's
list rather than replacing it with "no restriction"; a repo file that names only
entries outside your floor is ignored as a whole. Both cases are reported by
`hush doctor`, so a floor that is doing nothing is never silent.
