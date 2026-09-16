<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/omarei-omoto/hush/main/assets/logo-dark.png">
    <img src="https://raw.githubusercontent.com/omarei-omoto/hush/main/assets/logo-light.png" alt="hush" width="260">
  </picture>
</p>

<h1 align="center">hush</h1>

<p align="center"><strong>Envelope-encrypted team secrets your AI agent can use but never read.</strong></p>

[![CI](https://github.com/omarei-omoto/hush/actions/workflows/ci.yml/badge.svg)](https://github.com/omarei-omoto/hush/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@omarei/hush.svg)](https://www.npmjs.com/package/@omarei/hush)
[![node](https://img.shields.io/node/v/@omarei/hush.svg)](https://nodejs.org)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![runtime deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen.svg)](./package.json)

You keep your API keys in a `.env` file. It is plaintext, every process you
launch can read it, and the day you pointed an AI coding agent at the repo it
went into the agent's context window — and from there, wherever transcripts go.

hush fixes that without a server, an account, or a shared password. Your
secrets live **encrypted inside the repo itself**. `hush npm run dev` puts them
in that one process and nowhere else. Your coding agent gets tools that can
*use* a key but never read one. A teammate gets access with one command, and
removing them re-encrypts everything. Zero dependencies; one `npm install`.

```bash
hush init acme                  # a vault in .hush/vault.json — commit it
hush add .env --as "Dev"        # your existing secrets, now encrypted, as a set called dev
hush npm run dev                # injected into the process, never onto disk
hush team add sam hush_pk_1xM…  # commit; sam can decrypt. no invite email.
hush team rm sam                # re-keys the vault, re-seals every value
```

> [!IMPORTANT]
> **Status: early.** This works and is heavily tested, but it is pre-1.0, it has
> one author, and **it has not had an external security review**. The crypto is
> a standard construction ([age](https://age-encryption.org)'s, rebuilt on
> `node:crypto`) rather than anything invented here, and there is a
> [differential test suite](./test/scheme-conformance.test.ts) against an
> independent reimplementation — but that is not the same as someone qualified
> having looked at it.
>
> Development happens on macOS; Linux is covered by CI.
> **Windows is not supported yet** — the package declares it, so `npm install`
> refuses there rather than half-working. [Tell me what broke](https://github.com/omarei-omoto/hush/issues)
> if you try it somewhere unusual.
>
> Found a way to read a vault you should not? Please [report it
> privately](https://github.com/omarei-omoto/hush/security/advisories/new)
> rather than opening an issue.

## Contents

- [Install](#install) · [Quick start](#quick-start) · [Why this exists](#why-this-exists)
- **Using it** — [Sets](#sets) · [Coming from another tool](#coming-from-another-tool) · [Several keys for one service](#several-keys-for-one-service) · [Running things](#running-things) · [Credentials that are a file](#credentials-that-are-a-file) · [The app](#the-app)
- **Checking config** — [What a value should look like](#what-a-value-should-look-like) · [Finding what a codebase needs](#finding-what-a-codebase-needs)
- **Agents** — [What your agent gets](#what-your-agent-gets) · [Adding a key off-transcript](#adding-a-key-without-pasting-it-into-the-chat) · [Approvals](#approving-what-runs) · [Policy](#what-the-agent-may-run)
- **Your team** — [Adding someone](#adding-a-teammate) · [Removing someone](#removing-someone) · [CI](#ci)
- **Hardening** — [The security ladder](#the-security-ladder) · [Touch ID](#touch-id) · [Hardware keys](#hardware-keys)
- **Reference** — [Commands](#commands) · [How the crypto works](#how-the-crypto-works) · [What hush does not do](#what-hush-does-not-do)
- **Contributing** — [Development](#development) · [Contributing](#contributing-1) · [License](#license)

---

## Install

Needs Node ≥ 22.6.

```bash
npm install -g @omarei/hush
```

From a clone there is no build step — Node runs the TypeScript directly:

```bash
git clone https://github.com/omarei-omoto/hush.git
cd hush && node src/cli.ts --help
```

<details>
<summary>Why the published package ships compiled output</summary>

Node will not strip TypeScript types for anything under `node_modules`, so an
installed copy cannot run `src/`. The tarball ships JavaScript in `dist/` (built
by `npm run build`, run automatically by `prepack`), and the `hush` command
prefers `dist/` when it exists and falls back to `src/` otherwise — so a clone
and an install behave identically. Still zero runtime dependencies.

</details>

## Quick start

```bash
cd your-project
hush start
```

That is the whole thing. It looks for your keys, gets them in, asks whether an
AI assistant will be near them, and offers to run your project. A few questions,
nothing you have to know already.

Prefer to see every step yourself? The same thing, by hand:

```bash
hush init                    # creates your key + a vault, safe to commit
hush add .env --as "Dev"     # what you already have, encrypted, as a set called dev
rm .env                      # you don't need it any more
git add .hush && git commit -m "encrypted secrets"
```

From now on, put `hush` in front of whatever you run:

```bash
hush npm run dev             # anything after hush runs with the secrets injected
hush dev                     # or: find package.json and run its dev script
```

Secrets exist in that process's environment and nowhere else. Not on disk, not
in your shell, not in your scrollback.

## Why this exists

`.env` files have quietly become the worst artifact in your repo. They are
plaintext, they are readable by every process you launch, and they are now
routinely slurped into an LLM's context — [researchers caught a coding agent
uploading whole repos with `.env` credentials verbatim and
unredacted](https://www.sonarsource.com/blog/your-secrets-are-leaking-to-ai-coding-agents/).

The existing tools each cover part of this:

| | What it gets right | What it costs you |
|---|---|---|
| **SOPS / age** | per-recipient crypto, real revocation | no idea agents exist; YAML and key juggling |
| **secretctl** | the agent story | explicitly single-user |
| **dotenvx / nevr-env** | encrypted file in git | one key for the whole team, so no real revocation |
| **1Password CLI + MCP** | real vault, real hardware, real audit, agent access | an account and a subscription for everyone on the team |
| **Doppler / Infisical + MCP** | proper secrets management, agent access | a server to run or seats to buy |

**hush is the local, free, no-account option**, not a replacement for the last
two. If your team already pays for 1Password or Doppler, their MCP servers do
what hush does with better hardware and a real audit trail — use them. hush is
for the solo developer and the small team who want age's security model and an
agent that cannot read a value, with nothing to sign up for and nothing to
deploy: the git repo is the backend.

Where the line is: the moment you need dynamic credentials, leasing, expiry, or
an audit log someone else cannot edit, you have outgrown a file in git. hush
will not get you there and does not pretend to. Full comparison in
[RESEARCH.md](./RESEARCH.md).

---

# Using it

## Sets

Everything in hush is a **set**: some keys, a name you chose, an optional
description, and an optional note on when to use it. `dev`, `prod`,
`Personal fal`, `Acme Production` — all sets. There is no second concept to
learn.

A set lives in one of two places:

- **Your library** — `~/.hush/vaults/<name>`, yours alone, never in any repo.
  A key you use across projects lives here once, so rotating it is one edit.
- **This project** — `.hush/vault.json`, committed, shared with your team.

A project *uses* sets. Its own `default` set is always used, as the floor;
everything else layers on top in the order you added it, later wins. Under
even that sits your library's `default` — your **global environment**,
injected in every folder (`hush add K=v --library` with no `--to` lands there).
`.hush/envs.json` records only the *names* — a teammate who clones the repo
gets "this project uses a set called acme-production" and supplies their own.

```bash
hush add .env.production --as "Acme Production" --library \
  --description "Live Stripe + Convex" --when "deploys only"
hush add DATABASE_URL=postgres://… --to "Acme Production"   # one value into a set
hush add fal --as "Personal fal" --library                   # a known service: asks for FAL_KEY, hidden

hush use acme-production      # this project uses it
hush use                      # what this project uses, in order
hush use --not acme-production
```

A set you make from inside a project is used by that project automatically
(`--no-use` to opt out), so `hush add .env --as Dev` followed by `hush npm
run dev` just works.

```
$ hush ls

YOUR LIBRARY  (global)
  ● Acme Production (acme-production)  12 key(s)
      Live Stripe + Convex
      when: deploys only
    Personal fal (personal-fal)  1 key(s)

THIS PROJECT
  ● default (default)  2 key(s)

  ● = used by this project.
```

`hush ls <set>` lists one set's key names — never values.

**Everything already in one pile?** That is where everyone starts. Make the
sets you want and move keys across — the value is re-encrypted under its new
name, so it is a real move rather than a relabelling:

```bash
hush env move STRIPE_SECRET_KEY DATABASE_URL --to "Acme Production"
```

**Renaming works properly.** `hush env rename acme-production "Acme Prod EU"`
re-seals every value under `acme-prod-eu` and updates any project using the old
name. Nothing is left pointing at a name that no longer exists.

Values are cryptographically bound to their set: a `staging` ciphertext cannot
be moved into the `prod` slot, even by someone editing the JSON by hand.

## Coming from another tool

`hush add` reads a `.env`. For everything else there is `hush import`, which
reads what your current tool already exports — no accounts, no API tokens, no
vendor SDK:

```bash
# Doppler
doppler secrets download --format json --no-file | hush import - --as "Prod"

# AWS Secrets Manager (the SecretString envelope is unwrapped for you)
aws secretsmanager get-secret-value --secret-id app/prod --query SecretString \
  --output text | hush import - --as "Prod"

# 1Password
op item get "Stripe" --format json | hush import - --format 1password --as "Work"

# any JSON file, checked before anything is stored
hush import secrets.json --format json --as "Prod" --dry-run
```

`--dry-run` lists the names it would write and stores nothing. Nothing prints a
value, in any mode. `--format` is `dotenv` (the default), `json`, or
`1password`; a field whose value is not a string is skipped and counted rather
than stringified into a variable.

## Several keys for one service

The thing you hit every day: a personal key for a service, another for work,
another for a client. Same variable name, different values. Each is a set:

```bash
hush add fal --as "Personal fal" --library    # hush knows fal needs FAL_KEY; asks, hidden
hush add fal --as "Work fal" --library
hush add fal --as "Client fal" --library
```

Use one per project, or one per run:

```bash
hush use work-fal                             # this project, from now on
hush run --use client-fal -- ./build.sh       # this run only — layered last, so it wins
```

**Unknown service?** Tell it the variables once:

```bash
hush add myapi --as "Staging myapi" --vars MYAPI_KEY,MYAPI_SECRET
```

**From a script or CI**, pipe one line per variable, in the order hush asks:

```bash
printf '%s\n' "$FAL_KEY" | hush add fal --as "CI fal"
printf '%s\n%s\n' "$SID" "$TOKEN" | hush add twilio --as "Main twilio"
```

If nothing arrives on stdin, `hush add` fails rather than reporting success — a
run that stored no credential must not look like one that did.

## Running things

```bash
hush npm run dev              # anything after hush that is not a hush command
hush bun dev                  #   runs with this project's sets injected
hush python app.py
hush ./deploy.sh

hush dev                      # find package.json, run its dev script with the
hush dev build                #   package manager the lockfile names (bun/pnpm/yarn/npm)

hush run --use prod -- ./deploy.sh    # the explicit form; --use adds a set for this run
```

Output is redacted: an injected value that shows up in stdout or stderr comes
out as `[redacted:KEY]`. A hush command always wins over a same-named program,
so `hush ls` is hush's `ls`, never `/bin/ls`.

## Credentials that are a file

Some tools do not read a secret from the environment at all. They read a
*path*: `GOOGLE_APPLICATION_CREDENTIALS`, `KUBECONFIG`, a `.p12` keystore, a
client certificate. `hush export` is the wrong answer to that — it writes every
value in the vault to disk and leaves it there.

`--materialize` writes the one file that was asked for, hands the child the
path, and removes it afterwards:

```bash
hush run --materialize GOOGLE_APPLICATION_CREDENTIALS -- node app.js
hush run --materialize KUBECONFIG=/tmp/kube.config -- kubectl get pods
```

With no `=` hush chooses a private path (a `0700` directory, removed with the
file). With a path, that path is used exactly. Either way the file is `0600`,
created with `wx` so an existing file or a planted symlink is a refusal rather
than a write through it, and removed even when the command fails. The value
stays masked in the child's output: reading the file back does not print it.

Because this writes plaintext somewhere the caller chose, it is gated on
**`reveal`**, not on `run` — it is the same class of act as `hush get`. There is
no MCP tool for it, and there never will be: an agent that can materialise a
value to a path and read that path has read the value.

## The app

Don't want to type commands? Don't.

```bash
hush ui
```

A local app in your browser: add keys, name and describe sets, choose which
ones a project uses, manage the team. It binds to `127.0.0.1` only, needs a
one-time token in the URL, refuses non-loopback `Host` headers, and sends the
browser **masked previews** — never the real values, unless you click *reveal*
(which is written to the audit log).

**Dropping in a `.env`.** Drag one or more files onto it. Nothing is saved yet —
you name the set first, and get a review table:

```
Save all of this as one named set
  [ Acme Production            ] [ what is it for? (optional)     ]
  [ in my library — every project can use it  ▾ ]  [ Save as a named set ]

Review 4 variable(s)                          [ move all to… ▾ ]

.ENV.PRODUCTION
 ☑ FAL_KEY            fal…le (25 chars)   already in personal-fal   [personal-fal ▾]
 ☑ STRIPE_SECRET_KEY  sk_…op (24 chars)   stripe                    [default ▾]
 ☑ DATABASE_URL       pos…db (23 chars)   postgres                  [prod ▾]
 ☑ PEM_KEY            ---…-- · multi-line                           [default ▾]
   skipped "bad name" — not a usable variable name

 [Import 4 secret(s)]  ☐ overwrite keys that already exist        [Discard]
```

Keys that already exist are flagged and skipped unless you tick overwrite.
Multi-line values (PEM keys) survive intact. **Values never come back to the
browser** — staging returns names, masked previews and suggestions only; the
plaintext stays server-side until you import.

---

# Agents

```bash
hush install-mcp
```

It looks for the coding agents on this machine and registers hush with each one
it finds, in the file that agent actually reads: **Codex**
(`~/.codex/config.toml`), **Claude Code** (`.mcp.json`), **Cursor**
(`.cursor/mcp.json`). It never rewrites an entry you already have, and when it
cannot write one it prints the line to paste instead of a tick that means
nothing.

If hush cannot see your agent (a fresh machine, an unusual setup):

```bash
hush install-mcp --for codex        # or: claude-code, cursor
```

An existing entry is left alone; to point it at a different hush, edit that
file yourself.

## What your agent gets

| Tool | What the agent can do |
|---|---|
| `hush_list_secrets` | See which secrets **exist**. Names only. |
| `hush_list_sets` | See which named sets exist — library and project, and whether this project uses each. (`hush_list_accounts` is a deprecated alias for this.) |
| `hush_describe_secret` | Confirm one is set — length, masked preview, who set it. |
| `hush_check_repo` | Scan the code, report which env vars are missing from the vault. |
| `hush_provision` | Prepare a CLI to run with the right set. |
| `hush_add_secret` | **Have you type a new key on your screen**, never in the chat. |
| `hush_run` | **Run a command with secrets injected.** Sees output, not values. |
| `hush_request` | **Make an authenticated API call.** The secret goes in on the wire; the response comes back masked. |

There is no `hush_get_secret`, and no flag that adds one. That is the whole
design.

```
Agent: hush_run { command: "node", args: ["-e", "…connect to DB…"] }
  →  exit 0 · injected 3 secret(s) · 1 value(s) masked in output
     connecting to db.internal
     oops here is the key: [redacted:STRIPE_SECRET_KEY]
```

The agent got its answer. The credential never entered the transcript.

### Calling an API that has no CLI

`hush_run` covers a program that already knows how to authenticate itself —
`vercel`, `gh`, `psql`. When there is no such program and something just needs
to hit an endpoint, `curl` is the wrong answer twice over: it is denied by
default, and a shell holding the value can post it anywhere redaction cannot
follow.

`hush request` makes the call itself. The value goes from the vault into a
header *inside the hush process* and onto the wire; you and your agent only see
the response, with any reflected value masked:

```bash
hush request POST https://api.stripe.com/v1/refunds \
  --header 'Authorization: Bearer $STRIPE_KEY' \
  --data '{"charge": "ch_123"}'
```

`--header` is repeatable, `--data` takes a literal, `@file`, or `@-` for stdin,
and `--include` adds the status line and response headers. Secrets are
substituted into **header values only** unless you name another surface with
`--substitute body` or `--substitute query`. https is required — loopback is
excepted so a local dev server works — redirects to a *different* host are
refused rather than followed, and the response is capped and redacted before
anything is printed. For an agent this is the `hush_request` tool, with the same
rules and the same approval prompt.

## Adding a key without pasting it into the chat

This is the flow that matters. You tell your agent *"set up the deploy script
with my personal fal key"*. It calls `hush_provision`, finds no set that holds
one yet, and calls `hush_add_secret`. A **secure input box opens on your
screen**:

```
┌─ hush — add a secret ──────────────────────────┐
│  needed to authenticate the deploy script      │
│                                                │
│  Service:  fal.ai                              │
│  Set:  personal-fal                            │
│                                                │
│  Paste the value for FAL_KEY:                  │
│  [••••••••••••••••••••••••]                    │
│                        [Cancel]  [Save]        │
└────────────────────────────────────────────────┘
```

You paste it there. It is encrypted straight into the vault. The agent gets back
`Stored FAL_KEY in "personal-fal" (this project). The value never entered this conversation.`

The key went from your keyboard to the vault. It was never in a prompt, never in
a transcript, never in a provider log.

## Approving what runs

Anything that injects a live credential asks first:

```
┌─ hush — approve this? ─────────────────────────┐
│  Run:  ./deploy.sh --target production         │
│                                                │
│  Using sets:  default, personal-fal            │
│  Injects:  FAL_KEY                             │
│  Directory:  /Users/you/myapp                  │
│                                                │
│  Approval code: 7431                           │
│      [Deny]  [Allow once]  [Allow 15 min]      │
└────────────────────────────────────────────────┘
```

The code also comes back in the agent's tool result, so the transcript and your
screen can be checked against each other. "Allow 15 min" is scoped to *that
command and that list of sets*, and it lasts for as long as the thing that asked
is running — a long agent session keeps the window, a fresh `hush` command asks
again. Nothing about an approval is stored in your project: a file the agent
could write is not an approval, so there is no such file.

The prompt does not disappear on you. Clicking outside it cannot dismiss it or
answer it, and if it ends up behind another window it comes back to the front
every 45 seconds with the same request and the same code, until you answer or
the wait runs out (two minutes by default). It also says how long is left, so a
prompt that lapses on its own is never a surprise. Nothing is allowed if it
lapses: you get a refusal, not a quiet yes.

```json
{
  "requireApproval": ["run", "add", "reveal", "request"],
  "approvalTtlSeconds": 900,
  "approvalTimeoutSeconds": 120
}
```

Set `"requireApproval": []` to turn it off. On a Linux desktop the dialog is
`zenity` or `kdialog`, whichever is installed. With no desktop at all — a
server, CI — there is nothing to put the request in front of you, so an
approval-gated action is refused rather than waved through; set `biometry` to
`"required"` on a machine with a fingerprint reader, or leave the gated
actions out of that machine's policy.

## What the agent may run

```bash
hush install-skill            # this project
hush install-skill --global   # every project
```

Installs a skill telling your agent never to ask for a pasted key, to use
`hush_run` rather than reading values, and how to pick a set when you name
one. It goes where each agent looks for instructions: Codex reads
`.agents/skills/hush/SKILL.md` (and `~/.agents/skills/…` for `--global`),
Claude Code reads `.claude/skills/hush/SKILL.md`, and Cursor gets a rule at
`.cursor/rules/hush.mdc`. Without it the tools still work — the tool
descriptions explain themselves — you just have to say so each time.

`.hush/policy.json` controls what it may run — through the MCP tools *and*
through the CLI, so an agent that shells out to `hush run` or `hush export`
meets the same policy and the same approval prompt. Anything that exists to dump
or re-encode the environment is denied by default — shells, `env`, `base64`,
`curl`, and every interpreter, because `node -e` can write the whole environment
to a file that output redaction never sees:

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
  `reveal`, and `request`. `--materialize` is gated by `reveal`, not `run`,
  because it writes plaintext to a path the caller chose.
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
is your floor: a repo's policy can only *tighten* relative to it. `allowCommands`,
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

## What a value should look like

The most common failure is not a leak, it is a wrong value: the test key in the
production set, a truncated paste, a key whose prefix the SDK checks before it
will talk to the API. A `.env.schema` declares the shape, in the same
`@env-spec` syntax Varlock reads, so a schema you already have works here
unchanged:

```bash
# @required @type=url
API_URL=

# @type=string(startsWith=sk-) @required
STRIPE_SECRET_KEY=

# @type=enum(development, preview, production) @sensitive=false
APP_ENV=development

# @type=port
PORT=3000
```

`@sensitive=false` is a *request*, not a permission. It asks for a key to be
printed unmasked (useful for `NODE_ENV` or a `PORT`, which otherwise show as
`[redacted:…]` on every line). Because the schema is a file in the repo, hush
honours it only for keys you have listed in your own floor's `unmaskKeys`; every
other request is ignored and named in a warning on the run. Without that, a
repository could turn output masking off for a credential it can never read.

Supported: `@required`, `@type=` `string`/`number`/`boolean`/`url`/`port`/
`email`/`enum(...)`, `@type=string(startsWith=…, minLength=…, maxLength=…)`,
`@pattern=`, and `@sensitive=false`. The placeholder after `=` is ignored:
hush reads this file for *rules*, and the vault is the only source of values.
`@default` is deliberately not implemented, because an injected default would
make "the vault is the source of truth" quietly false.

`hush run` and `hush request` check the keys they are about to use and refuse
before anything is spawned or sent (`--no-validate` overrides; an agent cannot).
Only the keys in play are checked, so a production rule cannot block a dev
command that never touches it. `hush doctor` reports everything. A failure
names the key, the rule, and the length — never the value.

`@sensitive=false` means "do not mask this in output", which is what the mask is
for: `NODE_ENV=production` arriving as `[redacted:NODE_ENV]` on every line is
how people learn to ignore it. The value is still encrypted at rest.

## Finding what a codebase needs

`hush scan` reads your source — `process.env.X`, `os.environ["X"]`,
`os.Getenv("X")`, `std::env::var("X")`, `.env.example`, and a dozen more across
JS/TS, Python, Go, Rust, Ruby, Java, PHP, C# — and reconciles it against the
vault:

```
$ hush scan

  ✓ 12 satisfied by the vault
  ✗ 1 missing

Missing:
  SENDGRID_API_KEY  src/mail.ts, src/jobs/digest.ts

  add them:  hush add SENDGRID_API_KEY
```

Nobody has to maintain a manifest. The code is the manifest.

---

# Your team

## Adding a teammate

They run `hush id --create` and send you one line:

```
hush_pk_1xMUlHhmUKj0O_oRPgusa3rYileLjwFcLdSLS2H8KhY
```

You run:

```bash
hush team add sam hush_pk_1xMUlHhmUKj0O_oRPgusa3rYileLjwFcLdSLS2H8KhY
git commit -am "add sam"
```

That is onboarding. They `git pull` and `hush run` works. No account, no invite,
no server, nothing pasted into chat.

## Removing someone

```bash
hush team rm sam
```

That mints a **new data key**, re-encrypts every value under it, and re-wraps it
for everyone except Sam. Sam's old checkout of the repo decrypts nothing new.

> hush tells you the honest part too: Sam can still use any value he already
> read. Rotate those at the provider. No tool can undo a value someone saw.

## CI

```bash
# store the private key as a CI secret
HUSH_IDENTITY=$HUSH_CI_KEY hush run -- npm test
```

Give CI its own identity (`hush id --create` on a throwaway machine, then
`hush team add ci <pk>`) so you can revoke it independently.

---

# Hardening

## The security ladder

hush works at every rung, including the bottom one. That is deliberate: a tool
that refuses to run until you buy a YubiKey gets uninstalled, and the person goes
back to a plaintext `.env`. So it never blocks — it shows you where you are and
makes the next rung one command.

```
$ hush level

  ●●●○○  rung 3 of 5 — approved use

  ✓ secrets are encrypted at rest
  ✓ no plaintext .env left in the project
  ✓ your key is in the OS keychain, not a loose file
  ✓ using a credential needs your approval
  ○ approval needs your fingerprint, not a click
  ○ your key cannot be copied off this machine

  This vault holds:
    · 3 high-value secrets (AWS_SECRET_ACCESS_KEY, DATABASE_URL, STRIPE_SECRET_KEY)
    · 4 people can decrypt this vault

  Next → approval needs your fingerprint, not a click
    a click can be made by anything at your unlocked laptop; a fingerprint cannot
    hush secure --biometry
```

`hush secure` performs the next step rather than describing it: migrates your key
into the keychain, imports and deletes a stray `.env`, turns on approval, enables
Touch ID, or walks you onto a hardware key.

- **The rung is a strict checklist.** Passing a later check does not lift you
  past an earlier gap — you cannot claim "biometric" while a plaintext `.env`
  sits in the repo.
- **Nudges are risk-weighted and rate-limited.** hush judges what the vault holds
  from key *names* only, never by decrypting. A vault of feature flags gets a
  quiet hint once a week; three live payment keys shared with four people gets a
  louder one once a day. `HUSH_NO_NUDGE=1` or `hush secure --snooze 30` silences
  it.
- **It will not let you fool yourself.** `hush secure --hardware` refuses to
  count a *software* age key as hardware, because it would not change what an
  attacker running as you can do.

## Touch ID

```bash
hush biometry setup
```

Then set `"biometry": "required"` in `.hush/policy.json` and the approval step
becomes a fingerprint instead of a click. `"required"` refuses to proceed if
biometry is unavailable — it will not silently downgrade.

Be clear-eyed about what this is: it proves a human is physically at the machine,
so your agent cannot approve its own request and nobody can use your keys from
your unlocked laptop. It does **not** protect the key at rest — that needs a
non-extractable Secure Enclave key, which macOS only permits to a binary signed
with an Apple Developer ID.

## Hardware keys

For a key that is genuinely unreadable rather than merely gated, hush bridges to
[age](https://age-encryption.org). It does not implement age's plugin protocol —
it shells out to `age`, which drives whichever plugin owns the recipient. So
hush contains **zero hardware integrations** and supports all of them:

```bash
brew install age age-plugin-yubikey     # or age-plugin-se, age-plugin-tpm
hush age                                # check the bridge
hush team add ana age1yubikey1q2w3e…    # a hardware-backed teammate
```

A vault mixes both kinds of member freely:

```
acme  DEK generation 2
  ana   member  age18lf9g367pxtth0c0…  age  ✓
  sam   admin   hush_pk_1xMUlHhmUKj0…  key  ✓
```

Unwrapping the vault key then requires touching the YubiKey, or a fingerprint
for the Secure Enclave — enforced by the hardware, not by a prompt. `age` is
optional; you only need it if you want this.

[docs/BIOMETRY.md](./docs/BIOMETRY.md) has the full tiering and the exact reason
a first-party Secure Enclave implementation is not worth building.

## The shell hook

`hush hook zsh` (or `bash` / `fish`) prints a directory hook that loads secrets
on `cd` and **unsets them again when you leave**. Without that unload you carry
production credentials into every unrelated process you start afterwards, which
is worse than not using hush at all.

It is still the least safe way to use hush: anything launched from that shell —
your coding agent included — inherits the secrets. `hush run` is the safe form,
and the hook prints that warning every time.

---

# Reference

## Commands

```

daily
  hush add <file>                          save a .env-shaped file as a named set
  hush add KEY=value [KEY=value…]          save one or more values directly
  hush add <service>                       e.g. hush add fal — prompted, hidden input
  hush use <set> [<set>…]                  this project uses these sets, in order (later wins)
  hush use                                 show what this project uses, and where from
  hush use --not <set>                     stop using it here
  hush run [--use <set>…] -- <cmd>         run with them injected, output redacted
  (pass-through: npm run dev, python app.py, … run the same way)
  hush dev [script]                        find package.json, run it with them injected
  hush ls [<set>]                          library, project, what is used — or one set's keys
  hush rm <KEY> [--from <set>]             remove a key
  hush rm <set> [--yes]                    remove a whole set
  hush ui                                  open the local app to manage everything
  hush team ls|add|rm                      share this project's vault

sets          — a set you name, describe and reuse
  hush env rename <name> <new name>    re-seals every value under the new name
  hush env describe <name> [--description <t>] [--when <t>]
  hush env move <KEY>… --to <set>      carve one big pile into named sets
  hush global [<vault>|--create]       which vault holds your library

sharing
  hush team ls
  hush team add <name> <pk>     re-wraps the key for them; commit and they're in
  hush team rm <name>           removes them and re-encrypts everything
  hush id [--create]            show or create this machine's key
  hush link <vault> [--env e]   point this repo at a vault you already have

hardening
  hush level                    where you are on the security ladder
  hush secure                   climb the next rung
  hush biometry [setup|test]    gate approvals behind Touch ID
  hush age                      use a YubiKey / Secure Enclave / TPM via age
  hush verify                   check the vault decrypts and has not been rolled back
  hush rotate                   new vault key, same values

agents
  hush install-mcp              register hush with your coding agent
  hush install-skill            teach the agent the rules (--global for all projects)

other
  hush init [name]               create a vault here (.hush/vault.json — commit it)
  hush doctor                    check this machine's setup
  hush hook <zsh|bash|fish>      auto-load on cd (least safe; unloads on leave)
  hush export [--out .env]       write plaintext out (last resort)
  hush get <KEY>                 reveal one value (asks first)
  hush scan [dir]                what does this codebase need, and is it in the vault?
  hush root                      the project root hush would act on

flags
  --use <set>     an extra set for this run only (repeatable; --env is an alias)
  --json          machine-readable output where it makes sense

Deprecated, still work — each prints a one-line notice: hush set,
hush accounts, hush env ls / env / env use / env drop / env new, --with a:b, use a=b.

Vault files hold only ciphertext and public keys. Your private key never leaves this machine.
```

## How the crypto works

```
                        ┌─ wrapped for ana ────┐
  DEK (random 32B) ─────┼─ wrapped for sam ────┼──► .hush/vault.json
        │               └─ wrapped for ci ─────┘      (commit this)
        │
        └─► AES-256-GCM per value, AAD = "hush/v1|<env>|<KEY>"
```

- **Per-value:** AES-256-GCM under the vault's data key. The AAD binds the
  ciphertext to its `env|KEY` slot, so values cannot be swapped between slots.
- **Per-recipient:** the DEK is wrapped once per member — ephemeral X25519 →
  ECDH → HKDF-SHA256 → AES-256-GCM. This is the age/ECIES construction.
- **Adding a member** re-wraps the existing DEK. Nothing is re-encrypted.
- **Removing a member** mints a new DEK generation and re-seals every value.
- **Your private key** lives in the macOS Keychain, or `~/.hush/identity` at
  mode 0600. It is never in a vault file, never in a repo, and is stripped from
  the environment of anything `hush run` launches.

The vault file holds ciphertext, public keys, and metadata. That is all:

```json
{
  "scheme": "hush/v1",
  "dek": { "generation": 2, "wraps": { "a1b2…": { "epk": "…", "ct": "…" } } },
  "recipients": { "a1b2…": { "name": "ana", "pk": "hush_pk_…", "role": "admin" } },
  "envs": {
    "default": {
      "DATABASE_URL": { "iv": "…", "ct": "…", "tag": "…", "gen": 2,
                        "updatedBy": "ana", "updatedAt": "2026-01-01T00:00:00Z" }
    }
  }
}
```

## What hush does not do

**Read [SECURITY.md](./SECURITY.md) before trusting it with anything real**, and
[docs/SAFETY.md](./docs/SAFETY.md) for which of it matters in *your* situation —
alone, with an agent, or as a team. The most important line in both: with a *software* identity, anything running as your
user can invoke hush and read the vault — including a shell command from an
agent. The policy gates hush's own tools and CLI; it cannot gate a process that
goes around hush, and `policy.json` is a file in your repo that an agent with
write access can loosen. Use a hardware identity if that matters to you.

- It is **not a KMS** — no dynamic credentials, no leasing, no expiry.
- It **cannot rotate your provider credentials**. `hush team rm` re-keys the
  vault; only Stripe can rotate a Stripe key.
- **Git history is forever.** A deleted secret is still in history as ciphertext.
- **Redaction is defence in depth, not a boundary.** It masks known values in
  output; a program that base64-encodes a secret before printing defeats it.
  That is what the command policy is for.
- **Revocation protects future values only.** Anyone who could read a secret has
  read it.

---

# Contributing

## Development

No build step and nothing to install — Node 22.6+ runs the TypeScript directly.

```bash
git clone https://github.com/omarei-omoto/hush.git
cd hush
npm install            # devDependencies only: typescript and @types/node
npm test
npm run typecheck
npm link               # use your working copy as the real `hush`
```

Some tests need extra things and skip cleanly without them: `age` on your PATH
turns on the hardware-key path (driven through a real
[C2SP age plugin](https://github.com/C2SP/C2SP/blob/main/age-plugin.md)), and
macOS turns on Touch ID, the Keychain and the native approval dialogs.

Testing is weighted toward the security properties rather than line coverage:
that associated data binds a value to its slot, that per-recipient wrapping makes
revocation real, that the redactor does not split a match across a chunk
boundary, and that no MCP tool can be made to hand back a value. The bar for a
change is a test that fails without it — see [CONTRIBUTING.md](./CONTRIBUTING.md),
which explains why that is stated so bluntly.

```bash
HUSH_FUZZ_SCALE=40 node --test test/fuzz.test.ts   # the same search, 40x deeper
```

## Contributing

Very welcome, especially: running it somewhere I cannot (Linux, Windows, a
YubiKey I do not own), finding a way to get a value out that should not come
out, or telling me where it confused you.

- [CONTRIBUTING.md](./CONTRIBUTING.md) — how to set up, and the bar for a change
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) — Contributor Covenant 2.1
- [SECURITY.md](./SECURITY.md) — threat model, and how to report a vulnerability
- [docs/AUDIT.md](./docs/AUDIT.md) — every defect found so far, and what changed

**Security problems do not go in issues.** Open a [private
advisory](https://github.com/omarei-omoto/hush/security/advisories/new) instead.

## License

MIT — see [LICENSE](./LICENSE).
