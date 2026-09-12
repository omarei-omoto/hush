# hush

**Envelope-encrypted team secrets your AI agent can use but never read.**

[![CI](https://github.com/omarei-omoto/hush/actions/workflows/ci.yml/badge.svg)](https://github.com/omarei-omoto/hush/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@omarei/hush.svg)](https://www.npmjs.com/package/@omarei/hush)
[![node](https://img.shields.io/node/v/@omarei/hush.svg)](https://nodejs.org)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![runtime deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen.svg)](./package.json)

No server. No SaaS. No shared password. Your git repo is the backend, and your
coding agent gets to run `stripe migrate` without `sk_live_…` ever entering its
context window.

```bash
hush init acme                  # a vault in .hush/vault.json — commit it
hush import .env && rm .env     # your existing secrets, now encrypted
hush run -- npm run dev         # injected into the process, never onto disk
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
> Development happens on macOS. Linux is covered by CI; Windows is not yet.
> [Tell me what broke](https://github.com/omarei-omoto/hush/issues) if you try it
> somewhere unusual.
>
> Found a way to read a vault you should not? Please [report it
> privately](https://github.com/omarei-omoto/hush/security/advisories/new)
> rather than opening an issue.

## Contents

- [Install](#install) · [Quick start](#quick-start) · [Why this exists](#why-this-exists)
- **Using it** — [Named env sets](#named-env-sets) · [Several accounts for one service](#several-accounts-for-one-service) · [Environments](#environments) · [The app](#the-app)
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
hush init                    # creates your key + a vault, safe to commit
hush import .env             # pull in what you already have
rm .env                      # you don't need it any more
git add .hush && git commit -m "encrypted secrets"
```

From now on, instead of `npm run dev`:

```bash
hush run -- npm run dev
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

## Named env sets

A `.env` is not twenty loose keys. It is *a thing*: "Acme production", "my
personal fal key", "the client's staging box". hush keeps them that way — each
one named, with a description and a note about when to use it, all optional.

They live at two levels:

- **Your library** — `~/.hush/vaults/<name>`. Your own sets, in one place. A key
  lives here once, so rotating it is one edit rather than one per project.
- **This project** — `.hush/vault.json`, committed, shared with your team.

A project *uses* a library set rather than copying it. `.hush/envs.json` names
the set; the keys never enter the repo. So a teammate who clones it does not get
your keys — the repo says "this project needs a set called acme-production" and
each person supplies their own.

```bash
hush global --create                  # make your library (once)
hush global personal                  # or adopt a vault you already have

hush env new "Acme Production" --from .env.production \
  --description "Live Stripe + Convex" --when "deploys only"

hush env use acme-production          # this project uses it
hush run -- npm start                 # its keys are there
```

```
$ hush env

Your library  (personal)
  ● Acme Production (acme-production)  12 key(s)
      Live Stripe + Convex
      when: deploys only
    Personal / fal (personal-fal)  3 key(s)
      my own fal key for side projects

  ● = used by this project.  hush env use <name> / hush env drop <name>

This project
  ● default (default)  2 key(s)
```

**Everything already in one pile?** That is where everyone starts. Make the sets
you want and move keys across — the value is re-encrypted under its new name, so
it is a real move rather than a relabelling:

```bash
hush env new "Acme Production"
hush env move STRIPE_SECRET_KEY DATABASE_URL --to acme-production
```

**Renaming works properly.** The name you type *is* the name: `hush env rename
acme-production "Acme Prod EU"` re-seals every value under `acme-prod-eu` and
updates any project pinned to the old one. Nothing is left pointing at a name
that no longer exists.

## Several accounts for one service

This is the thing you hit every day: a personal key for a service, another for
work, another for a client. Same variable name, different values.

```bash
hush add fal --account personal
hush add fal --account acme
hush add fal --account client
hush add gemini --account team
```

hush knows what the common services need, so it just asks for `FAL_KEY`:

```
$ hush accounts

fal.ai (fal)
  ● acme          FAL_KEY   ← this project's default
    client        FAL_KEY
    personal      FAL_KEY

Google Gemini (gemini)
  ● team          GEMINI_API_KEY   ← this project's default
```

Pick one per run, or pin the project's defaults once:

```bash
hush run --with fal:client -- ./build.sh      # this run only
hush use fal=acme gemini=team                 # the default from now on
hush run -- ./build.sh                        # uses acme + team
```

`.hush/use.json` records only *which account*, never a key — commit it, and your
team runs against the same accounts you do.

**Unknown service?** Tell it the variables once:

```bash
hush add myapi --account staging --vars MYAPI_KEY,MYAPI_SECRET
```

**From a script or CI**, pipe one line per variable, in the order hush asks:

```bash
printf '%s\n' "$FAL_KEY" | hush add fal --account ci
printf '%s\n%s\n' "$SID" "$TOKEN" | hush add twilio --account main
```

If nothing arrives on stdin, `hush add` fails rather than reporting success — a
run that stored no credential must not look like one that did.

## Environments

```bash
hush set DATABASE_URL --env prod
hush run --env prod -- ./deploy.sh
hush envs
```

Values are cryptographically bound to their environment: a staging ciphertext
cannot be moved into the prod slot, even by someone editing the JSON by hand.

## The app

Don't want to type commands? Don't.

```bash
hush ui
```

A local app in your browser: add keys, name and describe env sets, choose which
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
 ☑ FAL_KEY            fal…le (25 chars)   already in fal/personal   [fal/personal ▾]
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

## What your agent gets

| Tool | What the agent can do |
|---|---|
| `hush_list_secrets` | See which secrets **exist**. Names only. |
| `hush_list_accounts` | See which accounts exist per service. |
| `hush_describe_secret` | Confirm one is set — length, masked preview, who set it. |
| `hush_check_repo` | Scan the code, report which env vars are missing from the vault. |
| `hush_provision` | Prepare a CLI to run with the right account. |
| `hush_add_secret` | **Have you type a new key on your screen**, never in the chat. |
| `hush_run` | **Run a command with secrets injected.** Sees output, not values. |

There is no `hush_get_secret`, and no flag that adds one. That is the whole
design.

```
Agent: hush_run { command: "node", args: ["-e", "…connect to DB…"] }
  →  exit 0 · injected 3 secret(s) · 1 value(s) masked in output
     connecting to db.internal
     oops here is the key: [redacted:STRIPE_SECRET_KEY]
```

The agent got its answer. The credential never entered the transcript.

## Adding a key without pasting it into the chat

This is the flow that matters. You tell your agent *"set up the deploy script
with my personal fal account"*. It calls `hush_provision`, finds the account has
no key yet, and calls `hush_add_secret`. A **secure input box opens on your
screen**:

```
┌─ hush — add a secret ──────────────────────────┐
│  needed to authenticate the deploy script      │
│                                                │
│  Service:  fal.ai                              │
│  Account:  personal                            │
│                                                │
│  Paste the value for FAL_KEY:                  │
│  [••••••••••••••••••••••••]                    │
│                        [Cancel]  [Save]        │
└────────────────────────────────────────────────┘
```

You paste it there. It is encrypted straight into the vault. The agent gets back
`Stored FAL_KEY in fal/personal. The value never entered this conversation.`

The key went from your keyboard to the vault. It was never in a prompt, never in
a transcript, never in a provider log.

## Approving what runs

Anything that injects a live credential asks first:

```
┌─ hush — approve this? ─────────────────────────┐
│  Run:  ./deploy.sh --target production         │
│                                                │
│  Using accounts:  fal:personal                 │
│  Injects:  FAL_KEY                             │
│  Directory:  /Users/you/myapp                  │
│                                                │
│  Approval code: 7431                           │
│      [Deny]  [Allow once]  [Allow 15 min]      │
└────────────────────────────────────────────────┘
```

The code also comes back in the agent's tool result, so the transcript and your
screen can be checked against each other. "Allow 15 min" is scoped to *that set
of accounts* — switching to a different client's key asks again, which is the
point.

```json
{
  "requireApproval": ["run", "add", "reveal"],
  "approvalTtlSeconds": 900,
  "approvalTimeoutSeconds": 120
}
```

Set `"requireApproval": []` to turn it off. On Linux and Windows, where there is
no native dialog, requests queue and you answer them with `hush approve` in your
own terminal.

## What the agent may run

```bash
hush install-skill            # this project
hush install-skill --global   # every project
```

Installs a skill telling your agent never to ask for a pasted key, to use
`hush_run` rather than reading values, and how to pick an account when you name
one. Without it the tools still work — you just have to say so each time.

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
  "allowEnvs": ["default", "fal/dev"],
  "denyKeys": ["STRIPE_LIVE_KEY"],
  "maxRunMs": 120000
}
```

- **`denyCommands`** is *added* to the built-in list, never substituted for it —
  an old config cannot hold you below the current floor.
- **`unsafeAllowCommands`** is the only way below that floor. Named to be
  off-putting: allowing `node` or `bash` lets an agent read every injected
  secret and write it anywhere.
- **`allowEnvs`** covers service accounts too, so `["default", "fal/dev"]` keeps
  an agent out of `fal/prod`.
- **`allowCommands`**, if non-empty, is an allowlist — the only command control
  that actually holds. Prefer it for anything sensitive.

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

  add them:  hush set SENDGRID_API_KEY --env default
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
setup
  hush init [name]              create a vault here (.hush/vault.json — commit it)
  hush ui                       open the local app to manage everything
  hush id [--create]            show or create this machine's key
  hush link <vault> [--env e]   point this repo at a vault you already have
  hush install-mcp              register hush with your coding agent
  hush install-skill            teach the agent the rules (--global for all)
  hush approve                  answer a pending approval (non-macOS)
  hush doctor                   check this machine's setup
  hush verify                   check it decrypts, is not rolled back, fully re-sealed
  hush level                    where you are on the security ladder
  hush secure                   climb the next rung

named env sets                  — a .env you name, describe and reuse
  hush env                      list your library and this project's sets
  hush env new <name> [--from <file>] [--description <t>] [--when <t>]
  hush env rename <name> <new name>    re-seals every value under the new name
  hush env describe <name> [--description <t>] [--when <t>]
  hush env move <KEY>… --to <set>      carve one big pile into named sets
  hush env use <name>           this project uses that library set
  hush env drop <name>          stop using it here
  hush global [<vault>|--create]  which vault holds your library

accounts                        — several keys for the same service
  hush add <service> --account <name>    e.g. hush add fal --account acme
  hush accounts [service]                what you have, and for whom
  hush use fal=acme gemini=team          pin this project's defaults
  hush run --with fal:client -- <cmd>    override for a single run

secrets
  hush set <KEY> [--env e]      add or update (prompts, never echoes)
  hush get <KEY>                reveal one value (asks first)
  hush ls [--env e]             list names — never values
  hush rm <KEY>
  hush import [file]            pull in an existing .env
  hush export [--out .env]      write plaintext out (last resort)

using them
  hush run -- <cmd> [args]      run with secrets injected, output redacted
  hush scan [dir]               what does this codebase need, and is it in the vault?
  hush envs                     which environments this vault has
  hush hook <zsh|bash|fish>     auto-load on cd (least safe; unloads on leave)

team
  hush team ls
  hush team add <name> <pk>     re-wraps the key for them; commit and they're in
  hush team rm <name>           removes them and re-encrypts everything
  hush rotate                   new vault key, same values
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

**Read [SECURITY.md](./SECURITY.md) before trusting it with anything real.** The
most important line in it: with a *software* identity, anything running as your
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
