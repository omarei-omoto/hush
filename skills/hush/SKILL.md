---
name: hush
description: Use for any task involving API keys, credentials, .env files, or tokens — running a CLI that needs auth (stripe, gh, vercel, fal, supabase, aws, psql), setting up a service, choosing between several accounts for one service ("use my acme fal key"), adding a new key, or diagnosing missing environment variables. Keys stay encrypted and never enter the conversation.
---

# hush — using credentials without ever seeing them

This project keeps its credentials in a hush vault. You can find out what exists
and you can **use** any of it, but you cannot read a value — that is deliberate,
and there is no flag that changes it.

## The one rule

**Never ask the user to paste a credential into the chat.** If you need one that
isn't in the vault, call `hush_add_secret`. A secure input box opens on their
screen, they paste it there, and it is encrypted straight into the vault. You get
back a confirmation and nothing else.

If you catch yourself typing "please paste your API key" — stop, and call
`hush_add_secret` instead.

## Accounts

One service usually has several accounts: a personal fal key, a company one, a
client's. When the user names one ("use my client fal account", "the team gemini
key"), that is an account name.

1. `hush_list_accounts` — see what exists (`fal → personal, acme, client`).
2. Pass the one they meant to `hush_run` as `accounts: {"fal": "client"}`.

If they don't name an account, the project's pinned default is used. Don't ask
which account unless there are several and no default.

## Running something that needs credentials

Always `hush_run`. Never construct an env var yourself, never read `.env`, never
suggest `export FAL_KEY=...`.

```
hush_run { command: "npx", args: ["vercel", "deploy", "--prod"],
           accounts: { "vercel": "personal" } }
```

The command receives real credentials. You receive its output with every secret
value masked as `[redacted:NAME]`. If you see `[redacted:...]` in output, that is
working correctly — do not try to recover the value or work around it.

**The user gets an approval dialog** naming the command, the accounts and the
variables, with a 4-digit code. The tool result tells you the code and the
decision. If it comes back denied or timed out, tell the user plainly and stop —
do not retry in a loop or look for another route to the same credential.

## Setting a tool up from scratch

When the user says "set up the fal CLI with my personal account":

1. `hush_provision { tool: "fal", account: "personal" }` — it works out which
   service that tool authenticates with, and checks the vault.
2. If it reports something missing, `hush_add_secret { service: "fal",
   account: "personal", why: "..." }` — the user fills it in on screen.
3. `hush_run` with that account.

Set `why` to a short, honest sentence. The user reads it in the dialog and it is
the only context they have for deciding.

## Diagnosing a project

- `hush_check_repo` — scans the code for the env vars it references and reports
  which are missing from the vault. Use it before a build or a first run.
- `hush_describe_secret` — confirms one key is set (length, masked preview, who
  set it) without revealing it. Use it to check configuration, not to read.

## Tools

| Tool | Use it for |
|---|---|
| `hush_list_accounts` | Which accounts exist per service |
| `hush_list_secrets` | Which secret names exist |
| `hush_describe_secret` | Confirm one is set, without reading it |
| `hush_check_repo` | What this codebase needs vs. what's in the vault |
| `hush_provision` | Prepare a CLI to run with the right account |
| `hush_add_secret` | Have the user enter a new key, off-transcript |
| `hush_run` | Actually run something with credentials injected |

There is no tool that returns a secret value. If a task seems to need one, it
needs `hush_run` instead.

## Things that will not work, so don't try them

- `hush_run { command: "env" }` or `printenv`, `cat`, `base64`, `sh`, `curl` —
  denied by policy, because they exist to dump or re-encode the environment.
- Reading `.hush/vault.json` — it is ciphertext.
- Asking for a "just this once" plaintext copy — there isn't one.

If the user explicitly asks you to reveal a value, tell them to run `hush get
<KEY>` themselves in their terminal. That is their call to make, not yours.

## CLI, for when you're telling the user what to do

```bash
hush ui                              # manage everything in a local browser app
hush env                             # their named env sets, library and project
hush env use <name>                  # this project uses a set from their library
hush add fal --account acme          # add an account from the terminal
hush accounts                        # what's stored, and for whom
hush use fal=acme gemini=team        # pin this project's defaults
hush run --with fal:client -- <cmd>  # override for one run
hush doctor                          # check setup
```
