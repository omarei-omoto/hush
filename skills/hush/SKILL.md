---
name: hush
description: Use for any task involving API keys, credentials, .env files, or tokens — running a CLI that needs auth (stripe, gh, vercel, fal, supabase, aws, psql), setting up a service, choosing between several accounts for one service ("use my acme fal key"), adding a new key, or diagnosing missing environment variables. Keys stay encrypted and never enter the conversation.
---

# hush — using credentials without ever seeing them

This project keeps its credentials in a hush vault. You can find out what exists
and you can **use** any of it, but you cannot read a value — that is deliberate,
and there is no flag that changes it.

## If the project is not set up yet

Run `hush doctor`, or just try the task: if hush answers "this folder isn't set
up", stop and tell the user to run **`hush start`**. It is a short guided
conversation that finds their keys, gets them in and asks the one question about
whether you will be near them. Do not try to set a project up on their behalf:
the questions are theirs to answer, and the keys belong in their hands.

Once they say it is done, `hush_list_sets` will show what arrived.

## The one rule

**Never ask the user to paste a credential into the chat.** If you need one that
isn't in the vault, call `hush_add_secret`. A secure input box opens on their
screen, they paste it there, and it is encrypted straight into the vault. You get
back a confirmation and nothing else.

If you catch yourself typing "please paste your API key" — stop, and call
`hush_add_secret` instead.

## Sets

Everything hush stores lives in a named **set**: a name, optionally a label and
a description, and some keys. One service can have several — a personal fal
key, a work one, a client's — each its own set ("Personal fal", "Work fal").
When the user names one ("use my client fal key", "the work-fal account"), that
is a set name.

1. `hush_list_sets` — see what exists, in the user's own library and in this
   project's vault, and which of them this project already uses.
2. Pass the one they meant to `hush_run` as `sets: ["work-fal"]`.

If they don't name one, this project's usual sets are used — the project's
own `default` plus whatever it links. The user's library is a catalog: nothing
in it applies here until it is added (`hush use <set>`, or
`hush use default --library` for their catch-all set). Don't ask which set unless there are several and no
obvious default.

## Running something that needs credentials

Always `hush_run`. Never construct an env var yourself, never read `.env`, never
suggest `export FAL_KEY=...`.

```
hush_run { command: "npx", args: ["vercel", "deploy", "--prod"],
           sets: ["work-vercel"] }
```

The command receives real credentials. You receive its output with every secret
value masked as `[redacted:NAME]`. If you see `[redacted:...]` in output, that is
working correctly — do not try to recover the value or work around it.

**The user gets an approval dialog** naming the command, the sets and the
variables, with a 4-digit code. The tool result tells you the code and the
decision. If it comes back denied or timed out, tell the user plainly and stop —
do not retry in a loop or look for another route to the same credential.

## Calling an API directly

`hush_run` needs a program that already knows how to authenticate itself. When
there is no such program and something just needs to hit an endpoint, use
`hush_request` — never try to assemble the request yourself.

```
hush_request { url: "https://api.stripe.com/v1/refunds",
               method: "POST",
               headers: { "Authorization": "Bearer $STRIPE_KEY" },
               body: "{\"charge\": \"ch_123\"}",
               sets: ["work-stripe"] }
```

Write `$NAME` where the secret belongs. hush substitutes it inside its own
process, so the value never reaches you, a shell, or the transcript, and the
response comes back with any reflected value masked as `[redacted:NAME]`.

- Secrets go into **header values only**, unless you pass `substitute: ["body"]`
  or `["query"]`. Leave that out unless the API genuinely needs it, and never
  put a secret in the URL path — hush refuses it, because paths land in logs.
- https only, and the host must be one the user's policy allows. If you get a
  refusal naming the allowed hosts, tell the user rather than looking for
  another route.
- A non-2xx status is a normal result, not a failed tool call: read it.

## Setting a tool up from scratch

When the user says "set up the fal CLI with my personal set":

1. `hush_provision { tool: "fal", set: "personal-fal" }` — it works out which
   service that tool authenticates with, and checks which of this project's
   sets already provide it.
2. If it reports something missing, `hush_add_secret { service: "fal",
   set: "personal-fal", why: "..." }` — the user fills it in on screen.
3. `hush_run` with that set.

Set `why` to a short, honest sentence. The user reads it in the dialog and it is
the only context they have for deciding.

## Diagnosing a project

- `hush_check_repo` — scans the code for the env vars it references and reports
  which are missing from the vault. Use it before a build or a first run.
- `hush_describe_secret` — confirms one key is set in a given set (length,
  masked preview, who set it) without revealing it. Use it to check
  configuration, not to read.

## What a value should look like

If the project has a `.env.schema`, `hush_run` and `hush_request` check the
values they are about to use and refuse before anything happens. A refusal
names the key, the rule and the length — never the value:

```
hush_run → ".env.schema rejected 1 value(s), so nothing was run:
  STRIPE_SECRET_KEY does not start with "sk-" (it is 24 characters)"
```

There is no override from here, on purpose: a human may overrule their own
schema, an agent should not be able to talk past it. When you see one of these,
the fix is almost always the wrong set — check `hush_list_sets` — or a value
that needs re-entering with `hush_add_secret`. Do not retry the same call.

## Things an agent cannot do, and should not ask for

- **No tool writes a secret to a file.** `hush run --materialize` exists on the
  command line for `GOOGLE_APPLICATION_CREDENTIALS` and friends, and is gated on
  the user's `reveal` approval. If a task seems to need a credential in a file,
  say so: a program that reads credentials from a path is the case for the user
  to run, not for you to arrange.
- **No tool returns a value**, including through the clipboard
  (`hush get --copy` is a human command).

## Tools

| Tool | Use it for |
|---|---|
| `hush_list_sets` | Which named sets exist — library and project — and which this project uses |
| `hush_list_secrets` | Which secret names exist in one set |
| `hush_describe_secret` | Confirm one is set, without reading it |
| `hush_check_repo` | What this codebase needs vs. what's in the vault |
| `hush_provision` | Prepare a CLI to run with the right set |
| `hush_add_secret` | Have the user enter a new key, off-transcript |
| `hush_run` | Actually run something with credentials injected |
| `hush_request` | Make an API call with a secret injected; the response comes back masked |

`hush_list_accounts` still answers — it is a deprecated alias for
`hush_list_sets` that returns exactly the same thing, kept so a skill file
written before sets replaced accounts does not break. Prefer `hush_list_sets`.

There is no tool that returns a secret value. If a task seems to need one, it
needs `hush_run` (for a program that authenticates itself) or `hush_request`
(for an API call) instead.

## Things that will not work, so don't try them

- `hush_run { command: "env" }` or `printenv`, `cat`, `base64`, `sh`, `curl` —
  denied by policy, because they exist to dump or re-encode the environment.
  For an API call this is not a dead end: use `hush_request` instead.
- Reading `.hush/vault.json` — it is ciphertext.
- Asking for a "just this once" plaintext copy — there isn't one.

If the user explicitly asks you to reveal a value, tell them to run `hush get
<KEY>` themselves in their terminal. That is their call to make, not yours.

## CLI, for when you're telling the user what to do

```bash
hush ui                              # manage everything in a local browser app
hush ls                              # every set — library and project — and which are used
hush add fal --as "Work fal"         # a set for a known service, typed in the terminal (work-fal)
hush add .env --as "Dev"             # a .env file as a named set
hush use work-fal                    # this project uses a set by name
hush run --use work-fal -- <cmd>     # one extra set for a single run
hush request POST https://api.x/v1/y --header 'Authorization: Bearer $X_KEY'
hush dev                             # run the package.json dev script with the sets injected
hush npm run build                   # any command after hush runs the same way
```
