# What your agent gets

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

## Calling an API that has no CLI

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
