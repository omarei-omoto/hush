# Secrets in saved conversations

Coding agents keep every conversation on disk. Claude Code writes them under
`~/.claude/projects`, Codex under `~/.codex/sessions`, opencode into a SQLite
file. Whatever passed through a conversation is in there: a key pasted into
the chat, the output of `cat .env`, a tool result that printed a token. It was
also sent to the model provider when it happened.

```
$ hush scan --transcripts

transcripts  879 file(s), 24.6 GB — Claude Code, Codex, opencode · 27.0s

  Your hush values, word for word:
    ✗ STRIPE_SECRET_KEY  global · Stripe Live
        3 conversation file(s) · Claude Code, Codex · last 2026-09-28
  Keys from your agents' config files:
    ✗ FIGMA_API_KEY  Cursor config (figma)
        1 conversation file(s) · Codex · last 2026-10-02
  Other strings shaped like a key (hush has never seen these):
    ✗ GitHub  ghp…B6 (40 chars)
        1 conversation file(s) · Codex · last 2026-08-11

  Each of these went to the model provider with the conversation, and is still
  on disk in the files above (--verbose lists them). Replace each key at its provider:
    STRIPE_SECRET_KEY      https://dashboard.stripe.com/apikeys
    GitHub                 https://github.com/settings/tokens

  Nothing was changed: hush only read these files.
```

It looks for three things:

- **Your hush values**: every credential in every vault this machine can
  read (this project's, your library, your other named vaults). It reports
  the variable name and where the value lives, never the value. A setting
  such as `NODE_ENV=production` or a deployment name is not looked for, or
  every conversation would match.
- **Plaintext keys from agents' config files**, the ones
  [`hush scan --agents`](keys-in-your-agents-configs.md) lists.
- **Strings shaped like a provider's key** that hush has never seen: `ghp_…`,
  `sk-ant-…`, `AKIA…` and other real key formats, bounded on both sides so a
  long encoded blob is not mistaken for one. Shown as a masked preview.
  Obvious examples (`ghp_abcdef…`, `sk_live_xxxx…`) are skipped.

A value is also found when it sits inside a JSON string, escaped once or
twice, which is how most transcripts store tool output.

```bash
hush scan --transcripts --since 30d   # only conversations changed in the last 30 days
hush scan --transcripts --verbose     # each file, newest first
hush scan --transcripts --json        # for scripts: names, places, previews, never a hush value
```

## What to do about one

Replace the key at its provider. hush prints the page for every service it
knows. Removing it from the conversation does not undo the leak: the model
provider already received it, and a transcript may have been synced or backed
up.

hush does not edit, redact or delete conversations. Those files belong to the
agents, and changing them should be its own deliberate step.

## Where it looks

Claude Code (`~/.claude/projects`, `history.jsonl`, shell snapshots), Codex
(`~/.codex/sessions`, `history.jsonl`), Gemini CLI (`~/.gemini/tmp`), opencode
(`~/.local/share/opencode`: its database and stored messages, but not its git
snapshots), Continue (`~/.continue/sessions`), Cline (its task folder in VS
Code's storage) and Cursor (its `state.vscdb` databases).

Big histories are read in parallel, and large sessions are split across
threads. About 25 GB takes half a minute on a laptop.
