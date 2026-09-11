# Landscape: what already exists, and what doesn't

Surveyed before writing any code. The short version: **every
individual piece of this exists. The combination does not.**

## What is already out there

| Tool | What it actually is | Team sharing | Agent-safe | Server needed |
|---|---|---|---|---|
| **direnv** | Auto-loads `.envrc` on `cd`. Plaintext on disk. | ✗ | ✗ (exports to every child process) | ✗ |
| **mise** | Dev-tool/runtime version manager that also does env vars. | ✗ | ✗ | ✗ |
| **nevr-env** | TS-first schema validation (Zod/Valibot) + a git-committable AES-256-GCM vault. | ⚠️ **one shared passphrase** | ✗ | ✗ |
| **Varlock** | `.env.schema` DSL, type-safety, leak scanning, log redaction. Explicitly "AI-safe". | n/a — **stores nothing** | ✓ (schema not values) | depends on backend |
| **SOPS + age** | Encrypts values inside YAML/JSON/env files. Per-recipient public keys. | ✓ **real** | ✗ | ✗ |
| **Doppler** | Hosted secrets platform, `doppler run` injection. | ✓ | ✗ | ✓ SaaS |
| **Infisical** | Open-source, self-hostable Doppler. ~12.7k stars. | ✓ | ✗ | ✓ server |
| **Vault / OpenBao** | Enterprise dynamic secrets. | ✓ | ✗ | ✓ cluster |
| **dotenvx** | Encrypted `.env` committed to git; public key in the file. | ⚠️ **one shared private key** | ✗ | ✗ |
| **secretctl** | Go, single binary, MCP server, injects into commands, sanitizes output. | ✗ **explicitly none** | ✓ **yes** | ✗ |
| **1Password MCP** | Agent uses secrets without seeing them. | ✓ | ✓ | ✓ subscription, closed |

## The two clusters, and the canyon between them

Read that table and the field splits cleanly in half.

**Cluster A — good team crypto, no idea agents exist.** SOPS/age is the gold
standard: per-recipient X25519 keys, add and remove members by re-wrapping, no
server, your git repo is the transport. But the DX is rough (YAML-centric,
manual key juggling, no discovery), and nothing in it knows what an AI coding
agent is.

**Cluster B — good agent story, no team story.** `secretctl` is the closest
thing to this and it is genuinely good: single binary, MCP server,
injects credentials into commands so the model sees results and never values.
Its README is unambiguous that this is single-user by design — *"No cloud sync,
no third-party servers"*. Sharing means exporting a plaintext `.env` and sending
it to your teammate, which is the problem you were trying to leave behind.

**The middle is empty.** Nobody has shipped per-member asymmetric crypto with
real revocation *and* an agent-blind access layer *and* zero infrastructure.

## Where the "team" tools actually fail

The git-committed-vault tools (dotenvx, nevr-env) look like they solve team
sharing, but they share **one symmetric key or one private key** across the
whole team. That has three consequences:

1. **No revocation.** Removing someone means rotating the key and telling
   everyone else out-of-band. In practice nobody does it.
2. **No attribution.** The vault cannot tell you who added a value, because
   everyone is the same key.
3. **The key travels.** Slack, 1Password notes, a CI variable — the shared key
   ends up in exactly the places the secrets were not supposed to be.

age solved this a decade ago with per-recipient key wrapping. The dotenv-shaped
tools didn't adopt it, and the SaaS platforms solved it by selling you a server.

## Why the agent angle is not a gimmick

This got materially worse in the last two years, and it is well documented:

- Secrets in `.env` become part of the prompt, and land in provider and gateway
  logs in plaintext. A researcher caught xAI's Grok Build agent uploading whole
  repos with `.env` API keys and DB passwords **verbatim and unredacted**.
- Coding agents auto-approve reads. A prompt injection that says "read `.env`"
  gets fake AWS, Stripe and DB credentials back with no approval prompt —
  because reading a file is a read-only tool.
- ~48% of surveyed MCP servers tell you to put credentials in a plaintext `.env`
  or JSON config.

So `.env` is now not just bad hygiene. It is an **exfiltration surface with a
network connection attached**.

## The gap, stated as one sentence

> **age's security model, Doppler's ergonomics, an agent that can use a secret
> without ever being able to read it — and no server anywhere.**

That is what `hush` is.

## What hush deliberately does not do

Being honest about the boundaries is part of the pitch:

- **It is not a KMS.** No dynamic credentials, no leasing, no auto-expiry.
- **It does not rotate provider credentials.** Removing a teammate re-keys the
  vault; it cannot rotate your Stripe key. The CLI says so, out loud, every time.
- **Git history is forever.** A value committed and later deleted is still in
  the history as ciphertext. If the vault key ever leaks, so does the history.
- **Redaction is defence in depth, not a boundary.** It matches known values in
  output. A program that base64-encodes a secret before printing defeats it —
  which is exactly why the MCP command policy exists as the real control.
- **A teammate who could read a secret has read it.** No cryptography takes that
  back. Revocation protects future values.

## Sources

- [Varlock — AI-safe .env files](https://varlock.dev/) · [github](https://github.com/dmno-dev/varlock) · [secrets guide](https://varlock.dev/guides/secrets/)
- [nevr-env](https://github.com/nevr-ts/nevr-env) · [author's writeup](https://dev.to/yalelet_dessalegn_b87ed18/why-i-built-nevr-env-and-why-processenv-deserves-better-4iod)
- [secretctl](https://github.com/forest6511/secretctl) · [MCP listing](https://mcpservers.org/servers/forest6511/secretctl)
- [dotenvx](https://github.com/dotenvx/dotenvx) · [private keys](https://dotenvx.com/docs/learn/encrypting/private-keys) · [encryption](https://dotenvx.com/docs/quickstart/encryption/)
- [Infisical — open source secrets management 2026](https://infisical.com/blog/open-source-secrets-management-devops)
- [GitGuardian — top secrets management tools](https://blog.gitguardian.com/top-secrets-management-tools/)
- [Sonar — your secrets are leaking to AI coding agents](https://www.sonarsource.com/blog/your-secrets-are-leaking-to-ai-coding-agents/)
- [Knostic — mishandling of secrets by coding agents](https://www.knostic.ai/blog/claude-cursor-env-file-secret-leakage)
- [LLM-Redactor](https://github.com/WangYihang/llm-redactor) · [Defenter proxy](https://github.com/Defenter-AI/defenter-proxy)
- [Doppler — MCP servers and secrets management risk](https://www.doppler.com/blog/mcp-server-secure-secrets-management)
- [1Password — secure AI access](https://www.1password.dev/get-started/secure-ai-access)
