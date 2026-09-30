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

<p align="center"><img src="assets/demo.gif" alt="A .env file goes into a hush vault; what is committed is ciphertext; hush run gives the program the key and prints [redacted:FAL_KEY]" width="820"></p>

> [!IMPORTANT]
> **Status: early.** This works and is heavily tested, but it is pre-1.0, it has
> one author, and **it has not had an external security review**. The crypto is
> a standard construction ([age](https://age-encryption.org)'s, rebuilt on
> `node:crypto`) rather than anything invented here, and there is a
> [differential test suite](./test/scheme-conformance.test.ts) against an
> independent reimplementation — but that is not the same as someone qualified
> having looked at it. [docs/REVIEW-SCOPE.md](docs/REVIEW-SCOPE.md) is the brief
> for the review it needs.
>
> Development happens on macOS; Linux is covered by CI. **Windows is in beta**:
> your key is kept with DPAPI, approvals are a native Windows dialog, `hush run
> npm …` works through `npm.cmd`, secret files get owner-only ACLs, and there is
> a PowerShell hook — a Windows CI job checks those paths, but it has not had
> much real use yet. Fingerprint approval (Windows Hello) is not there yet.
> [Tell me what broke](https://github.com/omarei-omoto/hush/issues) if you try
> it somewhere unusual.
>
> Found a way to read a vault you should not? Please [report it
> privately](https://github.com/omarei-omoto/hush/security/advisories/new)
> rather than opening an issue.

## Install

One file, no Node needed — macOS, Linux (glibc and musl), and Windows (beta):

```bash
curl -fsSL https://raw.githubusercontent.com/omarei-omoto/hush/main/scripts/install.sh | sh
brew install omarei-omoto/tap/hush
```

```powershell
irm https://raw.githubusercontent.com/omarei-omoto/hush/main/scripts/install.ps1 | iex
scoop install https://github.com/omarei-omoto/hush/releases/latest/download/hush.json
```

The installer refuses a binary whose sha256 is not the one in the release's
`SHA256SUMS`, checks its build-provenance attestation too when the GitHub CLI is
signed in, and installs to `~/.local/bin` without sudo. To check a download by
hand: `gh attestation verify hush-darwin-arm64 --repo omarei-omoto/hush`.

Or from npm, with Node ≥ 22.6:

```bash
npm install -g @omarei/hush
```

From a clone there is no build step — Node ≥ 22.18 runs the TypeScript directly
(on 22.6–22.17, run `npm run build` first):

```bash
git clone https://github.com/omarei-omoto/hush.git
cd hush && node src/cli.ts --help
```

<details>
<summary>Why the published package ships compiled output</summary>

Node will not strip TypeScript types for anything under `node_modules`, so an
installed copy cannot run `src/`. The tarball ships JavaScript in `dist/` (built
by `npm run build`, run automatically by `prepack`). The `hush` command decides
by where it lives, not by what exists: under `node_modules` it runs `dist/`; in
a checkout (including one `npm link`ed) it runs `src/`, so a stale build can
never shadow your edits. Still zero runtime dependencies.

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

## Documentation

Everything else is in the guide — on GitHub under [docs/guide](docs/guide/), or
as a site at **[omarei-omoto.github.io/hush](https://omarei-omoto.github.io/hush/)**.

- **Using it** — [Sets](docs/guide/sets.md) · [Coming from another tool](docs/guide/coming-from-another-tool.md) · [Several keys for one service](docs/guide/several-keys-for-one-service.md) · [Running things](docs/guide/running-things.md) · [Credentials that are a file](docs/guide/credentials-that-are-a-file.md) · [The app](docs/guide/the-app.md) · [The shell hook (including Nushell)](docs/guide/the-shell-hook.md)
- **Checking config** — [What a value should look like](docs/guide/what-a-value-should-look-like.md) · [Finding what a codebase needs](docs/guide/finding-what-a-codebase-needs.md)
- **Agents** — [Connecting your agent](docs/guide/connecting-your-agent.md) · [What your agent gets](docs/guide/what-your-agent-gets.md) · [Adding a key off-transcript](docs/guide/adding-a-key-without-pasting-it-into-the-chat.md) · [Approvals](docs/guide/approving-what-runs.md) · [Policy](docs/guide/what-the-agent-may-run.md)
- **Your team** — [Adding someone](docs/guide/adding-a-teammate.md) · [Only some sets](docs/guide/giving-someone-only-some-sets.md) · [Removing someone](docs/guide/removing-someone.md) · [Membership changes](docs/guide/when-someone-else-changes-who-can-read-it.md) · [Merging](docs/guide/when-two-branches-both-change-the-vault.md) · [CI](docs/guide/ci.md) · [After someone leaves](docs/guide/what-someone-removed-could-still-use.md)
- **Hardening** — [The security ladder](docs/guide/the-security-ladder.md) · [Touch ID](docs/guide/touch-id.md) · [Hardware keys](docs/guide/hardware-keys.md)
- **Reference** — [Commands](docs/guide/commands.md) · [How the crypto works](docs/guide/how-the-crypto-works.md) · [What hush does not do](docs/guide/what-hush-does-not-do.md) · [The approval relay](docs/RELAY.md) · [Architecture](docs/ARCHITECTURE.md) · [Hardware unlock](docs/BIOMETRY.md)
- **Trust** — [SECURITY.md](SECURITY.md) (threat model, reporting) · [Review scope](docs/REVIEW-SCOPE.md) · [Red team](docs/RED-TEAM.md) · [Every defect found](docs/AUDIT.md) · [RESEARCH.md](RESEARCH.md)

## Contributing

Very welcome, especially: running it somewhere I cannot (Linux, Windows, a
YubiKey I do not own), finding a way to get a value out that should not come
out, or telling me where it confused you.

- [CONTRIBUTING.md](./CONTRIBUTING.md) — how to set up, and the bar for a change
- [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) — how it fits together, and the tests that hold it
- [Development](docs/guide/development.md) — running the suite, the fuzzers and the binary
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) — Contributor Covenant 2.1
- [SECURITY.md](./SECURITY.md) — threat model, and how to report a vulnerability
- [docs/AUDIT.md](./docs/AUDIT.md) — every defect found so far, and what changed

**Security problems do not go in issues.** Open a [private
advisory](https://github.com/omarei-omoto/hush/security/advisories/new) instead.

## License

MIT — see [LICENSE](./LICENSE).
