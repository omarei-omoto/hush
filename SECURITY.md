# Security policy

## Reporting a vulnerability

**Please do not open a public issue for anything that lets someone read a vault
they should not.**

Open a [private security advisory](https://github.com/omarei-omoto/hush/security/advisories/new)
instead. Tell me what you did, what happened, and what you expected; a failing
test or a short script is ideal. I will confirm receipt, and I would rather hear
about something that turns out to be fine than not hear about it.

There is no bounty. This is one person's project.

## Supported versions

`hush` is pre-1.0 and has not been through an external security review. Fixes go
to the latest release only.

| Version | Supported |
|---|---|
| 0.1.x | yes |

## What is in scope

Anything that lets someone read a secret they should not be able to:

- Recovering a value from a committed vault without being a recipient of it.
- Getting a value back through the MCP server, which is supposed to be blind to
  them — including through `hush_run`'s output.
- Reaching the local UI from another machine, or without the session token.
- A revoked member still being able to decrypt.
- Getting a value out through `hush_request` / `hush_request`: in a header the
  caller named, in a query string or body it opted into, or reflected back in a
  response the redactor failed to mask.
- `hush_request` reaching a host the policy does not allow, being redirected to
  one, or sending a credential in cleartext to a host that is not loopback.
- Any approval being pre-authorised by a file in the project. Grants live in
  the process the human answered and nowhere else, so there is no
  `grants.local.json` to forge — see the approval section below.
- `hush run --materialize` writing a value to a path the caller chose, handing
  that path to a child, or leaving the file behind after the child exits.
- The clipboard path in `hush get --copy`: the value reaching it, or the
  clipboard tool being chosen from somewhere other than a real file on `PATH`.
- `.env.schema` validation printing a value, or a schema declaring a value.
- Code execution from something a vault or a repository can carry: a value, a
  key name, `.hush/link.json`, `.hush/vault.json`.

## What is already known, and not a finding

These are documented trade-offs rather than oversights. The threat model below
covers them in full — see *What it does not protect* — but in short:

- A software identity can be used by anything running as you. That is what the
  hardware rung exists for.
- Output redaction is defeated by encoding. It stops an accident, not an
  adversary.
- `hush_request` inherits that: the response is masked by matching known values,
  and it is read as plain text — the request asks for `Accept-Encoding:
  identity` for exactly that reason, and the body is capped before it is
  scanned. A remote that base64-encodes a reflected credential still defeats it.
- `allowHosts` is empty by default, so an agent may send an allowed set to any
  https host. The approval dialog is what makes that visible; the host list is
  what bounds it.
- **Materialising is a reveal, and is treated as one.** It writes plaintext to
  the filesystem, so it needs the `reveal` approval, and it is deliberately
  absent from the MCP surface. The file is `0600` and removed on exit, but a
  `SIGKILL` cannot be caught: the file survives that, and page cache holds it
  regardless.
- **Values under five characters are not masked at all.** `redact.ts` skips
  them as noise; `hush add` and `hush adopt` now say so when they store one.
- `.env.schema` is read for rules only. The placeholder after `=` is ignored,
  and a validation failure prints the key, the rule and the length, never the
  value.
- The command deny list is a speed bump, not a boundary.
- Revocation protects future values only. Anyone who could read a secret has.
- Git history is permanent.
- An approval has to come from something the gated process cannot supply: a
  dialog drawn on your screen by an OS-owned program, or your fingerprint. There
  is deliberately no file to answer. A host with no desktop *and* no biometric
  helper cannot ask you anything, so it refuses the gated action instead of
  pretending. Nothing in the environment can make an approval easier — the one
  switch that exists (`HUSH_NO_DIALOG`) can only make hush refuse.

---

## Threat model

What hush protects, what it does not, and where the edges are. Written to be
read before you trust it with anything real.

### What it protects

| | How |
|---|---|
| Secrets at rest in your repo | AES-256-GCM per value, under a per-vault data key |
| A value moved between slots | AAD binds each ciphertext to `env\|KEY` — a staging URL cannot be pasted into the prod slot |
| Sharing without a server | The data key is wrapped once per member (X25519 ECDH → HKDF → AES-GCM), so `git push` is the whole distribution mechanism |
| Offboarding | `hush team rm` mints a new data key and re-seals every value; the removed member's checkout decrypts nothing new |
| Secrets reaching a model | The MCP server has no tool that returns a value. `hush_run` injects and streams back redacted output |
| A credential reaching an API without reaching the caller | `hush_request` substitutes inside hush's own process; nothing is substituted into the URL, and a redirect to another host is refused rather than followed |
| A secret reaching a file without reaching the scrollback | `hush run --materialize` writes one file at `0600`, created with `wx`, removed on ordinary exit and best-effort after a `SIGKILL` (see the known-limitations list above), gated on `reveal` |
| A credential reaching the clipboard instead of the terminal | `hush get --copy` pipes it to `pbcopy`/`wl-copy`/`xclip`, resolved from `PATH`, never through argv |
| A value of the wrong shape | `.env.schema` rules, checked before anything runs or is sent; messages carry the rule and the length, never the value |
| A key entering a transcript | `hush_add_secret` opens a native input box; the value goes keyboard → vault |
| Silent use of a credential | Approval dialog naming the command, accounts and variables, optionally gated on Touch ID |
| Key theft from disk | Only with a hardware identity — see below |

### The ladder

Most of what follows is a limitation of a *particular rung*, not of hush. Run
`hush level` to see which one you are on.

| Rung | Name | The key is | An attacker running as you |
|---|---|---|---|
| 1 | encrypted | a file at `~/.hush/identity` | reads the file, decrypts everything |
| 2 | keychain-backed | in the login keychain | calls `security` or `hush export`, decrypts everything |
| 3 | approved use | same | must get past a dialog you will see |
| 4 | biometric | same | must produce your fingerprint |
| 5 | hardware-backed | inside a YubiKey or Secure Enclave, non-extractable | cannot steal the key at all, and cannot use it without you touching the device |

Rungs 3 and 4 are *presence* controls: they stop silent and remote use, not a
determined local attacker who bypasses hush entirely. **Rung 5 is the only one
that changes what is cryptographically possible.**

For which of this matters in your situation — alone, with an agent, or as a
team — and what to turn on for each, see [docs/SAFETY.md](./docs/SAFETY.md).
What has actually been tried against these surfaces, and with what result, is
in [docs/RED-TEAM.md](./docs/RED-TEAM.md).

### What it does not protect

**A software identity is usable by anything running as you.** This is the big
one. The identity key lives in the login keychain, and hush retrieves it with the
`security` CLI. Any process running as your user can do the same — including a
shell command from an agent. Once `.hush/policy.json` exists, `hush get`,
`hush export`, `hush run` and `hush add` apply the same policy and approval
as the MCP tools, so shelling out to hush does not skip the *policy*. The
approval is a separate question and depends on the mode: the dialog program is
resolved only from fixed OS-owned paths (`/usr/bin`, `/bin`, `/usr/local/bin`,
root-owned and not group- or world-writable) and is always executed by absolute
path, so a caller cannot choose it by editing `PATH`, and there is no longer any
environment variable that selects, replaces or skips it. There is also no file
to answer: the pending-request queue that used to back this up was a second
place the same caller could answer from, and it is gone. **An agent with a
shell cannot answer an approval by itself**: it would have to click a dialog on
your screen or touch the fingerprint reader for you. Where a machine can offer
neither of those, hush refuses the gated action rather than accepting a file.
The fingerprint helper is built fresh from hush's own source, per process, into
a private folder — it is never read from a path anything running as you could
have written, which is what makes "touch the sensor" mean what it says.
The policy
in the repo can only tighten what `~/.hush/policy.json`, your floor outside
the repo, allows — so an agent editing project files cannot loosen it — but
nothing stops a process from reading the keychain directly. The policy
constrains hush; it cannot constrain a process that bypasses hush.

The prompt itself is app-modal: a click anywhere else cannot answer it and
cannot dismiss it. On macOS it is re-presented every 45 seconds until it is
answered or the configured wait runs out, so a window that slips behind
something comes back to the front, and a request that nobody answers lapses
into a refusal rather than a quiet yes.

This holds for a project directory; it assumes `hush` is being asked about
*this* vault. `.hush/vault.json` is meant to be committed and read by anyone
with repo access — that is the design, envelope encryption protects the
values, not the file — so nothing stops a copy of it, plus `HUSH_VAULT`
pointing at the copy, from being opened from a directory that has no
`policy.json` of its own. With no `~/.hush/policy.json` floor configured,
that reverts to "no policy anywhere for this invocation," which is opt-in by
design for a project that was never set up for an agent, not for a copy of
one that was. **Set a floor if an agent can set environment variables when it
spawns `hush`** — true of any agent with a shell — even an empty
`~/.hush/policy.json` is enough to keep `requireApproval` from disappearing.
The floor and the approval now hold on their own terms: the floor keeps the
*policy* in force, and the approval is answered by a dialog or a fingerprint,
neither of which the caller can supply.

If that matters for your threat model, use a hardware identity
([docs/BIOMETRY.md](./docs/BIOMETRY.md)): with `age-plugin-yubikey` or
`age-plugin-se` the key is non-extractable and every unwrap needs a touch.

**Redaction is defence in depth, not a boundary.** It masks known values in a
child's output. It cannot see a value that has been base64'd, encrypted,
reversed, or written to a file. The controls that hold are `allowCommands` and
human approval.

**The command deny list is a speed bump.** It blocks the obvious interpreters and
exfiltration tools, and it is a floor that a stale `policy.json` cannot lower.
But no deny list is complete: `npm run <script>` executes whatever `package.json`
says. Use `allowCommands` for anything sensitive.

**Revocation protects future values only.** Anyone who could read a secret has
read it. `hush team rm` re-keys the vault; only Stripe can rotate a Stripe key.
The CLI says so every time.

**Git history is permanent.** A deleted secret remains in history as ciphertext.
If the vault key ever leaks, so does everything the history contains.

**No zeroisation.** Decrypted values live in JS strings and are collected
whenever the runtime feels like it. A core dump or swap file may contain them.

**hush is not a KMS.** No dynamic credentials, no leasing, no expiry.

---

Every defect found so far, and what changed, is in [docs/AUDIT.md](./docs/AUDIT.md).
