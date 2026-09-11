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
- Code execution from something a vault or a repository can carry: a value, a
  key name, `.hush/link.json`, `.hush/vault.json`.

## What is already known, and not a finding

These are documented trade-offs rather than oversights. The threat model below
covers them in full — see *What it does not protect* — but in short:

- A software identity can be used by anything running as you. That is what the
  hardware rung exists for.
- Output redaction is defeated by encoding. It stops an accident, not an
  adversary.
- The command deny list is a speed bump, not a boundary.
- Revocation protects future values only. Anyone who could read a secret has.
- Git history is permanent.

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

### What it does not protect

**A software identity is usable by anything running as you.** This is the big
one. The identity key lives in the login keychain, and hush retrieves it with the
`security` CLI. Any process running as your user can do the same — including a
shell command from an agent, which can simply run `hush export`. The MCP policy
constrains hush's own tools; it cannot constrain a process that bypasses hush.

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
