# External security review: scope

**Status: not yet reviewed.** hush has had internal audits and a red-team pass
([RED-TEAM.md](RED-TEAM.md), [AUDIT.md](AUDIT.md)), but no one outside the
project has reviewed it. This page is the brief for whoever does: what hush
claims, where each claim lives in the code, and the questions most worth an
expert's time. The report will be published in `docs/` and linked from the
README, where the "not reviewed" note is now.

## What hush is, in one paragraph

A vault of secrets that lives *in the git repository*, encrypted, next to the
code: one data key per vault, sealed to each member's key, and values sealed
under it with AES-256-GCM. A command gets the values in its environment
(`hush run`) and nowhere else. Coding agents get MCP tools that can *use* a
secret, by running a command or making an HTTP request with it injected, but
never *return* one. A gated action needs a person to approve it, through an OS
dialog, a fingerprint, or a paired device. The threat model is in
[SECURITY.md](../SECURITY.md), and [ARCHITECTURE.md](ARCHITECTURE.md) maps the
code.

## In scope, most important first

### 1. The scheme — `src/crypto.ts`, `src/header.ts`

- **Data-key wraps.** Ephemeral X25519 → HKDF-SHA256 (salt = ephemeral ‖
  recipient) → AES-256-GCM, with the recipient's key as AAD. For Secure Enclave
  members, the same construction on P-256.
- **Values.** AES-256-GCM under the data key, with AAD `hush/v2|<generation>|<set>|<KEY>`.
- **Signing keys.** An Ed25519 key derived from the X25519 private key via
  HKDF (label `hush/v3/signing`). Hardware identities keep a stored Ed25519 key
  instead.
- **The signed vault header (hush/v3).** Canonical JSON over the members (keys,
  roles, signing keys, sets), the data key's generation and a commitment to it
  (`dekCommit`), and each set key's generation and commitment. Only an admin's
  signature is accepted.
- **Per-set keys.** A set can have a key of its own, wrapped only to the members
  who may read it (`setKeys`). The data key is not wrapped to scoped members at all.

`test/scheme-conformance.test.ts` rebuilds the scheme with WebCrypto as an
independent check.

### 2. Trust in a vault that arrives by `git pull` — `src/integrity.ts`, `src/vault-core.ts`, `src/merge.ts`

A vault file is written by whoever can push to the repository. hush pins what
this machine has accepted (in `~/.hush/seen/`): the members, the data-key
commitments per generation, the admins, and whether the vault was signed. It
refuses any change it cannot explain until a person accepts it, and it refuses
outright a change that no legitimate operation produces. The three-way merge
driver re-signs a merged vault as the merging admin.

### 3. Approvals — `src/approval.ts`, `src/dialogs.ts`, `src/biometry.ts`, `src/swift.ts`, `src/relay.ts`

The rule: an approval must come from something the gated process cannot
supply. That is a dialog drawn by an OS-owned program resolved from fixed,
root-owned paths; a fingerprint checked by a helper compiled by
`/usr/bin/swiftc` in a scrubbed environment; or an answer signed by a paired
device ([RELAY.md](RELAY.md)). No environment variable can make an approval
easier.

### 4. Value-blindness toward agents — `src/mcp.ts`, `src/mcp-tools.ts`, `src/run.ts`, `src/redact.ts`, `src/request.ts`, `src/policy.ts`

No tool returns a value. Output is redacted by a streaming matcher. Commands
that defeat redaction trivially (interpreters) are refused unless both the
user's policy floor (`~/.hush/policy.json`) and the repository's policy allow
them. A repository's policy can only tighten the floor.

### 5. Keys in hardware — `src/age.ts`, `src/enclave.ts`, `native/hush-enclave.swift`

YubiKey, TPM and the like, through age plugins. A first-party Secure Enclave
identity through CryptoKit (`SecureEnclave.P256.KeyAgreement`, with
`.userPresence`), whose sealed `dataRepresentation` is kept in `~/.hush`.

### 6. Getting hush onto a machine — `scripts/install.sh`, `scripts/build-binaries.mjs`, `.github/workflows/release.yml`

Checksums and build-provenance attestations, reproducible builds, and the
single-file binary's runtime (Bun, with `.env` and `bunfig.toml` autoloading
turned off).

## Questions we most want answered

1. Is the wrap and value construction sound as used, including the HKDF salts
   and labels, and the AAD? Is deriving the Ed25519 signing key from the X25519
   private key with HKDF acceptable, or should the two be independent?
2. Is anything in a vault's security-relevant state **not** covered by the
   signed header, so that someone who can push to the repository could change it
   without an admin's signature and without the pinning noticing? (Members,
   roles, set membership, key commitments, generations.)
3. Trust on first use: a machine that has never seen a vault pins whatever it
   first sees. Is the prompt that asks a person to compare a safety number
   enough, and is the moment it appears the right one?
4. Revocation: after `hush team rm`, is there any path by which the removed
   member's key still opens a value written afterwards, including through set
   keys, merges, or a stale copy of the file?
5. The three-way merge (`src/merge.ts`): can a crafted branch make a merge
   produce a vault that the merging admin signs but did not intend? For example,
   a member added only on the other side.
6. Approvals: is there a way for a process running as the user to produce an
   approval without a person? We know about, and document, the case where it
   rewrites `~/.hush`. Consider the dialog program resolution, the Touch ID
   helper build, and the relay's pairing and replay protection.
7. The redactor: any way for a *permitted* command's output to carry a value
   through, beyond the encodings SECURITY.md already concedes?
8. The MCP tools: any tool, argument, or error path that returns a value, or
   enough of one to reconstruct it?
9. The installer and release: is anything in the path from a tag to a user's
   `~/.local/bin/hush` not covered by a checksum or an attestation?

## Known and out of scope

These are documented limitations. We would like to hear if any is worse than
we think, but they are not what the review is for:

- Code running as the user can read a software identity key. That is what
  hardware identities are for.
- Redaction is defence in depth. A program that encodes a value before
  printing it defeats it; the command policy is the control.
- A member can read what they are a member of, and revocation protects future
  values only.
- Timing side channels in the redactor and the approval path.
- Windows support is in beta.

## Working with the code

```bash
git clone https://github.com/omarei-omoto/hush && cd hush
npm install && npm test          # the whole suite; macOS also runs Touch ID, Keychain, dialogs
node --test test/invariants.test.ts test/trust.test.ts test/signed.test.ts test/relay.test.ts
```

Everything runs locally with a throwaway `HUSH_HOME` (see CONTRIBUTING.md). A
dependency-free WebCrypto reimplementation of the scheme is in
`test/scheme-conformance.test.ts`.

## What we ask for

- Findings with a severity, and where possible a failing test or a
  reproduction. The project's bar for a fix is a test that fails without it.
- Private disclosure through a [GitHub security
  advisory](https://github.com/omarei-omoto/hush/security/advisories/new). We
  fix, release, and publish the advisory with credit. The target is under 30
  days for anything that exposes a value.
- Permission to publish the report, with the fixes, as `docs/review/`.

## How we are looking for reviewers

In order: people who work on the constructions hush builds on (the age and
C2SP communities); programmes that fund reviews of small open-source security
tools (OSTIF, Radically Open Security); and a paid, focused engagement of one
to two weeks.
