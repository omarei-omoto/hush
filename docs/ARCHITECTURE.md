# How hush is put together

A map for someone about to change hush: how one command flows, where each part
lives, and the properties the tests hold it to. It is short on purpose. The
source files open with a comment saying what they are for and why; this doc
tells you which one to open.

## One `hush run`, end to end

```
hush run -- npm test
   │
   ▼
 cli.ts ─────────────── picks the command (src/commands/run.ts)
   │
   ▼
 cli/context.ts ──────── which project: .hush/ found upward from here, or HUSH_VAULT
   │                     which vault file, which policy (.hush/policy.json ∪ ~/.hush/policy.json floor)
   ▼
 identity.ts ─────────── your private key: keychain / DPAPI / file / age plugin / Secure Enclave
   │
   ▼
 vault.ts (+ vault-core, vault-values, vault-files)
   │   open the file ──► integrity.ts: is this the vault this machine accepted?
   │                     (pinned roster, key commitments, signed header — header.ts)
   │   unwrap the data key for you (crypto.ts; age.ts / enclave.ts for hardware)
   ▼
 library.ts + vault-values.ts ── resolve the sets this project uses, library first,
   │                              later sets winning, each value opened with its AAD
   ▼
 policy.ts ───────────── may this command run at all? (deny list, allowed sets)
   │
   ▼
 approval.ts ─────────── does a person have to say yes? cached grant → fingerprint
   │                     (biometry.ts) → dialog (dialogs.ts) → paired device (relay.ts)
   │                     → otherwise refuse
   ▼
 run.ts ──────────────── spawn with the values in its environment, nothing on disk;
   │                     stdout/stderr through the streaming redactor (redact.ts)
   ▼
 audit.ts ────────────── one hash-chained line in .hush/audit.log: what ran, which keys,
                         how it was approved — never a value
```

The agent's path is the same pipeline behind a different front door.
`mcp.ts` speaks the protocol, `mcp-tools.ts` implements each tool, and every
tool that uses a credential goes through the same policy, approval, run and
redaction steps. None of them returns a value.

## Where things live

| Area | Files |
|---|---|
| The command line | `cli.ts` (dispatch), `cli/` (arguments, context, output, prompts, help), `commands/<command>.ts` (one per command) |
| The scheme | `crypto.ts` (sealing values, wrapping data keys, signing), `header.ts` (the signed vault header), `merge.ts` (three-way merge of vault files) |
| The vault | `vault-files.ts` (the file format, finding it, locking) → `vault-core.ts` (keys, members, trust) → `vault-values.ts` (sets and values) → `vault.ts` (the class you use) |
| Trust | `integrity.ts` (what this machine has seen of each vault, and what it refuses), `audit.ts` (the chained log), `freshness.ts` (value age, exposure) |
| Your key | `identity.ts` (where it lives), `age.ts` (hardware keys through age plugins), `enclave.ts` + `native/hush-enclave.swift` (Secure Enclave), `swift.ts` (building the macOS helpers safely) |
| Asking a person | `approval.ts`, `dialogs.ts` (one backend per desktop), `biometry.ts` + `native/hush-touchid.swift`, `relay.ts` + `relay-server.ts` + `qr.ts` (a paired device) |
| Using a secret | `run.ts` + `redact.ts`, `request.ts` (an HTTP call with the secret substituted inside hush), `materialize.ts` (a secret that has to be a file) |
| Rules | `policy.ts` (the policy and its floor), `schema.ts` (`.env.schema`), `posture.ts` + `secure.ts` (the security ladder) |
| Getting secrets in | `import.ts` (dotenv, JSON, 1Password), `scan.ts` (what a codebase reads), `services.ts` (known providers), `start.ts` (the first run) |
| Agents | `mcp.ts`, `mcp-tools.ts`, `agents.ts` (writing each agent's config), `skills/hush/SKILL.md` |
| The app | `ui.ts` (server), `ui-api.ts` (endpoints), `ui-state.ts` (what the page is told), `ui-page.ts` + `ui/*.ts` (the page) |
| Platforms | `platform.ts` (what differs on Windows), `which.ts`, `clipboard.ts` |
| Distribution | `assets.ts`, `scripts/build-binaries.mjs`, `scripts/install.sh`, `scripts/install.ps1`, `scripts/package-manifests.mjs`, `action.yml` |

## The invariants, and the tests that hold them

These are the properties hush exists for. Each one is guarded by tests that fail
when it breaks. That is checked by breaking it on purpose, as CONTRIBUTING.md
describes.

| Invariant | Guarded in |
|---|---|
| **No tool returns a value.** The MCP server has no getter, and every output is redacted. | `test/mcp.test.ts` ("never returns a secret value, only its effects"), `test/fuzz-surfaces.test.ts` |
| **A ciphertext is bound to its set, key and generation (AAD).** It cannot be moved or replayed into another slot. | `test/crypto-properties.test.ts`, `test/scheme-conformance.test.ts` (checked against an independent WebCrypto implementation) |
| **A vault this machine did not accept is refused, not used.** Members, data-key commitments and the header signature are all pinned. | `test/trust.test.ts` (the V-1 reproduction), `test/signed.test.ts` |
| **Only an admin's signature changes who can read.** | `test/signed.test.ts`, `test/merge.test.ts` (the merge matrix) |
| **The policy floor only tightens.** A repo's policy cannot drop below `~/.hush/policy.json`. | `test/floor.test.ts`, `test/policy.test.ts` |
| **No file answers an approval.** An approval comes from a dialog, a fingerprint or a paired device's signature, never from anything the caller can write. | `test/approval.test.ts` ("a grant file cannot stand in for an approval…"), `test/relay.test.ts` |
| **Nothing in the environment makes an approval easier.** Test seams are parameters, not variables. | `test/biometry.test.ts`, `test/approval.test.ts` |
| **Values never touch disk in a run.** | `test/commands/run.test.ts` ("while the command runs, no file under the project, HUSH_HOME or tmp holds the value"), `test/materialize.test.ts` (the one deliberate exception, removed afterwards) |
| **The audit log cannot be edited quietly.** | `test/audit.test.ts` |
| **Revocation re-keys.** Removing a member rotates what they could read, and marks it exposed. | `test/hush.test.ts`, `test/freshness.test.ts` |
| **The docs match the code.** Every command is in the help, every MCP tool is in the README, and nothing is exported unused. | `test/consistency.test.ts` |

`test/invariants.test.ts` is worth reading first. It is a list of properties
that once turned out not to hold.

## Conventions that are not obvious from one file

- **Test seams are parameters, never environment variables.** Anything running
  as you can set an environment variable. A switch like `HUSH_BIOMETRY_FAKE=ok`
  would be a way around the fingerprint for every agent. Tests pass a stand-in
  in-process: `ApprovalDeps`, `setEnclaveForTests`, `setRelayTransportForTests`.
  The environment switches that do exist can only make hush *stricter*
  (`HUSH_NO_DIALOG`).
- **Library calls never write trust state.** Pinning happens through a hook the
  CLI installs (`setTrustHook`), so a test or an embedding program using
  `Vault` directly does not touch `~/.hush/seen`.
- **`erasableSyntaxOnly`.** Node runs `src/` directly by stripping types, so
  there are no enums, namespaces or parameter properties.
- **Zero runtime dependencies.** The QR encoder, the relay and the merge driver
  are all in-tree.
- **Comments say why, not what.** Most say what went wrong before, and what
  breaks if you change it back.
