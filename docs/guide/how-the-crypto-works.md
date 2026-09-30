# How the crypto works

```
                        ┌─ wrapped for ana ────┐
  vault key (32B) ──────┼─ wrapped for sam ────┼──► .hush/vault.json
        │               └─ wrapped for ci  ──X  (ci is scoped: no vault key)
        │
        └─► AES-256-GCM per value, AAD = "hush/v2|<generation>|<set>|<KEY>"

  "staging" key (32B) ──── wrapped for ana, sam, ci   (a set with a key of its own)

  header { members, roles, sets each may read, key generations, key commitments }
        └─► Ed25519 signature by an admin
```

- **Per-value:** AES-256-GCM under the key of the set it is in — the vault key,
  or the set's own key if it has one. The AAD binds the ciphertext to its
  `set|KEY` slot and to the key generation that sealed it, so values cannot be
  swapped between slots and a generation cannot be edited to fake freshness.
- **Per-recipient:** a key is wrapped once per member who may hold it —
  ephemeral X25519 → ECDH → HKDF-SHA256 → AES-256-GCM. This is the age/ECIES
  construction. Full members hold the vault key and every set key; a scoped
  member holds only the keys of their sets.
- **Adding a member** re-wraps the existing keys. Nothing is re-encrypted.
- **Removing a member** mints new keys for everything they could read and
  re-seals it.
- **The signed header (hush/v3).** Encrypting to a public key says nothing
  about who did it, and every member's public key is in the file — so without a
  signature anyone could build a vault that opens for your whole team. The
  header lists every member, their role, the sets a scoped member may read, and
  a commitment to each data key (`HKDF(key, vault id, generation)`, which
  reveals nothing about the key). An admin signs it with an Ed25519 key derived
  from their identity (a hardware identity keeps a separate one). A member
  checks the signature against an admin their machine already trusts, and
  checks that the key they unwrapped is the one the header commits to.
- **Pinning.** Each machine also remembers, per vault, the members and admins
  it accepted, the key commitment for each generation, and which vault lives at
  which path — which is what catches an unsigned or downgraded copy, and what
  an older, unsigned vault relies on alone.
- **Your private key** lives in the macOS Keychain, or `~/.hush/identity` at
  mode 0600. It is never in a vault file, never in a repo, and is stripped from
  the environment of anything `hush run` launches.

The vault file holds ciphertext, public keys, and metadata. That is all:

```json
{
  "scheme": "hush/v3",
  "dek": { "generation": 2, "commit": "9f1c…", "wraps": { "a1b2…": { "epk": "…", "ct": "…" } } },
  "recipients": {
    "a1b2…": { "name": "ana", "pk": "hush_pk_…", "spk": "hush_spk_…", "role": "admin" },
    "c3d4…": { "name": "ci", "pk": "hush_pk_…", "role": "member", "ci": true, "sets": ["staging"] }
  },
  "setKeys": { "staging": { "generation": 1, "commit": "4e07…", "wraps": { "a1b2…": {}, "c3d4…": {} } } },
  "envs": {
    "default": {
      "DATABASE_URL": { "iv": "…", "ct": "…", "tag": "…", "gen": 2, "v": 2,
                        "updatedBy": "ana", "updatedAt": "2026-01-01T00:00:00Z" }
    }
  },
  "signature": { "by": "a1b2…", "sig": "…" }
}
```
