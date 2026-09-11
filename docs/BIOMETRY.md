# Hardware-backed unlock: what's shipped, what's next, what to skip

Short version: **Touch ID is shipped. The age bridge is shipped, which is how
YubiKey / Secure Enclave / TPM get in without hush containing a single hardware
integration. A first-party Secure Enclave implementation would need $99 and is
therefore not worth building.**

## The distinction that decides everything

There are two completely different things people mean by "unlock it with my
fingerprint":

**A gate.** Something asks for your fingerprint before proceeding. The key is
still sitting in a file or the login keychain. Malware running as you reads it
directly and never triggers the prompt. This is a *usability and presence*
control — real, but modest.

**A cryptographic boundary.** The key material physically lives inside hardware
that will not export it. Every use requires the hardware, and the hardware
requires your fingerprint. Malware running as you can *ask the enclave to
decrypt* but can never steal the key, and it cannot use it without you touching
the sensor.

Shipping a gate and describing it as the second thing is the most common lie in
this space. hush ships the gate and says so.

## Tier 1 — Touch ID gate (shipped)

```bash
hush biometry setup
hush biometry test
```

Then in `.hush/policy.json`:

```json
{ "biometry": "required" }
```

`"preferred"` uses Touch ID when available and falls back to the click dialog.
`"required"` refuses to proceed if biometry is unavailable — it will not
silently downgrade. `"off"` disables it.

Implementation: a small Swift helper calling
`LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`, compiled on
demand to `~/.hush/bin/` and cached by source hash. No entitlements, no signing,
no native dependency at install.

**What it buys:** nothing runs with your credentials unless a human with an
enrolled finger is physically present. Your agent cannot approve its own
request. Someone at your unlocked laptop cannot use your keys.

**What it does not buy:** protection of the key at rest. It is a gate.

## Tier 2 — Secure Enclave identity (the real thing, blocked on signing)

The correct end state. Instead of an X25519 key in the login keychain, your hush
identity becomes a **P-256 key generated inside the Secure Enclave**, created
with:

```swift
SecAccessControlCreateWithFlags(
  kCFAllocatorDefault,
  kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
  [.privateKeyUsage, .biometryCurrentSet],   // ← invalidated if fingerprints change
  &error)
```

The private key **cannot be extracted, by anyone, including root**. Unwrapping
the vault's data key becomes `SecKeyCopyKeyExchangeResult(...)`, which the
enclave will only perform after a successful Touch ID.

This fits hush's existing crypto almost exactly: the DEK wrap is already
ephemeral-ECDH → HKDF-SHA256 → AES-256-GCM. Swapping X25519 for P-256 for these
recipients is a contained change, because Apple's `.ecdhKeyExchangeStandard` and
Node's `diffieHellman` both return the raw X coordinate.

### Why it isn't shipped

Creating a *permanent* Secure Enclave key requires the `keychain-access-groups`
entitlement. Verified on an M1 Max running macOS 26:

```
ad-hoc signed, no entitlements    → OSStatus -34018 (errSecMissingEntitlement)
ad-hoc signed, with entitlements  → process killed by AMFI (exit 137)
```

There is no way around it. The entitlement must be backed by a real provisioning
profile, which means an **Apple Developer ID ($99/year)**.

### The path when you want it

1. Enrol in the Apple Developer Program.
2. Build `hush-se` (a ~150-line Swift helper: `create`, `pubkey`, `ecdh`,
   `delete`), sign it with your Developer ID, notarize it.
3. Ship the signed binary as an optional package — `@omarei/hush-secure-enclave` —
   rather than in the core, so `npm i -g @omarei/hush` stays dependency-free.
4. Add a `hush_pk_se_…` recipient type. P-256 public keys are 65 bytes (X9.63
   uncompressed) versus X25519's 32.

**One consequence worth wanting:** an enclave key cannot move between machines.
Each device gets its own identity and is added with `hush team add`. That is
strictly better — you can revoke a stolen laptop without touching your desktop.

`[.biometryCurrentSet]` also means the key self-destructs if someone enrols a new
fingerprint. Use `.biometryAny` if that is too aggressive for your users.

## Tier 3 — YubiKey, Secure Enclave, TPM: shipped, via age

The instinct is right and the implementation is a trap. Each is a separate
native dependency, a separate platform quirk surface, and a separate thing to
keep working forever:

| | How it would have to work | Cost |
|---|---|---|
| **YubiKey** | PIV applet P-256 ECDH via PKCS#11, or FIDO2 `hmac-secret` via libfido2 | native dep, per-OS build matrix |
| **Windows Hello** | `UserConsentVerifier` (gate) + NCrypt/TPM Platform Crypto Provider (real) | WinRT interop, C# or native shim |
| **Linux TPM 2.0** | `tpm2-tss` sealed objects | libtss2, distro variance |
| **Linux fingerprint** | fprintd over D-Bus | gate only, no key protection |

Four hardware backends is four maintenance burdens for a project whose entire
pitch is *zero dependencies*.

### What was built instead

`src/age.ts` — one small adapter. hush does **not** implement age's plugin
protocol. It shells out to the `age` binary, and age invokes whichever plugin
owns the recipient. hush hands over the 32-byte data key and gets it back; it
never learns whether a YubiKey, an enclave, or a file was involved.

```bash
hush age                                   # status of the bridge
hush team add sam age1yubikey1q2w3e...     # a hardware-backed teammate
```

A vault can mix both kinds of member freely:

```
acme  DEK generation 2
  ana   member  age18lf9g367pxtth0c0…  age  ✓
  sam   admin   hush_pk_1xMUlHhmUKj0…  key  ✓
```

Revocation re-wraps the data key for every remaining member of either kind —
that path is tested, because it is the one that would silently lock out a
hardware user.

Everything below arrives for free:

- `age-plugin-yubikey` — PIV, already maintained, already packaged
- `age-plugin-tpm` — TPM 2.0
- `age-plugin-se` — Apple Secure Enclave, **already signed and notarized by its
  author**, which sidesteps the $99 problem entirely
- `age-plugin-fido2-hmac` — any FIDO2 key

One dependency (`age`, optional, only for people who want hardware keys), four
hardware backends nobody on this project has to maintain. hush recipients are
also now interoperable with age identities, which is a better story than any
bespoke integration would have been.

**`age-plugin-se` is signed and notarized by its author**, so the Tier 2
Developer-ID wall is simply routed around. That is the whole argument for this
approach in one sentence.

### Still not built, deliberately

**Windows Hello.** `UserConsentVerifier` is a gate; the real version needs
NCrypt with the TPM Platform Crypto Provider and a C#/WinRT shim. If a Windows
user wants hardware protection today, `age-plugin-tpm` already covers it.

## Where this leaves things

1. **Tier 1 Touch ID** — shipped, honest about being a gate.
2. **age bridge** — shipped. Covers YubiKey, Secure Enclave, TPM, FIDO2.
3. **First-party `hush-se`** — not worth $99/yr unless `age-plugin-se` proves
   too slow or too awkward in practice. Revisit only with evidence.

## Things to get right whenever you do this

- **Never let a hardware failure silently downgrade.** `"required"` must refuse,
  not fall back. (This is tested.)
- **Scope the grace window to the accounts in use.** hush already keys its
  approval cache on the resolved account set, so switching from `fal:personal`
  to `fal:client` re-prompts. Do not widen this.
- **A stolen laptop is the real threat model**, not a nation state. Enclave keys
  plus per-device identities plus `hush team rm <device>` handles it well.
- **Say plainly what is protected.** `hush biometry` prints both the ✓ and the ✗
  every time it runs, on purpose.
