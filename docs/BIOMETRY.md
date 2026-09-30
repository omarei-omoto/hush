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
`LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`, compiled
on demand from hush's own source into a private scratch folder, once per process
and never stored anywhere a later run would trust. No entitlements, no signing,
no native dependency at install.

It used to be compiled once into `~/.hush/bin/` and reused while a stamp matched
the source hash. That was a hole rather than a cache: `~/.hush` is inside your
own home, so anything running as you could have replaced the program there,
stamp and all, and answered "ok" with no finger anywhere near the sensor. The
cost of not trusting it is about a third of a second per process that needs a
prompt (three seconds the very first time on a machine, while `swiftc` warms its
module cache).

**What it buys:** nothing runs with your credentials unless a human with an
enrolled finger is physically present. Your agent cannot approve its own
request. Someone at your unlocked laptop cannot use your keys.

**What it does not buy:** protection of the key at rest. It is a gate.

## Tier 2 — Secure Enclave identity (shipped in 1.0)

The correct end state, and it no longer needs anything bought or installed:

```bash
hush secure --hardware        # on a Mac: makes the key, adds it to the vault as you
hush id --enclave             # or just make the key and print it
```

Your hush identity becomes a **P-256 key generated inside the Secure Enclave**,
created with `[.privateKeyUsage, .userPresence]`. The private key **cannot be
extracted, by anyone, including root**. What hush keeps is the sealed
`dataRepresentation` the enclave hands back (`~/.hush/enclave-identity.blob`) —
useless on any other Mac — and the public half beside it. Unwrapping the vault's
data key is a key agreement the enclave performs only after a fingerprint (or
the Mac's password, the system fallback), enforced by the enclave itself.

The wrap mirrors hush's X25519 one: ephemeral P-256 ECDH → HKDF-SHA256 (salt
`epk ‖ recipient`, info `hush/v3/se-kek`) → AES-256-GCM with the recipient's
public key as AAD. Members show up as `hush_se_…` (65-byte X9.63 point, base64url)
and as `enclave` in `hush team ls`. An enclave key cannot sign, so like an age
hardware key it carries the machine's stored Ed25519 signing key (`--spk`); your
own enclave key, added by you as an admin, gets it automatically.

`test/enclave.test.ts` checks the wrap against an independent WebCrypto
implementation and runs the whole upgrade — add the enclave key, read with it
alone, retire the software key, the enclave member signs the change — through a
software P-256 stand-in. The same flow was run against the real enclave on an
M1 Max, macOS 26.

### Why this used to be blocked, and isn't

The first attempt made a *keychain* Secure Enclave key (`SecKeyCreateRandomKey`
with `kSecAttrTokenIDSecureEnclave` and `kSecAttrIsPermanent`). That needs the
`keychain-access-groups` entitlement:

```
ad-hoc signed, no entitlements    → OSStatus -34018 (errSecMissingEntitlement)
ad-hoc signed, with entitlements  → process killed by AMFI (exit 137)
```

and the entitlement needs a provisioning profile — an Apple Developer ID.

CryptoKit's `SecureEnclave.P256.KeyAgreement.PrivateKey` sidesteps the keychain
entirely: the key is not a keychain item, and `dataRepresentation` is an
enclave-sealed blob the app stores itself. No entitlement is involved, so the
ad-hoc-signed helper hush compiles for itself (`native/hush-enclave.swift`,
built by `/usr/bin/swiftc` only — see `src/swift.ts`) can create, reload and use
the key. Verified: create, reload from the blob in a new process, agreement
matches the software side.

### Choices worth knowing

- **`.userPresence`, not `.biometryCurrentSet`.** `biometryCurrentSet` destroys
  the key when a fingerprint is enrolled or removed — one new finger and every
  vault the key held is gone unless another member re-adds you. `userPresence`
  accepts Touch ID or the Mac's password. Someone running as you knows neither.
- **`--presence none`** makes a key that is still non-extractable but usable
  without anyone present: for a build Mac, never a laptop.
- **One key per machine.** An enclave key cannot move. Each device is its own
  member, which is what you want: `hush team rm <device>` revokes a stolen
  laptop without touching anything else.
- **The upgrade is not finished until the software key is retired.** `hush
  secure --hardware` says so and prints the `hush team rm` to run; until then
  the vault is as strong as the software key.

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

**`age-plugin-se` is signed and notarized by its author**, which is how hush
offered the Secure Enclave before Tier 2 found its way around the Developer-ID
wall. It still works, and a plugin identity someone set up wins over the
first-party one in `hush secure --hardware`.

### Still not built, deliberately

**Windows Hello.** `UserConsentVerifier` is a gate; the real version needs
NCrypt with the TPM Platform Crypto Provider and a C#/WinRT shim. If a Windows
user wants hardware protection today, `age-plugin-tpm` already covers it.

## Where this leaves things

1. **Tier 1 Touch ID** — shipped, honest about being a gate.
2. **Tier 2 Secure Enclave identity** — shipped in 1.0, first-party, nothing to
   install on a Mac with Xcode Command Line Tools.
3. **age bridge** — shipped. Covers YubiKey, TPM, FIDO2, and the enclave via
   `age-plugin-se` for anyone who prefers it.

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
