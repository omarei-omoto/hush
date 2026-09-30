---
title: "Windows and Linux: a TPM-backed identity, first-party"
labels: ["platform:windows", "platform:linux", "needs-design", "security"]
---

On a Mac, `hush id --enclave` puts the identity in the Secure Enclave with nothing to install (`src/enclave.ts`, `native/hush-enclave.swift`). Windows and Linux have a TPM, and today reach it only through `age-plugin-tpm`.

The shape to match: a P-256 key made in hardware, ECDH for unwrapping (`wrapDekP256` in `src/crypto.ts` already does the other half), and a user-presence check on use where the platform has one.

- Windows: NCrypt with the Platform Crypto Provider, plus Windows Hello for presence. Can it be reached from PowerShell without a native module (see `src/platform.ts`)?
- Linux: `tpm2-tools`. Presence is harder.

Please design it in this issue before writing code; a native dependency is a decision, not a detail.

---
**The bar:** a test that fails without the change (CONTRIBUTING.md, "The bar for a change"). Run it with `node --test <file>`; use a throwaway `HUSH_HOME` to try it by hand.
