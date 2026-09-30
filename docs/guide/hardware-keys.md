# Hardware keys

For a key that is genuinely unreadable rather than merely gated, move it into
hardware. On a Mac there is nothing to buy or install:

```bash
hush secure --hardware        # makes a key in the Secure Enclave, adds it as you
hush team rm <your-old-name>  # then retire the software key, and commit
```

The key is made inside the Secure Enclave and never leaves it; every read asks
for your fingerprint, enforced by the enclave rather than by hush. Each Mac is
its own member (`enclave` in `hush team ls`), so a stolen laptop is one
`hush team rm`. `hush id --enclave` makes the key without adding it anywhere,
for a teammate to add you.

For a YubiKey, a TPM, or anything else with an age plugin, hush bridges to
[age](https://age-encryption.org). It does not implement age's plugin protocol —
it shells out to `age`, which drives whichever plugin owns the recipient. So
hush contains **zero hardware integrations** and supports all of them:

```bash
brew install age age-plugin-yubikey     # or age-plugin-se, age-plugin-tpm
hush age                                # check the bridge
hush team add ana age1yubikey1q2w3e…    # a hardware-backed teammate
```

A vault mixes both kinds of member freely:

```
acme  DEK generation 2
  ana   member  age18lf9g367pxtth0c0…  age  ✓
  sam   admin   hush_pk_1xMUlHhmUKj0…  key  ✓
```

Unwrapping the vault key then requires touching the YubiKey, or a fingerprint
for the Secure Enclave — enforced by the hardware, not by a prompt. `age` is
optional; you only need it if you want this.

[docs/BIOMETRY.md](../BIOMETRY.md) has the full tiering, and how the
enclave key works without an Apple Developer ID.
