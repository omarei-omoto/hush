# The security ladder

hush works at every rung, including the bottom one. That is deliberate: a tool
that refuses to run until you buy a YubiKey gets uninstalled, and the person goes
back to a plaintext `.env`. So it never blocks — it shows you where you are and
makes the next rung one command.

```
$ hush level

  ●●●○○  rung 3 of 5 — approved use

  ✓ secrets are encrypted at rest
  ✓ no plaintext .env left in the project
  ✓ your key is in the OS keychain, not a loose file
  ✓ using a credential needs your approval
  ○ approval needs your fingerprint, not a click
  ○ your key cannot be copied off this machine

  This vault holds:
    · 3 high-value secrets (AWS_SECRET_ACCESS_KEY, DATABASE_URL, STRIPE_SECRET_KEY)
    · 4 people can decrypt this vault

  Next → approval needs your fingerprint, not a click
    a click can be made by anything at your unlocked laptop; a fingerprint cannot
    hush secure --biometry
```

`hush secure` performs the next step rather than describing it: migrates your key
into the keychain, imports and deletes a stray `.env`, turns on approval, enables
Touch ID, or walks you onto a hardware key.

- **The rung is a strict checklist.** Passing a later check does not lift you
  past an earlier gap — you cannot claim "biometric" while a plaintext `.env`
  sits in the repo.
- **Nudges are risk-weighted and rate-limited.** hush judges what the vault holds
  from key *names* only, never by decrypting. A vault of feature flags gets a
  quiet hint once a week; three live payment keys shared with four people gets a
  louder one once a day. `HUSH_NO_NUDGE=1` or `hush secure --snooze 30` silences
  it.
- **It will not let you fool yourself.** `hush secure --hardware` refuses to
  count a *software* age key as hardware, because it would not change what an
  attacker running as you can do.
