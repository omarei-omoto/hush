# What hush does not do

**Read [SECURITY.md](../../SECURITY.md) before trusting it with anything real**, and
[docs/SAFETY.md](../SAFETY.md) for which of it matters in *your* situation —
alone, with an agent, or as a team. The most important line in both: with a *software* identity, anything running as your
user can invoke hush and read the vault — including a shell command from an
agent. The policy gates hush's own tools and CLI; it cannot gate a process that
goes around hush, and `policy.json` is a file in your repo that an agent with
write access can loosen. Use a hardware identity if that matters to you.

- It is **not a KMS** — no dynamic credentials, no leasing, no expiry.
- It **cannot rotate your provider credentials**. `hush team rm` re-keys the
  vault; only Stripe can rotate a Stripe key.
- **Git history is forever.** A deleted secret is still in history as ciphertext.
- **Redaction is defence in depth, not a boundary.** It masks known values in
  output; a program that base64-encodes a secret before printing defeats it.
  That is what the command policy is for.
- **Revocation protects future values only.** Anyone who could read a secret has
  read it.
