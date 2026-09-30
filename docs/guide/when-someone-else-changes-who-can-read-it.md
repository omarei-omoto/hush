# When someone else changes who can read it

The vault file travels through git, and anyone who can get a change merged can
put a vault there — including one they built themselves, wrapped to every
member's public key and to their own. So each machine remembers who it has
accepted. When you pull a vault with a member *you* did not add, hush stops:

```
✗ This vault's membership changed, and nobody on this machine accepted it:
  new: dana  hush_pk_Q2hlY2sgd2l0aC…  (fingerprint 5c1e0d9a7b3f2e41)
  …
  If you expected this:  hush team accept
  If you did not:        hush team reject   (how to undo it)
```

In a **signed** vault this only happens when something is off: a change signed
by an admin your machine already trusts arrives with a one-line notice ("alice
changed who can read this vault: added dana (signed)"), and hush refuses a
header that is unsigned, signed by someone who is not an admin, or signed by an
admin your machine has never seen — the last one until you have checked them
with `hush team verify`. The prompt above is what an **unsigned** (older) vault
gets for any membership change.

Nothing is decrypted or added until you decide — a member added by someone who
is not a real teammate would read every secret added from then on. Check with
whoever added them (`hush team accept` shows the commit and author), then accept.
Removals and key rotations by teammates go through on their own; a rotation is
mentioned once. Your coding agent is told never to accept on your behalf, and
with approvals on, `hush team accept` asks on your screen like any other gated
action.
