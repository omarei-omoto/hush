# Touch ID

```bash
hush biometry setup
```

Then set `"biometry": "required"` in `.hush/policy.json` and the approval step
becomes a fingerprint instead of a click. `"required"` refuses to proceed if
biometry is unavailable — it will not silently downgrade.

Be clear-eyed about what this is: it proves a human is physically at the machine,
so your agent cannot approve its own request and nobody can use your keys from
your unlocked laptop. It does **not** protect the key at rest — for that, move
the key itself into hardware ([Hardware keys](hardware-keys.md)).
