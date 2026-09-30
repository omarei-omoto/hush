# Giving someone only some sets

Not everyone needs everything. A *scoped* member reads only the sets you name:

```bash
hush team add junior hush_pk_… --sets dev,staging
hush team rm junior --from staging     # take one away; that set gets a new key
```

Each of those sets gets a key of its own, wrapped for every full member and for
the scoped members given it; everything else stays out of reach — not hidden in
the UI, but unreadable with their key and the vault file both in hand. A run in
a project that also uses sets they were not given skips those and says so;
asking for one by name (`--use prod`) says who can grant it. `hush ls <set>`
shows who can read a restricted set.
