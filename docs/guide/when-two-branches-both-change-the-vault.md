# When two branches both change the vault

Two people adding keys on two branches is ordinary; a vault file that conflicts
as a wall of base64 is not something anyone can resolve by eye. hush merges it
key by key:

```bash
hush merge-driver --install   # once per clone: git hands vault merges to hush
```

After that, a `git merge` or `git pull` that touches `.hush/vault.json` just
works — keys added on each side are kept, a rotation or a removal on one branch
wins and everything from the other branch is re-sealed under the new key, and a
member added on one branch while the other rotated is given the new key. When
both branches changed the same key differently, git stops, the file keeps your
branch's value, and you choose:

```bash
hush merge status                    # set, key, who changed it on each side, when — never a value
hush merge pick STRIPE_KEY --theirs  # or --ours
```

Both branches rotating the key (two revocations) is never merged automatically.

The driver is switched on per clone, in `.git/info/attributes` and your git
config, never in a committed file: git falls back to a line-by-line text merge
when a named driver is not configured, which could quietly break a vault. A
teammate who has not installed it still gets a safe conflict, and `hush merge`
finishes it.
