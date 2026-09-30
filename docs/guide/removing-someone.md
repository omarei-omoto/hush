# Removing someone

```bash
hush team rm sam
```

That mints a **new data key**, re-encrypts every value under it, and re-wraps it
for everyone except Sam. Sam's old checkout of the repo decrypts nothing new.

> hush tells you the honest part too: Sam can still use any value they already
> read. Rotate those at the provider. No tool can undo a value someone saw.
