---
title: "hush import --format vault (HashiCorp Vault KV)"
labels: ["good first issue"]
---

`vault kv get -format=json secret/app` prints `{ "data": { "data": { KEY: value, … }, "metadata": … } }` for KV v2, or `{ "data": { KEY: value } }` for KV v1. Import either:

```bash
vault kv get -format=json secret/app | hush import - --format vault --as Prod
```

**Files**
- `src/import.ts`: the format and a parser that tells v1 from v2 by shape.
- `src/commands/import.ts`: the format name and help.

**Test** (`test/import.test.ts`): a v1 and a v2 fixture give the same pairs; a nested (non-string) value is refused, naming the key only.

---
**The bar:** a test that fails without the change (CONTRIBUTING.md, "The bar for a change"). Run it with `node --test <file>`; use a throwaway `HUSH_HOME` to try it by hand.
