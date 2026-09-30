---
title: "hush import --format infisical"
labels: ["good first issue"]
---

`infisical export --format=json` prints a list of `{ "key": …, "value": … }` objects. Today that has to go through `jq` first. hush should read it directly:

```bash
infisical export --env=prod --format=json | hush import - --format infisical --as Prod
```

**Files**
- `src/import.ts`: add `"infisical"` to `ImportFormat`, and a `parseInfisical()` beside `parse1Password()`. Keep its rules: keys must pass `assertKeyName`, and an error never quotes a value.
- `src/commands/import.ts`: accept the format name, and list it in the help line.

**Test** (`test/import.test.ts`): a fixture in the real export shape parses to the expected pairs; a malformed entry is refused with a message that does not contain the value; a duplicate key is reported.

---
**The bar:** a test that fails without the change (CONTRIBUTING.md, "The bar for a change"). Run it with `node --test <file>`; use a throwaway `HUSH_HOME` to try it by hand.
