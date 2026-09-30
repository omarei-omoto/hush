---
title: "hush import --format bitwarden"
labels: ["good first issue"]
---

`bw get item <id>` and `bw list items --search …` print items whose `login.password`, `notes` and `fields[]` hold secrets. Read them the way `--format 1password` reads `op item get --format json`: one key per concealed field, named from the field name (`fields[].name`), and `--as` names the set.

**Files**
- `src/import.ts`: add `"bitwarden"` to `ImportFormat` and a parser. `parse1Password()` is the model to follow: a single item or a list, skip empty fields, derive a valid key name or refuse.
- `src/commands/import.ts`: the format name and help.

**Test** (`test/import.test.ts`): one item, a list, a field whose name cannot be a key (refused, and the value is not in the message).

---
**The bar:** a test that fails without the change (CONTRIBUTING.md, "The bar for a change"). Run it with `node --test <file>`; use a throwaway `HUSH_HOME` to try it by hand.
