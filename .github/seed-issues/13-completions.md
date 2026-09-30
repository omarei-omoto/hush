---
title: "Shell completions: hush completion zsh|bash|fish"
labels: ["good first issue"]
---

Complete commands, flags, set names (from `hush ls --json`) and member names (from `hush team ls`). Set and member names are safe to offer. Values must never be; completion must never call anything that decrypts.

**Files**
- `src/commands/completion.ts` (new), registered in `src/cli.ts` and listed in `src/cli/help.ts`. The command list should come from the `COMMANDS` table, so a new command cannot be missed.

**Test**: the zsh, bash and fish scripts include every command in `hush help --all`. `test/consistency.test.ts` already walks that list, so reuse it.

---
**The bar:** a test that fails without the change (CONTRIBUTING.md, "The bar for a change"). Run it with `node --test <file>`; use a throwaway `HUSH_HOME` to try it by hand.
