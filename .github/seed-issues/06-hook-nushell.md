---
title: "Shell hook for nushell"
labels: ["help wanted"]
---

`hush hook zsh|bash|fish|powershell` prints a hook that loads a project's sets on `cd` and unloads them on leaving. nushell has `$env.config.hooks.env_change.PWD` for this.

**Files**
- `src/commands/hook.ts`: a `nu` branch beside `fish` and `powershell`. It asks `hush export --names` which keys to unset, the same as the others do, and must never `eval` a value.
- `src/cli/help.ts` and the README's "The shell hook" section.

**Test**: the printed hook parses (`nu --commands` when nushell is on the PATH; otherwise skip, and say so). Also: a key name that is not a valid identifier is filtered out, not escaped. See `toShellExports` in `src/run.ts` for why.

---
**The bar:** a test that fails without the change (CONTRIBUTING.md, "The bar for a change"). Run it with `node --test <file>`; use a throwaway `HUSH_HOME` to try it by hand.
