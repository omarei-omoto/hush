---
title: "hush doctor --json"
labels: ["good first issue"]
---

`hush doctor` prints a checklist for a person. Scripts and the app would like the same checks as data:

```json
{"checks":[{"id":"identity","ok":true,"detail":"macOS Keychain"}, …]}
```

**Files**
- `src/commands/doctor.ts`: collect the checks into an array first, then print them either as today or as JSON. Keep the exit code rules.

**Test** (`test/commands/doctor.test.ts`): `--json` parses, holds the same checks as the text output, and contains no private key or value (assert it does not contain the test identity's `hush_sk_…`).

---
**The bar:** a test that fails without the change (CONTRIBUTING.md, "The bar for a change"). Run it with `node --test <file>`; use a throwaway `HUSH_HOME` to try it by hand.
