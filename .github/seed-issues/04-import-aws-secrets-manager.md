---
title: "hush import --format aws (Secrets Manager)"
labels: ["good first issue"]
---

`aws secretsmanager get-secret-value --secret-id app/prod` prints `{ "SecretString": "<JSON or text>", … }`. When `SecretString` is a JSON object, import its pairs. When it is a single string, `--key NAME` names it.

**Files**
- `src/import.ts`: the format and a parser (the `SecretString` JSON is parsed a second time).
- `src/commands/import.ts`: the format name and `--key`.

**Test** (`test/import.test.ts`): object form, string form with `--key`, string form without `--key` (a refusal that says what to pass).

---
**The bar:** a test that fails without the change (CONTRIBUTING.md, "The bar for a change"). Run it with `node --test <file>`; use a throwaway `HUSH_HOME` to try it by hand.
