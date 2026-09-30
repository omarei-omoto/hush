---
title: "hush scan: Swift, Dart and Elixir"
labels: ["good first issue"]
---

`hush scan` finds the variables a codebase reads. It does not know:

- Swift: `ProcessInfo.processInfo.environment["STRIPE_KEY"]`
- Dart / Flutter: `Platform.environment['STRIPE_KEY']` and `String.fromEnvironment('STRIPE_KEY')`
- Elixir: `System.get_env("STRIPE_KEY")` and `System.fetch_env!("STRIPE_KEY")`. `.ex` and `.exs` files are already scanned, but no pattern matches.

**Files**
- `src/scan.ts`: add the extensions to `SCAN_EXT` (`.swift`, `.dart`) and one regex per form to `PATTERNS`, with a comment naming the language.

**Test** (`test/invariants.test.ts` has the scan cases; or a new block in `test/commands/scan.test.ts`): a file per language, and the names it must find. Include a lowercase name, which must *not* be reported.

---
**The bar:** a test that fails without the change (CONTRIBUTING.md, "The bar for a change"). Run it with `node --test <file>`; use a throwaway `HUSH_HOME` to try it by hand.
