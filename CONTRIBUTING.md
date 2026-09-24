# Contributing

Thanks for looking. This is a small project with one maintainer, so the most
useful things you can do are: try it and tell me where it confused you, find a
way to get a secret out of it that it should not allow, or run it somewhere I
cannot (Linux, Windows, a YubiKey I do not own).

## Getting set up

You need Node 22.18 or newer (the first 22.x that runs TypeScript without a
flag). There is no build step and no dependencies to install — Node runs the
TypeScript directly. The published package itself still runs on 22.6+.

```bash
git clone https://github.com/omarei-omoto/hush.git
cd hush
npm install        # devDependencies only: typescript and @types/node
npm test
npm run typecheck
```

To use your working copy as the real `hush` command:

```bash
npm link
hush --version
```

`bin/hush.js` runs `src/` from a clone and `dist/` from an installed copy, so
linking picks up your edits immediately with no rebuild.

Some tests need extra things and skip cleanly without them:

- `age` on your PATH exercises the hardware path through a real
  [C2SP age plugin](https://github.com/C2SP/C2SP/blob/main/age-plugin.md)
  (`brew install age`).
- macOS exercises Touch ID gating, the Keychain and the native approval dialogs.

A skipped test is reported as skipped, never as a pass.

## The bar for a change

**Every behavioural claim needs a test that fails without it.** Not "there is a
test in the area" — a test that goes red when you break the thing. The way to
check is to break it on purpose and watch:

```bash
# make the change, then revert just the fix and run the test again
npm test
```

This is not a style preference. Several tests in this repo passed for years
against broken code:

- A CLI helper wrapped `execFileSync` in a `try/catch` that turned *any*
  exception into `{ code: 1 }`, so a test asserting a non-zero exit passed
  without the CLI ever starting.
- A test for shell quoting asserted the *vulnerable* output format verbatim, so
  it faithfully pinned a command-injection bug in place.
- A control-character test asserted over `JSON.stringify` of the output, which
  escapes control characters — so its regex could never match.

There are now drift checks that refuse those patterns. If one fires on your
change, it has probably caught something real.

**Mutation testing is how the bar is checked.** The habit is: change a line to
something wrong, run the suite, and confirm something fails. If nothing does,
the property is untested no matter how many tests surround it. A run that cannot
come back bad is not a measurement — the harness used here has been wrong in
both directions and produced a page of confident nonsense each time.

**Say why in the comment, not what.** The code says what it does. A comment
earns its place by explaining the thing that is not visible: what went wrong
before, what breaks if you change it back, why the obvious approach was not
taken.

## What a good pull request looks like

- One concern per PR.
- `npm test` and `npm run typecheck` both clean.
- New behaviour comes with a test; a bug fix comes with the test that would have
  caught it.
- The commit message says what changed and why, in plain words.

I would rather see a small PR with a failing test attached than a large one
without.

## Things that are deliberate, so please ask before changing

- **Zero runtime dependencies.** Everything is `node:crypto` and friends. A
  dependency in a tool that holds credentials is a supply-chain decision, not a
  convenience one.
- **No tool ever returns a secret value.** The MCP server exposes no getter, and
  `hush_run` redacts. This is the whole premise; a "just this once" escape hatch
  would end it.
- **Values are bound to their environment and key name** through AEAD associated
  data, which is why renaming an environment re-encrypts everything rather than
  editing a map key.
- **The security ladder never blocks.** A tool that refuses to run until you buy
  a YubiKey gets uninstalled, and the person goes back to a plaintext `.env`.

## Reporting a security problem

Not here. See [SECURITY.md](./SECURITY.md) — open a private advisory rather than
an issue.

## Where the code is

| | |
|---|---|
| `src/crypto.ts` | The scheme: sealing values, wrapping data keys |
| `src/vault.ts` | The vault file, locking, merging, named env sets |
| `src/library.ts` | Your global library, and what a project takes from it |
| `src/run.ts` | Running a command with secrets injected, and redacting its output |
| `src/mcp.ts` | The agent-facing server and its policy |
| `src/ui.ts` | The local app, server and page |
| `src/cli.ts` | Every command |
| `docs/AUDIT.md` | Every defect found so far and what changed |

The tests are worth reading before the source: `test/invariants.test.ts` is a
list of properties that turned out not to hold.
