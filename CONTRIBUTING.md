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

### Running one test

```bash
node --test test/trust.test.ts                                   # one file
node --test --test-name-pattern "replayed" test/relay.test.ts    # one test, by name
node --test --test-only test/merge.test.ts                       # tests marked test.only(…)
```

### Trying things without touching your real setup

Everything hush keeps about you lives in `~/.hush` — or wherever `HUSH_HOME`
says. Point it at a scratch directory and nothing you do reaches your real
identity, library, pins or approvals:

```bash
export HUSH_HOME="$(mktemp -d)" HUSH_NO_KEYCHAIN=1
node src/cli.ts id --create
mkdir /tmp/demo && cd /tmp/demo && node ~/hush/src/cli.ts init demo --no-agent
```

`HUSH_NO_KEYCHAIN=1` keeps the identity out of the OS keychain too. The test
helpers do exactly this (`test/helpers/cli.ts`), so a test never sees your
machine's state.

### What needs which machine

| | Linux | macOS | Windows |
|---|---|---|---|
| The whole suite | ✓ | ✓ | the Windows job in CI runs the platform tests (beta) |
| Touch ID, Keychain, native dialogs, Secure Enclave | skipped | ✓ | — |
| zenity / kdialog dialogs | ✓ with a desktop (tests use a stand-in) | stand-in | — |
| DPAPI, the WinForms dialog, `.cmd` quoting | — | — | ✓ |
| The single-file binary | ✓ (`npm run build:binaries`, needs [Bun](https://bun.sh)) | ✓ | ✓ |

If you change something Mac-only and have no Mac, say so in the PR. CI runs
macOS on every push. Anything that shows a real dialog or asks for a real
fingerprint is driven through an in-process stand-in in the tests, never
through an environment variable. [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md)
says why.

### The binary

```bash
npm run build:binaries                                            # this machine's build, into release/
HUSH_TEST_BINARY=$PWD/release/hush-darwin-arm64 npm run test:binary  # the whole suite against it
```

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

## Releasing

Releases are published by `.github/workflows/release.yml`, never from a laptop.
There is no npm token: npm's trusted publishing checks the workflow's GitHub
identity, and the package page gets a provenance badge that links back to
the commit.

1. On a branch: `npm version <x.y.z> --no-git-tag-version`. This updates
   `package.json`, `package-lock.json` and `src/version.ts`. Then move the
   CHANGELOG's `Unreleased` notes under a `## x.y.z — date` heading.
2. Merge that PR once CI is green.
3. Tag the merge commit on `main` and push the tag:
   `git tag vx.y.z && git push origin vx.y.z`.

The workflow refuses a tag that does not match `package.json` and
`src/version.ts`, runs the full suite, then publishes. The one-time setup is
on npmjs.com: @omarei/hush → Settings → Trusted publishing → GitHub Actions,
repository `omarei-omoto/hush`, workflow `release.yml`, **Allow npm publish**
ticked. (For an approval step before each release, change the workflow's
last line to `npm stage publish` and approve on npmjs.com.)

## Reporting a security problem

Not here. See [SECURITY.md](./SECURITY.md) — open a private advisory rather than
an issue.

## Where the code is

[docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) has the map: how one `hush run`
flows through the code, which file does what, and which tests guard each
property. In short, `src/commands/<command>.ts` has one file per command,
`src/crypto.ts` has the scheme, and `docs/AUDIT.md` lists every defect found so
far and what changed.

The tests are worth reading before the source: `test/invariants.test.ts` is a
list of properties that turned out not to hold.

## Good first issues

Issues labelled `good first issue` name the files to touch and the test to
write. Adding an agent, an import format, a language to `hush scan` or a
provider's rotation link is usually one function, one fixture and one test.
