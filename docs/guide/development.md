# Development

No build step and nothing to install — Node 22.18+ runs the TypeScript directly.

```bash
git clone https://github.com/omarei-omoto/hush.git
cd hush
npm install            # devDependencies only: typescript and @types/node
npm test
npm run typecheck
npm link               # use your working copy as the real `hush`
```

Some tests need extra things and skip cleanly without them: `age` on your PATH
turns on the hardware-key path (driven through a real
[C2SP age plugin](https://github.com/C2SP/C2SP/blob/main/age-plugin.md)), and
macOS turns on Touch ID, the Keychain and the native approval dialogs.

Testing is weighted toward the security properties rather than line coverage:
that associated data binds a value to its slot, that per-recipient wrapping makes
revocation real, that the redactor does not split a match across a chunk
boundary, and that no MCP tool can be made to hand back a value. The bar for a
change is a test that fails without it — see [CONTRIBUTING.md](../../CONTRIBUTING.md),
which explains why that is stated so bluntly.

```bash
HUSH_FUZZ_SCALE=40 node --test test/fuzz.test.ts   # the same search, 40x deeper
```

The single-file binary is built with [Bun](https://bun.sh) (the version is
pinned in `.bun-version`), and the whole suite runs against it:

```bash
npm run build:binaries                                  # this machine's; --all for every target
HUSH_TEST_BINARY=$PWD/release/hush-darwin-arm64 npm run test:binary
```
