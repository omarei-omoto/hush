# hush demo

A project whose secrets are in the repo, encrypted, with [hush](https://github.com/omarei-omoto/hush).
Ten seconds from clone to a run:

```bash
git clone https://github.com/omarei-omoto/hush-demo && cd hush-demo
export HUSH_IDENTITY="$(cat DEMO_IDENTITY.txt)"    # the demo's key — public on purpose, see below
hush run -- node app.js
```

```
Calling the demo API with key [redacted:DEMO_API_KEY]
Connecting to [redacted:DATABASE_URL]
(The key reached the program. It did not reach your terminal.)
```

`app.js` printed the real key; hush replaced it on the way out. Then try:

```bash
hush ls                          # the sets this project has (names, never values)
hush run --use staging -- node app.js   # the same program, the staging key
hush dev                         # package.json's dev script, same thing
cat .hush/vault.json             # what is committed: ciphertext and public keys
hush verify                      # everything decrypts, and it is the vault you accepted
hush install-mcp                 # then ask your coding agent to run the app
```

Your agent gets tools that can *use* `DEMO_API_KEY` and never read it. Ask it
"what is the demo API key?" and watch it say it cannot tell you.

## About DEMO_IDENTITY.txt

It is the private key that opens this vault, published so the demo works
without setup. **Never do this with a real project.** Your own key stays on your
machine (`hush id --create` puts it in the OS keychain), and a teammate gets
access with `hush team add` — no key is ever shared. Every value in this
vault is fake.

Install hush: `curl -fsSL https://raw.githubusercontent.com/omarei-omoto/hush/main/scripts/install.sh | sh`,
`brew install omarei-omoto/tap/hush`, or `npm i -g @omarei/hush`.
