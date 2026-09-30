# CI

Give CI an identity of its own that reads only what the jobs need:

```bash
hush ci create github --sets ci,staging | gh secret set HUSH_IDENTITY
git commit -am "CI can read ci and staging"
```

Piped, it prints the private key alone, straight into the secret store, and
keeps it nowhere. A CI identity is a scoped member marked as a machine: never an
admin, never able to sign, and `hush ci rm github` rotates only the sets it
could read.

In GitHub Actions:

```yaml
- uses: omarei-omoto/hush@v1
  with:
    identity: ${{ secrets.HUSH_IDENTITY }}
    version: 1.0.0
- run: hush run -- npm test
```

The action masks the identity, installs the hush binary for the runner — no
Node needed; the sha256 and the build-provenance attestation are checked before
it runs (`install: npm` uses the npm package instead) — and checks the identity
can read the vault before any later step needs it. In a job, `hush run` also has GitHub
mask every injected value line by line, so GitHub's own log redaction applies on
top of hush's — only for a CI identity, so an agent on a laptop setting
`GITHUB_ACTIONS` itself gets nothing printed. Anywhere else,
`HUSH_IDENTITY=… hush run -- npm test` works the same way.
