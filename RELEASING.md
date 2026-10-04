# Releasing hush

A release is a signed tag. Nothing is published from anyone's laptop.

## Steps

1. **Everything green on `main`.** CI runs the suite on Linux and macOS, Node 22
   and 24, the packaged-install check, and `npm run build:check`.
2. **Changelog.** Move the `Unreleased` section under a new heading,
   `## x.y.z — YYYY-MM-DD`. Say plainly what changed for someone upgrading, and
   call out anything that breaks.
3. **Version.** `npm version x.y.z --no-git-tag-version` updates `package.json`
   and the lockfile, and the `version` script rewrites `src/version.ts` — the
   one place the version is written. The release workflow refuses a tag that
   disagrees with either.
4. **Commit** `Release x.y.z`.
5. **Tag, signed.** `git tag -s vx.y.z -m "hush x.y.z"`. A signed tag says who
   cut the release; GitHub shows it as verified when the signing key is on the
   maintainer's account. Set one up once with `git config --global
   user.signingkey …` (GPG or SSH signing both work).
6. **Push the tag.** `git push origin vx.y.z`. `.github/workflows/release.yml`
   then:
   - checks the tag matches `package.json` and `src/version.ts`,
   - type-checks, proves the build reproducible, runs the whole suite,
   - publishes through npm trusted publishing (no token exists anywhere) with
     provenance, which ties the tarball to that workflow run and commit;
   - builds the single-file binaries for every target on one Linux runner,
     twice, and fails if the two builds differ; runs the whole suite against
     the Linux binary;
   - signs and notarizes the macOS binaries when the Apple secrets exist (below),
     and runs the macOS binary end to end either way;
   - writes `SHA256SUMS` over the final bytes, attests every binary and the sums
     with GitHub build provenance (Sigstore), and creates the GitHub release
     from the tag with the changelog section as notes, the binaries, the sums,
     `hush.rb` (Homebrew), `hush.json` (Scoop) and the winget manifests;
   - lists the version in the official MCP registry (`server.json`), signed in
     with the workflow's GitHub OIDC identity;
   - pushes the formula to the Homebrew tap when `HOMEBREW_TAP_TOKEN` exists.
     Without it the tap catches up by itself within six hours: its own workflow
     takes `hush.rb` from the latest release after checking every hash in it
     against that release's `SHA256SUMS`.
7. **winget.** Submit the manifests from `winget-manifests.tar.gz` to
   [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) — by hand
   (`wingetcreate submit <dir>`) until the package is established there.

## A beta

A tag with a hyphen, `vx.y.z-beta.n`, is a prerelease: the same workflow
publishes it to npm's `beta` tag and as a GitHub prerelease, and leaves the
stable channel alone (npm `latest`, Homebrew, install.sh, the MCP registry).
Cut betas from the `beta` branch; when one is ready, merge `beta` into `main`
and tag the stable version there. The docs site deploys from `main` only.

## The binaries, once

Nothing here is needed for a release to work — without it the binaries ship
ad-hoc signed, and Homebrew users are one manual formula copy behind.

- **Homebrew tap.** `omarei-omoto/homebrew-tap` exists and updates itself from
  each release. For an immediate update instead of within six hours, make a
  fine-grained token with *Contents: write* on that repository only and store
  it as the `HOMEBREW_TAP_TOKEN` secret.
- **Apple Developer ID** ($99/year). With it, the macOS binaries are signed with
  the hardened runtime and notarized, so a copy downloaded in a browser opens
  without a Gatekeeper warning. (curl and Homebrew do not quarantine, so they
  work without it; the Secure Enclave identity does not need it either —
  docs/BIOMETRY.md.) Secrets:
  - `APPLE_CERTIFICATE_P12` — the Developer ID Application certificate and key,
    exported as .p12, base64-encoded; `APPLE_CERTIFICATE_PASSWORD` — its password;
  - `APPLE_SIGNING_IDENTITY` — e.g. `Developer ID Application: Name (TEAMID)`;
  - `APPLE_NOTARY_KEY`, `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER` — an App
    Store Connect API key (the .p8 text, its id, the issuer id) for notarytool.

  The one entitlement is `com.apple.security.cs.allow-jit`
  (`scripts/macos-entitlements.plist`, which says why the others Bun suggests
  are left out).
- **Bun.** The version that builds the binaries is `.bun-version`. Bumping it is
  a normal change: CI builds twice and runs the whole suite against the result.

## The docs site at tryhush.dev, once

The site is built by `.github/workflows/docs.yml` and served by GitHub Pages
under the custom domain `tryhush.dev` (the build writes the `CNAME` file).

1. **Verify the domain with GitHub first**, so nobody else's Pages site can
   claim it: GitHub → your Settings → Pages → Add a domain → `tryhush.dev`,
   then add the `TXT` record it shows in Cloudflare.
2. **DNS in Cloudflare** (DNS → Records), all *DNS only* (grey cloud) until
   GitHub has issued the certificate:
   - `A` `@` → `185.199.108.153`, `185.199.109.153`, `185.199.110.153`, `185.199.111.153`
   - `AAAA` `@` → `2606:50c0:8000::153`, `2606:50c0:8001::153`, `2606:50c0:8002::153`, `2606:50c0:8003::153`
   - `CNAME` `www` → `omarei-omoto.github.io`
3. **The repository**: Settings → Pages → Custom domain `tryhush.dev`, then
   tick *Enforce HTTPS* once the certificate is issued (it can take a while).
4. The site deploys from `main` only, so it always describes the stable
   release.

If you later switch the Cloudflare records to *Proxied*, set SSL/TLS to
*Full (strict)* so Cloudflare checks GitHub's certificate.

## Checking a release

- A binary: `gh attestation verify hush-linux-x64 --repo omarei-omoto/hush`
  shows the workflow and commit that built it; `sha256sum -c SHA256SUMS
  --ignore-missing` checks the bytes. To rebuild one yourself: check out the
  tag, install the Bun in `.bun-version`, `node scripts/build-binaries.mjs --all`
  — the ad-hoc-signed binaries match `SHA256SUMS` byte for byte; the Developer
  ID-signed macOS ones differ only by their signature.

- `npm view @omarei/hush@x.y.z --json | jq .dist` — the tarball's integrity hash.
- The package page on npmjs.com shows the provenance statement: the repository,
  the workflow, and the commit it was built from.
- To rebuild it yourself: check out the tag, `npm ci`, `npm run build:check`
  prints a sha256 over `dist/`; `npm pack` produces the same tarball contents.

## Security releases

Fix on a private branch or a draft GitHub security advisory (it provides a
private fork), release with a changelog line that says what to do without
explaining how to exploit it, and publish the advisory about a week later. See
[SECURITY.md](./SECURITY.md).
