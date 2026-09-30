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
     provenance, which ties the tarball to that workflow run and commit.
7. **GitHub release.** Create one from the tag with the changelog section as
   its notes.

## Checking a release

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
