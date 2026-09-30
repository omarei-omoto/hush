---
title: "GitLab CI and CircleCI templates"
labels: ["help wanted"]
---

The GitHub Action (`action.yml`) installs the checked binary, masks the identity and verifies the vault before any step uses it. GitLab CI and CircleCI users need the same thing:

- GitLab: a CI/CD component or an `include:` template.
- CircleCI: an orb.

Both run `scripts/install.sh`, keep `HUSH_IDENTITY` in a masked variable, and run `hush verify`.

**Test**: at minimum, a lint of each file in CI (`gitlab-ci-lint` via the API is not available offline, so a YAML shape test), plus a subsection for each under the README's "CI" heading.

---
**The bar:** a test that fails without the change (CONTRIBUTING.md, "The bar for a change"). Run it with `node --test <file>`; use a throwaway `HUSH_HOME` to try it by hand.
