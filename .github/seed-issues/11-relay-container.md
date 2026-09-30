---
title: "A container image and deploy notes for `hush relay serve`"
labels: ["help wanted"]
---

Some teams want one relay for everyone rather than `ssh -R`. `hush relay serve` is a single process with no state worth keeping (docs/RELAY.md).

- A `Dockerfile` that runs the single-file binary as a non-root user with a read-only filesystem, listening on `0.0.0.0:8787`.
- Notes for putting it behind TLS: Caddy, fly.io, a Cloudflare tunnel. hush refuses a plain-http relay that is not localhost.

**Test**: CI builds the image and runs the relay tests against it with `HUSH_TEST_BINARY` … or, simpler, `curl /v1/health` against the running container.

---
**The bar:** a test that fails without the change (CONTRIBUTING.md, "The bar for a change"). Run it with `node --test <file>`; use a throwaway `HUSH_HOME` to try it by hand.
