---
title: "Rotation links for 20 more providers"
labels: ["good first issue"]
---

`hush exposed` and `hush team rm` point at the page where a key is replaced at the provider, using `rotate:` in `CATALOG` (`src/services.ts`). Many common services have no entry yet. Some ideas: Postmark, Mailgun, Algolia, Sentry, Datadog, PlanetScale, Neon, Upstash, Fly.io, Render, Railway, Netlify, DigitalOcean, Heroku, Shopify, Square, PayPal, Plaid, Mapbox, Auth0, Clerk, Okta, Firebase, Cohere, Together, Fireworks, Perplexity.

**Files**
- `src/services.ts`: one line each: `{ vars, label, rotate }`. Check that each URL resolves while signed in, and say in the PR which you checked.

**Test** (`test/freshness.test.ts` or `test/consistency.test.ts`): every `rotate` is `https://`, and every `vars` entry is a valid key name. That test may already exist; if it does, extend it.

---
**The bar:** a test that fails without the change (CONTRIBUTING.md, "The bar for a change"). Run it with `node --test <file>`; use a throwaway `HUSH_HOME` to try it by hand.
