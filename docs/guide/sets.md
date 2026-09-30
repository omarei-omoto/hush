# Sets

Everything in hush is a **set**: some keys, a name you chose, an optional
description, and an optional note on when to use it. `dev`, `prod`,
`Personal fal`, `Acme Production` — all sets. There is no second concept to
learn.

A set lives in one of two places:

- **Your library** — `~/.hush/vaults/<name>`, yours alone, never in any repo.
  A key you use across projects lives here once, so rotating it is one edit.
- **This project** — `.hush/vault.json`, committed, shared with your team.

A project *uses* sets. Its own `default` set is always used, as the floor;
everything else layers on top in the order you added it, later wins.

**Your library is a catalog, not a floor.** Nothing in it reaches a folder
until that folder asks: `hush use <set>`, or tell your agent which ones you want
and it adds them. Its `default` set is your catch-all (`hush add K=v --library`
with no `--to` lands there); use it in a folder with
`hush use default --library`. Add more from the library any time.
`.hush/envs.json` records only the *names* — a teammate who clones the repo
gets "this project uses a set called acme-production" and supplies their own.

```bash
hush add .env.production --as "Acme Production" --library \
  --description "Live Stripe + Convex" --when "deploys only"
hush add DATABASE_URL=postgres://… --to "Acme Production"   # one value into a set
hush add fal --as "Personal fal" --library                   # a known service: asks for FAL_KEY, hidden

hush use acme-production      # this project uses it
hush use                      # what this project uses, in order
hush use --not acme-production
```

A set you make from inside a project is used by that project automatically
(`--no-use` to opt out), so `hush add .env --as Dev` followed by `hush npm
run dev` just works.

```
$ hush ls

YOUR LIBRARY  (global)
  ● Acme Production (acme-production)  12 key(s)
      Live Stripe + Convex
      when: deploys only
    Personal fal (personal-fal)  1 key(s)

THIS PROJECT
  ● default (default)  2 key(s)

  ● = used by this project.
```

`hush ls <set>` lists one set's key names — never values.

**Everything already in one pile?** That is where everyone starts. Make the
sets you want and move keys across — the value is re-encrypted under its new
name, so it is a real move rather than a relabelling:

```bash
hush env move STRIPE_SECRET_KEY DATABASE_URL --to "Acme Production"
```

**Renaming works properly.** `hush env rename acme-production "Acme Prod EU"`
re-seals every value under `acme-prod-eu` and updates any project using the old
name. Nothing is left pointing at a name that no longer exists.

Values are cryptographically bound to their set: a `staging` ciphertext cannot
be moved into the `prod` slot, even by someone editing the JSON by hand.
