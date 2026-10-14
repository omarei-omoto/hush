# Sets

Three things, from small to big:

- **A key** is one value: `STRIPE_SECRET_KEY`.
- **A set** is keys that only work together: "Stripe" holds the secret key,
  the publishable key and the webhook secret. Test and live keys for one
  service are two sets ("Stripe test", "Stripe live"), since they never mix.
  A set has a name you chose, an optional description, and an optional note on
  when to use it.
- **A group** is a folder of sets, for your global keys only: "AI stack"
  holding fal, OpenAI and Anthropic. A project given a group gets every set in
  it, including sets you add to the group later.

Every set is one of two kinds:

| | Who gets it | Where it lives |
|---|---|---|
| **Global** | Any project you give it to | Your library, `~/.hush/vaults/<name>`: yours alone, never in a repository |
| **Only this project** | That one project. hush refuses it in any other folder, for you and your agent | Your library too, marked as that project's |

A key you use in several projects lives once as a global key, so rotating it
is one edit. A key only one project needs is that project's own.

There is a third place, for teams: **the repository's vault**,
`.hush/vault.json`. It is committed, so everyone you add to the project
(`hush team add`) gets its keys. Use it for keys the team shares. A key there
can be made global like any other, but hush asks first, because your
teammates stop getting it from the repository.

## Moving a set or key between the two

- **Make global:** one of a project's own sets (or one key of it) joins your
  global keys, and the project keeps getting it. A single key goes into a
  global set you pick or name.
- **Keep for this project only:** a global set (or one key of it) becomes one
  project's own. If other projects use it, hush names them and asks first; if
  you go ahead, it takes the set or key out of their lists. Nothing is
  deleted.

The app has both in every set's and key's ⋯ menu. In the terminal:

```bash
hush env global stripe-test                        # this project's own set becomes global
hush env global STRIPE_KEY --from web-app --to Stripe   # just one key, into the global set "Stripe"
hush env here stripe                               # a global set, kept for this project only
hush env here FAL_KEY --from fal                   # one key of it
```

## Groups

```bash
hush env group fal "AI stack"        # file a global set under a group
hush env group openai "AI stack"
hush use "AI stack"                  # this project gets every set in the group
hush env group "AI stack" --rename "Gen AI"   # projects using it keep using it
hush env group "Gen AI" --ungroup    # projects that used it keep each set
hush env group fal --none            # out of its group
```

A project's list records a group as `group:<name>`. Like a set, the first time
a project you did not set up yourself names one of your groups, hush asks
before using it.

## Which sets a project uses

A project *uses* sets: its own, and the global ones you give it. Its own
`default` set (in the repository's vault) is always used, as the floor;
everything else layers on top in the order you added it, later wins. When two
of them give the same key, the app says which one wins and lets you switch.

**Your global keys are a catalog, not a floor.** None of them reaches a folder
until that folder asks: `hush use <set>`, a drag in the app, or tell your agent
which ones you want and it adds them. Your library's `default` set is your
catch-all (`hush add K=v --library` with no `--to` lands there); use it in a
folder with `hush use default --library`. `.hush/envs.json` records only the
*names*, so a teammate who clones the repo gets "this project uses a set
called acme-production" and supplies their own.

Because that list travels with the repository, it does not reach your library
on its own. The first time a project you did not link yourself names one of
your library sets, hush asks before using it (on the terminal, or in a dialog),
once per project on this machine; until then the set is left out and hush says
so. `hush use <set>` and the app's "Use here" count as confirming, and
`hush use --confirm` confirms the sets a cloned project already lists. The
confirmation is kept in `~/.hush`, where no repository can write it.

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
run dev` just works. In the app, importing a `.env` on a project makes it that
project's own set, named after the project; importing on Global keys makes it
global.

```
$ hush ls

GLOBAL KEYS  (your library: global)
  ● AI stack/ (group:ai-stack)  2 set(s)
        fal (fal)  1 key(s)
        OpenAI (openai)  1 key(s)
    Acme Production (acme-production)  12 key(s)
      Live Stripe + Convex
      when: deploys only

THIS PROJECT
  ● web-app (web-app)  3 key(s)  only this project
  ● default (default)  2 key(s)  in the repo
  uses from your global keys: AI stack (group)

  ● = used by this project.  hush env global <set> / hush env here <set> move a set between the two.
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
