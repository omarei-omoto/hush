# Sending keys to your hosts

Your app runs somewhere — a Cloudflare Worker, a Vercel project, a Fly app — and
that place needs its own copy of some keys. `hush push` sends one there through
the host's own CLI, with the value on the CLI's standard input:

```bash
hush push STRIPE_SECRET_KEY --to cloudflare            # the Worker named in wrangler.jsonc
hush push DATABASE_URL --to vercel --env production
hush push OPENAI_API_KEY --to fly                      # the app named in fly.toml, staged for the next deploy
hush push SENTRY_AUTH_TOKEN --to github --env production
```

The value never goes on a command line (where `ps` and your agent's transcript
would see it), never through a shell, and never through the chat. You approve
each push in a dialog that names where it goes. In the app, a key's ⋯ menu has
**Send to…**; your agent has `hush_push`.

hush remembers where each key went — on this machine, in `~/.hush`, never in the
repository — so after you replace a value:

```bash
hush push --again                 # every key, everywhere it was sent, with its current value
hush push --again STRIPE_SECRET_KEY
hush push --list                  # where this project's keys went, and which changed since
hush push --hosts                 # what hush can send to, and which this project deploys to
```

The app suggests the same: *"STRIPE_SECRET_KEY changed after it was sent to
Cloudflare Workers · linkdaisy — Send the new value"*.

## Exactly the value you keep, or nothing

Every host's CLI reads a secret from stdin a little differently: Wrangler trims
trailing whitespace, Fly trims both ends, Vercel keeps only the first chunk of
its input, Koyeb stops at an empty line. hush knows each one's rule — read from
the CLI's source — and **refuses a value the CLI would change**, saying why,
rather than sending something that arrives different. In practice: a value with
a space or a newline at either end, or a carriage return, is refused by most
hosts; remove it in hush (**Replace value**) if it is not meant to be there.

Before it sends anything, hush checks the CLI installed on your machine is one
those rules describe: its help must show the flags hush relies on, and where the
behaviour is not in the help, its version must be at least the first one checked.
An older CLI is refused, with the update to make — Railway before `railway
variable set --stdin`, for example.

## Hosts

| `--to` | Host | Where it goes (`--target`) | `--env` | Deploys? |
|---|---|---|---|---|
| `cloudflare` | Cloudflare Workers (`wrangler` 3.0+) | Worker — from `wrangler.jsonc`/`.toml` | Wrangler environment | yes, a new version |
| `cloudflare-pages` | Cloudflare Pages (`wrangler` 3.49+) | Pages project — from the config | — | next deployment |
| `vercel` | Vercel | project (default: the linked one) | `production`, `preview`, `development` (required) | redeploy to apply |
| `convex` | Convex (1.27+) | deployment name | `dev` (default) or `prod` | live right away |
| `fly` | Fly.io | app — from `fly.toml` | — | staged; `--deploy` to restart now |
| `railway` | Railway (with `variable set --stdin`) | service | environment | skipped; `--deploy` to deploy |
| `firebase` | Firebase Functions | project — from `.firebaserc` | — | next `firebase deploy` |
| `github` | GitHub Actions | `OWNER/REPO` (default: this repo) | GitHub environment | next workflow run |
| `gitlab` | GitLab CI/CD | `GROUP/PROJECT` (default: this repo) | environment scope | next pipeline |
| `gcloud` | Google Cloud Secret Manager | project | — | a new version |
| `koyeb` | Koyeb | — | — | next deploy |
| `fastly` | Fastly Secret Store | secret store ID (required) | — | read from the store |
| `pulumi` | Pulumi config (encrypted) | stack | — | next `pulumi up` |
| `sst` | SST | — | stage | `sst deploy` |

`--as NAME` gives it a different name there. `--from <set>` sends the value from
one set rather than the one a run here gets. `--dry-run` shows the exact command
each push would run, and sends nothing.

A few hosts have rules of their own: Firebase secret names are UPPER_SNAKE_CASE
(its CLI would otherwise rename one without asking), SST names start with a
capital letter, GitHub's cannot start with `GITHUB_`, and Fly takes one-line
values only, without `#` or a leading quote.

## Not here, on purpose

Netlify, Render, Heroku, Expo EAS, Deno Deploy, fal, Upsun, Nhost, Appwrite and
Bitwarden Secrets Manager take a secret only as a command-line argument — in
the process list, and in your agent's transcript if it runs the command. hush
does not drive those CLIs. Set those values in the host's dashboard for now.

## Any other CLI that reads a secret on stdin

```bash
hush run --stdin STRIPE_KEY -- some-cli secrets put STRIPE_KEY
```

`--stdin KEY` writes that one value to the command's standard input and closes
it, under the usual approval — no `sh -c`, nothing on the command line. Your
agent's `hush_run` takes `stdin: "KEY"` for the same.
