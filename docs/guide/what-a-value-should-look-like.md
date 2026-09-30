# What a value should look like

The most common failure is not a leak, it is a wrong value: the test key in the
production set, a truncated paste, a key whose prefix the SDK checks before it
will talk to the API. A `.env.schema` declares the shape, in the same
`@env-spec` syntax Varlock reads, so a schema you already have works here
unchanged:

```bash
# @required @type=url
API_URL=

# @type=string(startsWith=sk-) @required
STRIPE_SECRET_KEY=

# @type=enum(development, preview, production) @sensitive=false
APP_ENV=development

# @type=port
PORT=3000
```

`@sensitive=false` is a *request*, not a permission. It asks for a key to be
printed unmasked (useful for `NODE_ENV` or a `PORT`, which otherwise show as
`[redacted:…]` on every line). Because the schema is a file in the repo, hush
honours it only for keys you have listed in your own floor's `unmaskKeys`; every
other request is ignored and named in a warning on the run. Without that, a
repository could turn output masking off for a credential it can never read.

Supported: `@required`, `@type=` `string`/`number`/`boolean`/`url`/`port`/
`email`/`enum(...)`, `@type=string(startsWith=…, minLength=…, maxLength=…)`,
`@pattern=`, and `@sensitive=false`. The placeholder after `=` is ignored:
hush reads this file for *rules*, and the vault is the only source of values.
`@default` is deliberately not implemented, because an injected default would
make "the vault is the source of truth" quietly false.

`hush run` and `hush request` check the keys they are about to use and refuse
before anything is spawned or sent (`--no-validate` overrides; an agent cannot).
Only the keys in play are checked, so a production rule cannot block a dev
command that never touches it. `hush doctor` reports everything. A failure
names the key, the rule, and the length — never the value.

`@sensitive=false` means "do not mask this in output", which is what the mask is
for: `NODE_ENV=production` arriving as `[redacted:NODE_ENV]` on every line is
how people learn to ignore it. The value is still encrypted at rest.
