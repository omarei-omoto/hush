# The next five

What comes after `hush request`, and why in this order.

`hush request` closed the gap where a caller *is* the HTTP client. This is the
same exercise applied to the other places a credential has to go, plus the two
things that make a vault usable by more than its author.

Each section is the design record, not a wish list: the problem, the shape of
the answer, what it costs, and what it deliberately leaves alone. Status is
tracked per step so this file stays true as the work lands.

| Step | What | Status |
|---|---|---|
| 1 | `--materialize` — credentials that are a file, not a string | shipped |
| 2 | `.env.schema` validation | shipped |
| 3 | `hush import` — bringing in another tool's export | shipped |
| 4 | `hush get --copy` | shipped |
| 5 | Exposure warnings | shipped |

All five shipped together. Two things changed while building them, both
recorded in the sections below rather than quietly:

- **The command is `hush import`, after being `hush adopt` for an hour.** The
  first pass avoided the name because `hush import` already existed as a
  deprecated alias for `hush add <file>`. That alias turned out to be a thin
  wrapper around `hush add` with one legacy flag, and the obvious verb is worth
  more than the alias: everyone types `import`. So the name was taken over, and
  the one form that meant something else now fails with the exact replacement
  (`hush add <file> --to <set>`) instead of quietly doing a different thing.
- **`@default` is not implemented.** It was in the first draft of step 2. A
  default that hush injects when the vault has no value would make "the vault is
  the source of truth" quietly false, so the placeholder after `=` is ignored
  and the directive is left to tools that load config rather than store secrets.

---

## 1. `--materialize` — credentials that are a file, not a string

### The problem

A whole class of credentials is not a string in the environment. It is a
document at a path:

| Tool | What it wants |
|---|---|
| Google Cloud | `GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json` |
| kubectl | `KUBECONFIG=/path/to/config` |
| Docker | `~/.docker/config.json` |
| Java | a `.p12` keystore |
| anything using mutual TLS | a PEM, a client certificate |
| `gcloud`, `aws`, `terraform` with assume-role | a credentials file |

Today the only thing hush can do is `hush export --out .env`, which writes
**every value in the vault**, as plaintext, to a file that then stays there.
That is not a solution to "this one tool needs one file"; it is the problem the
project exists to avoid.

### The design

    hush run --materialize GOOGLE_APPLICATION_CREDENTIALS -- node app.js
    hush run --materialize KUBECONFIG=/tmp/kube.config -- kubectl get pods

Two forms, one rule:

- `--materialize KEY` (no `=`) — hush picks a private path: `mkdtemp` at mode
  0700, the file named after the key in lower case, the whole directory removed
  afterwards.
- `--materialize KEY=/path` — exactly that path.

The child receives the **path** in `KEY`, never the value. The file is created
with `openSync(path, "wx", 0o600)`: `wx` fails if anything already exists, which
is what makes a pre-planted symlink a refusal rather than a write through it.
Removal happens in a `finally`, plus a `process.on("exit")` hook for the
synchronous cases.

### Why this is gated as a *reveal*, not as a run

This is the important decision, and it is not obvious.

`hush run` is gated on the idea that the child is trusted-ish: it gets the value
in its environment, its output is redacted, and a credential stays on this
machine. `--materialize` is different in kind. It hands plaintext to *a path the
caller chose*. An agent holding both `hush_run` and an ordinary file-read tool
could ask hush to materialise the production Stripe key to `/tmp/x`, then read
`/tmp/x` itself. That is exactly the exfiltration the reveal gate exists to
stop, and it would make "you can use it but never read it" false.

So:

- `--materialize` requires the **`reveal`** approval when a policy exists, not
  the `run` approval. The dialog names the paths it is about to write.
- There is **no MCP tool** for it. The agent surface stays value-blind. An
  agent that needs a file-shaped credential is asking for the wrong thing.
- A run that both injects and materialises takes both prompts on first use
  (they are different risks, and "Allow 15 min" caches each separately).

### What could go wrong, and what is done about it

| Risk | Handling |
|---|---|
| A symlink at the target path | `wx` refuses to open an existing file at all |
| Clobbering a real file | Same |
| The world can read it | `0600` on the file, `0700` on a hush-made directory |
| The parent directory is world-writable (`/tmp`) | The hush-managed form avoids it; the explicit-path form is the caller's call, and the docs say so |
| hush is SIGKILLed and never cleans up | Nothing catches SIGKILL. Documented, and the reason the managed form exists |
| The value is left in page cache / the journal | Unavoidable for any file. Documented |
| A directory given as the target | Refused, by name |
| `~` not expanded | Expanded explicitly; a shell that already expanded it is a no-op |

### Tests

- The child sees the path; the file holds the value; mode is `0600`.
- The file is gone after a clean exit **and** after a non-zero exit.
- An existing target path is refused, and nothing is written.
- A symlink at the target is refused, and the link's target is untouched.
- `KEY` with no `=` produces a path that exists during the run and is gone
  after, under a directory that is `0700`.
- A directory as the target is refused.
- With `reveal` gated, the approval is required and the dialog names the path.
- The MCP tool list contains no materialise tool.

### Out of scope

Named pipes and `memfd` (Linux-only, and the platform split is worse than the
few milliseconds it saves); encrypted-at-rest temp files (the point is that the
tool reads it); Windows.

---

## 2. `.env.schema` validation

### The problem

The most common real-world failure is not a leak, it is a wrong value: the test
key in the production set, a truncated paste, a key that does not start with
the prefix the SDK checks for. Nothing in hush looks at a value's *shape*.

`src/scan.ts` already reads `.env.schema` as an input file — as a *list of
names*. Honouring the directives in it is the shortest path from where the code
already is to the feature people expect.

### The syntax: Varlock's, deliberately

The `.env.schema` decorator style is already a de-facto format thanks to
`@env-spec`. Reading it means a team's existing schema works in hush unchanged:

    # @required @type=url
    API_URL=

    # @type=string(startsWith=sk-) @required
    STRIPE_SECRET_KEY=

    # @type=enum(development, preview, production) @sensitive=false
    APP_ENV=development

    # @type=port @default=3000
    PORT=3000

Supported in this pass:

- `@required`
- `@type=string | number | boolean | url | port | email`
- `@type=string(startsWith=…)`, `(minLength=…)`, `(maxLength=…)`
- `@type=enum(a, b, c)`
- `@pattern=<regex>`
- `@sensitive=false` — see below

Deliberately **not** supported: coercion (a `@type=number` port stays the string
the vault holds — validating and rewriting are different jobs), `@import`,
per-environment schema overlays, `@default`, and `${…}` expansion inside values.
Each of those is a bigger change than this step, and expansion in particular
needs a dependency order and a cycle rule that deserve their own design. The
placeholder after `=` is ignored outright: hush reads this file for rules, and
the vault is the only source of values.

### Where it runs

- `hush doctor` reports violations, naming the key, the rule, and nothing else.
- `hush run` and `hush request` validate the keys they are about to use and
  **refuse before spawning or sending**, with `--no-validate` to override.
- `hush add` warns when the value it just wrote violates the schema.

Only the keys in play are validated for a run, so a schema describing a
production secret cannot block a dev command that never touches it.

### `@sensitive=false`

A value explicitly marked not-sensitive is **excluded from the redactor**.
`NODE_ENV=production` and `LOG_LEVEL=debug` currently produce `[redacted:…]`
noise in every run, which trains people to ignore the mask. One honest bit,
honoured in one place, makes the mask mean something again.

It does not change encryption at rest: everything is still sealed. It is a
statement about *output*, which is what the redactor is.

### Messages never carry values

A failed validation says `STRIPE_SECRET_KEY does not start with "sk-" (it is 24
characters)`. It never prints a prefix, a hash, or the value. The length is
there because "did I paste the right thing" is usually answered by the length.

### Tests

- The parser: each directive, several on one line, repeated above one key.
- Each type: pass and fail.
- Missing `@required` is reported by name with the file it is missing from.
- `hush run` refuses before the child is spawned; `--no-validate` runs anyway.
- Validation of a subset: a violation in an unused key does not block a run.
- `@sensitive=false` removes exactly that key from redaction, and no other.
- No message ever contains a value (asserted against the value string).
- No `.env.schema` anywhere is a complete no-op.

---

## 3. `hush import`

### The problem

"I already have sixty secrets in 1Password / Doppler / AWS and I am not
retyping them" is the single most likely reason someone closes the tab. `hush
add .env` is the only door in.

### The design: shapes, not APIs

Every one of those tools can already export. hush should read the export, not
learn fifteen APIs:

    hush import secrets.json --format json --as "Prod"
    doppler secrets download --format json --no-file | hush import - --as "Prod"
    aws secretsmanager get-secret-value --secret-id x --query SecretString \
      --output text | hush import - --format json --as "Prod"
    op item get "Stripe" --format json | hush import - --format 1password --as "Work"

Formats in this pass:

- `dotenv` (the default) — delegates to the existing `parseEnvFile`, so
  `hush import .env --as Dev` and `hush add .env --as Dev` are the same thing.
- `json` — a flat object of name to string. This is what Doppler, AWS Secrets
  Manager and most exports already are.
- `1password` — one `op item get` object, or a list of them: each string field
  becomes a variable, named from its label, upper-cased with everything that is
  not a letter or digit replaced by `_`.

No network calls, no SDKs, no new dependencies, and no vendor auth for hush to
get wrong. The recipes above are the documentation.

### `--dry-run`

Importing someone's whole vault is the moment to look before leaping:
`--dry-run` lists the names it would write and the set it would write them to,
and writes nothing. Output never contains a value, in any mode.

### Collisions

Within one import, a repeated name keeps the last value and says so. Across
sets, nothing is touched: importing into an existing set merges, and the
summary reports how many names were new versus overwritten.

### Tests

- `json`, `dotenv`, and both `1password` shapes (one item, a list).
- Names are sanitised (`Client Secret` becomes `CLIENT_SECRET`).
- A collision inside one import keeps the last and warns.
- Merging into an existing set reports new versus overwritten counts.
- `--dry-run` writes nothing to the vault.
- No output mode prints a value.
- Malformed input fails with a message naming the format, not a stack trace.

---

## 4. `hush get --copy`

### The problem

`hush get KEY` prints a live credential to the terminal, where it stays in
scrollback, in the tmux buffer, and in whatever is recording the session. The
command already warns about exactly this. Copying to the clipboard is the same
reveal with less residue.

### The design

    hush get STRIPE_SECRET_KEY --copy

The value goes to the clipboard through a pipe and is never written to stdout.
The output is `copied STRIPE_SECRET_KEY to the clipboard (24 characters)`.

The clipboard tool is found on `PATH` the same way the age bridge finds `age`:
`pbcopy` on macOS; `wl-copy`, then `xclip -selection clipboard`, then `xsel -b`
on Linux. None found is a clear message naming what to install, not a silent
fallback to printing.

Same `reveal` gate, same audit record. The warning changes: a clipboard is a
shared buffer that other applications can read, and it survives the command.

### A prerequisite refactor

`src/age.ts` holds a private `isExecutableFile` + `onPath` pair, including the
fix that a *directory* with the execute bit is not a program. Rather than
duplicate fifteen lines of path handling into a second security-relevant place,
that pair moves to `src/which.ts` and both callers use it. `test/age-bridge.ts`
already covers the behaviours, so the refactor is proved by the existing tests.

### Tests

- A fixture clipboard on `PATH` receives exactly the value.
- stdout carries the confirmation, never the value.
- The reveal gate applies; a denial leaves the clipboard untouched.
- Nothing on `PATH` is a clear error naming the candidates.
- Precedence: `pbcopy` is used in preference to `xclip` when both exist.

---

## 5. Exposure warnings

Two places where a value can escape in a way hush cannot mask, and currently
says nothing about.

### `MIN_REDACTABLE` is a silent cliff

`src/redact.ts` refuses to track values shorter than five characters, on the
grounds that masking them is noise. The consequence is that a four-character
PIN or a short password is injected, used, and **printed in full** in output,
with nothing anywhere having said so. `hush request` sharpened this, because a
response that reflects a short secret back is now printed too.

The constant is exported, and `hush add` / `hush set` warn when the value it
just stored is below it: "shorter than 5 characters — hush will not mask this in
command output". Not a refusal; short secrets are legitimate.

### A value in argv

`ps` shows the command line to every user on the machine. hush deliberately
offers no way to pass a secret as an argument, but nothing notices when one
arrives anyway. `hush run` checks the argv it is about to pass against the
values it is about to inject, and warns once per key, naming it.

This is a warning, not a refusal: by the time argv exists the value is already
in the process table, so blocking the command would add an obstacle without
removing the exposure.

### Tests

- A 3-character value warns at add; a 5-character one does not.
- The warning and the redactor read the same constant.
- A secret value in an argument warns, naming the key; a secret *name* does not.
- A value in argv is never itself printed in the warning.

---

## Order and dependencies

Worked in the order above because:

1. `--materialize` is the largest and the one with a real design decision in it
   (reveal-class gating). Getting it wrong is expensive later.
2. Validation is the cheapest thing on the list and removes the most common
   daily failure. It also gives the agent a way to check configuration without
   seeing values.
3. Import is what turns "I would try it" into "I can try it in one command".
4. `--copy` is small, and depends on the shared `which` helper that step 4
   introduces.
5. The warnings are last because they are one-liners once `MIN_REDACTABLE` is
   exported, and because step 2's `@sensitive=false` touches the same redactor.

## Deliberately not in this list

- **Per-set access for humans.** Recipients are per-vault; two subsets means two
  vaults and two `hush link`s. Stated plainly in the README rather than built.
- **Narrower CI identities.** A machine identity today is a full recipient. A
  set-scoped or `allowEnvs`-pinned CI key is the right fix and is its own step.
- **One-off sharing outside the vault.** "Send Sam this one key" has no safe
  shape here yet, and a careless one would be worse than none.
- **`${…}` expansion inside values.** Needs a dependency order and a cycle
  rule; a half-version would be a footgun.
- **Importing from an API directly.** Exports cover it without network calls,
  vendor auth, or another dependency.
- **Dynamic credentials, leasing, expiry.** Not a KMS; stays not a KMS.
