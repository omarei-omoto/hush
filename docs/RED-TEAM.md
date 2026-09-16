# Red team: can an agent get a secret value out?

**Date:** 2026-09-12
**Scope:** everything hush itself exposes to an agent — the seven MCP tools,
the CLI as an agent would invoke it, the policy files, the approval and grant
mechanism, output redaction, `.hush/` (audit log, journal, `pending/`,
`grants.local.json`), and the local app's HTTP API. Out of scope, per
SECURITY.md: a process reading the identity key directly from the keychain or
`~/.hush/identity` and decrypting with `src/crypto.ts` itself, without going
through any hush surface at all. Every probe here goes through hush.

**Method:** every experiment ran against a fresh `mkdtemp()` project and a
fresh `mkdtemp()` `HUSH_HOME`, with a `generateIdentity()` this session
created and passed as `HUSH_IDENTITY`, `HUSH_NO_KEYCHAIN=1`,
`HUSH_BIOMETRY=off` (or a specific value under test), `HUSH_APPROVAL_MODE=file`,
`HUSH_NO_NUDGE=1`, `NO_COLOR=1`, and made-up placeholder secret values
(`FAKE-VALUE-...`, `sk_live_cli`, `super-secret-value-here` — the latter two
are the existing test fixtures' own placeholders, not anything real). Nothing
here touched the real `~/.hush`, a real keychain entry, or a real vault. Real
findings got a failing test first, confirmed red against the pre-fix source
(either by reverting the fix and re-running, or diffing it out with a small
script), then green after the fix — the CONTRIBUTING.md bar.

## Findings

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | `grants.local.json` forgery bypasses approval, including `biometry: "required"` | Value out / policy bypass | **Fixed**: grants are memory-only (2026-09-16) |
| 2 | A symlinked `grants.local.json` turns a later legitimate approval into an overwrite of an arbitrary file (e.g. the policy floor) | Policy bypass (persistent) | **Fixed**: nothing is written there any more |
| 3 | Self-approval by forging `.hush/pending/<id>.answer` | Value out / policy bypass | Fixed: the file queue is gone (2026-09-16) |
| 4 | `HUSH_VAULT` pointed at a copy of `vault.json` bypasses the project's policy when no floor is configured | Policy bypass | Documented, not fixed |
| 5 | `npx node -e ...` reaches a denied interpreter; a one-liner hex-encode defeats redaction | Hardening gap (documented) | Pinned |
| 6 | Values under 5 characters are never redacted (`MIN_REDACTABLE`) | Hardening gap (documented, already tested) | No change — already covered |
| — | `hush_check_repo`'s `path` argument is not confined to the project root | Minor info disclosure (env-var *names*, never values) | Reported, not fixed |

---

### 1. `grants.local.json` forgery bypasses `reveal`/`add` approval — Fixed

**Tried:** `grants.local.json` (next to `policy.json`, inside the project) is
read by `requestApproval()` as a cache of prior human decisions: if a scope
key maps to a future timestamp, the action is approved with no dialog, no
biometry, nothing. It is a plain, unsigned JSON file written by `writeGrant()`.
An agent has ordinary write access to the project — the same access it needs
for basically everything else — so it can write this file itself. The scope
string format is not secret: it is spelled out in `policy.ts`'s `runScope()`
and in every call site (`reveal:${env}/${key}`, `reveal:export:${layers}`,
`add:${slug}/${key}`, `add:${slug}`), so an agent does not need to guess it,
only compute it from the arguments it is about to pass anyway.

```
writeFileSync(".hush/grants.local.json",
  JSON.stringify({ "reveal:default/FAKE_API_KEY": Date.now() + 3_600_000 }))
```

With `policy.json` set to `requireApproval: ["reveal"], biometry: "required"`
and nobody able to answer a biometric prompt (`HUSH_BIOMETRY=off`, as any
non-macOS host or CI box would be), `hush get FAKE_API_KEY --yes` **printed
the plaintext value**, exit 0. The same scope shape works for `hush add
KEY=value`, letting an agent plant a credential of its own choosing into the
vault with no approval and no record that a human ever saw it.

**What happened / why it holds:** the disk-cache check in `requestApproval()`
runs *before* the biometry branch, the dialog, and the file fallback — a hit
returns immediately. This is not the same risk as "an agent reads the
identity from the keychain" (out of scope): it never touches the identity or
the vault's crypto. It defeats the approval *gate*, using nothing but the
ordinary filesystem write access every coding agent already has.

**Existing precedent, and where the line is:** `test/cli.test.ts` already had
four tests establishing that a *forged* `run:`-scoped grant *is* honoured
across process boundaries — deliberately, so "Allow 15 min" survives the next
`hush` invocation being a new process (a CLI run is a fresh process every
time). That is an accepted trade-off for `run`: the action still only lets an
already-injected secret be used by a redacted child process, bounded by
`allowCommands`. `reveal` and `add` are categorically different — reveal hands
back plaintext directly, and add writes a secret with no human review — so
skipping either past a forged file is a value out or a planted credential, not
a redaction gap.

**Fix:** `src/approval.ts` — `reveal` and `add` grants are never read from or
written to disk (`persistToDisk = req.action !== "reveal" && req.action !==
"add"`). They still coalesce repeated calls within one long-lived process
(e.g. `hush ui`'s server) via the in-memory map, which a separate process
cannot forge into. `run` keeps disk persistence, unchanged.

**Tests:** `test/cli.test.ts` — *"a forged reveal grant on disk is never
honoured, even with biometry required"*, *"a forged add grant on disk is
never honoured — an agent cannot pre-approve planting its own secret"*.
Confirmed red (value printed / key planted) with the fix reverted, green with
it applied.

**Resolved further (2026-09-16).** The carve-out for `run` was the same defect
at lower volume: a correctly-spelled `grants.local.json` still pre-authorised a
run, and a run is enough to get a value out through the documented redaction
gap. So the file is gone entirely — no action is read from disk, and the
"accepted trade-off" paragraph above no longer applies. A grant lives in the
process the human answered, which is why a one-shot `hush` command now offers
"Allow once" only: it cannot honestly promise longer.

---

### 2. A symlinked `grants.local.json` clobbers an arbitrary file — Fixed

**Tried:** `writeGrant()` calls `writeFileSync`/`chmodSync` on
`.hush/grants.local.json`, which follow symlinks by default. An agent plants
that path as a symlink to a file it cannot write directly — the interesting
target is `~/.hush/policy.json`, the **floor** that is supposed to survive
exactly this kind of project-directory tampering:

```
symlinkSync("~/.hush/policy.json", ".hush/grants.local.json")
```

It then does nothing further. Later, a *human* legitimately approves an
ordinary action ("Allow 15 min" for `npm test`, say) through the real dialog
or file-approval flow. `writeGrant()` runs as it always does, but the path it
writes through now resolves to the floor file.

**What happened:** the floor's entire content — `requireApproval`,
`denyCommands` additions, `biometry`, everything a team lead put there
specifically so no repo edit could remove it — was silently replaced with
`{"run:npm:default": 1735689600000}`. The agent never touched the floor path
itself; it only arranged for hush's own later, legitimate write to land there.
From that point on, every project on the machine that relies on this floor is
unprotected, until someone notices `~/.hush/policy.json` no longer looks like
a policy file.

This is a real escalation, not a restatement of "a software identity is
usable by anything running as you": the floor's whole premise
(docs/SAFETY.md) is that it sits outside a project-confined agent's write
access. A symlink *inside the project* redirecting a write hush performs
*outside* the project defeats that premise without the agent ever needing
write access to `~/.hush` itself.

**Fix:** `src/approval.ts`'s `writeGrant()` now `lstatSync`s the path first
and refuses to write (silently, matching the function's existing "best
effort" failure mode) unless it is a regular file, not a symlink. Cost: a
session grant that would have been persisted through a symlink instead just
doesn't persist, so the next `hush` invocation re-prompts — the safe
direction to fail. `readGrantsFile()` was deliberately left following
symlinks on the *read* side: reading through an attacker's symlink cannot
disclose more than an attacker-controlled `grants.local.json` written
directly already would (same JSON shape, same effect on the reading
process's own decision), so there is no additional read-side risk to close.

**Test:** `test/cli.test.ts` — *"a symlinked grants.local.json cannot be used
to clobber the user's policy floor"*. Confirmed red (floor file replaced)
with the `lstatSync` guard removed, green with it restored.

---

### 3. Self-approval via a forged `.hush/pending/<id>.answer` — fixed 2026-09-16

**Tried:** when no native dialog backend is available (any non-macOS/GNOME/KDE
host, or `HUSH_APPROVAL_MODE=file`, which this entire red-team pass was
required to set), `askViaFile()` drops
`.hush/pending/<timestamp>-<code>.json` and polls for a matching `.answer`
file — the mechanism that exists so a **human** can run `hush approve` in a
separate terminal. The answer file carries no signature and no binding to who
wrote it: existence plus content `"session"`/`"once"` is the entire contract.

An agent's own file tool (the same Bash/Write access it has for everything
else, running *alongside* its hush MCP session — exactly the deployment
docs/SAFETY.md calls "Situation 2: me and an AI agent") can watch
`.hush/pending/` and answer its own request:

```
for f of readdirSync(".hush/pending") if f ends with .json:
  writeFileSync(f.replace(".json", ".answer"), "session")
```

**What happened:** with the default/common configuration (`biometry: "off"`
or `"preferred"` with biometry unavailable, which is every Linux/headless/CI
agent host), this fully approved a `hush get` reveal and a `hush_run` MCP
call under the *default* policy (`requireApproval: ["run","add","reveal"]`)
with **nobody answering** — confirmed both through the CLI (`hush get`
printed the plaintext) and through the actual MCP `hush_run` tool (the
injected secret was used, `exit 0`, no approval prompt blocked it). Chained
with finding 5 below (`npx node -e` hex-encoding), this is a complete,
zero-human-interaction path from "default policy, nobody watching" to a
transformed secret value in the agent's own tool result.

**Why no source fix was attempted:** this is not fixable at the file layer.
There is no local signal `askViaFile()` can check that distinguishes "a human
in a separate terminal wrote this" from "the same agent process wrote this",
when both have ordinary filesystem access to the same directory — embedding
the 4-digit code in the answer does not help, because the code is *also*
written into the plaintext `<id>.json` the agent can already read. This is
the same class of limit as rung 3/4 being "presence controls, not a wall"
(SECURITY.md): a *real* dialog (osascript/zenity/kdialog) requires an actual
click on the actual screen, which is what makes it "the control that holds";
the file fallback is explicitly the degraded substitute for a host with no
screen to click on, and degrades exactly this far when the agent shares that
host's filesystem. `biometry: "required"` is the actual, working mitigation —
it denies synchronously before ever reaching `askViaFile()` when biometry is
unavailable, so the pending file is never created (confirmed in the
reproduction script's second run).

**Fix:** none in `src/`. **Documentation:** added to SECURITY.md's "What is
already known, and not a finding" list, naming the exact mechanism and the
mitigation (`biometry: "required"`, or a real native dialog backend — neither
of which shares this failure mode). **Reproduction:**
`test/fixtures/redteam/pending-answer-self-approval.mts` (not run by `npm
test`) — running it prints both the vulnerable case (`biometry: "off"`,
value leaks) and the mitigated case (`biometry: "required"`, denied
synchronously).

**Resolved (2026-09-16).** The reasoning above was right about the file layer
and wrong about the conclusion. There is no signal that tells a human's answer
file apart from the agent's, so the answer was not to make the file
trustworthy — it was to stop treating a file as an approval at all. The queue,
`hush approve`, `/api/pending`, `/api/answer` and the `HUSH_APPROVAL_MODE`
switch are gone. An approval now has to come from a dialog on your screen or
your fingerprint; a host that can offer neither refuses the gated action. The
probe above now asserts exactly that: no secret out, no pending file written,
and a hand-written `.answer` file changes nothing.

---

### 4. `HUSH_VAULT` redirect bypasses policy when no floor is configured — documented, not fixed

**Tried:** `.hush/vault.json` is meant to be committed and read by anyone with
repo access — envelope encryption protects the *values*, not the file. An
agent copies it to a scratch directory that has no `policy.json`, and invokes
hush against the copy directly:

```
cp .hush/vault.json /tmp/scratch/vault.json
HUSH_VAULT=/tmp/scratch/vault.json hush get FAKE_API_KEY --yes   # cwd: /tmp/scratch
```

**What happened:** `resolveVaultPath()` derives `hushDir` from
`dirname(HUSH_VAULT)` with no check that this is the vault's "real" project.
`policyFor(hushDir)` finds neither a repo `policy.json` (none in the scratch
dir) nor a floor (`~/.hush/policy.json` — none configured in this run), so it
returns `null`, and the CLI runs exactly as it would for a project that never
opted into agent-safe policy at all: `hush get` printed the plaintext with no
prompt, even though the *real* project's own `policy.json` had `requireApproval:
["reveal"], biometry: "required"`. This directly contradicts SECURITY.md's
"shelling out to hush is not a way around" claim, under the specific — and
common — condition that the user never set up a floor (`hush init --agent`
alone never creates one; the floor is recommended in docs/SAFETY.md, not
required).

**The mitigation that already works:** with any floor file present — even a
near-empty `{"approvalTimeoutSeconds": 1}` — `policyFor()` no longer returns
`null`, so `DEFAULT_POLICY`'s own `requireApproval: ["run","add","reveal"]`
applies to the scratch-directory invocation regardless of its missing
`policy.json`, and the attack correctly times out and refuses (confirmed in
the reproduction script's second run). A floor's mere *existence* is what
matters here, more than its content.

**Why no source fix was attempted:** the underlying design — policy is a
property of a *directory*, resolved fresh per invocation from
`HUSH_VAULT`/`cwd` — is load-bearing for legitimate uses of `HUSH_VAULT`
(tests, CI, named vaults) documented right in `identity.ts`'s own comments.
Binding policy to "the vault's real project" instead would need the vault or
the policy to carry some notion of its own canonical location, which is a
design change, not a small patch, and risks being wrong in a different way
for a legitimate multi-machine setup.

**Fix:** none in `src/`. **Documentation:** added to SECURITY.md's "What it
does not protect" section, spelling out the condition (no floor) and telling
anyone whose agent can set environment variables — true of any agent with a
shell — to configure one. **Reproduction:**
`test/fixtures/redteam/hush-vault-redirect-bypass.mts` (not run by `npm
test`).

---

### 5. `npx` reaches a denied interpreter; a one-liner defeats redaction — pinned, not a new finding

**Tried:** `checkCommand()` denies by basename only (`node`, `bash`, etc. are
in the built-in `denyCommands`). `npx` is not itself an interpreter, so it is
not denied — and it is a completely ordinary, *intended* thing to run through
`hush_run` (the existing test suite's own fixtures use `"Run: npx vercel
deploy"` as a representative example). It runs whatever is already on PATH,
including `node`:

```
hush_run({ command: "npx", args: ["--yes", "node", "-e",
  "process.stdout.write(Buffer.from(process.env.API_KEY).toString('hex'))"] })
```

**What happened:** the command ran (`npx` is allowed), and the reply contained
the hex-encoded secret — the literal value never appeared (redaction still
catches an exact substring match), but the transformed one sailed through,
because the redactor can only ever match known values verbatim.

**Why this is not a new finding:** SECURITY.md already states both halves of
this explicitly and generically: *"The command deny list is a speed bump, not
a boundary… no deny list is complete: `npm run <script>` executes whatever
`package.json` says"*, and *"Redaction is defence in depth… it cannot see a
value that has been base64'd, encrypted, reversed"*. `npx node -e` is one
concrete instance of both at once, using nothing but what ships in the box —
worth pinning precisely because it is more surprising than the deny list's
"go write a wrapper script" framing suggests (no wrapper script needed), but
not a different category. Adding `npx` (or `pnpm dlx`/`bunx`) to the built-in
`denyCommands` was considered and rejected: `npx <tool>` running a one-off
CLI (`vercel`, `wrangler`, `supabase`) with secrets injected is a primary,
intended `hush_run` use case, and the existing test suite treats it as such.
Blocking it would be a real usability regression for the documented,
intended case, not a security fix.

**What actually holds, confirmed:** `allowCommands: ["npm"]` refused `npx`
outright (`"npx" is not in policy.allowCommands`) — this is the control
SECURITY.md and docs/SAFETY.md already point to ("Use `allowCommands` for
anything sensitive").

**Tests:** `test/mcp.test.ts` — *"npx reaches a denied interpreter and a
one-liner defeats redaction — the documented speed bump, pinned"* and
*"allowCommands — not denyCommands — is what actually stops the npx
indirection"*. These pin current, documented behaviour; they are not
regression tests for a fix.

---

### 6. Values under 5 characters are never redacted — already covered, not a new finding

`redact.ts`'s `Redactor` skips any value shorter than `MIN_REDACTABLE = 5`
entirely (`"Values this short or this common are not worth masking — masking
them is noise"`). A 4-character secret (a PIN, say) would print unmasked in
`hush_run` output. This is a real, if narrow, gap — but
`test/hush.test.ts`'s existing `"ignores values too short or too common to be
worth masking"` test already pins exactly this threshold, and it is a
deliberate, reasoned trade-off in the code, not an oversight nobody looked
at. No new test added; no change made.

---

### Minor, reported but not fixed: `hush_check_repo`'s `path` is not confined

`hush_check_repo({ path: "/etc" })` scanned outside the project without
complaint. `scanRepo()` only reports which environment-variable *names* look
referenced in source it finds there, plus which of them the vault satisfies —
never file content, never vault values — so this is not a "get a secret out"
vector. It is still a minor boundary an agent should not be able to reach
(the tool's own description says "scan the current codebase"), worth a
one-line confinement to the project root as a future cleanup. Not attempted
here: it is cosmetic relative to everything else in this pass, and a
five-minute fix risks being wrong about some legitimate monorepo layout this
red-team pass did not check for.

---

## Probes that failed (negative results)

- **`./node`, `/usr/bin/env node`.** `checkCommand()`'s basename extraction
  (`command.split("/").pop()`) reduces both to `node`, already denied;
  `/usr/bin/env` itself reduces to `env`, also denied by default. No path
  spelling reaches an interpreter past the deny list.
- **Colon-smuggled set names.** `run --env "prod:default"` and `--use
  "main:work-fal"` (the internal library-vault display prefix, typed
  literally) both came back `No set called "..."`.  `composeSets()` only ever
  matches a plain name against the single project vault and the single
  default library vault — there is no parsing of a `vault:set` form on input,
  and `assertScopeName`'s `SCOPE_SEGMENT` regex forbids `:` in a stored set
  name entirely, so no set can even exist that would need it.
- **Duplicate set names.** `--use default --use default` and `sets:
  ["prod","prod"]` are harmless — `lastMentionWins()` dedupes.
- **A grant scoped by a different set order / a different path to the same
  binary.** Reasoned through via code (`runScope()`, `basenameOf()`) rather
  than a live probe: the scope key is `basename(command)` + the *resolved*
  layer names, so `./npm` and `npm` and `/usr/local/bin/npm` collide on
  purpose (same binary, same capability) and a reordered `sets` array can
  only make an existing grant *fail* to match (forcing a fresh prompt), never
  match a narrower approval to a wider run.
- **`denyKeys`.** Removed exactly the named key from the injected set;
  everything else still arrived.
- **Audit log content.** `.hush/audit.log` after a `run`/`reveal`/`add` never
  contained the secret value in any of these probes — only actor, action,
  set/layer names, key names, exit codes and counts.
- **The UI's token and Host checks.** Read `src/ui.ts` end to end:
  `tokenOk()` uses `timingSafeEqual`, is required on every `/api/*` call and
  on `/`; `hostIsLocal()` rejects anything but an exact `127.0.0.1` /
  `localhost` / `[::1]` Host header, checked before routing, fail-closed on a
  missing header. `test/ui.test.ts` already has direct coverage of both
  (non-loopback Host, bad token). No bypass found; not re-tested live given
  the existing coverage is already adversarial.
- **`/api/stage` preview.** Uses the same bounded `preview()`/`length` as
  `hush_describe_secret` — no comparison against an existing vault value, so
  there is no "does my guess match" oracle from repeated staging.
- **Spawn-error messages.** A `hush_run` on a nonexistent binary surfaces
  Node's own `spawn ... ENOENT` message, which does not include the
  environment.
- **Exit-code oracle via `npm run <script>`.** Plausible in principle (a
  crafted `package.json` script comparing an injected value against a guess,
  observed one bit per `hush_run` call, potentially many calls covered by one
  cached `run` grant) — but this is the identical, already-documented
  `npm run <script>` indirection as finding 5, not a distinct mechanism. Not
  built out into a full byte-by-byte demonstration: it adds nothing SECURITY.md
  does not already say, and every such call is still in `audit.log` with its
  command, args and exit code.
- **Writing a secret to a file via an `npm run` script, then reading it back
  separately.** Redaction only ever touches the captured stdout/stderr
  stream — never a file the child process writes directly to disk. A crafted
  `package.json` script could write an injected value to a file with no
  redaction involved at all, then the agent's own filesystem tool (not a
  second `hush_run` call) reads it — but this is a consequence of the same
  `npm run` indirection SECURITY.md already names, not a new one. A *second*
  `hush_run` call reading the file back with an allowed command (e.g. `npm
  run cat-it`) would still have the literal value caught by redaction, since
  the redactor matches on the known value regardless of which command echoed
  it.
- **Named-vault / `hush link` path traversal.** `LINK_NAME` (`/^(?!\.+$)
  [A-Za-z0-9_.-]+$/`) forbids `/` and `.`/`..`-only names, so a crafted name
  cannot escape `~/.hush/vaults/`. The one place an explicit absolute path is
  honoured (`link.json` naming a path outside `~/.hush`) already prints an
  unconditional warning to stderr naming the path — not silent.
- **Deprecated aliases (`env`, `accounts`, `hush_list_accounts`).** Read the
  code paths: each returns exactly the same value-blind information as its
  replacement, nothing extra.
- **`hush_describe_secret` preview/length.** Matches README's documented
  behaviour ("length, masked preview") and is already pinned by
  `test/hush.test.ts`'s `"preview never reveals more than a quarter of a
  value"` and `"short values reveal no characters at all"`.
- **Timing side channels** (on approval, or on redaction's per-chunk scan)
  were not built out into a live measurement. This genuinely was not tested:
  a reliable timing measurement needs infrastructure (repeated sampling,
  noise control) that was not worth building for this pass, and SECURITY.md
  already treats every presence control as a speed bump against a co-located
  attacker (findings 3 and 4 above are sharper, concrete instances of exactly
  that same class). If this matters for a specific deployment, it needs a
  dedicated pass with real timing infrastructure, not a guess from here.

## What could not be tested, and why

- **Anything requiring the real OS keychain or a real `~/.hush`.** Explicitly
  out of bounds per the assignment; `HUSH_NO_KEYCHAIN=1` and a fresh
  `HUSH_HOME` were used for every probe instead.
- **Real native dialogs (osascript/zenity/kdialog) as the actual approver.**
  `HUSH_APPROVAL_MODE=file` was required for every probe, which is also
  exactly the condition finding 3 needs — real dialogs were read from source
  and cross-checked against `test/approval.test.ts`'s fixture-driven
  coverage rather than driven live (this session has no display to click).
- **A real hardware identity (YubiKey/Secure Enclave).** Not installed in
  this sandbox; `age`-availability-gated tests in the existing suite already
  skip cleanly without it, and this pass did not add anything in that area.
- **Timing side channels**, as noted above.

## Bite table

| Test | Fails without the fix | Passes with it |
|---|---|---|
| `test/cli.test.ts` — "a forged reveal grant on disk is never honoured, even with biometry required" | Yes — prints `sk_live_cli` | Yes |
| `test/cli.test.ts` — "a forged add grant on disk is never honoured — an agent cannot pre-approve planting its own secret" | Yes — plants `PLANTED_KEY` | Yes |
| `test/cli.test.ts` — "a symlinked grants.local.json cannot be used to clobber the user's policy floor" | Yes — floor file replaced with grant JSON | Yes |
| `test/mcp.test.ts` — "npx reaches a denied interpreter…" (pinning, not a fix) | N/A — pins existing, documented behaviour | Yes |
| `test/mcp.test.ts` — "allowCommands — not denyCommands — is what actually stops the npx indirection" (pinning) | N/A | Yes |

All confirmed by reverting each fix (or removing just its guard clause) and
re-running the specific test, per CONTRIBUTING.md's bar, then restoring it.
