# Changelog

All notable changes to hush. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [semver](https://semver.org). Pre-1.0, minor versions may break things — each entry says so when it does.

## Unreleased

### Keys in your agents' own config files

`hush scan --agents` reads the files coding agents keep MCP servers in
(Claude Code, Claude Desktop, Cursor, Windsurf, Gemini CLI, VS Code, Cline,
Zed, Codex, Continue) and lists every plaintext credential: which agent, which
server, which variable, and a masked preview, never the value. `--fix` moves
each one that sits in a command-started server's `env` into a library set,
reads it back, and only then rewrites the server to start through
`hush run --use mcp-<server>`, keeping every other setting and the file's own
indentation. Keys it cannot move (a header, a URL, an app's own setting) are
listed with what to do instead. `--json` for scripts.

### Your secrets in agents' saved conversations

`hush scan --transcripts` searches the conversations coding agents keep on disk
(Claude Code, Codex, Gemini CLI, opencode, Continue, Cline, Cursor) for three
things: the values in your hush vaults, the plaintext keys in agents' config
files, and strings shaped like a provider's key that hush has never seen. It
reports the variable, where it is stored, how many conversations hold it and
when — never a hush value — and where to replace each key. Read-only: it does
not edit, redact or delete a conversation. `--since 30d` narrows it,
`--verbose` lists each file, `--json` for scripts. It reads in parallel and
splits large sessions across threads; 25 GB of history takes about half a
minute.

### Fixed

- `hush ui` opened from the home folder no longer sits blank: the code scan
  behind "What your code reads" walked the whole folder. Every scan now has a
  budget and says when it stopped early; the page skips the home folder, and
  the Touch ID helper is built before the link opens rather than on the first
  request. The page now loads in about half a second.

### Approvals over a tailnet

When Tailscale is running, `hush relay serve` also prints the `tailscale serve`
line that gives the relay an https address only your tailnet can reach, and the
`hush approvals pair` line to run on any tailnet machine. Approvals from a
server-side agent then reach your laptop with no SSH tunnel. hush only reads
from Tailscale, and never changes a Tailscale setting. [docs/TAILNET.md](docs/TAILNET.md)
is the design for going further: a hush broker on the tailnet.

### A hush broker on your tailnet (beta)

`hush serve --tailnet --sets <set>,…` lets agents on your other tailnet
machines use credentials that stay on this one. It offers two MCP tools over
HTTP on the tailnet address: `hush_list_sets` (names only) and `hush_request`,
which makes the API call from the broker and returns the response redacted.
Callers are identified by the local Tailscale daemon from their WireGuard
address, never by anything they send, and checked against `--allow` (you by
default; logins, `tag:` names, devices). Every request asks for approval on
the broker, naming who asked. A browser's request is refused. Each call goes
into the audit log with the caller's name.

### Release channels

A tag like `v0.11.0-beta.1` publishes to npm's `beta` tag
(`npm i -g @omarei/hush@beta`) and a GitHub prerelease. The stable channel —
`npm i -g @omarei/hush`, Homebrew, install.sh and the MCP registry — never
serves a beta.

## 0.10.0 — 2026-10-01

### A key can be kept to some projects

`hush env describe "FAL MODIO" --only-in "~/code/modio-*"` makes a set usable
only in folders matching the pattern, and in folders inside them. Anywhere
else hush refuses it: for `run`, `get`, `export`, `request`, `hush use`, and
an agent's `hush_run` and `hush_request` alike. A project that linked it
earlier has it skipped, with a line saying so. `hush_list_sets`, `hush ls` and
the app show the rule, and mark where it doesn't apply. `--anywhere` lifts it.
In the app, a set's Edit dialog has the same rule as **Only in these folders**.

### A new look

hush has a mark and a wordmark (Manrope, as outlines, so no font is needed).
`hush ui` is redesigned around them: warm paper, white cards, ink for text and
the redaction bars, a matching dark theme, and the mark as the tab icon. The
docs site and the README use the same identity, and the README opens with a
banner. The app still fetches nothing from the network.

### Fixed

- `hush env describe <set> --when …` no longer clears the set's description
  and label. A flag left out now leaves that field as it was.
- `hush env describe` takes a set's shown name ("FAL MODIO") as well as its
  stored one (`fal-modio`).

## 0.9.0 — 2026-09-30

Everything planned for 0.9: hush without Node, a key in the Secure Enclave,
approvals for a machine nobody is sitting at, Windows in beta, and the docs as a
site. No vault format change: a 0.8 vault opens unchanged, and 0.8 can open a
vault written by this version, unless it has an enclave member (below).

### A key in the Secure Enclave, with nothing to install

`hush id --enclave` makes a P-256 key inside the Mac's Secure Enclave. It cannot
be copied off the machine, and every use asks for your fingerprint (or the
Mac's password), enforced by the enclave. `hush secure --hardware` now offers
this first on a Mac: it makes the key, adds it to the vault as you, and tells
you to retire the software key. No Apple Developer ID is involved; see
docs/BIOMETRY.md for how. An enclave member appears as `hush_se_…`, and as
`enclave` in `hush team ls`. **A vault with an enclave member needs this
version to open.**

### hush without Node: one file, an installer, Homebrew

- Single-file binaries for macOS (arm64, x64), Linux (x64, arm64, glibc and
  musl) and Windows (x64). The build is byte-for-byte reproducible, and the
  whole test suite runs against the binary.
- `curl -fsSL …/scripts/install.sh | sh` (and `install.ps1` on Windows)
  installs one. It refuses a binary whose sha256 is not in the release's
  `SHA256SUMS`, checks the build-provenance attestation when the GitHub CLI is
  signed in, and needs no sudo.
- Homebrew (`brew install omarei-omoto/tap/hush`), Scoop and winget manifests
  are generated for each release. The GitHub Action installs the checked binary
  by default and no longer needs Node.
- The binary does not load `.env` or `bunfig.toml` from the working directory;
  Bun-built programs do by default.

### Approvals where there is no desktop

Over SSH, in a devcontainer, on a server, there was no one to ask, so every
gated action was refused. Now `hush approvals pair` on the server and
`hush approvals accept` on your laptop pair the two. From then on, an approval
the server cannot show itself goes to your laptop (`hush approvals listen`):
the usual dialog, or Touch ID, and a signed answer back. The relay in between
can neither read nor forge a request or an answer, and cannot replay one.
`hush relay serve` runs one yourself; with `ssh -R` nobody else is involved.
The protocol is in docs/RELAY.md.

### Windows, in beta

`npm install` now works on Windows. Your key is kept with DPAPI, approvals are
a native Windows dialog, `hush run npm …` works through `npm.cmd`, secret
files get owner-only ACLs, and there is a PowerShell hook. A Windows CI job
checks these paths; tell us what breaks.

### Security

- The macOS helpers (Touch ID, Secure Enclave) are now compiled only with
  `/usr/bin/swiftc`, and only if it is root-owned and not writable by others,
  in an environment with nothing the caller can use to redirect it. Upgrading
  is recommended if you use `"biometry": "required"`.
- Text from a vault file — a member's name, the vault's id — can no longer put
  terminal control characters into hush's warnings and errors, including the
  one that says a vault looks forged. A vault id or member fingerprint hush
  would never write is refused when the vault is loaded.

### Docs

- The README is now a front page. Everything else is in a guide
  (docs/guide/, and a site at omarei-omoto.github.io/hush), unedited apart
  from links.
- The command reference is generated from `hush help --all`. The old one had
  fallen behind.
- A demo repository with a public, test-only key (`examples/hush-demo`), a
  contributor's map of the code (docs/ARCHITECTURE.md), and the brief for an
  external security review (docs/REVIEW-SCOPE.md).

### Fixed

- `hush verify` counted a member who reads only some sets as "without a key
  wrap".
- `hush install-mcp` and the git merge driver register the binary itself when
  hush is the single-file build.

## 0.8.0 — 2026-09-30

**Breaking: vault format hush/v3.** A signed vault can be opened only by hush
0.8 or newer. Vaults are signed when made with `hush init`, or the first time an
admin changes an existing vault's membership, or with `hush team sign`.
Everyone on the team should upgrade before that happens.

### Signed vaults: only an admin can change who can read one

An admin now signs the vault's header — every member's keys and role, the sets
a scoped member may read, and a commitment to every data key — and every
member's hush checks the signature against admins their machine already trusts,
and checks that the key it unwrapped is the one the header commits to.

- A change signed by an admin you trust arrives with a one-line notice ("alice
  changed who can read this vault: added dana (signed)"). A header that is
  unsigned, forged, signed by a non-admin, or stripped of a signature it had is
  refused and cannot be accepted — `hush team reject` shows how to restore it.
  One signed by an admin this machine has never seen waits for `hush team
  accept`.
- This closes what 0.6's pinning could not tell apart from a teammate's
  rotation: someone who is not a member re-keying the vault without adding
  themselves, to plant a value.
- Only admins can add or remove members, rotate, or change set access in a
  signed vault. Members still add and change values.
- `hush id` prints your encryption and signing key as one string. An older
  32-byte `hush_pk_` still joins a vault; it just cannot sign as an admin.
- `hush team verify <name>` prints a sixty-digit safety number to compare over a
  call.
- A hardware-only (age) admin signs with a separate software key kept in the
  keychain; adding your own hardware key as an admin attaches it for you.

### Giving someone only some sets

- `hush team add junior <key> --sets dev,staging` makes a scoped member who
  reads only those sets; each gets a key of its own, wrapped for every full
  member too. `hush team rm junior --from staging` takes one away and rotates
  only that set.
- A run skips sets you were not given and says so; `--use prod` says who can
  grant it. The app's Team section shows who reads what, and can add a scoped
  member.

### CI identities and a GitHub Action

- `hush ci create github --sets ci,staging | gh secret set HUSH_IDENTITY` makes a
  scoped machine identity — never an admin, never a signer — and hands its key
  straight to the secret store. `hush ci ls`, `hush ci rm`.
- `uses: omarei-omoto/hush@v1` installs hush, masks the identity, and checks it
  can read the vault. In GitHub Actions, `hush run` has GitHub mask every
  injected value line by line — for CI identities only.

### After someone leaves

- `hush team rm` marks every value the removed member could read as exposed
  until it is set again. `hush exposed` lists them with where to replace each
  (Stripe, OpenAI, AWS, GitHub and twenty-odd more).
- `hush ls --age` shows how long since each value was replaced.
  `"rotateAfterDays"` in a policy (a number, or per set) makes `hush level` and
  `hush doctor` list overdue values; a floor can ask sooner, never later.

### Also

- The vault merge understands signed vaults and set keys, re-signs a merged
  header as the admin merging (or refuses), and rotates a set's key when
  someone who held it is no longer entitled.
- `hush ui` links can name a section after the token (`#t=…&team`).
- `vault.ts` is split into `vault-files.ts` and `vault.ts`; the signed header
  lives in `header.ts`. An independent WebCrypto implementation verifies the
  signature format.

## 0.7.0 — 2026-09-30

### Vault merges go key by key

Two branches that both touched `.hush/vault.json` used to conflict as a wall of
base64, and taking one side dropped the other's secrets.

- `hush merge-driver --install` (once per clone) hands vault merges to hush.
  Keys added on either side are kept. A rotation or a removal on one branch
  wins, and everything from the other branch is re-sealed under the new key; a
  member added on the other branch is given it. Both branches rotating is
  refused, not guessed at.
- A key changed on both branches keeps this branch's value, and `hush merge
  status` lists it (set, key, who, when — never a value). `hush merge pick KEY
  --ours|--theirs` settles each; every hush command mentions an open choice
  until it is made.
- Without the driver, git still stops on the vault as before, and `hush merge`
  finishes the merge from the three versions git kept.
- The committed `.hush/.gitattributes` still says `-merge`: git falls back to a
  line-by-line text merge when a named driver is not configured, so the driver
  is switched on per clone in `.git/info/attributes` and git config instead.
- `hush doctor` says whether this clone has it.

### Nine coding agents

`hush install-mcp` and `hush install-skill` now know **Gemini CLI**, **VS
Code** (Copilot agent mode), **Windsurf**, **Zed**, **Cline** and **Continue**
as well as Claude Code, Codex and Cursor — each in the file its own
documentation names. Zed's settings file keeps every comment (the entry is
inserted, not re-serialised). Codex, Gemini CLI and Zed share
`.agents/skills/`, so the skill is written once for all three.

### The audit log is a hash chain

Each line of `.hush/audit.log` carries the SHA-256 of the line above it.
`hush audit` shows the log; `hush audit verify` names the first line that does
not follow — an edit, a removal, an insertion or a reorder. It makes an edit
visible, not impossible (SECURITY.md says so).

### The app's link keeps its token out of history

`hush ui` now prints `http://127.0.0.1:…/#t=<token>`. The fragment never
reaches a server or a log; the page reads it, wipes it from the address bar and
keeps it for the tab. The page itself no longer contains the token. It also
refuses to be framed by another page.

### Under the hood

- `src/cli.ts` is split into `src/cli/` (shared helpers) and one file per
  command in `src/commands/`. No behaviour change.
- `npm run build:check` builds `dist/` twice and fails on any difference; CI and
  the release run it, and releases publish with npm provenance. `RELEASING.md`
  describes the process.
- `.hush/.gitignore` for new projects also ignores `audit.log.*` (the rotated
  log and its lock) and `merge-conflicts.json`.

## 0.6.0 — 2026-09-30

**Upgrade recommended for every team vault.**

### hush notices when a vault's membership or key changes unexpectedly

Each machine now remembers, per vault, the members it has accepted, a
commitment to the data key behind each generation it has seen, and which vault
lives at which path. When something changes that nobody on this machine did —
a member someone else added, a different key where one was already seen, a
different vault in the same place — hush refuses to decrypt or add anything
there until a person looks:

- `hush team accept` shows what changed (who was added, their fingerprint, and
  the git commit and author that last touched the vault) and records it once
  you confirm. With approvals on, it asks on screen like any other gated action.
  Your agent is told never to run it for you.
- `hush team reject` changes nothing and explains how to restore the vault from
  before the change.
- `hush team ls` marks members this machine has not accepted.
- `hush verify` and `hush doctor` gain a trust check, and `hush verify` exits
  non-zero over an unaccepted change instead of printing all green.
- The MCP tools refuse with the same message, and `hush ui` loads with the
  previews hidden and a banner saying what to run.

Members removed and key rotations made by teammates go through on their own; a
rotation made elsewhere is mentioned once. The first time a machine sees a vault
it is accepted as it stands (trust on first use).

**Behaviour change:** after a teammate adds someone, everyone else runs
`hush team accept` once before their next `hush run`. That is the point.

### The policy floor is created when an agent is set up

`~/.hush/policy.json` — your floor, which no repository's policy can go below —
now gets written (empty) whenever an agent is brought near a vault: `hush
install-mcp` (it is on the "this will write" list), `hush install-skill`, and
answering yes to "will an AI agent use secrets here?". Its existence is what
keeps approvals on when a copy of the vault is opened from a folder with no
policy of its own. `hush level` has a new rung-3 check for a machine with an
agent registered and no floor, and `hush secure floor` writes one.

### Fixed

- `hush_check_repo` scanned any directory it was given, including outside the
  project. It is now confined to the project root, with symlinks resolved.
- Two MCP replies pointed at `hush_request_secret`, a tool that no longer
  exists; they name `hush_add_secret`. A test now fails if any reply or the
  agent skill names a tool the server does not have.
- The UI test suite read the real `~/.codex/config.toml` of whoever ran it.
- Docs: the supported-versions table, the README's description of how the
  `hush` command chooses between `src/` and `dist/`, and the value AAD in "How
  the crypto works" (it has bound the key generation since 0.4).

## 0.5.0 — 2026-09-24

### The app, redesigned around what you came to do

`hush ui` is rebuilt. The old page was five sections of lists and jargon ("What
a run gets", "rung 0 of 5"), with keys hidden behind a chevron and native
`prompt()` boxes for editing. The new one:

- **Opens on your project, and answers whether it will run.** The code is
  scanned for the variables it reads, and each is shown as provided (by which
  set) or missing. A missing key that an unused set already holds offers
  **Use that set**; otherwise **Add** opens the add dialog with the name filled
  in. The sidebar shows the missing count.
- **Shows every key.** The sets a run gets appear in order, each with its keys
  under a redaction bar. A key a later set overrides is struck through with
  "overridden by …". Up and down change the order.
- **Add secret** is always one click away. It handles multi-line values, saving
  to any set, making a new set, and using that set here. It warns before
  replacing an existing key.
- **Reveal** says when it is waiting on your approval. It shows the value for 15
  seconds with a visible countdown, offers Copy, and hides again.
- **Import .env** is a single review dialog. Save everything as one named set
  (library first when you have one), or file keys into existing sets one by
  one. Closing it discards the upload server-side.
- **Agent** shows setup as steps with copyable commands, approvals as switches
  with plain descriptions, a warning when this machine can't show a prompt, and
  your protection level with the next step.
- **Activity** reads as sentences ("Ran npm with 4 secrets · agent"), grouped
  by day.
- **Menus and dialogs** replace `prompt()` and `confirm()`, with keyboard
  support. There is a bottom tab bar on phones, and dark mode throughout.

Under the hood, the page lives in `src/ui-page.ts`, and the DOM is built only
through `textContent` and attributes. No string of HTML exists for a value to
escape from, and a test forbids every API that could create one.
`/api/state` adds `needs` (variable names and file paths, from a scan cached
for 10 s), `posture.next` and `policy.promptAvailable`.

### Changed — asks instead of refusing, and the library stays a library

**Breaking (pre-1.0):** your library's `default` set is no longer injected into
every folder. The library is a catalog: nothing in it reaches a project until
that project adds it. To keep the old behaviour in a folder, run
`hush use default --library` there. It is recorded as `library:default` in
`.hush/envs.json`, and you can add more from the library later.

- **Your own commands are no longer refused.** With a `.hush/policy.json`, the
  CLI used to refuse `hush node server.js`, `hush python app.py`,
  `hush bash deploy.sh` and a bun project's `hush dev`, all to the person who
  typed them. varlock gates nothing and 1Password's `op run` asks rather than
  blocks, so hush now does the same. With `run` approval on, these commands go
  to the approval prompt with a warning line. An agent shelling out to
  `hush run` still has to get a human to click Allow on that exact command.
  The agent's MCP tools keep the hard deny, and an `allowCommands` list you
  wrote still narrows both.
- **The setup questions in a new folder can be declined.** Answering `n` (or
  picking nothing) runs your command with nothing injected, says so, and
  writes nothing. The folder is asked again next time. It used to exit with
  "Nothing set up."

### Less that hush does to a project without asking

- **`hush install-mcp` and `hush install-skill` show what they will write, and
  ask**, on a terminal. Detection is broad (a `~/.cursor` left over from a trial
  counts), so registering hush for the one agent you use also dropped a
  `.cursor/` into the repo and appended to your user-wide
  `~/.codex/config.toml`. You now see the list, with files outside the project
  marked, and answer `Y`, `n` or `pick`. `--yes`, `--for` and scripts are
  unchanged. `install-skill` no longer quietly overwrites a skill file you
  edited: an identical file is "already up to date", and a different one is
  flagged before it is replaced.
- **`.mcp.json` gets `hush mcp`, not a path to your `node_modules`**, whenever
  the `hush` on PATH is the same install. Those files are committed, and the
  absolute path (an nvm version folder, your home directory) was wrong on every
  teammate's machine and on yours after the next Node upgrade.
- **Turning approvals on says what it does to *your* runs.** The CLI enforces
  the same policy as the agent's tools, so once `.hush/policy.json` exists,
  every `hush run` asks first and `node`, `python`, `bash` and the other
  interpreters are refused. `hush start`, `hush init` and `hush install-mcp`
  now say so, with the undo. On a machine with no dialog program they also warn
  that every run will be refused, where before your next `hush dev` simply
  failed.
- **`~/.hush` is never a project.** It shares a name with a project's `.hush`,
  so the upward search found it from anywhere under `$HOME`. One `hush use`
  from the home folder wrote `~/.hush/envs.json`, and every folder beneath
  silently became part of that "project". A `hush install-mcp` there would even
  have written the user-wide policy floor. It is now skipped when searching, and
  writing project files into it is refused.

### Fixed

- `hush ui` crashed a moment after printing its link on any machine without
  `xdg-open` (servers, containers, SSH sessions). It now says to open the link
  yourself.
- `hush install-mcp`, `hush install-skill` and the Touch ID helper broke under
  any install path containing a space, because they read a URL-encoded path.
- The app opens on **This folder** instead of an empty Library. An unnamed set
  no longer renders as a 120px row with a stray dashed rule, because it had
  picked up the empty-state style. All five tabs fit at phone width.
  Fingerprint approval reads "none on this machine" where there is none.
- The app and `hush doctor` count an agent as registered only when its config
  actually has a `hush` entry. The app used to look only at `.mcp.json`, and
  doctor accepted any `~/.codex/config.toml`.
- A folder that uses only library sets is no longer nudged with "your secrets
  are not encrypted". The `hush level` fix for a stray `.env` was
  `hush import .env`, which fails without `--as`.
- In a folder that is not set up, on a machine with no key yet, `hush <cmd>`
  now points at `hush start` instead of `hush id --create`.
- `/.env` in `.gitignore` counts as ignored in `hush start`.
- From a clone on Node 22.6–22.17, which cannot run TypeScript without a flag,
  `bin/hush.js` falls back to a build, or says what to do. The docs now say that
  working from source needs Node 22.18.

## 0.4.0 — 2026-09-16

### `hush install-mcp` learns which agent it is talking to

It wrote `.mcp.json` — Claude Code's file — whatever agent was in the room, and
printed a tick either way. In a Codex session that file is never read, so the
one step that was supposed to make your agent aware of hush did nothing, and
said it had worked. That is the worst shape a setup step can take.

It now detects the agents on the machine and writes what each one reads:
**Codex** gets `[mcp_servers.hush]` in `~/.codex/config.toml` (via
`codex mcp add` when the CLI is there, otherwise an append that leaves the rest
of the file untouched), **Claude Code** keeps `.mcp.json`, and **Cursor** gets
`.cursor/mcp.json`. An entry you already have is never rewritten, and a file
hush cannot parse is reported rather than clobbered. When it finds no agent at
all it says so and prints the line to paste instead of writing a file nobody
opens. `--for codex|claude-code|cursor` registers one it could not see.

`hush install-skill` follows the same map: Codex reads
`.agents/skills/hush/SKILL.md` (documented path, not `.codex/skills`), Claude
Code keeps `.claude/skills/…`, and Cursor gets a rule at
`.cursor/rules/hush.mdc` with the frontmatter it expects. `hush doctor` now
asks every agent rather than only Claude Code, so a working Codex setup no
longer reads as "run install-mcp".

### A security review, and the fixes it turned up

An outside audit (Cloudflare's `security-audit` skill) was pointed at the one
threat hush exists for: an AI agent with a shell that must not be able to hand
itself a credential a human did not approve. It confirmed nine issues, each
with a working local reproduction, and all nine are fixed. Two of them are
worth knowing about because the behaviour you see changes.

- **An approval can no longer be answered by a program the agent wrote.** The
  dialog program is now resolved only from `/usr/bin`, `/bin` or
  `/usr/local/bin`, must be owned by root and not group- or world-writable, and
  is always started by absolute path. `HUSH_DIALOG` is gone: the only caller
  that could set it is the one the gate exists to constrain. When no trusted
  program is found, the request goes to the pending-request file a human
  answers, instead of falling back to a program that may not be one.
- **`hush export --out` refuses a symlink.** Writing plaintext to a
  caller-named path now does what `--materialize` already did: a path that
  already exists as a symlink or other non-regular file is refused, so a link
  planted in a repository cannot send the whole decrypted set somewhere else
  and re-permission it.
- **A cached "Allow 15 min" covers exactly the command and the sets it named.**
  The grant key is now built structurally instead of by joining parts with `:`
  and `+`, which could collide: one approval could cover a different command
  and a different set. Grants cached under the old key simply stop matching, so
  you may be asked once more.
- **Response headers are redacted like everything else**, and an error raised
  while preparing a request no longer echoes a credential to the caller.
- **`/api/global` refuses a vault name that would leave the vault folder**, so
  a session-token holder cannot persistently repoint the machine-wide library.
- **A symlink planted at `.hush/policy.json` is refused** rather than followed,
  at both the app's policy save and the guided setup.
- **A repo policy that stays silent no longer voids your floor.** An inherited
  allow list now survives a policy that does not repeat the field, a repo list
  that shares nothing with the floor is ignored rather than applied, and the
  weakening is reported by `hush policy`.
- **Rollback detection can no longer be silenced by editing two integers.**
  Values are sealed under a `hush/v2` envelope that binds each entry's key
  generation into its AAD, so a hand-edited generation fails loudly. Existing
  vaults still open, and re-seal on the next write.
- **`.env.schema` cannot unmask a value on its own.** `@sensitive=false` is now
  a request; only the machine's own `unmaskKeys` floor can grant it, and the
  refusal names what asked and what to change.

- **There is no file to answer an approval with.** The pending-request queue is
  gone, along with `hush approve` and the `HUSH_APPROVAL_MODE` switch. The last
  way an agent could approve its own action was to write the file the approval
  flow was waiting on; a file inside the project is something an agent with a
  shell can write, so no signature or check could ever make it trustworthy. An
  approval now has to come from a dialog on your screen, drawn by an OS-owned
  program, or from your fingerprint. A machine that can offer neither refuses
  the gated action and says so. Removing the switch is the point: the one
  environment variable that used to exist could only ever make approvals
  weaker, and the one that replaces it (`HUSH_NO_DIALOG`) can only make them
  fail.
- **An approval is not remembered in a file either.** `.hush/grants.local.json`
  was the other half of the same problem: it let an agent pre-authorise its own
  `hush run` by writing one correctly-spelled JSON file into the project. Grants
  now live in memory, in the process you answered. The practical difference is
  small: the MCP server and the app are long-lived, so they still honour "Allow
  15 min" for as long as they run, and a fresh `hush` command asks once more
  (its dialog offers "Allow once" only, because that is all it can promise).
- **The prompt cannot be lost behind another window.** Clicking outside it never
  answered it and never dismissed it — it is app-modal — but another window
  could cover it, and then its own timer would end the script and the request
  would quietly lapse into a refusal. The macOS prompt is now re-presented every
  45 seconds until you answer or the wait runs out, with the same request and the
  same code every time, and it says how much of the wait is left. The secure
  input dialog for typing a secret is deliberately *not* re-presented: a fresh
  empty field would throw away what you had already typed.
- **The fingerprint helper is rebuilt instead of trusted.** It used to be
  compiled once into `~/.hush/bin/` and reused while a stamp matched the source
  hash — but that folder is inside your own home, so anything running as you
  could have replaced the program there, stamp and all, and answered "ok"
  without a finger touching the sensor. That would have made the fingerprint
  prompt decorative. It is now built from hush's own source, per process, into
  a folder only that process can name, and the old cached copy is never
  executed. The cost is a third of a second on the first gated action in a
  process (three seconds the very first time on a machine, while the Swift
  compiler warms up).

The five leads that were found but not independently validated were fixed too:
a repeated name in a dotenv import is now reported instead of silently
overwritten, the add-secret dialog names the vault the value goes into, the
request dialog names every secret the request really sends, key and set names
from a hand-edited vault file are scrubbed before they reach a terminal, and
the request summary and its substitution use one parser rather than two.

### `hush start` — a way in for someone who has never used this

Arriving at hush meant arriving at forty commands, a vocabulary (vault, set,
scope, layer) and a README. That is not how anyone wants to spend their first
five minutes: they want their keys in and their project running.

```bash
cd your-project
hush start
```

It finds the `.env` files in the folder, offers them first (the usual answer),
stores what it finds, asks the one question hush always asks up front (will an
AI agent be near these keys), offers to run the dev script, and ends by naming
**three** commands rather than forty. The other answers it accepts are "in
another tool" (it prints the exact one-line pipeline for Doppler, 1Password,
AWS, Infisical or Vault, and stores nothing itself) and "add one now" (the value
goes into a hidden prompt, never onto the screen).

The wording lives in `src/start.ts`, where it is tested as wording: the opening
never says "vault", "scope" or "layer"; the first choice always matches what is
actually on disk; and the ending is asserted to name exactly three commands.

Discoverability, since a guided run nobody finds is not a guided run:

- `hush` with no arguments in a folder nobody has set up says "New here? Run
  `hush start`" above the usual screen, and stops saying it once the folder is
  set up.
- The "this folder isn't set up" error names `hush start` first, because the
  other two suggestions assume you already know what a set is.
- The agent skill tells an agent to hand this to the human rather than setting
  anything up itself.

### `hush import` reads another tool's export (it used to be an alias)

The command everyone reaches for is `import`, so it now does the importing.
The name previously meant "the pre-unification spelling of `hush add <file>`",
which nobody should be typing, and its one legacy form fails with the exact
replacement rather than quietly doing something else:

    hush import .env --env prod      # removed
    hush add .env --to prod          # what it did

`hush import <file|-> --as <set> [--format dotenv|json|1password]` is the new
meaning. For a `.env` the two are the same thing, so the migration is one flag.
There is no `hush adopt`, which is what this was called for about an hour.

### How long an "Allow" lasts is now easy to change

The approval dialog has always offered "Allow once" and "Allow 15 min", with
the second one built from `approvalTtlSeconds`. Fifteen minutes was only
changeable by hand-editing `policy.json`, which is not a thing to ask of
someone who is being interrupted by it.

- In the app: the Agent section has a plain chooser (15 minutes, 30 minutes,
  1 hour, 4 hours, all day).
- From the terminal: `hush secure approval --for 30m` (also `1h`, or a number of
  seconds). This also works when approvals are already on, which is the case
  that matters, because "already done" would otherwise leave the duration alone.
- Bounded from a minute to a day: under a minute is a dialog per call, and over
  a day is "off" with extra steps. A value set by hand that is not one of the
  choices is shown as-is rather than silently rewritten.

### Credentials that are a file: `--materialize`

Some tools read a *path*, not an environment variable:
`GOOGLE_APPLICATION_CREDENTIALS`, `KUBECONFIG`, a `.p12`, a client certificate.
The only answer before this was `hush export`, which writes every value in the
vault to disk in plaintext and leaves it there.

```bash
hush run --materialize GOOGLE_APPLICATION_CREDENTIALS -- node app.js
hush run --materialize KUBECONFIG=/tmp/kube.config -- kubectl get pods
```

- With no `=`, hush picks a private path (a `0700` directory, removed with the
  file). With a path, that path is used exactly. Either way: `0600`, created
  with `wx` so an existing file or a planted symlink is a refusal rather than a
  write through it, and removed on exit including when the child fails.
- The child gets the **path**, and the value stays in the redaction set, so a
  child that reads the file back still prints `[redacted:KEY]`.
- **Gated on `reveal`, not `run`.** This writes plaintext to a path the caller
  chose, so an agent with a file-read tool could read it: it is the same class
  of act as `hush get`. There is no MCP tool for it, deliberately.

### `.env.schema` validation

The most common failure is not a leak, it is a wrong value. A `.env.schema` in
`@env-spec` syntax (the one Varlock reads, so an existing schema works) declares
what a value should look like:

    # @required @type=url
    API_URL=
    # @type=string(startsWith=sk-)
    STRIPE_SECRET_KEY=
    # @sensitive=false
    APP_ENV=development

- `@required`, `@type=` `string`/`number`/`boolean`/`url`/`port`/`email`/
  `enum(...)`, `@type=string(startsWith=…, minLength=…, maxLength=…)`,
  `@pattern=`, `@sensitive=false`. `@default` is not implemented: an injected
  default would make "the vault is the source of truth" quietly false.
- `hush run` and `hush request` check the keys they are about to use and refuse
  **before** spawning or sending; `--no-validate` overrides for a human, and an
  agent cannot override at all. Only the keys in play are checked, so a
  production rule cannot block a dev command.
- `hush doctor` reports everything, and `hush add` warns when a value it just
  stored does not match.
- A message names the key, the rule and the length. Never the value.
- `@sensitive=false` takes that key out of the redactor, so
  `NODE_ENV=production` stops printing as `[redacted:NODE_ENV]` on every line
  and the mask keeps meaning something.

### `hush import` — coming from another tool

`hush add .env` was the only door in. `hush import` reads what another tool
already exports — no accounts, no vendor SDKs, no network:

```bash
doppler secrets download --format json --no-file | hush import - --as "Prod"
op item get "Stripe" --format json | hush import - --format 1password --as "Work"
hush import secrets.json --format json --as "Prod" --dry-run
```

- Formats: `dotenv` (default), `json`, `1password`. The AWS Secrets Manager
  `SecretString` envelope is unwrapped. A field whose value is not a string is
  skipped and counted, never stringified into a variable.
- `--dry-run` lists what would be stored and writes nothing, not even a vault.
- Nothing prints a value, in any mode.
- `hush` already had a deprecated `hush import`; that keeps working and its
  notice now points at both `hush add <file>` and `hush import`.

### `hush get --copy`

`hush get KEY` prints a live credential into the scrollback. `--copy` sends it
to the clipboard through a pipe instead, printing `copied KEY to the clipboard
(24 characters)`. The tool is found on `PATH` (`pbcopy`, `wl-copy`, `xclip`,
`xsel`), the same way the age bridge finds `age`; finding none is a message
naming what to install rather than a silent fall back to printing. Same
`reveal` gate.

### Exposure warnings

Two places a value can escape in a way hush cannot mask, both previously silent:

- `redact.ts` does not track values under five characters, so a short secret is
  injected and printed in full. `hush add` and `hush import` now say so, naming
  the keys and the threshold, read from the same constant the redactor uses.
- `ps` shows the command line to every user on the machine. `hush run` now warns
  when a secret value appears in the argv it is about to pass, naming the key.
  A warning rather than a refusal: by then the value is already in the process
  table.

### `hush request` — an API call with a credential you never hold

`hush run` needs a program that already knows how to authenticate itself. When
there is no such program and something just needs to hit an endpoint, the only
answer used to be `curl` — which is denied by default, because a shell holding
the value can post it anywhere redaction cannot follow.

`hush request` makes the call itself. The value goes from the vault into a
header *inside the hush process* and onto the wire; you and your agent only ever
see the response, with any reflected value masked:

```bash
hush request POST https://api.stripe.com/v1/refunds \
  --header 'Authorization: Bearer $STRIPE_KEY' \
  --data '{"charge": "ch_123"}'
```

- **`hush_request`** is the same thing as an MCP tool, so an agent can call an
  API rather than being told no.
- Secrets are substituted into **header values only** unless you name another
  surface with `--substitute body` or `--substitute query`. Nothing is ever
  substituted into the URL path: that is refused, because paths land in every
  access log on the way.
- **https only**, loopback excepted so a local dev server works. A redirect to
  a *different* host is refused rather than followed, since `fetch`'s default
  would re-send the Authorization header wherever `Location` points.
- The request asks for `Accept-Encoding: identity` and the response is capped
  (256 KiB on the CLI, 64 KiB for a tool result) before it is scanned, because
  a compressed or unbounded body is one the redactor cannot read.
- **`allowHosts`** is a new policy field bounding where a credential may go.
  Empty means any host over https; entries are a bare host, a host with a port,
  or a subdomain glob. It narrows under your floor like the other allow lists.
- **`request` is gated by default** in agent mode, alongside `run`, `add` and
  `reveal`. It is the one that moves a credential off the machine, so the
  dialog naming the host and the keys is the control that matters. Grants are
  held in memory only — never read from `grants.local.json`, which is a file an
  agent with write access to the repo could otherwise use to pre-authorise a
  destination of its own choosing.

## 0.3.0 — 2026-09-14

- **The app is an application now.** A sidebar — Library, This folder, Team, Agent, Activity — one section at a time, the folder and its state in the header. Sets are ledger rows; every value is a redaction bar that lifts on *Reveal*. New pages: **Team** (who can decrypt, with what key, and what removing them does), **Agent** (registration status, the three approval switches, pending approvals you can answer in the app), **Activity** (the audit log). Paper, ink and wax; system serif, sans and mono; no external resources. Works at phone width.
- New endpoints: `/api/policy` (approval switches), `/api/pending` and `/api/answer` (the approval queue), `/api/audit`.
- A logo, and a README that opens with the problem in plain words.

## 0.2.0 — 2026-09-12

- **Works in any folder.** A folder with only `.hush/envs.json` is a project; the first run in a folder that is not set up scans the code and proposes which of your library sets it needs; a project vault is created the first time a project secret or a teammate needs one.
- **One question at setup** — "Will an AI agent use secrets here?" — turns approvals on.
- **"Allow 15 min" covers the command and the sets**, not the sets alone (`approvalScope`).
- **A user-level policy floor** in `~/.hush/policy.json` that a repo policy can only tighten.
- **Secure prompts on Linux** through `zenity` / `kdialog`, so off-transcript key entry and approvals are no longer macOS-only.
- `docs/SAFETY.md` — which of the security model matters in your situation; `docs/RED-TEAM.md` — an adversarial pass over every surface, with results.
- **Security:** a forged `grants.local.json` could skip the approval for `reveal` and `add` — those grants now live in memory only; a symlink planted at that path could make a later legitimate approval overwrite an arbitrary file — hush no longer writes through one.
- Windows declared unsupported (`package.json` `os`) until it has been run.
- **Your library's `default` is your global environment** — under everything, in every folder; `hush add K=v --library` with no set name lands there.
- `hush scan` reconciles against every set the project uses, not only the project vault.
- `hush install-mcp` / `install-skill` work in a folder that only uses library sets.
- `hush doctor` lists every set once and reports a repo policy that tried to go below your floor.
- The MCP fallback for key entry says which desktops have a dialog; the approval "covers" line names the policy's real TTL.

## 0.1.3 — 2026-09-12

### One vocabulary: everything is a set

0.1.2 had two ways to describe the same bytes — "environments" and "service accounts" — with two command families, two UI sections and two MCP argument shapes. 0.1.3 collapses them. A **set** is some keys with a name you chose, an optional description and a note on when to use it. It lives in your **library** (yours, never in a repo) or in the **project** vault (committed). A project *uses* sets: its own `default` is the floor, everything else layers on top in the order you added it, later wins.

### Eight commands, and `hush` in front of anything

```
hush add <file|KEY=value>   save secrets as a named set
hush use <set> ...          this project uses these sets
hush run -- <cmd>           run with them injected
hush dev                    run your dev script with them
hush ls                     library, project, what is used
hush rm <KEY|set>           remove
hush ui                     the app
hush team add|rm            share this project's vault

hush help --all             every command
```

- **Pass-through**: `hush npm run dev`, `hush bun dev`, `hush python app.py`, `hush ./deploy.sh` — anything after `hush` that is not a hush command runs with secrets injected, exactly as `hush run -- …` would. A hush command always wins over a same-named program.
- **`hush dev`** finds `package.json`, picks the package manager from the lockfile (bun / pnpm / yarn / npm) and runs the `dev` script (or `hush dev <script>`).
- **`hush add`** is the one way in: a `.env`-shaped file (`--as "Name"`), one or more `KEY=value` (`--to <set>`), or a known service (`hush add fal --as "Work fal"` asks for `FAL_KEY` with hidden input). `--library` / `--project` choose where; without a flag an existing set is found wherever it lives. A set you make from inside a project is used by that project (`--no-use` to opt out) — so the quick start is two lines.
- **`hush ls`** is one screen: your library, this project, `●` on what is used. `hush ls <set>` lists one set's key names, never values.
- **`hush use`** appends to the resolution order; `hush use --not <set>` removes; `hush use` alone shows the order and where each set comes from. Mentioning a set again moves it last, which is how you make it win.

Every old command still works and prints a one-line notice: `hush set`, `hush import`, `hush accounts`, `hush env …`, `hush use fal=acme`, `--with a:b`, `hush add <svc> --account`.

### The app

One list of sets at two levels. Every card has the same **use in this project** toggle showing its position (`● used · 2nd`), in-place rename, description and when-to-use, an add-key row, move/reveal/replace/delete per key. The *Service accounts* section is gone; a **New set** form with an optional "for a service…" hint pre-fills the variable names a service needs.

### Agents

- `hush_list_sets` replaces `hush_list_accounts` (kept as a deprecated alias); entries say where each set lives and whether this project uses it.
- `hush_run` takes `sets: ["work-fal"]`; `hush_add_secret` takes `set` and `where: "library"`; `hush_provision` reports which used sets satisfy a tool and hands back a `hush_run` call that works. `accounts: {…}` and `env` are accepted as deprecated aliases so an old skill file keeps working.
- The skill file is rewritten around sets.

### Policy now gates the CLI too

`.hush/policy.json` applies to `hush get`, `hush export`, `hush run` (and pass-through, and `hush dev`) and `hush add`, not only to the MCP tools — an agent that shells out meets the same policy and the same approval prompt. Approval grants persist across processes (`.hush/grants.local.json`, mode 0600). `allowEnvs` names sets the way you do (`work-fal`), wherever they live. SECURITY.md says what this does and does not change.

### Fixes

- `toShellExports` quoted with `JSON.stringify`, which is not shell quoting; values are single-quoted now (a value containing `$(…)` could run when `eval`'d).
- Set order in `.hush/envs.json` was sorted on save; position is precedence, so it is preserved.
- Revealing a library secret in the app read the project vault.

### Upgrading

Nothing to migrate. `use.json` pins are still read; old command spellings still work.

## 0.1.2 — 2026-09-11

First public release: envelope-encrypted vault in the repo, per-member wraps, the MCP server with value-blind tools, output redaction, the local app, the security ladder, the age bridge for hardware keys.
