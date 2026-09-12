# Changelog

All notable changes to hush. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [semver](https://semver.org). Pre-1.0, minor versions may break things — each entry says so when it does.

## Unreleased

Nothing yet.

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
