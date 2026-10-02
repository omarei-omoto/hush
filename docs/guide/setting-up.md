# Setting up, with or without your agent

hush has one checklist for setting up a machine and a project. You can walk it
yourself, or hand it to your coding agent. Both read the same list, worked out
from what is actually on disk, so they always agree about what is done.

```
$ hush setup

hush · set up  ●●●○○  3 of 5  ~/code/my-app

  ✓ Your key                      on this machine (macOS Keychain)
  ✓ Your library                  4 set(s), usable in any project
  ✓ This project's keys           a vault in this repo
  ✗ Your agents                   found Claude Code, Codex; none connected to hush yet
                                  hush install-mcp --yes && hush install-skill
  ✗ Keys in your agents' configs  14 plaintext key(s) in 6 file(s)
                                  hush scan --agents --fix
  ○ Keys in past conversations    read-only, about half a minute  (optional)
                                  hush scan --transcripts

  Next:  hush install-mcp --yes && hush install-skill
```

## Yourself

```bash
hush start
```

On a first run it asks where your keys are and gets them in. Then it goes
through whatever else is left, one step at a time: what the step is, and "do
it now?". Answer `s` to skip a step for good in this project. Run `hush start`
again any time and it carries on from the first step not done. `hush setup`
shows the list without asking anything.

## In the app

`hush ui` shows a **Finish setting up** card above your sets while steps are
left. Each step has its command to copy, a Skip, and a button that copies the
prompt below for your agent.

## With your coding agent

Paste this into Claude Code, Codex, Cursor or any agent with a shell:

> Set up hush in this project. Run `hush setup --json` and follow it: run each
> step's command as written, ask me in the chat for anything marked "choice",
> and for anything marked "person", run it and wait for me. Never open a `.env`
> file or ask me for a key in the chat.

`hush setup --json` gives the agent every step: its status, its exact command,
the options for a choice, and the rules it has to follow. An agent already
connected to hush can call the `hush_setup_status` tool for the same list. It
works in a project with no vault yet, and other hush tools point at it when
hush is not set up. What keeps this
safe does not depend on the agent following those rules:

- **auto** steps (create a key, import a `.env`) are safe for an agent to run.
  `hush import` reads the file itself, so its contents never pass through the
  conversation.
- **choice** steps (where your keys live, which approval prompt) have a
  recommended default. The agent asks you, then runs the command for your answer.
- **person** steps need you: deleting a `.env`, rewriting an agent's config,
  typing in a new key. Their commands ask you directly, on your terminal or,
  when an agent ran them, in a hush dialog on your screen. The agent cannot
  click that dialog, and adding `--yes` does not answer it. `--yes` only
  stands in where no dialog can be shown at all, such as headless CI.
- New keys are typed into hush's hidden prompt or secure input box, never into
  the chat.

## The steps

| Step | Kind | What it does |
|---|---|---|
| Your key | auto | `hush id --create`: this machine's key, in the OS keychain |
| Your library | auto | `hush global --create`: your own sets, usable in any project |
| This project's keys | choice | imports a `.env` (into this repo's vault, or your library), or links a set you already have |
| Your agents | choice | connects the coding agents on this machine to hush |
| Keys in your agents' configs | person | moves plaintext keys out of agent config files ([more](keys-in-your-agents-configs.md)) |
| No plaintext .env left | person | imports the file into the vault, then deletes it |
| Asked before a key is used | choice | approval prompts, a click or Touch ID ([more](approving-what-runs.md)) |
| Keys in past conversations | optional | finds your keys in saved agent conversations ([more](secrets-in-saved-conversations.md)) |
| See it work | optional | runs your app once, so you see `[redacted:…]` where a key would print |

`hush setup skip <step>` and `hush setup unskip <step>` change what is offered
in this project. The "no plaintext .env" and "approval" steps are the first two
rungs of [the security ladder](the-security-ladder.md); `hush level` shows the
rest.
