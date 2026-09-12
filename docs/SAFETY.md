# How safe is this for me?

hush works at every level of care, including the lowest, and it never blocks
you to make you climb. That is deliberate — a tool that refuses to run until
you buy a hardware key gets uninstalled, and the plaintext `.env` comes back.
The cost of that choice is that *you* have to know which situation you are in
and what it needs. This page is that, in three situations. Find yours.

The one sentence that applies to all three: **with a software identity,
anything running as you can read the vault.** Your private key sits in the OS
keychain (or `~/.hush/identity`); any process you run — including a shell
command an AI agent runs — can retrieve it the same way hush does and decrypt
everything. Policies and approval prompts constrain *hush*. They cannot
constrain a process that goes around hush. Only a hardware identity (rung 5)
changes what is cryptographically possible. Everything below is honest about
where that line falls.

---

## 1. Just me, no AI agent

**What you get for free**

- Values are encrypted at rest under a per-vault data key, wrapped for your
  public key. The repo holds ciphertext and public keys, nothing else.
- `hush npm run dev` (or `hush dev`, `hush run -- …`) puts secrets in that
  process's environment and nowhere else. Not in a file, not in your shell,
  not in your scrollback. Output is redacted.
- Your library (`~/.hush/vaults/…`) keeps personal keys out of every repo.

**Turn on:** nothing. This is rung 1. `hush secure` will offer rung 2 (key in
the OS keychain instead of a loose file) — take it; it costs nothing.

**What it does not protect against**

- Malware or a person at your unlocked laptop: they are "you".
- Git history: a secret you delete is still in history as ciphertext, readable
  by anyone who could read it before. Rotate at the provider.
- A `.env` you forgot: `hush level` refuses to call you rung 1 while one sits
  in the project.

---

## 2. Me and an AI agent

This is what hush is for. The agent gets tools that can *use* a secret and no
tool that returns one.

**What you get**

- `hush_run`: the agent runs a command with secrets injected and sees the
  output with every value masked as `[redacted:NAME]`.
- `hush_add_secret`: when the agent needs a key that is not there, a secure
  input box opens on *your* screen; you paste it there, it is encrypted
  straight into the vault, the agent gets back a confirmation. The value never
  enters the transcript. (macOS and Linux desktops with `zenity` or `kdialog`;
  elsewhere the agent is told to ask you to run `hush add`.)
- An approval prompt before anything injects a credential: the command, the
  sets, the variable names, a 4-digit code that also lands in the tool result
  so the transcript and your screen can be checked against each other.
- A policy the agent cannot loosen from inside the repo (see below).
- The CLI enforces the same policy: an agent that shells out to `hush run` or
  `hush export` meets the same prompt.

**Turn on**

- Answer **yes** when hush asks *"Will an AI agent use secrets here?"* the
  first time it sets a folder up (or `hush init --agent`). That writes
  `.hush/policy.json` with `requireApproval: ["run", "add", "reveal"]`.
- `hush install-mcp` and `hush install-skill`.
- A **floor** the repo cannot lower: put the parts of the policy you never
  want an agent to relax in `~/.hush/policy.json`. A repo's `policy.json` can
  only tighten relative to it — `unsafeAllowCommands` in a repo file that the
  floor does not also list is ignored, `allowCommands`/`allowEnvs` can only
  narrow, `requireApproval` can only grow, `biometry` can only get stricter.
  `hush doctor` shows when a repo policy tried to go below your floor.

**Understand**

- **The approval prompt is the control that holds.** Output redaction and the
  command deny list are speed bumps: a program can base64 a value before
  printing it, and `npm run <script>` executes whatever `package.json` says —
  which the agent can edit. Prefer `allowCommands` for anything sensitive.
- **"Allow 15 min" covers that command with those sets.** It does not cover a
  different command. (`approvalScope: "sets"` in the policy widens it to any
  allowed command with those sets, if you find the prompts too frequent.)
- **A click can be made by anything at your unlocked laptop.** If the agent
  can drive your screen, rung 4 — `hush biometry setup` and
  `"biometry": "required"` — makes the approval a fingerprint instead.
- **The line again:** with a software identity, an agent with an unrestricted
  shell can read your key directly and skip all of the above. The prompt is a
  strong deterrent and an audit trail, not a wall. If your agent has that
  much freedom and your keys matter, go to rung 5.

---

## 3. A team

**What you get**

- One vault in the repo, wrapped once per member. Adding someone re-wraps the
  existing key; removing someone mints a new one and re-seals every value, so
  their old checkout decrypts nothing new. No shared password, no invite
  email, no server.
- Each person's own library for personal keys; the repo records only *which*
  sets a project uses, by name.
- CI gets its own identity (`hush id --create` on a throwaway machine, then
  `hush team add ci <pk>`) that you can revoke on its own.

**Turn on**

- Everything in situation 2, for every member who uses an agent.
- Hardware identities for admins (`hush age`; YubiKey, Secure Enclave, TPM
  through age plugins) — rung 5, the only rung that changes what an attacker
  running as one of you can do.
- A user-level policy floor on every machine, so no single teammate's repo
  edit weakens the agent rules for everyone.

**Understand**

- Removing someone protects *future* values. Anything they already read, they
  have. Rotate those at the provider — hush tells you this every time, and
  cannot do it for you.
- The repository is the backend. Protect it like one: branch protection on
  `.hush/`, and treat a force-push to it as an incident.
- `hush verify` checks the vault decrypts, is fully re-sealed after a removal,
  and has not been rolled back to an older generation.

---

## The ladder

| rung | what it gives you | how |
|---|---|---|
| 1 | secrets are encrypted at rest; no plaintext `.env` in the project | `hush init`, `hush add .env --as …`, delete the file |
| 2 | your key is in the OS keychain, not a loose file | `hush secure` |
| 3 | using a credential needs your approval | answer *yes* to the agent question, or `hush secure` |
| 4 | approval needs your fingerprint, not a click | `hush biometry setup`, `"biometry": "required"` |
| 5 | your key cannot be copied off this machine | `hush age` with a hardware plugin |

`hush level` shows where you are and the one command for the next rung. The
rung is a strict checklist: a later check never lifts you past an earlier gap.

---

## Where hush stops

- It is not a KMS: no dynamic credentials, no leasing, no expiry, no audit log
  someone else cannot edit. When you need those you have outgrown a file in
  git; hush will not pretend otherwise.
- It has not had an external security review. The construction is age's,
  rebuilt on `node:crypto`, with a differential test against an independent
  implementation — which is not the same thing.
- Windows is not supported yet.

[SECURITY.md](../SECURITY.md) is the full threat model and how to report a
problem privately.
