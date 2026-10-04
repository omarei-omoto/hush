# Approving what runs

Anything that injects a live credential asks first:

```
┌─ hush — approve this? ─────────────────────────┐
│  Run:  ./deploy.sh --target production         │
│                                                │
│  Using sets:  default, personal-fal            │
│  Injects:  FAL_KEY                             │
│  Directory:  /Users/you/myapp                  │
│                                                │
│  Approval code: 7431                           │
│      [Deny]  [Allow once]  [Allow 15 min]      │
└────────────────────────────────────────────────┘
```

The code also comes back in the agent's tool result, so the transcript and your
screen can be checked against each other. "Allow 15 min" is scoped to *that
command and that list of sets*, and it lasts for as long as the thing that asked
is running — a long agent session keeps the window, a fresh `hush` command asks
again. Nothing about an approval is stored in your project: a file the agent
could write is not an approval, so there is no such file.

The prompt does not disappear on you. Clicking outside it cannot dismiss it or
answer it, and if it ends up behind another window it comes back to the front
every 45 seconds with the same request and the same code, until you answer or
the wait runs out (two minutes by default). It also says how long is left, so a
prompt that lapses on its own is never a surprise. Nothing is allowed if it
lapses: you get a refusal, not a quiet yes.

```json
{
  "requireApproval": ["run", "add", "reveal", "request"],
  "approvalTtlSeconds": 900,
  "approvalTimeoutSeconds": 120
}
```

A repository's `policy.json` can add to that list but never remove from it, so
a project you clone cannot switch your prompts off. Turning them off is your
choice, on your machine, for one project at a time: `hush secure approval --off`
(it asks you first), or the switches in the app's Agent section. Either is kept
in `~/.hush/policy.json`, and `hush secure approval` turns them back on.

On a Linux desktop the dialog is
`zenity` or `kdialog`, whichever is installed. With no desktop at all — a
server, CI — there is nothing to put the request in front of you, so an
approval-gated action is refused rather than waved through — unless you pair
it with a device that has you at it:

```bash
hush approvals pair --relay https://relay.example     # on the server: prints a code and a QR code
hush approvals accept hushpair1:…                     # on your laptop
hush approvals listen                                 # on your laptop: the dialog, or Touch ID
```

The request travels sealed to your laptop and the answer comes back signed; the
relay in between can read neither and forge neither. No relay? `hush relay serve`
on the laptop and `ssh -R 8787:localhost:8787 server` carries it over your SSH
session, with nobody else involved. On a tailnet, `tailscale serve` gives it an
https address your other machines can reach instead. [docs/RELAY.md](../RELAY.md)
has both setups, and is the protocol.
