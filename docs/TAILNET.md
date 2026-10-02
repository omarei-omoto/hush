# hush on a tailnet: design

Status: **steps 1 and 2 are on the beta branch.** Later steps are a plan, to be
argued with before they are built.

## Using it (step 2, beta)

On the machine that keeps the keys, with Tailscale running:

```bash
hush serve --tailnet --sets stripe-live,openai
```

```
hush broker  →  https://laptop.tail1234.ts.net:8788/mcp  (this tailnet only)
  offers:  stripe-live  STRIPE_SECRET_KEY
  allows:  you@example.com
  every request asks first; calls go out from this machine, values never leave it
  asks:    on this machine

  Add it to an agent on any tailnet machine:
    claude mcp add --transport http hush-broker https://laptop.tail1234.ts.net:8788/mcp
```

An agent on any of your tailnet machines then has two tools. `hush_list_sets`
shows the offered sets and their key names. `hush_request` makes an API call
*from the broker*, with `$STRIPE_SECRET_KEY` substituted there and the
response redacted. Nothing returns a value, and nothing runs a command.

- **Which sets** are offered is a list you give (`--sets`). There is no default.
- **Who** may call: you by default, as Tailscale knows you. `--allow` takes
  logins, `tag:` names and device names, repeatably (`--allow tag:ci`). A
  tagged device is matched by its tags only, never by a login.
- **How it knows:** the broker listens on the tailnet address only. Each
  connection's source address goes to the local Tailscale daemon (`whois`),
  and identity is never read from anything the caller sends. Answers are
  remembered for a minute per address. A request with a browser's `Origin`
  header is refused.
- **Approval:** a broker refuses to start unless the vault's policy asks
  before `request`. It also refuses to start when nothing can show that
  prompt, because then every request would be refused. Every request shows
  the usual prompt, saying who asked ("From: you@example.com on build-box (says
  it is claude-code)"). Where it shows:
  - **on the device of the person who asked**, if one is paired for them:
    `hush approvals pair --relay <url> --for sam@example.com` on the broker,
    accepted on Sam's laptop. A device paired for someone answers only for them.
  - otherwise **on the broker's own screen**, or, on a headless broker, on
    the devices paired for nobody in particular (your laptop, over the relay
    from step 1).
  - An "Allow 15 min" covers that caller only, never another person making
    the same request.
  `--without-approval` turns approval off for the broker and says so.
- **The app's name:** an agent's MCP client names itself when it connects
  (`claude-code`). The broker keeps that for the session and shows it in
  prompts and the log as "says it is …". It is a hint, never a permission:
  Tailscale cannot tell two agents on one machine apart, and a name an agent
  picks for itself proves nothing.
- **Audit:** every call, refusal and approval goes into the vault's
  `audit.log` with the caller's name.
- **https:** the broker serves https with this machine's tailnet certificate
  (`tailscale cert`, renewed daily; key kept in `~/.hush/broker`, readable by
  you only). It still listens on the tailnet address itself, so the caller
  check keeps working. If the tailnet has HTTPS certificates turned off, it
  says so and serves plain http inside WireGuard. `--no-tls` forces http.
- **Speed:** on Linux, identity comes straight from tailscaled's socket in
  milliseconds. Elsewhere the `tailscale` CLI answers in a second or so, once
  a minute per caller. `--port` changes 8788; `--vault <name>` serves a vault
  other than your library.

## The problem

hush decrypts on the machine you are sitting at. That fits an agent running in
your terminal. It fits badly the agents that increasingly run elsewhere: on a
VPS, in a devcontainer, in a cloud sandbox, on a home server, in CI. Each one
needs the vault and an identity copied onto it, or a way to ask you.

The approval relay already covers the asking ([RELAY.md](RELAY.md)): a sealed
request goes to your laptop, and a signed answer comes back. What is missing is
a place, other than your laptop, that can **hold** keys and **use** them on an
agent's behalf, with someone checking who is asking.

## Why a tailnet

A secrets broker normally has to build three hard things. A tailnet already
has all three:

| A broker needs | Tailscale already gives it |
|---|---|
| Who is calling | Every connection comes from a known device and user. The local daemon answers "who is 100.x.y.z" (`tailscale whois`, the LocalAPI), and `tailscale serve` passes the caller's login to the service it fronts. |
| What they may do | The tailnet policy file attaches **app capabilities** to users, groups and tags (`"grants": [{ "src": ["group:eng"], "dst": ["tag:hush"], "app": { "github.com/omarei-omoto/cap/hush": [{ "sets": ["staging"] }] } }]`). The same "who is calling" lookup returns them. |
| A reachable, encrypted address | `tailscale serve` gives `https://<device>.<tailnet>.ts.net` a real certificate, reachable only inside the tailnet. |

So the pitch stays "no SaaS": the broker is a machine you own, and identity
and permissions come from a tailnet you already run.

## Shape

A **hush broker** is `hush serve --tailnet` on one tailnet device: a home
server, a mini PC, a VPS. It holds a library vault, ideally with a hardware
key (Secure Enclave or YubiKey). It serves:

- **MCP over HTTPS**, through `tailscale serve`. Any agent on any tailnet
  machine adds `https://hush.<tailnet>.ts.net/mcp` as a remote MCP server,
  with no token to paste.
- **A small HTTP API** for `hush` on other tailnet machines (`hush run
  --from <broker>`).

The git vault stays. It is still the source of truth for a team, and the
offline fallback. The broker is optional and sits on top of it.

### What a remote caller can get, strongest first

1. **Nothing: the broker uses the key itself.** `hush_request` already makes
   an API call inside hush and returns a redacted response. On the broker, the
   key never reaches the agent's machine. This is where to start.
2. **A short-lived key the broker mints.** AWS STS, GitHub App tokens,
   Cloudflare API tokens and OpenAI project keys can be minted from a root
   credential. The root stays on the broker; the caller gets an hour.
3. **A lease of the real value**, for programs that must hold it (`psql`,
   `vercel`). `hush run --from broker` receives the values over WireGuard
   after approval, injects them into one child process, and keeps nothing.
   The value reaches that machine, but only in memory, and it is logged.

### Who is asking: three layers

- **Device and user**, from Tailscale. A tagged device (`tag:ci`) has no
  user, and its tag is its identity.
- **Which agent.** Tailscale cannot tell two agents on one machine apart. An
  agent that needs its own permissions gets an agent member key (planned
  separately), presented on top of the tailnet identity.
- **Whether a person agreed.** Approvals go to the owner's laptop or phone
  over the relay, as today. A tailnet identity says the request came from
  your machine; only an approval says you meant it.

## Threat model, first pass

| Risk | Answer |
|---|---|
| The broker host is compromised | It can decrypt everything it holds. Use a hardware-held key, require approval for anything sensitive, run nothing else on the device, and keep it to library sets rather than every project. |
| A stolen, unlocked device on the tailnet | It *is* that user to Tailscale. Approvals with a fingerprint, and Tailscale device posture or key expiry. |
| The tailnet's control plane or admin is compromised | They can rewrite who may ask. Approvals still stand between asking and using. Self-hosting the control plane (Headscale) is the user's choice, and which grants features Headscale supports needs checking. |
| The broker is down | Nothing gets secrets through it. The git vault and local hush keep working. |
| An agent on an allowed device | Allowed devices are not allowed agents. The command policy, `allowHosts` and approvals apply as they do locally. |

This needs a proper review before anyone puts production keys behind it.

## Steps

1. **The relay over the tailnet.** *Done (beta).* `hush relay serve` prints
   the `tailscale serve` line and the pairing URL when Tailscale is running.
   Approvals from server-side agents reach the laptop with no SSH tunnel.
   Checked live: the relay answered through `tailscale serve` with a valid
   certificate.
2. **`hush serve --tailnet`, request-only.** *Done (beta).* MCP over HTTP on
   the tailnet address, with callers identified by whois and checked against
   `--allow`. Tools: `hush_list_sets` and `hush_request`. No value leaves the
   broker. Checked live: a call over the tailnet reached the stand-in API with
   the real key and came back redacted. It binds the tailnet address directly
   rather than sitting behind `tailscale serve`: behind it, every connection
   comes from 127.0.0.1, and identity would have to come from headers that any
   local process could forge.
3. **Leases.** `hush run --from <broker>`, approval-gated and logged.
4. **Teams.** Sets granted through tailnet app capabilities. The broker's
   own audit log is append-only and readable by admins.
5. **Minting**, and **approving from a phone**, built on the same broker.

## Open questions

- Should hush talk to the local Tailscale daemon's LocalAPI over its socket
  (the daemon must be installed), or embed a tailnet node? Embedding (tsnet)
  is Go-only. hush is TypeScript, so the daemon is the realistic route.
- Where the broker's allow-list lives before app capabilities: in the broker's
  `policy.json`, with the floor rules hush already has.
- How a lease's lifetime is enforced on a machine hush does not control: it
  cannot be. A lease is "given once, logged". Minting is the answer where
  expiry matters.
