# hush on a tailnet: design

Status: **design, step 1 shipped on the beta branch.** Nothing below step 1 exists
yet. This is the plan and the reasoning, to be argued with before it is built.

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
2. **`hush serve --tailnet`, request-only.** MCP over HTTPS behind `tailscale
   serve`. Callers are identified with whois, and an allow-list of users and
   tags lives in the broker's policy. Tools: list and describe sets, and
   `hush_request`. No value ever leaves the broker.
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
