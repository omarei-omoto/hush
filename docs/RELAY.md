# The approval relay (`hush/relay/v1`)

Approvals for a machine nobody is sitting at: a server you SSH into, a
devcontainer, a Codespace. hush on that machine (the **requester**) cannot show
a dialog, so it sends the approval to a device that has a person at it (the
**approver** — your laptop, running `hush approvals listen`), which shows the
usual dialog or asks for a fingerprint and sends back a signed answer.

```bash
# on the laptop, if you have no relay: run one, and carry it over SSH
hush relay serve
ssh -R 8787:localhost:8787 build-box

# on the server
hush approvals pair --relay http://localhost:8787      # prints a code and a QR code

# on the laptop
hush approvals accept hushpair1:…@http://localhost:8787
hush approvals listen
```

Both sides print the same safety number when pairing finishes. From then on,
any approval the server cannot show itself goes to the laptop. `hush approvals
ls` shows what is paired; `hush approvals rm <name>` undoes it.

This document is the protocol, for anyone writing another relay or another
approver (a phone app, say). The reference implementation is
[src/relay.ts](../src/relay.ts) and [src/relay-server.ts](../src/relay-server.ts);
[test/relay.test.ts](../test/relay.test.ts) is the conformance suite.

## What the relay can and cannot do

The relay is a mailbox. It holds no keys and needs no accounts.

| A hostile relay tries to… | What happens |
|---|---|
| read a request or an answer | It cannot. Both are sealed to the recipient's X25519 key. |
| change a request, or write its own | Refused. The approver shows only requests signed by the paired requester's Ed25519 key. |
| change an answer, or write its own | Refused. The requester accepts only answers signed by a paired approver. |
| replay an old Allow | Refused. An answer names one request id (random, per request) and the hash of that request's exact bytes. |
| answer "Allow for 15 min" where only "Allow once" was offered | Refused. So is a click where the request required a fingerprint. |
| put its own keys in the middle of pairing | Refused. Pairing messages carry a MAC under a secret the relay never sees. |
| drop or delay messages | It can. The request then times out and is refused, the same as with no relay. |
| see who talks to whom, and when | It can: box ids, sizes and timing. Use https, or a relay you run yourself. |

**What it is as strong as.** Something running as you on the requester can
rewrite `~/.hush/relay/peers.json` and pair a fake "approver" of its own. It
could equally read a software identity key in the same directory and skip hush
entirely. A relay approval therefore adds a person to the loop for everything
that goes *through* hush. It is not a boundary against code that already runs
as you on that machine; a hardware identity is the answer to that. SECURITY.md
says the same.

## Keys

Each device has one relay key pair, kept in `~/.hush/relay/device.json` (mode 0600):

- an X25519 key, which messages are sealed to (`hush_pk_…`, 32 bytes);
- an Ed25519 key, which messages are signed with (`hush_spk_…`, 32 bytes).

## Pairing

The requester makes a 32-byte `secret` and shows a **pairing code**, as text
and as a QR code:

```
hushpair1:<base64url(secret), 43 chars>@<relay URL>
```

The code travels out of band: someone reads it on one screen and enters it on
the other. From the secret, both sides derive the following with HKDF-SHA256
(`ikm = secret`, `salt = "hush/relay/v1"`, 32 bytes each):

| `info` | used as |
|---|---|
| `box/to-approver` | box id for requests (base64url, 43 chars) |
| `box/to-requester` | box id for answers |
| `pair/hello-mac` | HMAC-SHA256 key for the two hellos |

1. The requester posts its hello to `to-approver`, then waits on `to-requester`.
2. The approver reads the requester's hello from `to-approver`, checks the MAC,
   and posts its own hello to `to-requester`. That hello includes `peer`, the
   requester's `spk`, so each side knows the other has the right key.
3. The requester checks the MAC, and that `peer` is its own `spk`.

A hello looks like this; `mac` is HMAC over the canonical JSON of every other field:

```json
{"t":"hello","v":"hush/relay/v1","role":"requester","name":"build-box",
 "x":"hush_pk_…","spk":"hush_spk_…","peer":"hush_spk_… (approver only)","mac":"…"}
```

Canonical JSON means keys sorted at every level, with no whitespace. The safety
number is `safetyNumber(spk_a, spk_b)` from src/crypto.ts: SHA-512 over
`"hush/safety-number/v1"` and the two keys in sorted order, shown as 12 groups
of 5 digits.

## Sealing

`seal(plaintext, recipient)`:

1. Make an ephemeral X25519 key pair: `epk`, `eph`.
2. `shared = X25519(eph, recipient)`.
3. `key = HKDF-SHA256(ikm = shared, salt = epk ‖ recipient, info = "hush/relay/v1/seal", 32)`.
4. AES-256-GCM with a random 12-byte `iv`, and `AAD = "hush/relay/v1|seal|" ‖ recipient`.

On the wire: `{"v":1,"epk":…,"iv":…,"ct":…,"tag":…}`, all base64url.

Inside the seal is a signed body, `{"body": "<canonical JSON>", "sig": base64url}`.
`sig` is Ed25519 over `"hush/relay/v1/<request|answer>\n" ‖ body`.

## Requests and answers

A **request**, sealed to the approver and signed by the requester:

```json
{"t":"request","id":"<16 random bytes, base64url>","from":"<requester spk>",
 "created":<ms>,"expires":<ms>,"host":"build-box","action":"run",
 "summary":"run npm test","detail":["sets: default"],"code":"4821",
 "ttlSeconds":900,"biometry":false}
```

The approver shows a request only if all of these hold:

- it opens;
- it is signed by the paired requester's key, and `from` matches that key;
- `created` is at most 5 minutes in the future;
- `expires` has not passed, and is at most 600 s after `created`;
- it has not been shown already.

`code` is the code in the agent's transcript on the requester, and the dialog
shows it. `ttlSeconds: null` means only "Allow once" may be offered.
`biometry: true` means only a fingerprint counts.

An **answer**, sealed to the requester and signed by the approver:

```json
{"t":"answer","id":"<the request's id>","request":"<sha256 hex of the request body>",
 "decision":"once"|"session"|"deny","via":"dialog"|"biometry"|"none","answeredAt":<ms>}
```

The requester accepts an answer only if all of these hold:

- it opens;
- it is signed by a paired approver;
- `id` and `request` match a request it is waiting on;
- `session` is used only where `ttlSeconds` was set;
- `via` is `biometry` wherever the request required it (unless the answer is `deny`).

It takes the first answer that passes, and ignores everything else.

## The relay's HTTP API

```
POST /v1/boxes/<id>                 {"body": "<text>"}           → 201 {"seq": n}
GET  /v1/boxes/<id>?after=n&wait=s                               → 200 {"messages": [{"seq","body"}], "next": n}
GET  /v1/health                                                  → 200 {"ok": true, "protocol": "hush/relay/v1"}
```

- A box id is 43 base64url characters.
- A read returns the messages with `seq > after`. It waits up to `wait` seconds
  (at most 25) when there are none. Reads do not consume messages.
- `next` is the newest `seq` in the box. A client reads again with `after = next`.
- The reference relay's limits: 64 KiB per message, 64 messages per box (the
  oldest is dropped), 10,000 boxes, 10 minutes' retention.

Clients accept an `https://` relay, or `http://` to `localhost` only. The
latter is how `ssh -R` carries a relay running on your laptop to a server.

## What is not in this protocol (yet)

- **Push notifications to a phone.** A phone app would be an approver like any
  other. A hosted relay with push is part of hush Pro, not of hush; the
  protocol stays open.
- **More than one approver answering.** A request goes to every paired
  approver, and the first valid answer wins.
