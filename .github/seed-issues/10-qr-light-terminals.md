---
title: "Pairing QR code on light-background terminals"
labels: ["good first issue"]
---

`hush approvals pair` draws its QR code for dark terminals: light modules are text-coloured blocks (`qrToTerminal` in `src/qr.ts`). On a light theme the code comes out inverted, and some phone cameras will not read that.

Add `--qr-invert`, or better, detect the background from `COLORFGBG` where the terminal sets it.

**Files**
- `src/qr.ts`: an `invert` option in `qrToTerminal`.
- `src/commands/approvals.ts`: the flag, or the detection.

**Test** (`test/relay.test.ts`, "the pairing QR code"): the inverted rendering is the exact complement inside the quiet zone, and the quiet zone stays light.

---
**The bar:** a test that fails without the change (CONTRIBUTING.md, "The bar for a change"). Run it with `node --test <file>`; use a throwaway `HUSH_HOME` to try it by hand.
