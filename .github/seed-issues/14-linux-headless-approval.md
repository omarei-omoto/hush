---
title: "Linux: approval on a desktop session without zenity or kdialog"
labels: ["platform:linux", "needs-design"]
---

On a Linux desktop with neither `zenity` nor `kdialog`, hush refuses every gated action (or uses the relay, if paired). Options:

- polkit (`pkcheck`): asks through the desktop's own authentication agent, the dialog people already trust for admin actions. It needs an action file installed as root.
- `systemd-ask-password`: terminal or plymouth. Is the answer something the caller cannot supply?
- the freedesktop portal (`org.freedesktop.portal`): is there a portal for confirmation?

The rule that decides it: the answer must come from something the gated process cannot fake (see `src/approval.ts`, and `dialogs.ts`'s `systemProgram`). Please argue the approach in this issue first.

---
**The bar:** a test that fails without the change (CONTRIBUTING.md, "The bar for a change"). Run it with `node --test <file>`; use a throwaway `HUSH_HOME` to try it by hand.
