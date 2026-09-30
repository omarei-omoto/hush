---
title: "Run `hush approvals listen` as a login service"
labels: ["help wanted", "platform:macos", "platform:linux"]
---

`hush approvals listen` has to be running for a paired server's approvals to reach you (docs/RELAY.md). Today that means a terminal left open. It should be one command to install as a launchd agent (macOS) or a systemd user unit (Linux) that starts at login and restarts on failure:

```bash
hush approvals listen --install      # and --uninstall
```

**Files**
- `src/commands/approvals.ts`: write `~/Library/LaunchAgents/dev.omarei.hush.approvals.plist` or `~/.config/systemd/user/hush-approvals.service`, pointing at `selfCommand(["approvals","listen"])` (`src/cli/programs.ts`), and load it.

**Test**: the generated plist and unit, from a fixture home: the right command, no environment carried over that could weaken hush, and `--uninstall` removes exactly what `--install` wrote. Loading them is not tested in CI.

---
**The bar:** a test that fails without the change (CONTRIBUTING.md, "The bar for a change"). Run it with `node --test <file>`; use a throwaway `HUSH_HOME` to try it by hand.
