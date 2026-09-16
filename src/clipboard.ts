/**
 * Putting a value on the clipboard instead of into the scrollback.
 *
 * `hush get KEY` prints a live credential to the terminal, where it stays in
 * the scrollback, in the tmux buffer, and in whatever is recording the session.
 * The clipboard is the same reveal with less residue, so this exists to make
 * the safer option the easier one.
 *
 * The value goes in through a pipe and never through argv, where `ps` would
 * show it to every user on the machine.
 */
import { spawnSync } from "node:child_process";
import { onPath } from "./which.ts";

export interface ClipboardCommand {
  cmd: string;
  args: string[];
}

/** In preference order: whichever exists is the one to use. */
export function clipboardCandidates(platform: NodeJS.Platform = process.platform): ClipboardCommand[] {
  if (platform === "darwin") return [{ cmd: "pbcopy", args: [] }];
  return [
    { cmd: "wl-copy", args: [] },
    { cmd: "xclip", args: ["-selection", "clipboard"] },
    { cmd: "xsel", args: ["-b"] },
  ];
}

/** The names to suggest when none of them is installed. */
export function clipboardNames(platform: NodeJS.Platform = process.platform): string[] {
  return clipboardCandidates(platform).map((c) => c.cmd);
}

/**
 * The binary that will be used, resolved to a path.
 *
 * Resolved rather than left to PATH at spawn time, for the same reason the age
 * bridge resolves its own: by the time a copy fails, "no such command" is a
 * long way from the cause.
 */
export function findClipboard(
  platform: NodeJS.Platform = process.platform,
): { cmd: string; args: string[]; path: string } | null {
  for (const candidate of clipboardCandidates(platform)) {
    const path = onPath(candidate.cmd);
    if (path) return { ...candidate, path };
  }
  return null;
}

/**
 * Copy `text` to the clipboard.
 *
 * Synchronous because every caller is a CLI command about to exit; a handle
 * would buy nothing. `spawnSync` with `input` is the one form that cannot leak
 * the value into argv.
 */
export function copyToClipboard(
  text: string,
  platform: NodeJS.Platform = process.platform,
): { ok: boolean; via?: string; reason?: string } {
  const found = findClipboard(platform);
  if (!found) return { ok: false, reason: "none" };

  const r = spawnSync(found.path, found.args, {
    input: text,
    stdio: ["pipe", "ignore", "ignore"],
  });
  if (r.error) return { ok: false, via: found.cmd, reason: r.error.message };
  if (r.status !== 0) return { ok: false, via: found.cmd, reason: `${found.cmd} exited ${r.status}` };
  return { ok: true, via: found.cmd };
}
