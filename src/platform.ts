/**
 * What is different on Windows (F-7, beta), in one place.
 *
 * - Programs hush trusts to draw a dialog or copy to the clipboard are resolved
 *   under %SystemRoot%\System32 — a directory an ordinary user cannot write —
 *   and always run by absolute path, the same rule the POSIX side follows with
 *   root-owned /usr/bin.
 * - A file mode means little to NTFS, so a file that holds a secret is also
 *   restricted with icacls to the current user alone.
 * - Node refuses to spawn a `.cmd` or `.bat` file directly (they need cmd.exe),
 *   and `npm`, `pnpm` and friends are exactly that on Windows. So those go
 *   through cmd.exe with every argument escaped for it — the rules cross-spawn
 *   uses, reproduced here because hush has no dependencies.
 */
import { spawnSync } from "node:child_process";
import { statSync } from "node:fs";
import { join } from "node:path";

export const isWindows = (platform: string = process.platform): boolean => platform === "win32";

/**
 * The Windows folder, decided without trusting the environment's say-so.
 *
 * %SystemRoot% is an environment variable, and the environment belongs to
 * whoever started this process — the gated agent included. Taken as given, it
 * chose which powershell.exe received the private identity key on its way
 * into DPAPI, and which program drew the approval dialog. So C:\Windows is
 * the answer wherever it exists, and the variable is consulted only on a
 * machine without one — Windows installed on another drive — and even then
 * only when it names `<drive>:\Windows`, never a folder of the caller's.
 */
export function windowsRoot(env: NodeJS.ProcessEnv = process.env, exists: (p: string) => boolean = isDirectory): string {
  const standard = "C:\\Windows";
  if (exists(standard)) return standard;
  const claimed = env.SystemRoot || env.SYSTEMROOT;
  return claimed && /^[A-Za-z]:\\Windows$/i.test(claimed) ? claimed : standard;
}

function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

/** A program under the Windows folder's System32, if it is there as a regular file. */
export function system32(...parts: string[]): string | null {
  const path = join(windowsRoot(), "System32", ...parts);
  try {
    return statSync(path).isFile() ? path : null;
  } catch {
    return null;
  }
}

/** Windows PowerShell 5.1, which every supported Windows ships. */
export const powershellPath = (): string | null => system32("WindowsPowerShell", "v1.0", "powershell.exe");

/**
 * Make a file readable by its owner only. A no-op off Windows, where the 0600
 * mode it was created with already does this.
 */
export function restrictToOwner(path: string, platform: string = process.platform): boolean {
  if (!isWindows(platform)) return true;
  const icacls = system32("icacls.exe");
  const user = process.env.USERNAME;
  if (!icacls || !user) return false;
  const domain = process.env.USERDOMAIN ? `${process.env.USERDOMAIN}\\${user}` : user;
  const r = spawnSync(icacls, [path, "/inheritance:r", "/grant:r", `${domain}:F`], { stdio: "ignore", windowsHide: true });
  return r.status === 0;
}

// ------------------------------------------------------ spawning on Windows

const META = /([()\][%!^"`<>&|;, *?])/g;

/** Escape one argument for a cmd.exe command line (cross-spawn's rules). */
export function escapeCmdArgument(arg: string, doubleEscapeMetaChars: boolean): string {
  let a = String(arg);
  // Backslashes before a quote are doubled, and the quote is escaped.
  a = a.replace(/(?=(\\+?)?)\1"/g, '$1$1\\"');
  // Trailing backslashes are doubled so they do not escape the closing quote.
  a = a.replace(/(?=(\\+?)?)\1$/, "$1$1");
  a = `"${a}"`;
  a = a.replace(META, "^$1");
  // A batch file parses its arguments a second time.
  if (doubleEscapeMetaChars) a = a.replace(META, "^$1");
  return a;
}

export const escapeCmdCommand = (cmd: string): string => cmd.replace(META, "^$1");

/**
 * How to spawn `command args…` so that it works on this platform: unchanged,
 * except a Windows `.cmd`/`.bat`, which goes through cmd.exe with every argument
 * escaped — never `shell: true`, which would pass them through unescaped.
 */
export function spawnPlan(
  command: string,
  args: string[],
  platform: string = process.platform,
): { command: string; args: string[]; windowsVerbatimArguments?: boolean } {
  if (!isWindows(platform) || !/\.(cmd|bat)$/i.test(command)) return { command, args };
  const shellCommand = [escapeCmdCommand(command), ...args.map((x) => escapeCmdArgument(x, true))].join(" ");
  const comspec = process.env.ComSpec || system32("cmd.exe") || "cmd.exe";
  return { command: comspec, args: ["/d", "/s", "/c", `"${shellCommand}"`], windowsVerbatimArguments: true };
}
