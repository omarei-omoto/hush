/**
 * Building hush's macOS helpers (Touch ID, the Secure Enclave) from its own
 * Swift source, with a compiler the caller cannot choose.
 *
 * A helper decides whether a fingerprint was given, or holds the only handle
 * to an enclave key, so whatever builds it is part of that decision. `swiftc`
 * used to come from PATH, which the process asking for an approval controls —
 * a planted `swiftc` could build a "helper" that says yes without anyone
 * touching the sensor. Now:
 *
 *   - `swiftc` is /usr/bin/swiftc only, and only if it is a root-owned regular
 *     file nobody else can write (Apple's shim; the toolchain it runs is the one
 *     `xcode-select` — an admin — chose);
 *   - it runs with a scrubbed environment: no DEVELOPER_DIR, SDKROOT or
 *     TOOLCHAINS to point the shim somewhere else, and a PATH of system
 *     directories only;
 *   - the source is written into a fresh 0700 directory this process just
 *     made, compiled there, and the directory is removed when the process ends.
 */
import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const SWIFTC = "/usr/bin/swiftc";

/** /usr/bin/swiftc, if it is a root-owned file that only root can change. */
export function trustedSwiftc(): string | null {
  try {
    const st = statSync(SWIFTC);
    if (!st.isFile() || st.uid !== 0 || (st.mode & 0o022) !== 0) return null;
    return SWIFTC;
  } catch {
    return null;
  }
}

/** The environment swiftc runs in: nothing the caller could use to redirect it. */
export function compilerEnv(): NodeJS.ProcessEnv {
  return {
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
    ...(process.env.HOME ? { HOME: process.env.HOME } : {}),
    ...(process.env.TMPDIR ? { TMPDIR: process.env.TMPDIR } : {}),
  };
}

/** Compile `source` into a private, process-lifetime binary called `name`. */
export function buildSwiftHelper(name: string, source: string): { ok: boolean; path?: string; reason?: string } {
  const swiftc = trustedSwiftc();
  if (!swiftc) {
    return { ok: false, reason: "swiftc not found at /usr/bin — install Xcode Command Line Tools (xcode-select --install)" };
  }
  try {
    const dir = mkdtempSync(join(tmpdir(), `hush-${name}-`));
    chmodSync(dir, 0o700);
    const src = join(dir, `${name}.swift`);
    const bin = join(dir, name);
    writeFileSync(src, source, { mode: 0o600 });
    // -Onone: a helper makes a handful of system calls; optimisation buys
    // nothing and costs compile time on someone's approval.
    execFileSync(swiftc, ["-Onone", src, "-o", bin], { stdio: "pipe", env: compilerEnv() });
    chmodSync(bin, 0o500);
    if (!statSync(bin).isFile()) throw new Error("swiftc did not produce a binary");
    process.once("exit", () => {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    });
    return { ok: true, path: bin };
  } catch (e) {
    return { ok: false, reason: `could not compile the ${name} helper: ${(e as Error).message.split("\n")[0]}` };
  }
}
