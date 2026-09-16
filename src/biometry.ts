/**
 * Touch ID / Face ID gating.
 *
 * WHAT THIS IS: proof that a human with an enrolled fingerprint is physically
 * at the machine at the moment a credential is used. It stops an agent from
 * approving its own request, it stops someone walking up to an unlocked laptop,
 * and it turns "allow" from a click into something only you can do.
 *
 * WHAT THIS IS NOT: protection of the key at rest. The identity key still lives
 * in the login keychain, and anything running as you can read it without ever
 * calling this. Making the key itself unreadable requires a non-extractable
 * Secure Enclave key, which macOS will only permit to a binary signed with a
 * real Apple Developer ID. See docs/BIOMETRY.md for that path.
 *
 * The helper is compiled on demand, every time, into a private scratch folder
 * that only this process can write, so there is no prebuilt binary in the repo
 * and no native dependency at install time. It used to be compiled once into
 * `~/.hush/bin/` and reused while a stamp matched — but that path is inside the
 * user's own home, which is exactly where anything running as the user can
 * write, so a program could have replaced it and answered "ok" without a finger
 * ever touching the sensor. Nothing is trusted from disk now: the binary is
 * built from hush's own source each time this process needs it, and the only
 * copies on disk are ones this process just made.
 */
import { execFile, execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { platform, tmpdir } from "node:os";

export type BiometryMode = "off" | "preferred" | "required";
export type BiometryResult = "ok" | "denied" | "unavailable";

function sourcePath(): string {
  return join(dirname(new URL(import.meta.url).pathname), "..", "native", "hush-touchid.swift");
}

function haveSwift(): boolean {
  try {
    execFileSync("which", ["swiftc"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/** Per-process cache: one compile per platform, however many times we ask. */
let compiled: { plat: string; result: { ok: boolean; reason?: string; path?: string } } | null = null;

/** Test seam: forget the compile done by this process. Real callers never need it. */
export function resetBiometryCache(): void {
  compiled = null;
}

/**
 * Build the helper, from hush's own Swift source, into a folder only this
 * process can write.
 *
 * The result is cached for the life of the process — a long-lived MCP server
 * or `hush ui` compiles once, a one-shot command compiles once — so the price
 * of not trusting a binary on disk is paid per process, not per approval.
 *
 * `plat` is a parameter only so the non-macOS answer can be checked from a mac,
 * which is the only machine this is ever developed on. Removing the platform
 * check is invisible here and turns every Linux install into a swiftc error, so
 * "untestable on this host" was not a good enough reason to leave it uncovered.
 */
export function ensureHelper(plat: string = platform()): { ok: boolean; reason?: string; path?: string } {
  // Escape hatch for headless machines, CI, and tests.
  if (process.env.HUSH_BIOMETRY === "off") return { ok: false, reason: OFF_REASON };
  if (plat !== "darwin") return { ok: false, reason: "biometry gating is macOS-only for now" };
  if (compiled?.plat === plat) return compiled.result;

  const src = sourcePath();
  if (!existsSync(src)) return { ok: false, reason: `helper source missing at ${src}` };
  if (!haveSwift()) {
    return (compiled = {
      plat,
      result: {
        ok: false,
        reason: "swiftc not found — install Xcode Command Line Tools (xcode-select --install)",
      },
    }).result;
  }

  try {
    // Created fresh, and the whole directory goes away when this process does:
    // the only binary in play is one this process just built. mkdtemp already
    // makes it 0700; asking again is the cross-check.
    const dir = mkdtempSync(join(tmpdir(), "hush-touchid-"));
    chmodSync(dir, 0o700);
    const bin = join(dir, "hush-touchid");
    // -Onone: this helper makes one LocalAuthentication call, so optimisation
    // buys nothing and costs compile time on someone's approval.
    execFileSync("swiftc", ["-Onone", src, "-o", bin], { stdio: "pipe" });
    // swiftc leaves it executable; say so explicitly so a umask cannot surprise
    // the spawn later, and prove it landed before claiming success.
    chmodSync(bin, 0o500);
    if (!statSync(bin).isFile()) throw new Error("swiftc did not produce a binary");
    process.once("exit", () => {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    });
    return (compiled = { plat, result: { ok: true, path: bin } }).result;
  } catch (e) {
    return (compiled = {
      plat,
      result: { ok: false, reason: `could not compile helper: ${(e as Error).message.split("\n")[0]}` },
    }).result;
  }
}

export interface BiometryStatus {
  available: boolean;
  kind: "Touch ID" | "Face ID" | "none";
  reason?: string;
}

/**
 * Seam for tests, and only for tests.
 *
 * The exit statuses that matter most — a cancelled prompt, a machine with no
 * enrolled finger — cannot be produced on demand. Injecting the program is the
 * only way to cover them. Deliberately *not* an environment variable: an
 * ambient `HUSH_TOUCHID_HELPER=/tmp/fake` would be a switch that makes every
 * fingerprint check succeed, which anything running as you could set. A
 * parameter can only be supplied by a caller inside this process, and no
 * production caller supplies one.
 */
export interface BiometryDeps {
  helperPath?: string;
  platform?: () => string;
}

const OFF_REASON = "disabled by HUSH_BIOMETRY=off";

/**
 * Which program to run. The injected path is a test seam; the opt-out is
 * checked here too, so a stubbed helper cannot make `HUSH_BIOMETRY=off` look
 * ignored — the escape hatch has to win wherever it is set.
 */
const helperFor = (deps: BiometryDeps): { ok: boolean; reason?: string; path?: string } => {
  if (process.env.HUSH_BIOMETRY === "off") return { ok: false, reason: OFF_REASON };
  if (deps.helperPath) return { ok: true, path: deps.helperPath };
  return ensureHelper(deps.platform ? deps.platform() : platform());
};

export function biometryStatus(deps: BiometryDeps = {}): BiometryStatus {
  const helper = helperFor(deps);
  if (!helper.ok) return { available: false, kind: "none", reason: helper.reason };
  try {
    const out = execFileSync(helper.path!, ["--check"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    const [can, type] = out.split(/\s+/);
    if (can !== "yes") return { available: false, kind: "none", reason: "no fingerprint enrolled" };
    return { available: true, kind: type === "2" ? "Face ID" : "Touch ID" };
  } catch {
    return { available: false, kind: "none", reason: "no fingerprint enrolled, or biometry is locked out" };
  }
}

/**
 * Prompt for a fingerprint. `reason` is shown verbatim in the system sheet, so
 * it must name the actual action — this is the only thing the human sees.
 */
export function authenticate(
  reason: string,
  timeoutMs = 60_000,
  deps: BiometryDeps = {},
): Promise<BiometryResult> {
  const helper = helperFor(deps);
  if (!helper.ok) return Promise.resolve("unavailable");

  return new Promise((res) => {
    execFile(helper.path!, [reason], { timeout: timeoutMs }, (err) => {
      if (!err) return res("ok");
      const code = (err as NodeJS.ErrnoException & { code?: number }).code;
      res(code === 2 ? "unavailable" : "denied");
    });
  });
}
