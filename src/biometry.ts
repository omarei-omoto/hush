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
 * The helper is compiled on demand and cached, so there is no prebuilt binary
 * in the repo and no native dependency at install time.
 */
import { execFile, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { platform } from "node:os";
import { hushHome } from "./identity.ts";

export type BiometryMode = "off" | "preferred" | "required";
export type BiometryResult = "ok" | "denied" | "unavailable";

const binDir = (): string => join(hushHome(), "bin");
const binPath = (): string => join(binDir(), "hush-touchid");
const stampPath = (): string => join(binDir(), "hush-touchid.stamp");

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

/**
 * Compile the helper if it is missing or the source has changed.
 *
 * `plat` is a parameter only so the non-macOS answer can be checked from a mac,
 * which is the only machine this is ever developed on. Removing the platform
 * check is invisible here and turns every Linux install into a swiftc error, so
 * "untestable on this host" was not a good enough reason to leave it uncovered.
 */
export function ensureHelper(plat: string = platform()): { ok: boolean; reason?: string; path?: string } {
  // Escape hatch for headless machines, CI, and tests.
  if (process.env.HUSH_BIOMETRY === "off") return { ok: false, reason: "disabled by HUSH_BIOMETRY=off" };
  if (plat !== "darwin") return { ok: false, reason: "biometry gating is macOS-only for now" };

  const src = sourcePath();
  if (!existsSync(src)) return { ok: false, reason: `helper source missing at ${src}` };

  const digest = createHash("sha256").update(readFileSync(src)).digest("hex").slice(0, 16);
  if (existsSync(binPath()) && existsSync(stampPath()) && readFileSync(stampPath(), "utf8").trim() === digest) {
    return { ok: true, path: binPath() };
  }
  if (!haveSwift()) {
    return { ok: false, reason: "swiftc not found — install Xcode Command Line Tools (xcode-select --install)" };
  }

  try {
    mkdirSync(binDir(), { recursive: true, mode: 0o700 });
    execFileSync("swiftc", ["-O", src, "-o", binPath()], { stdio: "pipe" });
    writeFileSync(stampPath(), digest);
    return { ok: true, path: binPath() };
  } catch (e) {
    return { ok: false, reason: `could not compile helper: ${(e as Error).message.split("\n")[0]}` };
  }
}

export interface BiometryStatus {
  available: boolean;
  kind: "Touch ID" | "Face ID" | "none";
  reason?: string;
}

export function biometryStatus(): BiometryStatus {
  const helper = ensureHelper();
  if (!helper.ok) return { available: false, kind: "none", reason: helper.reason };
  try {
    const out = execFileSync(binPath(), ["--check"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
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
export function authenticate(reason: string, timeoutMs = 60_000): Promise<BiometryResult> {
  const helper = ensureHelper();
  if (!helper.ok) return Promise.resolve("unavailable");

  return new Promise((res) => {
    execFile(binPath(), [reason], { timeout: timeoutMs }, (err) => {
      if (!err) return res("ok");
      const code = (err as NodeJS.ErrnoException & { code?: number }).code;
      res(code === 2 ? "unavailable" : "denied");
    });
  });
}
