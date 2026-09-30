/**
 * A hush identity in the Secure Enclave (F-8, macOS).
 *
 * The top rung of the ladder — a key that cannot be copied off this machine,
 * and that needs a fingerprint (or the Mac's password) for every use — without
 * buying anything or installing anything: hush compiles a small helper
 * (native/hush-enclave.swift) with the trusted builder in swift.ts, the helper
 * makes a P-256 key inside the enclave, and hush keeps only the sealed blob the
 * enclave hands back, in ~/.hush/enclave-identity.
 *
 * What an attacker running as you gets: the blob (useless on any other Mac),
 * and on this Mac an enclave that will agree a key only after a fingerprint.
 * They cannot read the key, copy it, or use it quietly.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { platform } from "node:os";
import { asset } from "./assets.ts";
import { buildSwiftHelper } from "./swift.ts";
import { hushHome } from "./identity.ts";

export const enclaveFile = (): string => join(hushHome(), "enclave-identity");

let helper: { ok: boolean; path?: string; reason?: string } | null = null;

function ensureHelper(): { ok: boolean; path?: string; reason?: string } {
  if (platform() !== "darwin") return { ok: false, reason: "the Secure Enclave is a Mac thing" };
  if (helper) return helper;
  const source = asset("enclave");
  if (!source) return (helper = { ok: false, reason: "the enclave helper's source is missing from this copy of hush" });
  return (helper = buildSwiftHelper("enclave", source));
}

/**
 * The seam for tests, and only for tests: a stand-in for the helper's key
 * agreement, supplied by a caller inside this process. Deliberately not an
 * environment variable — see biometry.ts for why a switch anything running as
 * you could set is not a seam.
 */
type Agree = (blobPath: string, peerPub: Buffer, reason: string) => Buffer;
let agreeOverride: Agree | null = null;
export function setEnclaveForTests(fn: Agree | null): void {
  agreeOverride = fn;
}

/** Is there an enclave here that hush can use? */
export function enclaveAvailable(): { ok: boolean; reason?: string } {
  const h = ensureHelper();
  if (!h.ok) return { ok: false, reason: h.reason };
  try {
    execFileSync(h.path!, ["available"], { stdio: "ignore" });
    return { ok: true };
  } catch {
    return { ok: false, reason: "this Mac has no Secure Enclave" };
  }
}

/** The enclave identity on this machine, if there is one. */
export function loadEnclaveIdentity(): { pub: Buffer; blobPath: string } | null {
  const file = enclaveFile();
  if (!existsSync(file)) return null;
  try {
    const { pub } = JSON.parse(readFileSync(file, "utf8")) as { pub: string };
    const raw = Buffer.from(pub, "base64");
    return raw.length === 65 ? { pub: raw, blobPath: `${file}.blob` } : null;
  } catch {
    return null;
  }
}

/**
 * Make an enclave identity. `touch` (the default) means the enclave asks for a
 * fingerprint or the Mac's password on every use; `none` makes a key that is
 * still non-extractable but usable without anyone present.
 */
export function createEnclaveIdentity(presence: "touch" | "none" = "touch"): { pub: Buffer; blobPath: string } {
  const h = ensureHelper();
  if (!h.ok) throw new Error(h.reason ?? "no Secure Enclave helper");
  const out = execFileSync(h.path!, ["create", presence], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const { blob, pub } = JSON.parse(out) as { blob: string; pub: string };
  mkdirSync(hushHome(), { recursive: true, mode: 0o700 });
  // The blob in its own file (the helper reads it by path); the public half
  // beside it, so `hush id` never has to wake the enclave.
  writeFileSync(`${enclaveFile()}.blob`, blob + "\n", { mode: 0o600 });
  chmodSync(`${enclaveFile()}.blob`, 0o600);
  writeFileSync(enclaveFile(), JSON.stringify({ pub, presence, createdAt: new Date().toISOString() }) + "\n", { mode: 0o600 });
  return { pub: Buffer.from(pub, "base64"), blobPath: `${enclaveFile()}.blob` };
}

/**
 * The enclave's half of a key agreement with `peerPub`. With a `touch` key, this
 * is where the fingerprint sheet appears, showing `reason`.
 */
export function enclaveAgree(blobPath: string, peerPub: Buffer, reason: string): Buffer {
  if (agreeOverride) return agreeOverride(blobPath, peerPub, reason);
  const h = ensureHelper();
  if (!h.ok) throw new Error(h.reason ?? "no Secure Enclave helper");
  const out = execFileSync(h.path!, ["ecdh", blobPath, reason], {
    input: peerPub.toString("base64"),
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
  });
  const shared = Buffer.from(out.trim(), "base64");
  if (shared.length !== 32) throw new Error("the enclave returned no shared secret");
  return shared;
}
