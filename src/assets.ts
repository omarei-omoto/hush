/**
 * Files hush reads from its own package at runtime: the agent skill, and the
 * Swift source of the macOS helpers it compiles for itself.
 *
 * From a checkout or an npm install they are read from beside the code. The
 * single-file binary (scripts/build-binaries.mjs) has no "beside": its build
 * puts their text in `globalThis.__HUSH_ASSETS__` before any of hush loads, and
 * that wins when present.
 */
import { readFileSync } from "node:fs";

const FILES = {
  skill: "../skills/hush/SKILL.md",
  touchid: "../native/hush-touchid.swift",
  enclave: "../native/hush-enclave.swift",
} as const;

export type AssetName = keyof typeof FILES;

/** The asset's text, or null when this copy of hush does not have it. */
export function asset(name: AssetName): string | null {
  const embedded = (globalThis as { __HUSH_ASSETS__?: Record<string, string> }).__HUSH_ASSETS__;
  if (embedded && typeof embedded[name] === "string") return embedded[name];
  try {
    return readFileSync(new URL(FILES[name], import.meta.url), "utf8");
  } catch {
    return null;
  }
}

/** Where each asset lives in the package, for the binary build. */
export const ASSET_FILES: Readonly<Record<AssetName, string>> = FILES;
