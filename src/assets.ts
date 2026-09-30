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

const embedded = (): Record<string, string> | undefined =>
  (globalThis as { __HUSH_ASSETS__?: Record<string, string> }).__HUSH_ASSETS__;

/**
 * Whether this is the single-file binary. There, `process.execPath` is hush
 * itself — not node — and there is no source tree beside anything.
 */
export const standalone = (): boolean => Boolean(embedded());

/** The asset's text, or null when this copy of hush does not have it. */
export function asset(name: AssetName): string | null {
  const assets = embedded();
  if (assets && typeof assets[name] === "string") return assets[name];
  try {
    return readFileSync(new URL(FILES[name], import.meta.url), "utf8");
  } catch {
    return null;
  }
}

/**
 * The `hush ui` page, as the binary build assembled it — or null outside the
 * binary. The page is five String.raw templates, and a bundler that writes
 * non-ASCII as `\u2026` changes a raw template's *value*: the binary served a
 * literal backslash-u where the page said "…". A plain string carries the
 * escape harmlessly, so the build embeds the finished page as one.
 */
export const builtPage = (): string | null => {
  const assets = embedded();
  return assets && typeof assets.page === "string" ? assets.page : null;
};

/** Where each asset lives in the package, for the binary build. */
export const ASSET_FILES: Readonly<Record<AssetName, string>> = FILES;
