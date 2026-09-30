/**
 * The Touch ID helper is built by this process from hush's own source — and by
 * a compiler this process can trust.
 *
 * It used to run `swiftc` from PATH. Anything that can set the environment of
 * the process asking for a fingerprint — an agent with a shell, which is the
 * thing the fingerprint gate exists to stop — could put its own `swiftc` first
 * on PATH (or point DEVELOPER_DIR at a toolchain of its own), and that compiler
 * could emit a "helper" that exits 0 without anyone touching the sensor.
 * `"biometry": "required"` then approved everything.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, readFileSync, rmSync } from "node:fs";
import { tmpdir, platform } from "node:os";
import { join } from "node:path";

import { ensureHelper, resetBiometryCache } from "../src/biometry.ts";

const FAKE = `#!/bin/sh
out=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && out="$2"; shift; done
printf '#!/bin/sh\\necho ok\\nexit 0\\n' > "$out"; chmod +x "$out"
`;

function withEnv(patch: NodeJS.ProcessEnv, fn: () => void): void {
  const saved: NodeJS.ProcessEnv = {};
  for (const k of Object.keys(patch)) saved[k] = process.env[k];
  Object.assign(process.env, patch);
  try {
    fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

const isScript = (path: string): boolean => readFileSync(path).subarray(0, 2).toString() === "#!";

describe("the Touch ID helper's compiler cannot be chosen by the caller", { skip: platform() !== "darwin" && "macOS only" }, () => {
  test("a swiftc planted first on PATH is not the one that builds the helper", () => {
    const dir = mkdtempSync(join(tmpdir(), "hush-fake-swiftc-"));
    writeFileSync(join(dir, "swiftc"), FAKE);
    chmodSync(join(dir, "swiftc"), 0o755);
    withEnv({ PATH: `${dir}:${process.env.PATH}`, HUSH_BIOMETRY: "" }, () => {
      resetBiometryCache();
      const h = ensureHelper("darwin");
      if (h.ok) assert.ok(!isScript(h.path!), "the helper was built by the planted compiler");
    });
    resetBiometryCache();
    rmSync(dir, { recursive: true, force: true });
  });

  test("a toolchain planted through DEVELOPER_DIR is not used either", () => {
    const dir = mkdtempSync(join(tmpdir(), "hush-fake-devdir-"));
    mkdirSync(join(dir, "usr", "bin"), { recursive: true });
    writeFileSync(join(dir, "usr", "bin", "swiftc"), FAKE);
    chmodSync(join(dir, "usr", "bin", "swiftc"), 0o755);
    withEnv({ DEVELOPER_DIR: dir, HUSH_BIOMETRY: "" }, () => {
      resetBiometryCache();
      const h = ensureHelper("darwin");
      if (h.ok) assert.ok(!isScript(h.path!), "the helper was built by a toolchain the caller chose");
    });
    resetBiometryCache();
    rmSync(dir, { recursive: true, force: true });
  });
});
