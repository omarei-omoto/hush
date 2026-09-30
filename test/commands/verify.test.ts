/**
 * `hush verify`.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { generateIdentity, encodeSecret } from "../../src/crypto.ts";
import { spawnSync } from "node:child_process";
import { CLI, project } from "../helpers/cli.ts";

describe("hush verify", () => {
  test("a healthy vault verifies and exits zero", () => {
    const p = project();
    const { out, code } = p.run(["verify"]);
    assert.equal(code, 0);
    assert.match(out, /freshness/);
    assert.match(out, /1 value\(s\) readable/);
    p.cleanup();
  });

  test("a vault you cannot decrypt reports it and exits non-zero", () => {
    const p = project();
    const stranger = encodeSecret(generateIdentity());
    const r = spawnSync(process.execPath, [CLI, "verify"], {
      cwd: p.root,
      env: { ...process.env, HUSH_HOME: p.home, HUSH_IDENTITY: stranger, HUSH_BIOMETRY: "off", NO_COLOR: "1" },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const out = (r.stdout ?? "") + (r.stderr ?? "");
    const code = r.status ?? 1;
    assert.notEqual(code, 0, "a broken vault reported success");
    assert.match(out, /not a recipient/);
    p.cleanup();
  });
});
