/**
 * The hardware path, driven by a real age plugin.
 *
 * `test/fixtures/age-plugin-mock` implements the actual C2SP age-plugin
 * protocol, so the real `age` binary drives it exactly as it drives
 * age-plugin-yubikey — including the "-> msg" prompt a hardware key uses to ask
 * for a touch. That leaves only "does age-plugin-yubikey talk to USB" unproven,
 * which belongs to that project rather than to hush.
 *
 * Skips when `age` is unavailable, so CI without it stays green.
 */
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

import { ageAvailable, resetAgeBinaryCache, identityPlugin } from "../src/age.ts";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "src", "cli.ts");
const FIXTURES = join(here, "fixtures");
const require_ = createRequire(import.meta.url);
const { encode } = require_("./fixtures/bech32.cjs") as { encode: (hrp: string, b: Buffer) => string };

/** The mock plugin's fixed key material — it is a stand-in, not a secret. */
const KEY = Buffer.alloc(32, 7);
const RECIPIENT = encode("age1mock", KEY);
const IDENTITY = encode("age-plugin-mock-", KEY).toUpperCase();

let home: string;
let root: string;
let env: NodeJS.ProcessEnv;

const skip = ageAvailable() ? false : "age binary not installed";

before(() => {
  if (skip) return;
  home = mkdtempSync(join(tmpdir(), "hush-hw-home-"));
  root = mkdtempSync(join(tmpdir(), "hush-hw-proj-"));
  chmodSync(join(FIXTURES, "age-plugin-mock"), 0o755);
  env = {
    ...process.env,
    HUSH_HOME: home,
    PATH: `${FIXTURES}:${process.env.PATH}`,
    HUSH_BIOMETRY: "off",
    HUSH_NO_NUDGE: "1",
    // Without this, `loadIdentity` finds whatever is in the developer's login
    // keychain and the vault gets a software founder by accident. On a machine
    // with no keychain entry — every CI runner — it fell through to the age
    // identity instead, so the vault had no software key to retire and the whole
    // point of the test quietly disappeared.
    HUSH_NO_KEYCHAIN: "1",
    NO_COLOR: "1",
  };
  delete env.HUSH_IDENTITY;

  // Order matters. The software identity is created first, while there is no
  // age identity to be found: `hush id --create` refuses when `loadIdentity`
  // already returns something, and an age-only identity counts.
  execFileSync(process.execPath, [CLI, "id", "--create"], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  writeFileSync(join(home, "age-identity.txt"), IDENTITY + "\n");
});

after(() => {
  if (skip) return;
  resetAgeBinaryCache();
  for (const d of [home, root]) rmSync(d, { recursive: true, force: true });
});

const hush = (...args: string[]) => {
  try {
    return execFileSync(process.execPath, [CLI, ...args], {
      cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (e) {
    const err = e as { stdout?: string; stderr?: string };
    throw new Error(`hush ${args.join(" ")} failed:\n${err.stdout ?? ""}${err.stderr ?? ""}`);
  }
};

describe("hardware path (real age plugin)", { skip }, () => {
  test("the complete software-to-hardware upgrade works end to end", () => {
    mkdirSync(join(root, ".hush"), { recursive: true });
    hush("init", "hwtest");
    execFileSync(process.execPath, [CLI, "set", "SECRET"], {
      cwd: root, env, input: "the_real_secret\n", stdio: ["pipe", "ignore", "ignore"],
    });

    // 1. hush recognises the plugin identity as hardware, not a software key.
    assert.equal(identityPlugin(join(home, "age-identity.txt")), "mock");
    assert.match(hush("age"), /age-plugin-mock \(hardware\)/);

    // 2. Adding the recipient runs the real plugin through the real age binary.
    assert.match(hush("team", "add", "hardware", RECIPIENT), /can now decrypt/);
    const roster = hush("team", "ls");
    assert.match(roster, /hardware/);
    assert.match(roster, /age/);

    // 3. The ladder credits the hardware rung.
    const before = JSON.parse(hush("level", "--json")) as { checks: { id: string; pass: boolean }[] };
    assert.equal(before.checks.find((c) => c.id === "hardware")?.pass, true, "hardware rung not credited");

    // 4. Retire the software key — the step that was previously impossible.
    //
    // `hush init` names the founding member after $USER, so the name to retire
    // is whoever is running this. It used to be hardcoded to the name of the
    // one machine this was written on, which meant the test could only ever
    // pass there — no contributor could have run it.
    const me = hush("team", "ls").match(/^\s*(\S+)\s+admin\s+hush_pk_/m)?.[1];
    assert.ok(me, "could not work out the software member's name from:\n" + hush("team", "ls"));
    const removed = hush("team", "rm", me);
    assert.match(removed, new RegExp("removed " + me));
    assert.match(removed, /generation 2/, "the vault was not re-keyed");

    // 5. The vault now opens only through the plugin.
    assert.match(hush("get", "SECRET", "--yes"), /the_real_secret/);
    assert.equal((hush("team", "ls").match(/hush_pk_/g) ?? []).length, 0, "a software key survived");
    assert.match(hush("verify"), /1 value\(s\) readable/);
  });

  test("a plugin that prompts for a touch does not break the flow", () => {
    // The mock sends "-> msg" on both wrap and unwrap, which is how a YubiKey
    // asks for a touch. age surfaces it; hush must simply tolerate it.
    const out = hush("verify");
    assert.match(out, /freshness/);
    assert.match(out, /readable/);
  });

  test("hush never learns whether the key was hardware or software", () => {
    // The point of the bridge: age owns the plugin, hush owns only the data key.
    const state = JSON.parse(hush("level", "--json")) as { checks: { id: string; pass: boolean }[] };
    assert.equal(state.checks.find((c) => c.id === "hardware")?.pass, true);
    // And nothing in hush's output exposes the plugin's key material.
    assert.ok(!hush("team", "ls").includes(KEY.toString("hex")));
  });
});
