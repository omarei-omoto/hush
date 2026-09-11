/**
 * The hardware path, without hardware.
 *
 * A real YubiKey cannot be plugged in here, but the plugin itself is age's
 * problem — hush only has to detect a plugin identity, shell out correctly, and
 * report failures usefully. Those are the parts hush owns, and they are all
 * testable with a stub plugin and a stub `age`.
 */
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, chmodSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  identityPlugin, isAgeRecipient, ageFingerprint, ageBinary,
  ageAvailable, resetAgeBinaryCache, recipientsForIdentity,
  wrapDekWithAge, unwrapDekWithAge,
} from "../src/age.ts";
import { newDek } from "../src/crypto.ts";

const REAL_RECIPIENT = "age1yubikey1qwt50d05nh5vupnpcxhpgc7v7xnzm3mmpjnv4d0q9wgw6l7jhc9k8vqlnyc";

let dir: string;
let originalPath: string | undefined;
let originalBin: string | undefined;

/** A stub `age` that records its argv and does a reversible byte flip. */
function writeStubAge(path: string, logFile: string) {
  writeFileSync(
    path,
    `#!/usr/bin/env node
const fs = require("fs");
fs.appendFileSync(${JSON.stringify(logFile)}, JSON.stringify(process.argv.slice(2)) + "\\n");
const input = fs.readFileSync(0);
if (process.argv[2] === "--version") { process.stdout.write("stub 1.0\\n"); process.exit(0); }
if (process.argv.includes("-d")) {
  // "decrypt": strip the armour and un-flip.
  const body = input.toString().replace(/-----(BEGIN|END) STUB-----/g, "").trim();
  process.stdout.write(Buffer.from(body, "base64").map((b) => b ^ 0x5a));
} else {
  const flipped = Buffer.from(input).map((b) => b ^ 0x5a);
  process.stdout.write("-----BEGIN STUB-----\\n" + flipped.toString("base64") + "\\n-----END STUB-----\\n");
}
`,
    { mode: 0o755 },
  );
  chmodSync(path, 0o755);
}

before(() => {
  dir = mkdtempSync(join(tmpdir(), "hush-age-"));
  originalPath = process.env.PATH;
  originalBin = process.env.HUSH_AGE_BIN;

  // A stub plugin that answers --identity with a recipient, as a real one does.
  const plugin = join(dir, "age-plugin-yubikey");
  writeFileSync(plugin, `#!/bin/sh\necho "${REAL_RECIPIENT}"\n`, { mode: 0o755 });
  chmodSync(plugin, 0o755);
  process.env.PATH = `${dir}:${process.env.PATH}`;
});

after(() => {
  process.env.PATH = originalPath;
  if (originalBin === undefined) delete process.env.HUSH_AGE_BIN;
  else process.env.HUSH_AGE_BIN = originalBin;
  resetAgeBinaryCache();
  rmSync(dir, { recursive: true, force: true });
});

describe("age bridge — hardware detection", () => {
  test("a plugin identity is recognised as hardware-backed", () => {
    const p = join(dir, "yubi-identity.txt");
    writeFileSync(p, "# created by age-plugin-yubikey\nAGE-PLUGIN-YUBIKEY-1QQPZQ9DUMMY\n");
    assert.equal(identityPlugin(p), "yubikey");
  });

  test("a plain software key is NOT reported as hardware", () => {
    // The upgrade prompt must refuse to credit a software key as rung 5.
    const p = join(dir, "software-identity.txt");
    writeFileSync(p, "# created by age-keygen\nAGE-SECRET-KEY-1QQQQQQDUMMY\n");
    assert.equal(identityPlugin(p), null);
  });

  test("a crafted identity file cannot name an arbitrary executable", () => {
    const p = join(dir, "evil-identity.txt");
    writeFileSync(p, "AGE-PLUGIN-../../../BIN/EVIL-1XXXX\n");
    assert.equal(identityPlugin(p), null, "plugin name was not constrained");
  });

  test("recipients are read back through the plugin when age-keygen cannot", () => {
    process.env.HUSH_AGE_BIN = join(dir, "age");
    writeStubAge(join(dir, "age"), join(dir, "argv.log"));
    resetAgeBinaryCache();

    const p = join(dir, "yubi2.txt");
    writeFileSync(p, "AGE-PLUGIN-YUBIKEY-1QQPZQ9DUMMY\n");
    const recipients = recipientsForIdentity(p);
    assert.deepEqual(recipients, [REAL_RECIPIENT], "did not fall back to the plugin binary");
  });

  test("plugin recipients are recognised and fingerprinted stably", () => {
    assert.ok(isAgeRecipient(REAL_RECIPIENT));
    assert.equal(ageFingerprint(REAL_RECIPIENT), ageFingerprint(` ${REAL_RECIPIENT} `));
    assert.notEqual(ageFingerprint(REAL_RECIPIENT), ageFingerprint(REAL_RECIPIENT + "x"));
  });
});

describe("age bridge — invocation contract", () => {
  const log = () => readFileSync(join(dir, "argv.log"), "utf8").trim().split("\n").map((l) => JSON.parse(l));

  test("hush passes age the arguments it expects, and round-trips the data key", () => {
    const logFile = join(dir, "argv.log");
    writeFileSync(logFile, "");
    process.env.HUSH_AGE_BIN = join(dir, "age");
    writeStubAge(join(dir, "age"), logFile);
    resetAgeBinaryCache();

    const dek = newDek();
    const wrapped = wrapDekWithAge(dek, REAL_RECIPIENT);
    const idFile = join(dir, "id-for-unwrap.txt");
    writeFileSync(idFile, "AGE-PLUGIN-YUBIKEY-1QQPZQ9DUMMY\n");
    const back = unwrapDekWithAge(wrapped, idFile);

    assert.deepEqual(back, dek, "the data key did not survive the round trip");

    const calls = log();
    assert.deepEqual(calls[0], ["-a", "-r", REAL_RECIPIENT], "wrong wrap invocation");
    assert.deepEqual(calls[1], ["-d", "-i", idFile], "wrong unwrap invocation");
  });

  test("a plugin that returns the wrong size is rejected, not trusted", () => {
    // A broken or hostile plugin must not be able to substitute a short key.
    const badAge = join(dir, "age-bad");
    writeFileSync(badAge, `#!/bin/sh\nprintf 'too-short'\n`, { mode: 0o755 });
    chmodSync(badAge, 0o755);
    process.env.HUSH_AGE_BIN = badAge;
    resetAgeBinaryCache();

    const idFile = join(dir, "id2.txt");
    writeFileSync(idFile, "AGE-PLUGIN-YUBIKEY-1QQPZQ9DUMMY\n");
    assert.throws(() => unwrapDekWithAge("whatever", idFile), /32-byte data key|could not decrypt/);
  });

  test("a missing identity file is reported before age is invoked", () => {
    process.env.HUSH_AGE_BIN = join(dir, "age");
    resetAgeBinaryCache();
    assert.throws(() => unwrapDekWithAge("x", join(dir, "nope.txt")), /identity file not found/);
  });

  test("a failing plugin surfaces age's own error text", () => {
    const failing = join(dir, "age-fail");
    writeFileSync(failing, `#!/bin/sh\necho "age: no YubiKey inserted" >&2\nexit 1\n`, { mode: 0o755 });
    chmodSync(failing, 0o755);
    process.env.HUSH_AGE_BIN = failing;
    resetAgeBinaryCache();

    const idFile = join(dir, "id3.txt");
    writeFileSync(idFile, "AGE-PLUGIN-YUBIKEY-1QQPZQ9DUMMY\n");
    assert.throws(() => unwrapDekWithAge("x", idFile), /no YubiKey inserted/);
  });
});

describe("age bridge — availability", () => {
  test("age appearing mid-session is noticed", async () => {
    // The MCP server is long-lived. Telling someone to `brew install age` and
    // then never noticing that they did would strand them for the session.
    delete process.env.HUSH_AGE_BIN;
    const emptyDir = mkdtempSync(join(tmpdir(), "hush-nopath-"));
    const saved = process.env.PATH;
    process.env.PATH = emptyDir;
    resetAgeBinaryCache();

    assert.equal(ageAvailable(), false, "should not find age on an empty PATH");

    // Now "install" it and wait out the short negative-cache window.
    writeFileSync(join(emptyDir, "age"), "#!/bin/sh\necho stub\n", { mode: 0o755 });
    chmodSync(join(emptyDir, "age"), 0o755);
    await new Promise((r) => setTimeout(r, 5100));

    assert.equal(ageAvailable(), true, "a negative result was cached for the whole session");
    assert.ok(existsSync(ageBinary()!));

    process.env.PATH = saved;
    resetAgeBinaryCache();
    rmSync(emptyDir, { recursive: true, force: true });
  });
});
