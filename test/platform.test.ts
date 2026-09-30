/**
 * F-7: the Windows paths, exercised from any platform through the same seams
 * the Linux dialog tests use. The real thing runs in CI's Windows job.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { escapeCmdArgument, spawnPlan, restrictToOwner } from "../src/platform.ts";
import { onPath } from "../src/which.ts";
import { detectBackend, powershellApprovalScript, powershellSecretScript } from "../src/dialogs.ts";
import { clipboardCandidates } from "../src/clipboard.ts";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.ts");

describe("F-7: spawning a .cmd without handing cmd.exe anything unescaped", () => {
  test("off Windows, and for a real .exe, the command is untouched", () => {
    assert.deepEqual(spawnPlan("/usr/bin/env", ["a b"], "darwin"), { command: "/usr/bin/env", args: ["a b"] });
    assert.deepEqual(spawnPlan("C:\\node\\node.exe", ["-v"], "win32"), { command: "C:\\node\\node.exe", args: ["-v"] });
  });

  test("a .cmd goes through cmd.exe, verbatim, with every argument quoted and metacharacters escaped", () => {
    const p = spawnPlan("C:\\npm\\npm.cmd", ["run", "dev & calc.exe", 'say "hi"', "100%"], "win32");
    assert.equal(p.windowsVerbatimArguments, true);
    assert.deepEqual(p.args.slice(0, 3), ["/d", "/s", "/c"]);
    const line = p.args[3];
    assert.ok(!/[^^]&/.test(line), "an unescaped & reached cmd.exe: " + line);
    assert.ok(!/[^^]%/.test(line), "an unescaped % reached cmd.exe: " + line);
    // A batch file re-parses its arguments, so each is escaped twice.
    assert.match(line, /\^\^\^"run\^\^\^"/);
  });

  test("the argument escaping follows the rules for quotes and trailing backslashes", () => {
    assert.equal(escapeCmdArgument("plain", false), '^"plain^"');
    assert.equal(escapeCmdArgument('a"b', false), '^"a\\^"b^"');
    assert.equal(escapeCmdArgument("dir\\", false), '^"dir\\\\^"');
    assert.equal(escapeCmdArgument("x&y", true), '^^^"x^^^&y^^^"');
  });
});

describe("F-7: finding a program on Windows", () => {
  test("npm.cmd wins over the plain npm shell script beside it, and node.exe is taken as named", () => {
    const dir = mkdtempSync(join(tmpdir(), "hush-win-path-"));
    for (const f of ["npm", "npm.cmd", "node.exe"]) {
      writeFileSync(join(dir, f), "x");
      chmodSync(join(dir, f), 0o755);
    }
    const prev = process.env.PATHEXT;
    process.env.PATHEXT = ".COM;.EXE;.BAT;.CMD";
    try {
      assert.equal(onPath("npm", dir, "win32"), join(dir, "npm.cmd"));
      assert.equal(onPath("node.exe", dir, "win32"), join(dir, "node.exe"));
      // The POSIX branch splits PATH on ":", so it can only be simulated with a
      // POSIX path: on a real Windows runner, dir is "C:\…" and the drive
      // letter would split it. (No Mac has drive letters.)
      if (process.platform !== "win32") assert.equal(onPath("npm", dir, "darwin"), join(dir, "npm"));
    } finally {
      if (prev === undefined) delete process.env.PATHEXT;
      else process.env.PATHEXT = prev;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("restricting a file to its owner is a no-op where the mode already does it", () => {
    assert.equal(restrictToOwner("/nonexistent", "darwin"), true);
  });

  test("the Windows clipboard is clip.exe", () => {
    assert.deepEqual(clipboardCandidates("win32").map((c) => c.cmd), ["clip"]);
  });
});

describe("F-7: the Windows approval dialog", () => {
  const evil = `'); Remove-Item C:\\ -Recurse; ('`;

  test("the request travels as base64 JSON: none of its text is ever part of the script", () => {
    const script = powershellApprovalScript(
      { summary: `Run: ${evil}`, detail: [evil], code: "4321", ttlLabel: "Allow 15 min" },
      60_000,
    );
    assert.ok(!script.includes("Remove-Item"), "request text reached the script");
    const payload = script.match(/FromBase64String\('([A-Za-z0-9+/=]+)'\)/)![1];
    const req = JSON.parse(Buffer.from(payload, "base64").toString("utf8"));
    assert.match(req.body, /Remove-Item/);
    assert.match(req.body, /Approval code: 4321/);
    assert.equal(req.ttl, "Allow 15 min");
    assert.ok(!powershellSecretScript({ title: evil, lines: [evil], label: "K" }, 1000).includes("Remove-Item"));
  });

  test("on Windows the backend is PowerShell, run by the path it was resolved to, and its answer is read", { skip: process.platform === "win32" && "the stand-in is a POSIX shell script; CI's Windows job runs the real dialog path" }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "hush-win-ps-"));
    const fake = join(dir, "powershell.exe");
    // A stand-in for powershell.exe: checks it was given an encoded command and
    // answers as the real script would.
    writeFileSync(fake, `#!/bin/sh\ncase "$*" in *-EncodedCommand*) printf once;; *) printf deny;; esac\n`);
    chmodSync(fake, 0o755);
    const backend = detectBackend({ env: {}, platform: () => "win32", resolveProgram: (c) => (c === "powershell" ? fake : null) });
    assert.equal(backend?.name, "powershell");
    assert.equal(backend?.program, fake);
    assert.equal(await backend!.approve({ summary: "Run", detail: [], code: "1", ttlLabel: null }, 5000), "once");
    assert.equal(detectBackend({ env: { HUSH_NO_DIALOG: "1" }, platform: () => "win32", resolveProgram: () => fake }), null);
    assert.equal(detectBackend({ env: {}, platform: () => "win32", resolveProgram: () => null }), null);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("F-7: the PowerShell shell hook", () => {
  test("loads values as JSON and never evaluates them", () => {
    const r = spawnSync(process.execPath, [CLI, "hook", "powershell"], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /ConvertFrom-Json/);
    assert.match(r.stdout, /_hush_unload/);
    assert.doesNotMatch(r.stdout, /Invoke-Expression|iex /i);
  });
});
