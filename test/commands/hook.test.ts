/**
 * hush hook Nushell integration.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { test } from "node:test";
import { onPath } from "../../src/which.ts";
import { CLI } from "../helpers/cli.ts";

const nuPath = onPath("nu", process.env.PATH, process.platform);

function emittedHook(): string {
  const result = spawnSync(process.execPath, [CLI, "hook", "nu"], {
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  assert.equal(result.status, 0, result.stderr ?? "");
  return result.stdout;
}

test("hush hook nu emits structured exports and filters invalid names", () => {
  const hook = emittedHook();
  assert.match(hook, /\$env\.config\.hooks\.env_change\.PWD/);
  assert.match(hook, /hush export --names/);
  assert.match(hook, /hush export --format json/);
  assert.ok(hook.includes("^[A-Za-z_][A-Za-z0-9_]*$"), "valid environment names are filtered");
  assert.match(hook, /load-env/);
  assert.doesNotMatch(hook, /\beval\b/i);
});

test("hush hook nu output parses in Nushell", {
  skip: nuPath ? false : "Nushell is not installed; skipping Nushell parser verification",
}, () => {
  if (!nuPath) throw new Error("Nushell is required for this check");
  const script = emittedHook().replace(/\n_hush_hook\s*$/, "");
  const result = spawnSync(nuPath, ["--commands", script], {
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  assert.equal(result.status, 0, result.stderr ?? "");
});

test("Nushell hook loads and removes only valid names without evaluating values", {
  skip: nuPath && process.platform !== "win32"
    ? false
    : "Nushell and a POSIX test host are required for the environment behavior check",
}, () => {
  if (!nuPath || process.platform === "win32") throw new Error("Nushell and POSIX are required");
  const dir = mkdtempSync(join(tmpdir(), "hush-nu-hook-"));
  const projectRoot = join(dir, "project");
  const fakeHush = join(dir, "hush");
  const canary = join(dir, "executed");
  const unsafeValue = "$(touch " + canary + ")";
  const secrets = JSON.stringify({ SAFE_KEY: unsafeValue, "BAD;NAME": "must not load" });
  mkdirSync(projectRoot);

  try {
    writeFileSync(fakeHush, [
      "#!/usr/bin/env node",
      "const [command, ...args] = process.argv.slice(2);",
      "if (command === \"root\") {",
      "  process.stdout.write((process.env.MOCK_HUSH_ROOT ?? \"\") + \"\\n\");",
      "} else if (command === \"export\" && args[0] === \"--names\") {",
      "  process.stdout.write(\"SAFE_KEY\\nBAD;NAME\\n\");",
      "} else if (command === \"export\" && args[0] === \"--format\" && args[1] === \"json\") {",
      "  process.stdout.write(" + JSON.stringify(secrets) + " + \"\\n\");",
      "} else {",
      "  process.exitCode = 2;",
      "}",
      "",
    ].join("\n"));
    chmodSync(fakeHush, 0o755);

    const script = emittedHook() + "\n" + [
      "print ($env.SAFE_KEY? | default \"missing\")",
      "$env.MOCK_HUSH_ROOT = \"\"",
      "_hush_hook",
      "print ($env.SAFE_KEY? | default \"missing\")",
      "print (($env | get -o \"BAD;NAME\") | default \"missing\")",
    ].join("\n");
    const result = spawnSync(nuPath, ["--commands", script], {
      cwd: projectRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        MOCK_HUSH_ROOT: projectRoot,
        PATH: [dir, dirname(process.execPath), process.env.PATH ?? ""].join(delimiter),
        NO_COLOR: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    assert.equal(result.status, 0, result.stderr ?? "");
    assert.deepEqual(result.stdout.trim().split(/\r?\n/), [unsafeValue, "missing", "missing"]);
    assert.equal(existsSync(canary), false, "the exported value was executed");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
