/**
 * Getting the binary onto a machine (F-8): the curl | sh installer and the
 * package-manager manifests.
 *
 * The installer is the one piece of hush that runs before anyone has hush, so
 * it is where a swapped download would land. These drive the real
 * scripts/install.sh against a release served from a local directory
 * (HUSH_DOWNLOAD_BASE=file://…) and check it installs what SHA256SUMS lists —
 * and nothing else.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { platform, tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { parseSums, homebrewFormula, scoopManifest, wingetManifests } from "../scripts/package-manifests.mjs";
import { TARGETS } from "../scripts/build-binaries.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const INSTALL = join(root, "scripts", "install.sh");
const sha = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");

/** A release directory: a stand-in binary for every unix target, and its SHA256SUMS. */
function fakeRelease(version = "9.9.9") {
  const dir = mkdtempSync(join(tmpdir(), "hush-release-"));
  const sums: string[] = [];
  for (const target of Object.keys(TARGETS).filter((t) => !t.startsWith("windows"))) {
    const name = `hush-${target}`;
    const body = `#!/bin/sh\necho ${version}\n`;
    writeFileSync(join(dir, name), body);
    sums.push(`${sha(body)}  ${name}`);
  }
  writeFileSync(join(dir, "SHA256SUMS"), sums.join("\n") + "\n");
  return { dir, base: pathToFileURL(dir).href };
}

function install(base: string, into: string, extra: NodeJS.ProcessEnv = {}) {
  const r = spawnSync("sh", [INSTALL], {
    env: { PATH: process.env.PATH, HOME: into, HUSH_DOWNLOAD_BASE: base, HUSH_INSTALL_DIR: join(into, "bin"), HUSH_VERIFY_ATTESTATION: "0", ...extra },
    encoding: "utf8",
  });
  return { out: r.stdout + r.stderr, code: r.status };
}

describe("scripts/install.sh", { skip: platform() === "win32" && "the Windows installer is install.ps1" }, () => {
  test("installs this machine's build once its checksum matches", () => {
    const rel = fakeRelease();
    const home = mkdtempSync(join(tmpdir(), "hush-inst-"));
    const r = install(rel.base, home);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /sha256 ok/);
    assert.match(r.out, /installed 9\.9\.9/);
    const bin = join(home, "bin", "hush");
    assert.equal(spawnSync(bin, ["--version"], { encoding: "utf8" }).stdout.trim(), "9.9.9");
    rmSync(rel.dir, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  });

  test("a binary that does not match SHA256SUMS is not installed", () => {
    const rel = fakeRelease();
    // Swap every binary for another program after the sums were written: the
    // download a compromised mirror or a tampered release would serve.
    for (const line of readFileSync(join(rel.dir, "SHA256SUMS"), "utf8").trim().split("\n")) {
      const file = join(rel.dir, line.split("  ")[1]);
      writeFileSync(file, "#!/bin/sh\necho pwned\n");
      chmodSync(file, 0o755);
    }
    const home = mkdtempSync(join(tmpdir(), "hush-inst-"));
    const r = install(rel.base, home);
    assert.notEqual(r.code, 0);
    assert.match(r.out, /checksum mismatch/);
    assert.ok(!existsSync(join(home, "bin", "hush")), "a mismatched binary was installed");
    rmSync(rel.dir, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  });

  test("a SHA256SUMS that does not list the build is a refusal, not a pass", () => {
    const rel = fakeRelease();
    writeFileSync(join(rel.dir, "SHA256SUMS"), `${"0".repeat(64)}  hush-plan9-mips\n`);
    const home = mkdtempSync(join(tmpdir(), "hush-inst-"));
    const r = install(rel.base, home);
    assert.notEqual(r.code, 0);
    assert.match(r.out, /does not list/);
    assert.ok(!existsSync(join(home, "bin", "hush")));
    rmSync(rel.dir, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  });

  test("a listed name that only contains the build's name does not count", () => {
    // `hush-linux-x64` must not be satisfied by a line for `hush-linux-x64-musl`,
    // or the other way round.
    const rel = fakeRelease();
    const lines = readFileSync(join(rel.dir, "SHA256SUMS"), "utf8").trim().split("\n");
    writeFileSync(join(rel.dir, "SHA256SUMS"), lines.map((l) => l + ".old").join("\n") + "\n");
    const home = mkdtempSync(join(tmpdir(), "hush-inst-"));
    const r = install(rel.base, home);
    assert.notEqual(r.code, 0, r.out);
    assert.ok(!existsSync(join(home, "bin", "hush")));
    rmSync(rel.dir, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  });

  test("it never asks for sudo and never edits a shell profile", () => {
    const text = readFileSync(INSTALL, "utf8");
    const code = text.split("\n").filter((l) => !l.trimStart().startsWith("#"));
    assert.ok(!code.some((l) => /\bsudo\b/.test(l)), "the installer runs sudo");
    assert.ok(!code.some((l) => />>\s*"?\$?HOME\/?\.?(profile|bashrc|zshrc)|>>\s*~\//.test(l) && !/say /.test(l)), "the installer edits a profile");
  });
});

describe("package-manager manifests", () => {
  const sums = parseSums(
    Object.keys(TARGETS)
      .map((t, i) => `${String(i).repeat(64).slice(0, 64)}  hush-${t}${t.startsWith("windows") ? ".exe" : ""}`)
      .join("\n"),
  );

  test("the Homebrew formula names every build with its own hash", () => {
    const rb = homebrewFormula("1.2.3", sums);
    for (const t of ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"]) {
      assert.ok(rb.includes(`/releases/download/v1.2.3/hush-${t}"`), `no url for ${t}`);
      assert.ok(rb.includes(`sha256 "${sums[`hush-${t}`]}"`), `wrong hash for ${t}`);
    }
    assert.match(rb, /assert_equal version\.to_s, shell_output\("#\{bin\}\/hush --version"\)\.strip/);
    const ruby = spawnSync("ruby", ["-c"], { input: rb, encoding: "utf8" });
    if (ruby.error === undefined) assert.equal(ruby.status, 0, ruby.stderr);
  });

  test("Scoop and winget carry the Windows build's hash", () => {
    const scoop = JSON.parse(scoopManifest("1.2.3", sums)) as { architecture: { "64bit": { url: string; hash: string } } };
    assert.equal(scoop.architecture["64bit"].hash, sums["hush-windows-x64.exe"]);
    assert.match(scoop.architecture["64bit"].url, /v1\.2\.3\/hush-windows-x64\.exe$/);
    const winget = wingetManifests("1.2.3", sums);
    assert.match(winget["omarei.hush.installer.yaml"], new RegExp(`InstallerSha256: ${sums["hush-windows-x64.exe"].toUpperCase()}`));
    assert.match(winget["omarei.hush.installer.yaml"], /InstallerType: portable/);
  });

  test("a build missing from SHA256SUMS is an error, not an empty hash", () => {
    const partial = { ...sums };
    delete partial["hush-linux-arm64"];
    assert.throws(() => homebrewFormula("1.2.3", partial), /hush-linux-arm64/);
  });
});

describe("the GitHub Action", () => {
  const action = readFileSync(join(root, "action.yml"), "utf8");

  test("installs the checked binary by default, through the same installer people run", () => {
    assert.match(action, /install:\n(?:.*\n)*?\s+default: binary/);
    assert.match(action, /sh "\$GITHUB_ACTION_PATH\/scripts\/install\.sh"/);
    assert.match(action, /scripts\\install\.ps1/);
    // The token is what lets install.sh check the attestation on a runner.
    assert.equal((action.match(/GH_TOKEN: \$\{\{ github\.token \}\}/g) ?? []).length, 2);
    assert.ok(!/HUSH_VERIFY_ATTESTATION/.test(action), "the action switches the attestation check off");
  });
});
