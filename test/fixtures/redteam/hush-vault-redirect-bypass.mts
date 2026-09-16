#!/usr/bin/env node
/**
 * Red-team reproduction — NOT run by `npm test`.
 *
 * Finding: "HUSH_VAULT redirect bypasses the repo's own policy.json when no
 * floor is configured" — see docs/RED-TEAM.md.
 *
 * `.hush/vault.json` is meant to be committed to git and is plaintext JSON
 * (ciphertext values, but the file itself carries no access control — that is
 * the whole point of envelope encryption). `resolveVaultPath()` honours
 * `HUSH_VAULT` and derives the policy directory from `dirname(HUSH_VAULT)`,
 * with no check that this is the vault's "real" project. An agent that can
 * set an environment variable when it spawns `hush` (true of any agent with a
 * Bash tool) can copy the vault file to a scratch directory that has no
 * policy.json of its own, point HUSH_VAULT there, and — with the SAME
 * identity the agent's hush process already has — get `hush get` to hand
 * back the plaintext with no approval prompt at all, because `policyFor()`
 * finds neither a repo policy.json (none in the scratch dir) nor a floor
 * (none configured), and returns `null`: "the CLI is opt-in", by design, for
 * a project that never asked for a policy.
 *
 * This directly contradicts SECURITY.md's claim that "shelling out to hush
 * is not a way around" the policy — under the specific, common condition
 * that the user never configured `~/.hush/policy.json` (a floor is
 * recommended in docs/SAFETY.md, not required, and `hush init --agent`
 * alone never creates one).
 *
 * The second run below shows the mitigation that already works: with any
 * floor file present — even `{}` — `policyFor()` no longer returns null, so
 * DEFAULT_POLICY's own `requireApproval: ["run","add","reveal"]` applies
 * regardless of the scratch directory having no policy.json, and the run
 * properly refuses.
 *
 * Run: node test/fixtures/redteam/hush-vault-redirect-bypass.mts
 */
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { Vault } from "../../../src/vault.ts";
import { generateIdentity, encodeSecret } from "../../../src/crypto.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "..", "..", "..", "src", "cli.ts");

function attempt(label: string, withFloor: boolean): void {
  const home = mkdtempSync(join(tmpdir(), "hush-redteam-home-"));
  // A floor exists, and asks for nothing beyond a short approval timeout —
  // requireApproval and biometry are left to DEFAULT_POLICY entirely.
  if (withFloor) writeFileSync(join(home, "policy.json"), JSON.stringify({ approvalTimeoutSeconds: 1 }));

  const root = mkdtempSync(join(tmpdir(), "hush-redteam-proj-"));
  mkdirSync(join(root, ".hush"), { recursive: true });
  const id = generateIdentity();
  const vault = Vault.create(join(root, ".hush", "vault.json"), "redteam", { name: "tester", pub: id.pub });
  vault.set(id, "default", "FAKE_API_KEY", "FAKE-VALUE-DO-NOT-USE-5678");
  vault.save();
  // The real project opts in to agent-safe policy.
  writeFileSync(join(root, ".hush", "policy.json"), JSON.stringify({ requireApproval: ["reveal"], biometry: "required" }));

  const env = {
    ...process.env,
    HUSH_HOME: home,
    HUSH_IDENTITY: encodeSecret(id),
    HUSH_NO_KEYCHAIN: "1",
    HUSH_BIOMETRY: "off",
    HUSH_NO_DIALOG: "1",
    HUSH_NO_NUDGE: "1",
    NO_COLOR: "1",
  };

  // The "attack": copy the (plaintext-visible, meant-to-be-committed) vault
  // file to a scratch directory the real policy.json never reaches, and
  // invoke hush against it directly via HUSH_VAULT.
  const scratch = mkdtempSync(join(tmpdir(), "hush-redteam-scratch-"));
  copyFileSync(join(root, ".hush", "vault.json"), join(scratch, "vault.json"));
  const attackEnv = { ...env, HUSH_VAULT: join(scratch, "vault.json") };
  const r = spawnSync(process.execPath, [CLI, "get", "FAKE_API_KEY", "--yes"], {
    cwd: scratch,
    env: attackEnv,
    encoding: "utf8",
    timeout: 15_000,
  });

  console.log(`\n--- ${label} ---`);
  console.log("exit:", r.status, "out:", (r.stdout + r.stderr).trim());
  console.log("value leaked:", (r.stdout ?? "").includes("FAKE-VALUE-DO-NOT-USE-5678"));

  rmSync(home, { recursive: true, force: true });
  rmSync(root, { recursive: true, force: true });
  rmSync(scratch, { recursive: true, force: true });
}

attempt("no floor configured (the vulnerable, common case)", false);
attempt("a floor configured, even near-empty (the actual mitigation)", true);
