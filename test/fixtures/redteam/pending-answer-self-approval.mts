#!/usr/bin/env node
/**
 * Regression probe — NOT run by `npm test`.
 *
 * History: this file used to *demonstrate* a live finding. `HUSH_APPROVAL_MODE=file`
 * (or any host with no zenity/kdialog/osascript) made approval.ts's `askViaFile()`
 * drop `.hush/pending/<id>.json` and poll for a matching `<id>.answer`, which was
 * meant to be written by a human running `hush approve` in another terminal. The
 * file carried no signature and no binding to who wrote it, so any process with
 * ordinary write access to the project — exactly what a coding agent's own Bash
 * or file tool has — could answer its own request with a plain `writeFileSync`.
 * It defeated the approval *gate* itself without touching the identity or the
 * vault's crypto.
 *
 * The fix removes the file as an approval channel. There is no `hush approve`,
 * no `.hush/pending/`, and no `HUSH_APPROVAL_MODE`. An approval has to come from
 * something the gated process cannot supply: a dialog on the human's screen, or
 * their fingerprint. A host with neither — no desktop, no biometric helper —
 * refuses the request instead of offering a file.
 *
 * This probe now asserts that shape: with no desktop, the secret must not come
 * out, no pending file may appear, and hand-writing one must change nothing.
 *
 * Run: node test/fixtures/redteam/pending-answer-self-approval.mts
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
const SECRET = "FAKE-VALUE-DO-NOT-USE-1234";

let failures = 0;
const check = (ok: boolean, what: string): void => {
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${what}`);
  if (!ok) failures++;
};

async function attempt(label: string, policy: Record<string, unknown>): Promise<void> {
  const home = mkdtempSync(join(tmpdir(), "hush-redteam-home-"));
  const root = mkdtempSync(join(tmpdir(), "hush-redteam-proj-"));
  mkdirSync(join(root, ".hush"), { recursive: true });
  const id = generateIdentity();
  const vault = Vault.create(join(root, ".hush", "vault.json"), "redteam", { name: "tester", pub: id.pub });
  vault.set(id, "default", "FAKE_API_KEY", SECRET);
  vault.save();
  writeFileSync(
    join(root, ".hush", "policy.json"),
    JSON.stringify({ requireApproval: ["reveal"], ...policy }),
  );

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

  const child = spawn(process.execPath, [CLI, "get", "FAKE_API_KEY", "--yes"], { cwd: root, env });
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (out += d));

  // What the agent's own file tool did before: watch for a request hush wrote,
  // and answer it itself. There must be nothing to answer.
  const pendingDir = join(root, ".hush", "pending");
  let sawPendingFile = false;
  const deadline = Date.now() + 10_000;
  const timer = setInterval(() => {
    if (existsSync(pendingDir)) {
      for (const f of readdirSync(pendingDir).filter((f) => f.endsWith(".json"))) {
        sawPendingFile = true;
        writeFileSync(join(pendingDir, f.replace(/\.json$/, ".answer")), "session");
      }
    }
    if (Date.now() > deadline) clearInterval(timer);
  }, 50);

  const code: number | null = await new Promise((resolve) => {
    child.on("exit", (c) => resolve(c));
  });
  clearInterval(timer);

  console.log(`\n--- ${label} ---`);
  console.log("policy:", JSON.stringify(policy));
  console.log("exit:", code);
  console.log("output:", out.trim());
  check(code !== 0, "the gated command did not succeed");
  check(!out.includes(SECRET), "the secret did not leak");
  check(!sawPendingFile, "no pending-request file was written for anyone to answer");

  rmSync(home, { recursive: true, force: true });
  rmSync(root, { recursive: true, force: true });
}

await attempt("biometry off (the case that used to be vulnerable)", { biometry: "off" });
await attempt("biometry required", { biometry: "required" });

console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
