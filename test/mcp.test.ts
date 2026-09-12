/**
 * End-to-end tests for the MCP server: spawn it, speak JSON-RPC, check replies.
 *
 * The unit tests never exercised the transport, which is where a self-inflicted
 * unhandled rejection was taking the whole server down on the first tool error.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { Vault } from "../src/vault.ts";
import { generateIdentity, encodeSecret } from "../src/crypto.ts";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.ts");

interface Reply {
  id: number | string | null;
  result?: { content?: { text?: string }[]; isError?: boolean };
  error?: { code: number; message: string };
}

interface Session {
  exitCode: number | null;
  crashed: boolean;
  replies: Reply[];
  stderr: string;
}

/** A project with a vault, an identity, and approval turned off. */
function project(policy: Record<string, unknown> = {}) {
  const home = mkdtempSync(join(tmpdir(), "hush-mcp-home-"));
  const root = mkdtempSync(join(tmpdir(), "hush-mcp-proj-"));
  const hushDir = join(root, ".hush");
  mkdirSync(hushDir, { recursive: true });

  const id = generateIdentity();
  const vault = Vault.create(join(hushDir, "vault.json"), "t", { name: "tester", pub: id.pub });
  vault.set(id, "default", "API_KEY", "super-secret-value-here");
  vault.set(id, "fal/prod", "FAL_KEY", "fal_production_key");
  vault.set(id, "fal/dev", "FAL_KEY", "fal_dev_key");
  // An account that exists but is only half filled in — aws needs three vars.
  vault.set(id, "aws/partial", "AWS_ACCESS_KEY_ID", "AKIAPARTIALONLY");
  vault.save();

  writeFileSync(
    join(hushDir, "policy.json"),
    JSON.stringify({ requireApproval: [], biometry: "off", ...policy }),
  );
  return { home, root, secret: encodeSecret(id), cleanup: () => {
    for (const d of [home, root]) rmSync(d, { recursive: true, force: true });
  } };
}

/** Send every request, close stdin immediately, and collect what comes back. */
function talk(
  p: ReturnType<typeof project>,
  requests: unknown[],
  extraEnv: NodeJS.ProcessEnv = {},
): Promise<Session> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, "mcp"], {
      cwd: p.root,
      stdio: ["pipe", "pipe", "pipe"],
      // HUSH_APPROVAL_MODE=file matters on macOS: without it an enforced
      // approval opens a real osascript dialog on the developer's screen and
      // the test sits there until someone clicks it.
      env: {
        ...process.env,
        HUSH_HOME: p.home,
        HUSH_IDENTITY: p.secret,
        HUSH_BIOMETRY: "off",
        HUSH_APPROVAL_MODE: "file",
        NO_COLOR: "1",
        ...extraEnv,
      },
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.stdin.on("error", () => {});

    child.on("exit", (code) => {
      const replies: Reply[] = [];
      for (const line of out.split("\n")) {
        if (!line.trim()) continue;
        try { replies.push(JSON.parse(line) as Reply); } catch { /* not a reply */ }
      }
      resolve({ exitCode: code, crashed: /throw er|Unhandled|at Object\.<anonymous>/.test(err), replies, stderr: err });
    });

    for (const r of requests) child.stdin.write(JSON.stringify(r) + "\n");
    child.stdin.end();
  });
}

const call = (id: number, name: string, args: Record<string, unknown> = {}) =>
  ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
const init = { jsonrpc: "2.0", id: 0, method: "initialize", params: {} };

describe("mcp server", () => {
  test("answers every request and exits cleanly even when tools fail", async () => {
    const p = project();
    const s = await talk(p, [
      init,
      call(1, "hush_run"),                                   // missing command
      call(2, "hush_run", { command: "node", args: ["-e", "1"] }), // denied by policy
      call(3, "hush_list_secrets"),
      call(4, "hush_run", { command: "npm", args: ["--version"] }), // slow but valid
    ]);

    assert.equal(s.crashed, false, `server crashed:\n${s.stderr.slice(0, 400)}`);
    assert.equal(s.exitCode, 0, "server exited non-zero");
    assert.deepEqual(s.replies.map((r) => r.id).sort(), [0, 1, 2, 3, 4], "a reply was lost");
    p.cleanup();
  });

  test("in-flight work survives stdin closing", async () => {
    const p = project();
    const s = await talk(p, [
      init,
      call(1, "hush_run", { command: "npm", args: ["--version"] }),
    ]);
    const reply = s.replies.find((r) => r.id === 1);
    assert.ok(reply, "the reply was abandoned when stdin closed");
    assert.match(reply.result?.content?.[0]?.text ?? "", /exit 0/);
    p.cleanup();
  });

  test("a missing required argument is a clear message, not a spawn error", async () => {
    const p = project();
    const s = await talk(p, [init, call(1, "hush_run"), call(2, "hush_describe_secret")]);
    assert.match(s.replies.find((r) => r.id === 1)!.result!.content![0].text!, /needs a non-empty "command"/);
    assert.match(s.replies.find((r) => r.id === 2)!.result!.content![0].text!, /needs a non-empty "key"/);
    p.cleanup();
  });

  test("an oversized line is refused rather than buffered", async () => {
    const p = project();
    const s = await talk(p, [init]);
    assert.equal(s.crashed, false);
    // Sent separately: a raw non-JSON blob.
    const big = await new Promise<Session>((resolve) => {
      const child = spawn(process.execPath, [CLI, "mcp"], {
        cwd: p.root, stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, HUSH_HOME: p.home, HUSH_IDENTITY: p.secret, NO_COLOR: "1" },
      });
      let out = ""; let err = "";
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (err += d));
      child.stdin.on("error", () => {});
      child.on("exit", (code) => {
        const replies: Reply[] = [];
        for (const l of out.split("\n")) { if (l.trim()) { try { replies.push(JSON.parse(l)); } catch {} } }
        resolve({ exitCode: code, crashed: /throw er/.test(err), replies, stderr: err });
      });
      child.stdin.write("x".repeat(5_000_000) + "\n");
      child.stdin.end();
    });
    assert.equal(big.crashed, false);
    assert.match(big.replies[0]?.error?.message ?? "", /too large/);
    p.cleanup();
  });

  test("never returns a secret value, only its effects", async () => {
    const p = project();
    const s = await talk(p, [
      init,
      call(1, "hush_list_secrets"),
      call(2, "hush_describe_secret", { key: "API_KEY" }),
      call(3, "hush_run", { command: "npm", args: ["--version"] }),
    ]);
    const all = JSON.stringify(s.replies);
    assert.ok(!all.includes("super-secret-value-here"), "a secret value reached the client");
    assert.match(s.replies.find((r) => r.id === 1)!.result!.content![0].text!, /API_KEY/);
    p.cleanup();
  });

  test("a permitted command that prints the injected value still returns nothing usable", async () => {
    // The case above runs `npm --version`, which never echoes a secret — so it
    // would pass with redaction switched off entirely.
    //
    // This is the attack that actually exercises redaction. It deliberately
    // takes the escape the deny-list message itself suggests: put the work in a
    // script. `leak.sh` is not a denied name, the kernel runs it through a shell
    // hush never sees, and it prints every injected value. The deny list is
    // documented as a speed bump rather than a boundary — so this is precisely
    // the case where the control that is supposed to hold has to hold.
    const p = project();
    const script = join(p.root, "leak.sh");
    writeFileSync(script, '#!/bin/sh\necho "$API_KEY"\necho "$FAL_KEY"\nset\n', { mode: 0o755 });

    const s = await talk(p, [
      init,
      call(1, "hush_run", { command: "./leak.sh" }),
      call(2, "hush_run", { command: "./leak.sh", accounts: ["fal:prod"] }),
    ]);

    const all = JSON.stringify(s.replies);
    for (const value of ["super-secret-value-here", "fal_production_key"]) {
      assert.ok(!all.includes(value), `hush_run returned ${value} verbatim`);
    }
    // It really did run and really was masked — otherwise this proves nothing.
    const first = s.replies.find((r) => r.id === 1)!.result!.content![0].text ?? "";
    assert.doesNotMatch(first, /Refused/, `the command never ran:\n${first}`);
    assert.match(first, /redacted/, `nothing was masked, so nothing was injected:\n${first}`);
    p.cleanup();
  });
});

describe("mcp policy — the command deny list", () => {
  test("an interpreter is refused, because it defeats output redaction", () => {
    // Mutation testing found the deny list had no assertion of its own: the
    // existing test only checked that every request got *a* reply.
    const p = project();
    return talk(p, [
      init,
      call(1, "hush_run", { command: "node", args: ["-e", "1"] }),
      call(2, "hush_run", { command: "bash", args: ["-c", "env"] }),
      call(3, "hush_run", { command: "curl", args: ["https://example.com"] }),
      call(4, "hush_run", { command: "npm", args: ["--version"] }),
    ]).then((s2) => {
      for (const id of [1, 2, 3]) {
        const reply = s2.replies.find((r) => r.id === id)!;
        assert.equal(reply.result?.isError, true, `command ${id} was not refused`);
        assert.match(reply.result!.content![0].text!, /denied by default|unsafeAllowCommands/);
      }
      assert.match(s2.replies.find((r) => r.id === 4)!.result!.content![0].text!, /exit 0/);
      p.cleanup();
    });
  });

  test("unsafeAllowCommands is the only way past it", () => {
    const p = project({ unsafeAllowCommands: ["node"] });
    return talk(p, [
      init,
      call(1, "hush_run", { command: "node", args: ["-e", "console.log('allowed')"] }),
      call(2, "hush_run", { command: "bash", args: ["-c", "echo nope"] }),
    ]).then((s2) => {
      assert.match(s2.replies.find((r) => r.id === 1)!.result!.content![0].text!, /exit 0/);
      assert.equal(s2.replies.find((r) => r.id === 2)!.result?.isError, true, "it opened the whole list");
      p.cleanup();
    });
  });

  test("a stale policy cannot drop the list below the built-in floor", () => {
    const p = project({ denyCommands: ["env"] }); // what an older hush wrote
    return talk(p, [init, call(1, "hush_run", { command: "python3", args: ["-c", "print(1)"] })]).then((s2) => {
      assert.equal(s2.replies.find((r) => r.id === 1)!.result?.isError, true, "an old config reopened a hole");
      p.cleanup();
    });
  });
});

describe("mcp policy — allowEnvs covers service accounts", () => {
  // Regression: allowEnvs was checked against the base environment only, so an
  // agent pinned to "dev" could name any account, including a production one.
  // Mutation testing found this fix had no test at all.
  test("an account outside allowEnvs is refused", async () => {
    const p = project({ allowEnvs: ["default", "fal/dev"] });
    const s = await talk(p, [
      init,
      call(1, "hush_run", { command: "npm", args: ["--version"], accounts: { fal: "prod" } }),
    ]);
    const reply = s.replies.find((r) => r.id === 1)!;
    assert.equal(reply.result?.isError, true, "a forbidden production account was injected");
    assert.match(reply.result!.content![0].text!, /Policy forbids agent access to "fal\/prod"/);
    p.cleanup();
  });

  test("an account inside allowEnvs still works", async () => {
    const p = project({ allowEnvs: ["default", "fal/dev"] });
    const s = await talk(p, [
      init,
      call(1, "hush_run", { command: "npm", args: ["--version"], accounts: { fal: "dev" } }),
    ]);
    const text = s.replies.find((r) => r.id === 1)!.result!.content![0].text!;
    assert.match(text, /exit 0/, "the allowed account was blocked");
    assert.ok(!text.includes("fal_dev_key"), "the value leaked into the reply");
    p.cleanup();
  });

  test("with no allowEnvs set, accounts are unrestricted", async () => {
    const p = project();
    const s = await talk(p, [
      init,
      call(1, "hush_run", { command: "npm", args: ["--version"], accounts: { fal: "prod" } }),
    ]);
    assert.match(s.replies.find((r) => r.id === 1)!.result!.content![0].text!, /exit 0/);
    p.cleanup();
  });

  test("hush_add_secret cannot write into a forbidden account either", async () => {
    const p = project({ allowEnvs: ["default"] });
    const s = await talk(p, [init, call(1, "hush_add_secret", { service: "fal", account: "prod" })]);
    const text = s.replies.find((r) => r.id === 1)!.result!.content![0].text!;
    assert.match(text, /Policy forbids|not available/, `unexpected: ${text.slice(0, 120)}`);
    p.cleanup();
  });
});

describe("policy has no dead knobs", () => {
  test("every field in the Policy interface is actually read", async () => {
    // `allowReveal` shipped for weeks: declared, defaulted, written into every
    // generated policy.json — and never consulted. A setting that looks like a
    // security control but is inert is worse than no setting at all.
    const { readFileSync } = await import("node:fs");
    const { join, dirname } = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const src = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

    const mcpSrc = readFileSync(join(src, "mcp.ts"), "utf8");
    const iface = mcpSrc.slice(mcpSrc.indexOf("export interface Policy {"), mcpSrc.indexOf("const DEFAULT_POLICY"));
    const fields = [...new Set([...iface.matchAll(/^\s{2}([a-zA-Z]+):/gm)].map((x) => x[1]))];
    assert.ok(fields.length >= 6, `only found ${fields.length} policy fields`);

    // policy.ts now holds checkCommand/checkEnv/checkScopes — moved out of
    // mcp.ts so cli.ts can call the same checks — which is where
    // allowCommands and allowEnvs are actually read.
    const all = ["mcp.ts", "cli.ts", "ui.ts", "secure.ts", "posture.ts", "approval.ts", "policy.ts"]
      .map((f) => readFileSync(join(src, f), "utf8"))
      .join("\n");

    for (const field of fields) {
      // A real read looks like policy.field / ctx.policy.field / raw.field —
      // not the declaration or the default.
      const reads = [...all.matchAll(new RegExp(`\\.${field}\\b`, "g"))].length;
      assert.ok(reads > 0, `policy field "${field}" is declared but never read`);
    }
  });

  test("a generated policy.json contains only live fields", async () => {
    const p = project();
    const { readFileSync, existsSync } = await import("node:fs");
    const { join } = await import("node:path");
    const policyPath = join(p.root, ".hush", "policy.json");
    if (existsSync(policyPath)) {
      const written = Object.keys(JSON.parse(readFileSync(policyPath, "utf8")));
      assert.ok(!written.includes("allowReveal"), "wrote a setting that does nothing");
    }
    p.cleanup();
  });
});

describe("mcp discovery tools", () => {
  test("hush_list_accounts names the accounts and never their values", async () => {
    const p = project();
    const s = await talk(p, [init, call(1, "hush_list_accounts")]);
    const text = s.replies.find((r) => r.id === 1)!.result!.content![0].text!;

    // This is how "use my acme fal key" gets resolved, so the names must be there.
    assert.match(text, /fal/);
    assert.match(text, /prod/);
    assert.match(text, /dev/);
    assert.ok(!text.includes("fal_production_key"), "an account listing leaked a value");
    assert.ok(!text.includes("fal_dev_key"));
    assert.match(text, /hush_run/, "does not tell the agent what to do with them");
    p.cleanup();
  });

  test("hush_list_accounts can be filtered, and says so when there is nothing", async () => {
    const p = project();
    const s = await talk(p, [
      init,
      call(1, "hush_list_accounts", { service: "fal" }),
      call(2, "hush_list_accounts", { service: "nonexistent" }),
    ]);
    assert.match(s.replies.find((r) => r.id === 1)!.result!.content![0].text!, /fal/);
    assert.match(s.replies.find((r) => r.id === 2)!.result!.content![0].text!, /No accounts for "nonexistent"/);
    p.cleanup();
  });

  test("hush_check_repo reports what the code needs against what the vault has", async () => {
    const p = project();
    const { writeFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    writeFileSync(
      join(p.root, "app.js"),
      "const a = process.env.API_KEY;\nconst b = process.env.MISSING_FROM_VAULT;\n",
    );

    const s = await talk(p, [init, call(1, "hush_check_repo")]);
    const text = s.replies.find((r) => r.id === 1)!.result!.content![0].text!;

    assert.match(text, /satisfied by vault:\s*1/);
    assert.match(text, /MISSING:\s*1/);
    assert.match(text, /MISSING_FROM_VAULT/);
    assert.match(text, /app\.js/, "does not say where the variable is used");
    assert.ok(!text.includes("super-secret-value-here"), "the scan leaked a value");
    p.cleanup();
  });

  test("hush_provision resolves a CLI to a service and an account", async () => {
    const p = project();
    // A tool name maps to a service; the agent should not need to know which.
    const s = await talk(p, [
      init,
      call(1, "hush_provision", { tool: "genmedia", account: "prod" }), // a real hint-table entry
      call(2, "hush_provision", { tool: "genmedia", account: "no-such-account" }),
      call(3, "hush_provision", { tool: "totally-unknown-binary" }),
    ]);

    const ready = s.replies.find((r) => r.id === 1)!.result!.content![0].text!;
    assert.match(ready, /Ready/);
    assert.match(ready, /FAL_KEY/);
    assert.match(ready, /"fal": "prod"/, "does not hand back the call to make");
    assert.ok(!ready.includes("fal_production_key"), "provisioning leaked a value");

    const wrong = s.replies.find((r) => r.id === 2)!.result!;
    assert.equal(wrong.isError, true);
    assert.match(wrong.content![0].text!, /Available: dev, prod|Available: prod, dev/);

    const unknown = s.replies.find((r) => r.id === 3)!.result!.content![0].text!;
    assert.match(unknown, /Don't know which service/);
    p.cleanup();
  });

  test("hush_provision says what is missing rather than half-preparing", async () => {
    const p = project();
    const s = await talk(p, [init, call(1, "hush_provision", { tool: "stripe" })]);
    const text = s.replies.find((r) => r.id === 1)!.result!.content![0].text!;
    assert.match(text, /no stripe accounts in the vault yet/);
    assert.match(text, /hush_add_secret/, "does not point at the way to fix it");
    p.cleanup();
  });
});

describe("mcp provisioning does not overstate readiness", () => {
  test("an account missing some of the service's variables is reported, not called ready", async () => {
    // aws needs AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_REGION. An
    // account holding only the first must not come back as "Ready" — the agent
    // would run a deploy that fails halfway with a confusing auth error.
    const p = project();
    const s = await talk(p, [init, call(1, "hush_provision", { tool: "aws", account: "partial" })]);
    const text = s.replies.find((r) => r.id === 1)!.result!.content![0].text!;

    assert.ok(!/^Ready/.test(text), `claimed ready while incomplete: ${text.slice(0, 120)}`);
    assert.match(text, /missing/i);
    assert.match(text, /AWS_SECRET_ACCESS_KEY/);
    assert.match(text, /AWS_REGION/);
    assert.ok(!text.includes("AWS_ACCESS_KEY_ID: AKIA"), "leaked the value it does have");
    assert.match(text, /hush_add_secret/, "does not say how to finish it");
    p.cleanup();
  });

  test("a fully populated account is ready", async () => {
    const p = project();
    const s = await talk(p, [init, call(1, "hush_provision", { tool: "fal", account: "prod" })]);
    assert.match(s.replies.find((r) => r.id === 1)!.result!.content![0].text!, /^Ready/);
    p.cleanup();
  });
});

describe("mcp policy — the gaps mutation testing found", () => {
  test("the deny list matches the command's name, not the path it was reached by", async () => {
    // Checking the whole string instead of the basename means `/bin/sh` sails
    // past a list that contains "sh" — and an agent chooses the string.
    const p = project();
    const s = await talk(p, [
      init,
      call(1, "hush_run", { command: "/bin/sh", args: ["-c", "echo hi"] }),
      call(2, "hush_run", { command: "/usr/bin/env", args: [] }),
      call(3, "hush_run", { command: "./node_modules/.bin/../../../usr/bin/python3", args: ["-c", "1"] }),
    ]);
    for (const id of [1, 2, 3]) {
      const reply = s.replies.find((r) => r.id === id)!;
      assert.equal(reply.result?.isError, true, `a path-qualified denied command ran (id ${id})`);
      assert.match(reply.result!.content![0].text!, /denied by default/);
    }
    p.cleanup();
  });

  test("allowCommands is a whitelist: anything not on it is refused", async () => {
    const p = project({ allowCommands: ["npm"] });
    const s = await talk(p, [
      init,
      call(1, "hush_run", { command: "npm", args: ["--version"] }),
      call(2, "hush_run", { command: "git", args: ["--version"] }),
    ]);
    assert.match(s.replies.find((r) => r.id === 1)!.result!.content![0].text!, /exit 0/);
    const refused = s.replies.find((r) => r.id === 2)!;
    assert.equal(refused.result?.isError, true, "a command outside allowCommands ran");
    assert.match(refused.result!.content![0].text!, /allowCommands/);
    p.cleanup();
  });

  test("allowEnvs gates the plain environments too, not only accounts", async () => {
    const p = project({ allowEnvs: ["fal/dev"] });
    const s = await talk(p, [
      init,
      call(1, "hush_list_secrets", { env: "default" }),
      call(2, "hush_list_secrets", { env: "fal/dev" }),
    ]);
    const refused = s.replies.find((r) => r.id === 1)!;
    assert.equal(refused.result?.isError, true, "an environment outside allowEnvs was listed");
    assert.match(refused.result!.content![0].text!, /Policy forbids agent access to environment "default"/);
    assert.equal(s.replies.find((r) => r.id === 2)!.result?.isError, undefined);
    p.cleanup();
  });

  test("requireApproval actually gates a run", async () => {
    // Every other test here sets requireApproval to [] so it can get on with
    // things, which left the gate itself never exercised. With no terminal and
    // no macOS dialog to answer, an enforced gate can only time out — and a run
    // that was never approved must not have happened.
    const p = project({ requireApproval: ["run"], approvalTtlSeconds: 1, approvalTimeoutSeconds: 1 });
    const s = await talk(p, [init, call(1, "hush_run", { command: "npm", args: ["--version"] })]);
    const reply = s.replies.find((r) => r.id === 1)!;
    assert.equal(reply.result?.isError, true, "an unapproved run went ahead");
    assert.match(reply.result!.content![0].text!, /approv|denied|timed out/i);
    p.cleanup();
  });
});

describe("mcp policy — a refusal is a refusal", () => {
  test("an approval that comes back denied stops the run", async () => {
    // Distinct from the timeout case above, and it has its own branch: with
    // biometry required and no enrolled finger, requestApproval denies outright
    // rather than waiting for anyone.
    const p = project({ requireApproval: ["run"], biometry: "required", approvalTimeoutSeconds: 1 });
    const s = await talk(p, [init, call(1, "hush_run", { command: "npm", args: ["--version"] })]);
    const reply = s.replies.find((r) => r.id === 1)!;
    assert.equal(reply.result?.isError, true, "a denied run went ahead");
    assert.match(reply.result!.content![0].text!, /requires biometry|denied/i);
    p.cleanup();
  });
});
