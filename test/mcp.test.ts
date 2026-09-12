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
import { saveLinks } from "../src/library.ts";

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
  // A plain set — no "/" — so sets are exercised without the old account shape.
  vault.set(id, "work-fal", "FAL_KEY", "work-fal-key-value");
  vault.save();

  writeFileSync(
    join(hushDir, "policy.json"),
    JSON.stringify({ requireApproval: [], biometry: "off", ...policy }),
  );
  return { home, root, id, secret: encodeSecret(id), cleanup: () => {
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
    // Bites: a version that checked policy against "prod" (the bare account)
    // rather than the derived set name would still say "Policy forbids", so
    // the exact set name is what proves service+account really became "fal/prod".
    assert.match(text, /Policy forbids agent access to "fal\/prod"/, `unexpected: ${text.slice(0, 120)}`);
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

describe("mcp discovery — sets replace accounts", () => {
  test("hush_list_sets returns library and project sets, tagged where/used, never a value", async () => {
    const p = project();
    // A library set, so both "where" values actually appear in one listing.
    const libPath = join(p.home, "vaults", "global", "vault.json");
    mkdirSync(dirname(libPath), { recursive: true });
    const lib = Vault.create(libPath, "global", { name: "tester", pub: p.id.pub });
    lib.set(p.id, "acme-production", "FAL_KEY", "acme-library-key");
    lib.save();

    const s = await talk(p, [init, call(1, "hush_list_sets")]);
    const text = s.replies.find((r) => r.id === 1)!.result!.content![0].text!;

    // This is how "use my acme fal key" gets resolved, so the names must be there.
    assert.match(text, /\bdefault\b/);
    assert.match(text, /fal\/prod/);
    assert.match(text, /fal\/dev/);
    assert.match(text, /work-fal/);
    assert.match(text, /acme-production/, "a library-only set is missing from the listing");
    assert.match(text, /project/, "does not say which sets are the project's own");
    assert.match(text, /library/, "does not say which sets come from the library");
    assert.match(text, /used by this project/, "the project's own default should be marked used");
    assert.match(text, /hush_run/, "does not tell the agent what to do with them");
    for (const value of ["super-secret-value-here", "fal_production_key", "fal_dev_key", "work-fal-key-value", "acme-library-key"]) {
      assert.ok(!text.includes(value), `hush_list_sets leaked ${value}`);
    }
    p.cleanup();
  });

  test("hush_list_accounts still answers, and its description says deprecated", async () => {
    const p = project();
    const s = await talk(p, [
      init,
      { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} },
      call(2, "hush_list_accounts"),
    ]);

    const list = s.replies.find((r) => r.id === 1)!.result as unknown as {
      tools: { name: string; description: string }[];
    };
    const accountsTool = list.tools.find((t) => t.name === "hush_list_accounts");
    assert.ok(accountsTool, "hush_list_accounts is no longer registered");
    assert.match(accountsTool!.description, /deprecated/i);
    assert.match(accountsTool!.description, /hush_list_sets/);

    const text = s.replies.find((r) => r.id === 2)!.result!.content![0].text!;
    assert.match(text, /fal\/prod/, "hush_list_accounts no longer answers with real data");
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

  test("hush_provision resolves a CLI to a service and a set", async () => {
    const p = project();
    // A tool name maps to a service; the agent should not need to know which.
    const s = await talk(p, [
      init,
      call(1, "hush_provision", { tool: "genmedia", set: "fal/prod" }), // a real hint-table entry
      call(2, "hush_provision", { tool: "genmedia", set: "nope" }),
      call(3, "hush_provision", { tool: "totally-unknown-binary" }),
    ]);

    const ready = s.replies.find((r) => r.id === 1)!.result!.content![0].text!;
    assert.match(ready, /Ready/);
    assert.match(ready, /FAL_KEY/);
    assert.match(ready, /sets: \["fal\/prod"\]/, "does not hand back the call to make");
    assert.ok(!ready.includes("fal_production_key"), "provisioning leaked a value");

    const wrong = s.replies.find((r) => r.id === 2)!.result!;
    assert.equal(wrong.isError, true);
    assert.match(wrong.content![0].text!, /No set called "nope"/);
    assert.match(wrong.content![0].text!, /work-fal/, "does not list the sets that do exist");

    const unknown = s.replies.find((r) => r.id === 3)!.result!.content![0].text!;
    assert.match(unknown, /Don't know which service/);
    p.cleanup();
  });

  test("hush_provision says what is missing rather than half-preparing", async () => {
    const p = project();
    const s = await talk(p, [init, call(1, "hush_provision", { tool: "stripe" })]);
    const text = s.replies.find((r) => r.id === 1)!.result!.content![0].text!;
    assert.match(text, /none of this project's used sets have it yet/);
    assert.match(text, /hush_add_secret/, "does not point at the way to fix it");
    p.cleanup();
  });

  // Bites: a version that only checked an explicitly-named `set` (never the
  // sets the project already uses) would answer this with "missing" instead.
  test("hush_provision, with no set given, checks the sets this project already uses", async () => {
    const p = project();
    saveLinks(join(p.root, ".hush"), ["work-fal"]);
    const s = await talk(p, [init, call(1, "hush_provision", { tool: "genmedia" })]);
    const text = s.replies.find((r) => r.id === 1)!.result!.content![0].text!;
    assert.match(text, /^Ready/);
    assert.match(text, /\bset work-fal\b|\bsets\b.*work-fal/, "does not say which used set satisfies it");
    assert.ok(!text.includes("work-fal-key-value"), "leaked the value");
    p.cleanup();
  });
});

describe("mcp provisioning does not overstate readiness", () => {
  test("a set missing some of the service's variables is reported, not called ready", async () => {
    // aws needs AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_REGION. A set
    // holding only the first must not come back as "Ready" — the agent would
    // run a deploy that fails halfway with a confusing auth error.
    const p = project();
    const s = await talk(p, [init, call(1, "hush_provision", { tool: "aws", set: "aws/partial" })]);
    const text = s.replies.find((r) => r.id === 1)!.result!.content![0].text!;

    assert.ok(!/^Ready/.test(text), `claimed ready while incomplete: ${text.slice(0, 120)}`);
    assert.match(text, /missing/i);
    assert.match(text, /AWS_SECRET_ACCESS_KEY/);
    assert.match(text, /AWS_REGION/);
    assert.ok(!text.includes("AWS_ACCESS_KEY_ID: AKIA"), "leaked the value it does have");
    assert.match(text, /hush_add_secret/, "does not say how to finish it");
    p.cleanup();
  });

  test("a fully populated set is ready", async () => {
    const p = project();
    const s = await talk(p, [init, call(1, "hush_provision", { tool: "fal", set: "fal/prod" })]);
    assert.match(s.replies.find((r) => r.id === 1)!.result!.content![0].text!, /^Ready/);
    p.cleanup();
  });
});

describe("mcp discovery — set/env aliasing on hush_list_secrets and hush_describe_secret", () => {
  // Bites: a version that only read args.env (never args.set) would resolve
  // "default" instead of "fal/dev" for the `set` call, so it would see
  // API_KEY rather than FAL_KEY.
  test("hush_list_secrets accepts `set`, and `env` still works as a deprecated alias", async () => {
    const p = project();
    const s = await talk(p, [
      init,
      call(1, "hush_list_secrets", { set: "fal/dev" }),
      call(2, "hush_list_secrets", { env: "fal/dev" }),
    ]);
    for (const id of [1, 2]) {
      const text = s.replies.find((r) => r.id === id)!.result!.content![0].text!;
      assert.match(text, /FAL_KEY/, `id ${id}: "set"/"env" did not select fal/dev`);
      assert.ok(!text.includes("fal_dev_key"), "leaked a value");
    }
    p.cleanup();
  });

  test("hush_describe_secret accepts `set`, and `env` still works as a deprecated alias", async () => {
    const p = project();
    const s = await talk(p, [
      init,
      call(1, "hush_describe_secret", { key: "FAL_KEY", set: "fal/dev" }),
      call(2, "hush_describe_secret", { key: "FAL_KEY", env: "fal/dev" }),
    ]);
    for (const id of [1, 2]) {
      const text = s.replies.find((r) => r.id === id)!.result!.content![0].text!;
      assert.match(text, /is set in set "fal\/dev"/, `id ${id}: "set"/"env" did not select fal/dev`);
    }
    p.cleanup();
  });
});

describe("mcp run — sets replace accounts", () => {
  test("hush_run injects a named set's key, redacted in output", async () => {
    const p = project();
    const script = join(p.root, "echofal.sh");
    writeFileSync(script, '#!/bin/sh\necho "$FAL_KEY"\n', { mode: 0o755 });

    const s = await talk(p, [init, call(1, "hush_run", { command: "./echofal.sh", sets: ["work-fal"] })]);
    const text = s.replies.find((r) => r.id === 1)!.result!.content![0].text!;

    assert.match(text, /work-fal/, "the tool result does not say which set it used");
    assert.match(text, /redacted/, "nothing was masked, so nothing was injected");
    assert.ok(!text.includes("work-fal-key-value"), "the set's value leaked verbatim");
    p.cleanup();
  });

  test("hush_run refuses an unknown set, naming it and listing what exists", async () => {
    const p = project();
    const s = await talk(p, [init, call(1, "hush_run", { command: "npm", args: ["--version"], sets: ["nope"] })]);
    const reply = s.replies.find((r) => r.id === 1)!;
    assert.equal(reply.result?.isError, true, "an unknown set was silently accepted");
    assert.match(reply.result!.content![0].text!, /No set called "nope"/);
    assert.match(reply.result!.content![0].text!, /work-fal/, "does not list the sets that do exist");
    p.cleanup();
  });

  test("hush_run still accepts accounts as a deprecated alias for sets", async () => {
    const p = project();
    const s = await talk(p, [
      init,
      call(1, "hush_run", { command: "npm", args: ["--version"], accounts: { fal: "prod" } }),
    ]);
    const text = s.replies.find((r) => r.id === 1)!.result!.content![0].text!;
    assert.match(text, /exit 0/);
    assert.match(text, /fal\/prod/, "the accounts alias did not resolve to the fal/prod set");
    p.cleanup();
  });

  // Bites: a version that merged layers with a plain object spread in whatever
  // order Object.assign happened to run — rather than iterating `sets` in the
  // given order — would leave this at the mercy of key insertion order instead
  // of proving the later NAME actually wins.
  test("a later set wins: sets: [a, b] resolves with b's value, not a's", async () => {
    const p = project();
    const vault = Vault.open(join(p.root, ".hush", "vault.json"));
    vault.set(p.id, "set-a", "SHARED_LEN", "short"); // length 5
    vault.set(p.id, "set-b", "SHARED_LEN", "much-longer-value"); // length 17
    vault.save();

    const script = join(p.root, "len.sh");
    writeFileSync(script, '#!/bin/sh\necho ${#SHARED_LEN}\n', { mode: 0o755 });

    const forward = await talk(p, [init, call(1, "hush_run", { command: "./len.sh", sets: ["set-a", "set-b"] })]);
    const forwardOut = forward.replies.find((r) => r.id === 1)!.result!.content![0].text!;
    const forwardLen = forwardOut.match(/--- stdout ---\n(\d+)/)?.[1];
    assert.equal(forwardLen, "17", `expected set-b (length 17) to win:\n${forwardOut}`);

    const backward = await talk(p, [init, call(1, "hush_run", { command: "./len.sh", sets: ["set-b", "set-a"] })]);
    const backwardOut = backward.replies.find((r) => r.id === 1)!.result!.content![0].text!;
    const backwardLen = backwardOut.match(/--- stdout ---\n(\d+)/)?.[1];
    assert.equal(backwardLen, "5", `reversing the order should flip the winner:\n${backwardOut}`);
    p.cleanup();
  });

  test("allowEnvs refuses an extra set outside it, and still allows a run with none", async () => {
    const p = project({ allowEnvs: ["default"] });
    const s = await talk(p, [
      init,
      call(1, "hush_run", { command: "npm", args: ["--version"], sets: ["work-fal"] }),
      call(2, "hush_run", { command: "npm", args: ["--version"] }),
    ]);
    const refused = s.replies.find((r) => r.id === 1)!;
    assert.equal(refused.result?.isError, true, "a forbidden extra set was injected");
    assert.match(refused.result!.content![0].text!, /Policy forbids agent access to "work-fal"/);
    assert.match(
      s.replies.find((r) => r.id === 2)!.result!.content![0].text!,
      /exit 0/,
      "a plain run without extra sets was blocked",
    );
    p.cleanup();
  });
});

describe("mcp add_secret — sets replace accounts", () => {
  test("hush_add_secret with an explicit set is refused by policy before any dialog", async () => {
    const p = project({ allowEnvs: ["default"] });
    const s = await talk(p, [init, call(1, "hush_add_secret", { set: "work-fal", key: "FAL_KEY" })]);
    const reply = s.replies.find((r) => r.id === 1)!;
    assert.equal(reply.result?.isError, true, "a forbidden set was reachable");
    assert.match(reply.result!.content![0].text!, /Policy forbids agent access to "work-fal"/);
    p.cleanup();
  });

  // Bites: a version that used the bare account ("acme") as the scope, rather
  // than setNameFor(service, account), would still be refused by this same
  // policy but would name "acme" instead of "fal/acme" — this pins the exact
  // derived name.
  test("hush_add_secret derives service/account into a set name", async () => {
    const p = project({ allowEnvs: ["work-fal"] });
    const s = await talk(p, [init, call(1, "hush_add_secret", { service: "fal", account: "acme" })]);
    const reply = s.replies.find((r) => r.id === 1)!;
    assert.equal(reply.result?.isError, true, "a forbidden set was reachable");
    assert.match(reply.result!.content![0].text!, /Policy forbids agent access to "fal\/acme"/);
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

describe("mcp — the pre-sets argument names still mean what they meant", () => {
  // Bites: a hush_run that ignored `env` would inject nothing from fal/dev
  // and print 0, instead of erroring or honouring the old base-env meaning.
  test("hush_run: env is a deprecated alias for the base set, and sets still go on top of it", async () => {
    const p = project();
    const script = join(p.root, "len.sh");
    writeFileSync(script, '#!/bin/sh\necho ${#FAL_KEY}\n', { mode: 0o755 });

    const base = await talk(p, [init, call(1, "hush_run", { command: "./len.sh", env: "fal/dev" })]);
    const baseOut = base.replies.find((r) => r.id === 1)!.result!.content![0].text!;
    assert.equal(baseOut.match(/--- stdout ---\n(\d+)/)?.[1], String("fal_dev_key".length), `env was ignored:\n${baseOut}`);

    const layered = await talk(p, [init, call(1, "hush_run", { command: "./len.sh", env: "fal/dev", sets: ["fal/prod"] })]);
    const layeredOut = layered.replies.find((r) => r.id === 1)!.result!.content![0].text!;
    assert.equal(
      layeredOut.match(/--- stdout ---\n(\d+)/)?.[1],
      String("fal_production_key".length),
      `sets should win over env:\n${layeredOut}`,
    );
    p.cleanup();
  });

  // Bites: without the alias the bare key lands in "default", which this
  // policy allows, so the refusal never happens.
  test("hush_add_secret: env is a deprecated alias for set, so the policy sees the set it names", async () => {
    const p = project({ allowEnvs: ["default"] });
    const s = await talk(p, [init, call(1, "hush_add_secret", { key: "FAL_KEY", env: "fal/dev" })]);
    const reply = s.replies.find((r) => r.id === 1)!;
    assert.equal(reply.result?.isError, true, "a forbidden set named via env was accepted");
    assert.match(reply.result!.content![0].text!, /Policy forbids agent access to "fal\/dev"/);
    p.cleanup();
  });

  // Bites: with layer names in the suggestion, the agent gets
  // sets: ["global:acme-production"] — which hush_run rejects as unknown.
  test("hush_provision names a library set the way hush_run and hush use accept it", async () => {
    const p = project();
    const libPath = join(p.home, "vaults", "global", "vault.json");
    mkdirSync(dirname(libPath), { recursive: true });
    const lib = Vault.create(libPath, "global", { name: "tester", pub: p.id.pub });
    lib.set(p.id, "acme-production", "FAL_KEY", "acme-library-key");
    lib.save();
    saveLinks(join(p.root, ".hush"), ["acme-production"]);

    const s = await talk(p, [init, call(1, "hush_provision", { tool: "genmedia" })]);
    const text = s.replies.find((r) => r.id === 1)!.result!.content![0].text!;
    assert.match(text, /^Ready/, text);
    assert.match(text, /sets: \["acme-production"\]/, "the hush_run call handed back is not one that works");
    assert.match(text, /hush use acme-production/, "the hush use hint is not a name the user can type");
    assert.doesNotMatch(text, /:acme-production/, "a layer name leaked into the suggestion");

    // And the suggestion actually works when fed straight back.
    const run = await talk(p, [init, call(1, "hush_run", { command: "npm", args: ["--version"], sets: ["acme-production"] })]);
    assert.match(run.replies.find((r) => r.id === 1)!.result!.content![0].text!, /exit 0/);
    p.cleanup();
  });
});
