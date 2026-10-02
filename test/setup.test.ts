/**
 * Onboarding as one checklist (src/setup.ts) that a person (`hush start`,
 * `hush setup`) and a coding agent (`hush setup --json`) both follow. These
 * walk a first run in a scratch HOME and HUSH_HOME: nothing real is read or
 * written, and no agent config outside the scratch folder is touched.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, existsSync, rmSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { CLI } from "./helpers/cli.ts";
import { walkSetup, type WalkIO } from "../src/commands/setup.ts";
import type { SetupState, SetupStep } from "../src/setup.ts";

/** A machine that has never seen hush: its own HOME, its own HUSH_HOME, no keychain. */
function freshMachine() {
  const base = mkdtempSync(join(tmpdir(), "hush-setup-"));
  const home = join(base, "home");
  const proj = join(base, "my-app");
  mkdirSync(home);
  mkdirSync(proj);
  const env: NodeJS.ProcessEnv = {
    ...process.env, HOME: home, HUSH_HOME: join(home, ".hush"), HUSH_NO_KEYCHAIN: "1", HUSH_NO_NUDGE: "1",
    HUSH_BIOMETRY: "off", HUSH_NO_DIALOG: "1", NO_COLOR: "1",
  };
  delete env.HUSH_IDENTITY;
  delete env.HUSH_VAULT;
  const run = (args: string[], input?: string) => {
    const r = spawnSync(process.execPath, [CLI, ...args], { cwd: proj, env, encoding: "utf8", input, stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"] });
    return { code: r.status ?? 1, out: (r.stdout ?? "") + (r.stderr ?? "") };
  };
  const json = () => JSON.parse(run(["setup", "--json"]).out) as { next: string | null; done: number; total: number; steps: (SetupStep & { command?: string })[]; agent: string[] };
  const step = (id: string) => json().steps.find((s) => s.id === id)!;
  return { base, home, proj, env, run, json, step, cleanup: () => rmSync(base, { recursive: true, force: true }) };
}

test("a first run, step by step, exactly as an agent would follow it: each command moves the checklist on", () => {
  const m = freshMachine();
  try {
    writeFileSync(join(m.proj, ".env"), "STRIPE_SECRET_KEY=sk_live_setup_Rq7Tz2Lp9Wx4\nAPI_URL=https://api.example.com\n");
    let j = m.json();
    assert.ok(j.agent.length >= 4, "no rules for the agent");
    assert.equal(j.next, "key");
    assert.equal(m.step("key").kind, "auto");
    assert.equal(m.step("project").kind, "choice", "where the keys go is the person's choice");
    assert.match(m.step("project").command!, /^hush import \.env --as "My App" --project$/);
    assert.ok(!JSON.stringify(j).includes("sk_live_setup"), "the checklist leaked a value from .env");

    for (const id of ["key", "library", "project"]) {
      const cmd = m.step(id).command!.replace(/^hush /, "");
      const args = cmd.match(/"[^"]*"|\S+/g)!.map((x) => x.replace(/^"|"$/g, ""));
      const r = m.run(args);
      assert.equal(r.code, 0, `${id}: ${r.out}`);
      assert.equal(m.step(id).status, "done", `${id} did not become done`);
    }
    j = m.json();
    assert.ok(j.done >= 3);
    // With keys in, the safety steps appear; the .env is still there, so that one is to do.
    assert.equal(m.step("no-plaintext").status, "todo");
    assert.equal(m.step("no-plaintext").kind, "person", "deleting a file must need a person");
  } finally {
    m.cleanup();
  }
});

test("a skipped step stays skipped for this project until unskipped, and hush setup says so", () => {
  const m = freshMachine();
  try {
    assert.equal(m.run(["setup", "skip", "library"]).code, 0);
    assert.equal(m.step("library").status, "skipped");
    assert.match(m.run(["setup"]).out, /Your library.*\(skipped\)/);
    assert.equal(m.run(["setup", "unskip", "library"]).code, 0);
    assert.equal(m.step("library").status, "todo");
    assert.notEqual(m.run(["setup", "skip", "no-such-step"]).code, 0);
  } finally {
    m.cleanup();
  }
});

test("hush start off a terminal shows the checklist and exits cleanly; nothing is created", () => {
  const m = freshMachine();
  try {
    const r = m.run(["start"]);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /hush · set up/);
    assert.ok(!existsSync(join(m.home, ".hush", "vaults")), "showing the checklist created a library");
  } finally {
    m.cleanup();
  }
});

// ------------------------------------------------------------------ the walk

function fakeWalk(steps: () => SetupStep[], answers: string[]) {
  const ran: string[][] = [];
  const skipped: string[] = [];
  const io: WalkIO = {
    state: (): SetupState => {
      const s = steps().map((x) => (skipped.includes(x.id) && x.status === "todo" ? { ...x, status: "skipped" as const } : x));
      const req = s.filter((x) => x.status !== "optional");
      return { root: "/p", steps: s, next: s.find((x) => x.status === "todo") ?? null, done: req.filter((x) => x.status === "done").length, total: req.length };
    },
    ask: async () => answers.shift() ?? "",
    run: async (argv) => {
      ran.push(argv);
      return 0;
    },
    skip: (id) => skipped.push(id),
    print: () => {},
  };
  return { io, ran, skipped };
}

test("the walk runs what is agreed, skips what is skipped, offers each step once, and never runs what was declined", async () => {
  const done = new Set<string>();
  const steps = (): SetupStep[] => [
    { id: "agents", title: "Agents", kind: "choice", status: done.has("agents") ? "done" : "todo", detail: "", argv: [["install-mcp", "--yes"], ["install-skill"]] },
    { id: "agent-configs", title: "Configs", kind: "person", status: "todo", detail: "", argv: [["scan", "--agents", "--fix"]] },
    { id: "approval", title: "Approvals", kind: "choice", status: "todo", detail: "", argv: [["secure", "--approval"]], options: [{ label: "dialog", argv: [["secure", "--approval"]] }, { label: "Touch ID", argv: [["secure", "--approval"], ["secure", "--biometry"]] }] },
    { id: "conversations", title: "Conversations", kind: "auto", status: "optional", detail: "", argv: [["scan", "--transcripts"]] },
  ];
  // agents: yes (and it becomes done); configs: n (not now); approval: option 2; conversations: no.
  const w = fakeWalk(steps, ["", "n", "2", "n"]);
  const realRun = w.io.run;
  w.io.run = async (argv) => {
    if (argv[0] === "install-skill") done.add("agents");
    return realRun(argv);
  };
  await walkSetup(w.io);
  assert.deepEqual(w.ran, [["install-mcp", "--yes"], ["install-skill"], ["secure", "--approval"], ["secure", "--biometry"]]);
  assert.ok(!w.ran.some((a) => a[0] === "scan"), "it ran a step that was declined");

  done.clear();
  const s = fakeWalk(steps, ["s", "s", "s", "n"]);
  await walkSetup(s.io);
  assert.deepEqual(s.ran, []);
  assert.deepEqual(s.skipped, ["agents", "agent-configs", "approval"]);
});

test("an agent cannot answer the consent for rewriting configs: off a terminal, with no dialog and no --yes, nothing changes", () => {
  const m = freshMachine();
  try {
    const desktop = join(m.home, ".cursor", "mcp.json");
    mkdirSync(join(desktop, ".."), { recursive: true });
    const before = JSON.stringify({ mcpServers: { gh: { command: "npx", env: { GITHUB_TOKEN: "ghp_Qw8eR2tY6uI0oP4aS1dF5gH9jK3lZ7xC2vB6" } } } });
    writeFileSync(desktop, before);
    m.run(["id", "--create"]);
    const r = m.run(["scan", "--agents", "--fix"]);
    assert.notEqual(r.code, 0);
    assert.equal(readFileSync(desktop, "utf8"), before);
  } finally {
    m.cleanup();
  }
});
