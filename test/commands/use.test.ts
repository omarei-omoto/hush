/**
 * `hush use`, and a folder hush has not been told about yet.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { Vault } from "../../src/vault.ts";
import { generateIdentity, encodePub } from "../../src/crypto.ts";
import { CLI, bareFolder, project } from "../helpers/cli.ts";

describe("hush use", () => {
  test("using two sets writes envs.json in order; unknown name lists what exists; the list shows sources; --not removes", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=v", "--to", "work-fal"]).code, 0);
      assert.equal(p.run(["add", "DB_URL=v", "--to", "db-prod"]).code, 0);

      const unknown = p.run(["use", "not-a-real-set"]);
      assert.equal(unknown.code, 1, unknown.out);
      assert.match(unknown.out, /No set called "not-a-real-set"/);
      assert.match(unknown.out, /work-fal/, "the message does not say what sets exist");

      const used = p.run(["use", "work-fal", "db-prod"]);
      assert.equal(used.code, 0, used.out);
      const links = JSON.parse(readFileSync(join(p.hushDir, "envs.json"), "utf8")) as { use: string[] };
      assert.deepEqual(links.use, ["work-fal", "db-prod"]);

      const listed = p.run(["use"]).out;
      assert.match(listed, /work-fal\s+project/);
      assert.match(listed, /db-prod\s+project/);
      assert.match(listed, /default\s+project/);

      const removed = p.run(["use", "--not", "db-prod"]);
      assert.equal(removed.code, 0, removed.out);
      const after = JSON.parse(readFileSync(join(p.hushDir, "envs.json"), "utf8")) as { use: string[] };
      assert.deepEqual(after.use, ["work-fal"]);
    } finally {
      p.cleanup();
    }
  });
});

describe("a folder that isn't set up yet", () => {
  test("non-interactive: exits 1, names the library's sets, runs nothing, writes nothing", () => {
    const p = bareFolder();
    try {
      p.librarySet("acme-production", { DATABASE_URL: "x" });
      const marker = join(p.root, "marker.txt");
      const r = p.run(["sh", "-c", `touch ${marker}`]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /isn't set up for hush yet/);
      assert.match(r.out, /acme-production/, `the library's sets are not named:\n${r.out}`);
      assert.ok(!existsSync(marker), "the command ran despite the refusal");
      assert.ok(!existsSync(p.hushDir), "a .hush directory was created for a refused run");
    } finally {
      p.cleanup();
    }
  });

  test("non-interactive with no library at all only offers the two ways in", () => {
    const p = bareFolder();
    try {
      const r = p.run(["sh", "-c", "echo hi"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /hush add \.env --as Dev/);
      assert.match(r.out, /hush global --create/);
    } finally {
      p.cleanup();
    }
  });

  test("interactive: a single unambiguous match is proposed; Y + N (agent) links it and the run is injected", () => {
    const p = bareFolder({ HUSH_INTERACTIVE: "1" });
    try {
      p.librarySet("acme-production", { DATABASE_URL: "dburl", FAL_KEY: "falval" });
      p.librarySet("work-fal", { FAL_KEY: "workval" });
      writeFileSync(join(p.root, "index.js"), "process.env.FAL_KEY; process.env.DATABASE_URL;\n");

      const r = p.run(["sh", "-c", "echo ${FAL_KEY:-absent}"], "y\nn\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /Its code references: DATABASE_URL, FAL_KEY/, r.out);
      assert.match(r.out, /acme-production/);
      assert.ok(!r.out.includes("work-fal"), `a tied-loser set was named in the proposal:\n${r.out}`);
      assert.match(r.out, /redacted:FAL_KEY/, r.out);
      assert.ok(!r.out.includes("falval"), "a live value leaked into output");

      const links = JSON.parse(readFileSync(join(p.hushDir, "envs.json"), "utf8")) as { use: string[] };
      assert.deepEqual(links, { use: ["acme-production"] });
      assert.ok(!existsSync(join(p.hushDir, "policy.json")), "answering N to the agent question still wrote a policy");
      assert.ok(!existsSync(join(p.hushDir, "vault.json")), "a vault was created for a library-only setup");
    } finally {
      p.cleanup();
    }
  });

  test("an ambiguous key is asked about by name, and the numbered answer picks it", () => {
    const p = bareFolder({ HUSH_INTERACTIVE: "1" });
    try {
      p.librarySet("personal-fal", { FAL_KEY: "personalval" });
      p.librarySet("work-fal", { FAL_KEY: "workval" });
      writeFileSync(join(p.root, "index.js"), "process.env.FAL_KEY;\n");

      const r = p.run(["use"], "2\ny\nn\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /FAL_KEY is in personal-fal and work-fal — which one\?/, r.out);

      const links = JSON.parse(readFileSync(join(p.hushDir, "envs.json"), "utf8")) as { use: string[] };
      assert.deepEqual(links, { use: ["work-fal"] }, "option 2 was not the one linked");
    } finally {
      p.cleanup();
    }
  });

  test("n leaves nothing written", () => {
    const p = bareFolder({ HUSH_INTERACTIVE: "1" });
    try {
      p.librarySet("acme-production", { FAL_KEY: "v" });
      writeFileSync(join(p.root, "index.js"), "process.env.FAL_KEY;\n");

      // Declining is an answer, not an error.
      const r = p.run(["use"], "n\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /Nothing saved here/);
      assert.ok(!existsSync(join(p.hushDir, "envs.json")), "envs.json was written despite declining");

      // And a run that was declined still runs — with nothing, and saying so.
      const marker = join(p.root, "ran.txt");
      const run = p.run(["sh", "-c", `touch ${marker}`], "n\n");
      assert.equal(run.code, 0, run.out);
      assert.match(run.out, /running without secrets/);
      assert.ok(existsSync(marker), "the declined run never ran");
      assert.ok(!existsSync(join(p.hushDir, "envs.json")), "a declined run wrote envs.json");
    } finally {
      p.cleanup();
    }
  });

  test("edit replaces the proposal with the typed list", () => {
    const p = bareFolder({ HUSH_INTERACTIVE: "1" });
    try {
      // acme-production covers both keys outright (no tie with work-fal), so
      // this reaches the Y/n/edit question rather than the ambiguity prompt —
      // edit is then what overrides the proposal to work-fal instead.
      p.librarySet("acme-production", { DATABASE_URL: "d", FAL_KEY: "v1" });
      p.librarySet("work-fal", { FAL_KEY: "v2" });
      writeFileSync(join(p.root, "index.js"), "process.env.FAL_KEY; process.env.DATABASE_URL;\n");

      const r = p.run(["use"], "edit\nwork-fal\nn\n");
      assert.equal(r.code, 0, r.out);
      const links = JSON.parse(readFileSync(join(p.hushDir, "envs.json"), "utf8")) as { use: string[] };
      assert.deepEqual(links, { use: ["work-fal"] }, "edit did not replace the proposal");
    } finally {
      p.cleanup();
    }
  });

  test("edit refuses a typo, naming the known sets", () => {
    const p = bareFolder({ HUSH_INTERACTIVE: "1" });
    try {
      p.librarySet("acme-production", { DATABASE_URL: "d", FAL_KEY: "v1" });
      writeFileSync(join(p.root, "index.js"), "process.env.FAL_KEY; process.env.DATABASE_URL;\n");

      const r = p.run(["use"], "edit\nnot-a-real-set\n");
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /No set called "not-a-real-set"/);
      assert.match(r.out, /acme-production/, "the refusal does not name the known sets");
      assert.ok(!existsSync(join(p.hushDir, "envs.json")), "a rejected edit still wrote links");
    } finally {
      p.cleanup();
    }
  });

  test("the agent question, answered y, writes the three approvals", () => {
    const p = bareFolder({ HUSH_INTERACTIVE: "1" });
    try {
      p.librarySet("acme-production", { FAL_KEY: "v" });
      writeFileSync(join(p.root, "index.js"), "process.env.FAL_KEY;\n");

      const r = p.run(["use"], "y\ny\n");
      assert.equal(r.code, 0, r.out);
      const policy = JSON.parse(readFileSync(join(p.hushDir, "policy.json"), "utf8")) as { requireApproval: string[] };
      assert.deepEqual(policy.requireApproval.sort(), ["add", "request", "reveal", "run"]);
    } finally {
      p.cleanup();
    }
  });

  test("--agent and --no-agent answer the question without asking", () => {
    const setUp = () => {
      const p = bareFolder({ HUSH_INTERACTIVE: "1" });
      p.librarySet("acme-production", { FAL_KEY: "v" });
      writeFileSync(join(p.root, "index.js"), "process.env.FAL_KEY;\n");
      return p;
    };

    const withAgent = setUp();
    try {
      // Only one line piped: the agent question is skipped entirely, so a
      // second line here would be left unread — proof it was never asked.
      const r = withAgent.run(["use", "--agent"], "y\n");
      assert.equal(r.code, 0, r.out);
      assert.ok(existsSync(join(withAgent.hushDir, "policy.json")), "--agent did not write a policy");
    } finally {
      withAgent.cleanup();
    }

    const withoutAgent = setUp();
    try {
      const r = withoutAgent.run(["use", "--no-agent"], "y\n");
      assert.equal(r.code, 0, r.out);
      assert.ok(!existsSync(join(withoutAgent.hushDir, "policy.json")), "--no-agent still wrote a policy");
    } finally {
      withoutAgent.cleanup();
    }
  });

  test("hush init --agent writes the policy too, without asking", () => {
    const home = mkdtempSync(join(tmpdir(), "hush-cli-home-"));
    const proj = mkdtempSync(join(tmpdir(), "hush-cli-init-"));
    try {
      const env = { ...process.env, HUSH_HOME: home, HUSH_NO_NUDGE: "1", HUSH_NO_KEYCHAIN: "1", NO_COLOR: "1" };
      const r = spawnSync(process.execPath, [CLI, "init", "agenttest", "--agent"], { cwd: proj, env, encoding: "utf8" });
      assert.equal(r.status, 0, (r.stdout ?? "") + (r.stderr ?? ""));
      const policy = JSON.parse(readFileSync(join(proj, ".hush", "policy.json"), "utf8")) as { requireApproval: string[] };
      assert.deepEqual(policy.requireApproval.sort(), ["add", "request", "reveal", "run"]);
    } finally {
      rmSync(home, { recursive: true, force: true });
      rmSync(proj, { recursive: true, force: true });
    }
  });

  test("hush use <set> in a bare folder creates envs.json and .hush/.gitignore, with no vault", () => {
    const p = bareFolder();
    try {
      p.librarySet("work-fal", { FAL_KEY: "v" });
      const r = p.run(["use", "work-fal"]);
      assert.equal(r.code, 0, r.out);
      assert.ok(existsSync(join(p.hushDir, "envs.json")));
      assert.ok(existsSync(join(p.hushDir, ".gitignore")));
      assert.ok(!existsSync(join(p.hushDir, "vault.json")), "hush use created a vault");
    } finally {
      p.cleanup();
    }
  });

  test("hush ls in a vault-less set-up folder says so and lists what it uses", () => {
    const p = bareFolder();
    try {
      p.librarySet("work-fal", { FAL_KEY: "v" });
      assert.equal(p.run(["use", "work-fal"]).code, 0);
      const out = p.run(["ls"]).out;
      assert.match(out, /no vault yet — this folder uses library sets only/);
      assert.match(out, /work-fal/);
    } finally {
      p.cleanup();
    }
  });

  test("hush ls in a folder not set up at all points at both ways in", () => {
    const p = bareFolder();
    try {
      const out = p.run(["ls"]).out;
      assert.match(out, /not set up yet/);
      assert.match(out, /hush use <set>/);
      assert.match(out, /hush run -- <cmd>/);
    } finally {
      p.cleanup();
    }
  });

  test("add K=v --to <new set> lands in the library when there is no project vault", () => {
    const p = bareFolder();
    try {
      p.librarySet("seed", { SEED_KEY: "v" }); // only to make a library exist
      const r = p.run(["add", "K=v", "--to", "fresh"]);
      assert.equal(r.code, 0, r.out);
      const library = Vault.open(join(p.home, "vaults", "global", "vault.json"));
      assert.ok(library.has("fresh", "K"), "K did not land in the library");
      assert.ok(!existsSync(join(p.hushDir, "vault.json")), "a project vault was created for a plain add");
    } finally {
      p.cleanup();
    }
  });

  test("add K=v --to <new set> --project creates the vault and prints the one-line notice", () => {
    const p = bareFolder();
    try {
      const r = p.run(["add", "K=v", "--to", "fresh", "--project"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /made this folder's own vault at \.hush\/vault\.json — commit it/);
      const vault = Vault.open(join(p.hushDir, "vault.json"));
      assert.ok(vault.has("fresh", "K"));
    } finally {
      p.cleanup();
    }
  });

  test("hush team add on a vault-less project creates the vault", () => {
    const p = bareFolder();
    try {
      const other = generateIdentity();
      const r = p.run(["team", "add", "colleague", encodePub(other.pub)]);
      assert.equal(r.code, 0, r.out);
      const vault = Vault.open(join(p.hushDir, "vault.json"));
      assert.ok(vault.members().some((m) => m.name === "colleague"), "team add did not add the member");
    } finally {
      p.cleanup();
    }
  });

  test("get and export --format json resolve a key from the library in a vault-less set-up folder", () => {
    const p = bareFolder();
    try {
      p.librarySet("acme-production", { FAL_KEY: "libval" });
      assert.equal(p.run(["use", "acme-production"]).code, 0);

      const got = p.run(["get", "FAL_KEY", "--yes"]);
      assert.equal(got.code, 0, got.out);
      assert.match(got.out, /libval/);

      const exported = JSON.parse(p.run(["export", "--format", "json"]).out) as Record<string, string>;
      assert.equal(exported.FAL_KEY, "libval");
    } finally {
      p.cleanup();
    }
  });

  test("a strict command (hush rotate) on a set-up-but-vault-less folder names --project and hush team add", () => {
    const p = bareFolder();
    try {
      p.librarySet("acme-production", { FAL_KEY: "v" });
      assert.equal(p.run(["use", "acme-production"]).code, 0);
      const r = p.run(["rotate"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /no vault of its own yet/);
      assert.match(r.out, /--project/);
      assert.match(r.out, /hush team add/);
    } finally {
      p.cleanup();
    }
  });
});

describe("the library is a catalog, not a floor", () => {
  test("its default reaches a folder only after `hush use default --library`", () => {
    const p = bareFolder();
    try {
      p.librarySet("default", { CATCH_ALL: "catch_all_value_123" });
      p.librarySet("work", { WORK_KEY: "work_value_1234" });
      assert.equal(p.run(["use", "work"]).code, 0);

      const before = p.run(["run", "--", "sh", "-c", 'echo "[${CATCH_ALL:-unset}]"']);
      assert.equal(before.code, 0, before.out);
      assert.match(before.out, /\[unset\]/, "the library's default leaked into a folder that never asked");

      const use = p.run(["use", "default", "--library"]);
      assert.equal(use.code, 0, use.out);
      const links = JSON.parse(readFileSync(join(p.hushDir, "envs.json"), "utf8")) as { use: string[] };
      assert.deepEqual(links.use, ["work", "library:default"]);

      const after = p.run(["run", "--", "sh", "-c", 'echo "[${CATCH_ALL:-unset}]"']);
      assert.match(after.out, /\[redacted:CATCH_ALL\]/, after.out);
    } finally {
      p.cleanup();
    }
  });
});
