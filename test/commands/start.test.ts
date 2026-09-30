/**
 * `hush start`, the guided first run.
 */
import { test, describe } from "node:test";
import { writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";
import { project } from "../helpers/cli.ts";

describe("hush start", () => {
  /** A folder with a .env and nothing else, which is where most people are. */
  function folderWithEnv(body = "STRIPE_SECRET_KEY=sk_live_from_env\nAPI_URL=https://api.example.com\n") {
    const p = project({ HUSH_INTERACTIVE: "1" });
    writeFileSync(join(p.root, ".env"), body);
    return p;
  }

  test("off a terminal it says so, rather than reading answers nobody gave", () => {
    const p = project();
    try {
      const r = p.run(["start"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /needs a terminal/);
      assert.match(r.out, /hush import <file> --as <name>/, "it does not name the non-interactive path");
    } finally {
      p.cleanup();
    }
  });

  test("the .env path: finds the file, stores it, says what to do with the file", () => {
    const p = folderWithEnv();
    try {
      // Answers: where are your keys (1), what to call them, will an agent use
      // them (n). No dev script here, so nothing is offered to run.
      const r = p.run(["start"], "1\nProd\nn\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /I can see \.env in this folder/);
      assert.match(r.out, /stored 2 key\(s\) as Prod/);
      assert.match(r.out, /not in \.gitignore/, "it did not warn about the plaintext file");
      assert.doesNotMatch(r.out, /sk_live_from_env/, "a value was printed");
      // The ending is three commands, not the command list.
      assert.match(r.out, /three commands you'll actually use/);
      assert.match(r.out, /hush ls/);

      // The keys really are in the vault, and the set is used here.
      assert.match(p.run(["get", "STRIPE_SECRET_KEY", "--yes"]).out, /sk_live_from_env/);
      assert.match(p.run(["ls"]).out, /● /);
    } finally {
      p.cleanup();
    }
  });

  test("it says when the file is already ignored, and never deletes it", () => {
    const p = folderWithEnv();
    try {
      writeFileSync(join(p.root, ".gitignore"), ".env\n");
      const r = p.run(["start"], "1\nProd\nn\n");
      assert.match(r.out, /already gitignored/);
      assert.match(r.out, /You can delete it now/);
      assert.equal(existsSync(join(p.root, ".env")), true, "hush deleted the file for them");
    } finally {
      p.cleanup();
    }
  });

  test("the agent question is asked here too, and answering yes gates things", () => {
    const p = folderWithEnv();
    try {
      const r = p.run(["start"], "1\nProd\ny\n");
      assert.match(r.out, /Will an AI agent use secrets here/);
      const policy = JSON.parse(readFileSync(join(p.root, ".hush", "policy.json"), "utf8"));
      assert.ok(policy.requireApproval.includes("run"), "answering yes did not turn approvals on");
    } finally {
      p.cleanup();
    }
  });

  test("'in another tool' prints one command and stores nothing", () => {
    const p = project({ HUSH_INTERACTIVE: "1" });
    try {
      const r = p.run(["start"], "2\ndoppler\nProd\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /doppler secrets download --format json --no-file \| hush import - --as "Prod"/);
      assert.match(r.out, /Then run `hush start` again/);
      assert.equal(existsSync(join(p.root, ".hush", "envs.json")), false, "it set something up anyway");
    } finally {
      p.cleanup();
    }
  });

  test("'add one now' takes the value hidden, and stores it", () => {
    const p = project({ HUSH_INTERACTIVE: "1" });
    try {
      // The secret is piped last because the hidden prompt reads the rest of
      // stdin as one value (a multi-line key has to survive that).
      const r = p.run(["start"], "3\nProd\nstripe\nsk_test_1234567890\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /stored STRIPE_SECRET_KEY as Prod/);
      assert.doesNotMatch(r.out, /sk_test_1234567890/, "the value was echoed");
      assert.match(p.run(["get", "STRIPE_SECRET_KEY", "--yes"]).out, /sk_test_1234567890/);
    } finally {
      p.cleanup();
    }
  });

  test("with a package.json it offers to run the dev script, and does not run it unasked", () => {
    const p = folderWithEnv();
    try {
      writeFileSync(join(p.root, "package.json"), JSON.stringify({ scripts: { dev: "echo DEV-RAN" } }));
      // Answering nothing to the run question means no: a piped run must never
      // start a dev server by accident.
      const r = p.run(["start"], "1\nProd\nn\n");
      assert.match(r.out, /Want to run it now\?/);
      assert.match(r.out, /hush dev/, "the ending did not name hush dev");
      assert.doesNotMatch(r.out, /DEV-RAN/, "it ran the dev script without being asked");

      const yes = p.run(["start"], "1\nProd\nn\ny\n");
      assert.match(yes.out, /DEV-RAN/, "answering yes did not run it");
    } finally {
      p.cleanup();
    }
  });

  test("a folder with no .env asks for the file name and refuses to guess", () => {
    const p = project({ HUSH_INTERACTIVE: "1" });
    try {
      const r = p.run(["start"], "1\nProd\nnope.env\n");
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /I can't find nope\.env/);
      assert.match(r.out, /pick another answer/);
    } finally {
      p.cleanup();
    }
  });

  test("the pointer appears in a folder nobody has set up, and not after", () => {
    const fresh = project({ HUSH_INTERACTIVE: "1" });
    try {
      writeFileSync(join(fresh.root, ".env"), "A_KEY=value\n");
      rmSync(join(fresh.root, ".hush"), { recursive: true, force: true });
      const before = fresh.run([]);
      assert.match(before.out, /New here\? Run hush start/);

      const ran = fresh.run(["start"], "1\nProd\nn\n");
      assert.equal(ran.code, 0, ran.out);
      assert.ok(existsSync(join(fresh.root, ".hush", "envs.json")), "start did not set the folder up");

      // Now that the folder is set up, the eight-command screen is the screen.
      const after = fresh.run([]);
      assert.doesNotMatch(after.out, /New here\?/);
    } finally {
      fresh.cleanup();
    }
  });

  test("the not-set-up error points at the guided run first", () => {
    const p = project();
    try {
      rmSync(join(p.root, ".hush"), { recursive: true, force: true });
      const r = p.run(["run", "--", "echo", "hi"]);
      assert.match(r.out, /isn't set up for hush yet/);
      assert.match(r.out, /hush start/, "the error does not mention the guided run");
    } finally {
      p.cleanup();
    }
  });
});
