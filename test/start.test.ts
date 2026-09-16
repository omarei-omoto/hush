/**
 * `hush start` — the guided first run.
 *
 * The wording is the feature here, so most of this file asserts what a person
 * is *shown*: which choice comes first, that the first choice matches what is
 * actually on disk, and that the ending names three commands rather than forty.
 */
import { test, describe, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  findEnvFiles, isGitignored, detectDevCommand, openingLines,
  keySourceChoices, importRecipe, closingLines,
} from "../src/start.ts";

const dirs: string[] = [];
function scratch(): string {
  const d = mkdtempSync(join(tmpdir(), "hush-start-test-"));
  dirs.push(d);
  return d;
}

after(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("findEnvFiles", () => {
  test("finds the usual names, .env first", () => {
    const root = scratch();
    writeFileSync(join(root, ".env.local"), "A=1\n");
    writeFileSync(join(root, ".env"), "B=2\n");
    assert.deepEqual(findEnvFiles(root), [".env", ".env.local"]);
  });

  test("an empty folder finds nothing, which is a different question", () => {
    assert.deepEqual(findEnvFiles(scratch()), []);
  });
});

describe("isGitignored", () => {
  test("recognises the name and the wildcards people actually write", () => {
    const root = scratch();
    writeFileSync(join(root, ".gitignore"), "node_modules/\n.env\n");
    assert.equal(isGitignored(root, ".env"), true);
    assert.equal(isGitignored(root, ".env.local"), false);

    writeFileSync(join(root, ".gitignore"), ".env*\n");
    assert.equal(isGitignored(root, ".env.local"), true);
  });

  test("no .gitignore at all is not ignored", () => {
    assert.equal(isGitignored(scratch(), ".env"), false);
  });
});

describe("detectDevCommand", () => {
  const pm = () => "npm";

  test("prefers dev, then start, then serve", () => {
    const root = scratch();
    writeFileSync(join(root, "package.json"), JSON.stringify({ scripts: { serve: "x", dev: "y" } }));
    assert.deepEqual(detectDevCommand(root, pm), { pm: "npm", script: "dev" });

    writeFileSync(join(root, "package.json"), JSON.stringify({ scripts: { start: "x" } }));
    assert.deepEqual(detectDevCommand(root, pm), { pm: "npm", script: "start" });
  });

  test("no package.json, no scripts, or broken JSON all mean no offer to run", () => {
    assert.equal(detectDevCommand(scratch(), pm), null);
    const noScripts = scratch();
    writeFileSync(join(noScripts, "package.json"), JSON.stringify({ name: "x" }));
    assert.equal(detectDevCommand(noScripts, pm), null);
    const broken = scratch();
    writeFileSync(join(broken, "package.json"), "{nope");
    assert.equal(detectDevCommand(broken, pm), null);
  });

  test("looks upward, the way `hush dev` does", () => {
    const root = scratch();
    writeFileSync(join(root, "package.json"), JSON.stringify({ scripts: { dev: "y" } }));
    const nested = join(root, "packages", "app");
    mkdirSync(nested, { recursive: true });
    assert.deepEqual(detectDevCommand(nested, pm), { pm: "npm", script: "dev" });
  });
});

describe("the questions", () => {
  test("the opening says how many questions, and what it noticed", () => {
    const withFile = openingLines({ envFiles: [".env"] }).join("\n");
    assert.match(withFile, /I can see \.env in this folder/);
    assert.match(withFile, /nothing you have to know already/);
    assert.doesNotMatch(withFile, /vault|scope|layer/i, "the opening uses hush's own vocabulary");
  });

  test("the first choice is the file that is actually there", () => {
    const choices = keySourceChoices({ envFiles: [".env"], librarySetCount: 0 });
    assert.equal(choices[0].key, "1");
    assert.match(choices[0].label, /In a file in this folder \(\.env\)/);
    // No library means no fourth choice to offer.
    assert.deepEqual(choices.map((c) => c.key), ["1", "2", "3"]);
  });

  test("with nothing on disk it still leads with the file, saying it will look", () => {
    const choices = keySourceChoices({ envFiles: [], librarySetCount: 0 });
    assert.match(choices[0].label, /I'll look for one/);
    assert.equal(choices[0].note, "nothing here yet");
  });

  test("a library adds the fourth choice, and says how many", () => {
    const choices = keySourceChoices({ envFiles: [], librarySetCount: 3 });
    assert.deepEqual(choices.map((c) => c.key), ["1", "2", "3", "4"]);
    assert.equal(choices[3].note, "3 you made earlier");
  });
});

describe("importRecipe", () => {
  test("names a real pipeline for the tools people are on", () => {
    assert.match(importRecipe("doppler", "Prod")!, /^doppler secrets download.*hush import - --as "Prod"$/);
    assert.match(importRecipe("1Password", "Prod")!, /^op item get .*--format 1password --as "Prod"$/);
    assert.match(importRecipe("op", "Prod")!, /^op item get /);
    assert.match(importRecipe("AWS Secrets Manager", "Prod")!, /^aws secretsmanager get-secret-value/);
    assert.match(importRecipe("vault", "Prod")!, /^vault kv get/);
  });

  test("an unknown tool gets no recipe, so the caller can print the generic form", () => {
    assert.equal(importRecipe("mystery", "Prod"), null);
    assert.equal(importRecipe("", "Prod"), null);
  });
});

describe("the ending", () => {
  test("names three commands, and the run line matches what is here", () => {
    const lines = closingLines({ devCommand: { pm: "npm", script: "dev" } }).join("\n");
    assert.match(lines, /hush dev/);
    assert.match(lines, /hush ls/);
    assert.match(lines, /hush start/);
    // Three, deliberately: a first run that lists thirty is a wall of text again.
    assert.equal((lines.match(/\n {2}hush /g) ?? []).length, 3);
  });

  test("with no dev script it teaches the general form instead", () => {
    const lines = closingLines({ devCommand: null }).join("\n");
    assert.match(lines, /hush run -- <your command>/);
    assert.doesNotMatch(lines, /hush dev/);
  });
});
