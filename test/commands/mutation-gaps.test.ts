/**
 * Gaps mutation testing found in get, import, run, export and use.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync, statSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { Vault } from "../../src/vault.ts";
import { generateIdentity, encodePub } from "../../src/crypto.ts";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { CLI, project } from "../helpers/cli.ts";

describe("hush get / import / run — the gaps mutation testing found", () => {
  test("`hush get` will not print a live credential without --yes", () => {
    // Non-interactive, so the confirmation can only decline. Removing the
    // confirmation entirely made every `hush get` print the value.
    const p = project();
    try {
      const r = p.run(["get", "STRIPE_SECRET_KEY"]);
      assert.ok(!r.out.includes("sk_live_cli"), `a credential was printed unasked:\n${r.out}`);
      assert.match(r.out, /aborted|stays in scrollback/);

      // With --yes it does print it — otherwise this proves only that get is broken.
      const yes = p.run(["get", "STRIPE_SECRET_KEY", "--yes"]);
      assert.match(yes.out, /sk_live_cli/);
    } finally {
      p.cleanup();
    }
  });

  test("`hush import` does not overwrite an existing secret unless told to", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.in"), "STRIPE_SECRET_KEY=a_different_value\nNEW_ONE=brand_new_value\n");

      const first = p.run(["import", ".env.in", "--as", "default"]);
      assert.equal(first.code, 0, first.out);
      assert.match(first.out, /1 secret\(s\)|1 already present/);
      assert.match(p.run(["get", "STRIPE_SECRET_KEY", "--yes"]).out, /sk_live_cli/, "the existing value was replaced");
      assert.match(p.run(["get", "NEW_ONE", "--yes"]).out, /brand_new_value/);

      // --overwrite is the opt-in, and it must actually do it.
      const second = p.run(["import", ".env.in", "--as", "default", "--overwrite"]);
      assert.equal(second.code, 0, second.out);
      assert.match(p.run(["get", "STRIPE_SECRET_KEY", "--yes"]).out, /a_different_value/, "--overwrite did nothing");
    } finally {
      p.cleanup();
    }
  });

  test("`hush import --as` creates a named set in the project vault, not default", () => {
    // The quick-start command is `hush import`, and without a name every key
    // lands in one unnamed pile under "default" — the exact thing the named
    // env-set feature exists to prevent. `--as` is the way `import` gets there.
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.in"), "ACME_API_KEY=key1\nACME_DB_URL=db1\n");
      const r = p.run(["import", ".env.in", "--as", "Acme Production", "--description", "live keys"]);
      assert.equal(r.code, 0, r.out);

      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      const sets = vault.sets();
      const set = sets.find((s) => s.name === "acme-production");
      assert.ok(set, `no set named acme-production among: ${sets.map((s) => s.name).join(", ")}`);
      assert.equal(set!.label, "Acme Production");
      assert.equal(set!.description, "live keys");
      assert.deepEqual(set!.keys.sort(), ["ACME_API_KEY", "ACME_DB_URL"]);

      const def = sets.find((s) => s.name === "default")!;
      assert.ok(
        !def.keys.includes("ACME_API_KEY") && !def.keys.includes("ACME_DB_URL"),
        `default gained the imported keys: ${def.keys.join(", ")}`,
      );
    } finally {
      p.cleanup();
    }
  });

  test("`hush import` with no flags now requires --as: a run that stores nothing must not look like one that did", () => {
    // This used to default quietly into "default" with a tip; `hush import`
    // is now a pure alias for `hush add <file>`, whose non-TTY rule (same
    // principle `hush add <service>` already applied to an empty stdin pipe)
    // is stricter — see specs/cli.md's `hush add` test list, bullet 1.
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.in"), "PLAIN_ONE=v1\nPLAIN_TWO=v2\n");
      const r = p.run(["import", ".env.in"]);
      assert.equal(r.code, 1, `expected failure, got:\n${r.out}`);
      assert.match(r.out, /--as/);

      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      const def = vault.sets().find((s) => s.name === "default")!;
      assert.ok(!def.keys.includes("PLAIN_ONE") && !def.keys.includes("PLAIN_TWO"), "keys were stored despite the failure");
    } finally {
      p.cleanup();
    }
  });

  test("the removed `--env` shortcut fails, naming the exact replacement", () => {
    // The name was given a real job, so the old shortcut must not quietly come
    // to mean something else: a script that means one thing and gets another is
    // worse than one that stops and says what to type instead.
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.in"), "PROD_ONE=v1\n");
      const r = p.run(["import", ".env.in", "--env", "prod"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /--env <set>` was removed/);
      assert.match(r.out, /hush add \.env\.in --to prod/, "the error does not name the replacement");

      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.ok(!vault.sets().some((s) => s.name === "prod"), "the removed form stored something anyway");
    } finally {
      p.cleanup();
    }
  });

  test("`hush import --as` into an existing set adds to it, respecting --overwrite", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.a"), "SHARED_KEY=first_value\nONLY_IN_A=a_value\n");
      writeFileSync(join(p.root, ".env.b"), "SHARED_KEY=second_value\nONLY_IN_B=b_value\n");

      const first = p.run(["import", ".env.a", "--as", "Acme Production"]);
      assert.equal(first.code, 0, first.out);

      // The user is adding to the set they already named — this must not fail.
      const second = p.run(["import", ".env.b", "--as", "Acme Production"]);
      assert.equal(second.code, 0, second.out);
      assert.match(second.out, /1 already present/, second.out);

      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      const set = vault.sets().find((s) => s.name === "acme-production");
      assert.ok(set, "set missing after second import");
      assert.deepEqual(set!.keys.sort(), ["ONLY_IN_A", "ONLY_IN_B", "SHARED_KEY"]);

      assert.match(
        p.run(["get", "SHARED_KEY", "--env", "acme-production", "--yes"]).out,
        /first_value/,
        "the existing value in the named set was replaced without --overwrite",
      );

      const third = p.run(["import", ".env.b", "--as", "Acme Production", "--overwrite"]);
      assert.equal(third.code, 0, third.out);
      assert.match(
        p.run(["get", "SHARED_KEY", "--env", "acme-production", "--yes"]).out,
        /second_value/,
        "--overwrite did nothing for a named set",
      );
    } finally {
      p.cleanup();
    }
  });

  test("`hush import --as` records the source file in the set's metadata", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.prod"), "SRC_KEY=v\n");
      const r = p.run(["import", ".env.prod", "--as", "Acme Production"]);
      assert.equal(r.code, 0, r.out);

      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      const set = vault.sets().find((s) => s.name === "acme-production");
      assert.ok(set && set.source && set.source.endsWith(".env.prod"), `source not recorded: ${JSON.stringify(set)}`);
    } finally {
      p.cleanup();
    }
  });

  test("`hush run` injects the set this project uses, redacted", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=fal_default_value", "--to", "work-fal"]).code, 0);
      assert.equal(p.run(["use", "work-fal"]).code, 0);
      const ran = p.run(["run", "--quiet", "--", "sh", "-c", "echo \"${FAL_KEY:-absent}\""]);
      assert.equal(ran.code, 0, ran.out);
      assert.match(ran.out, /redacted:FAL_KEY/, `the used set's key did not reach the child:\n${ran.out}`);
      assert.ok(!ran.out.includes("fal_default_value"), "a live value leaked into output");
    } finally {
      p.cleanup();
    }
  });

  test("sets are layers, not exclusive choices: --use appended last wins a shared key, but keeps the other layer's own keys", () => {
    // Pre-unification, picking a different "account" replaced the injected
    // keys wholesale — the two accounts here would have had the very same
    // variable name, and choosing one meant the other's value simply could
    // not be observed at the same time. Named sets compose instead: each
    // layer's own keys always show up, and only a key both layers hold is
    // decided by order (later wins). Two different keys plus one shared key
    // is what actually exercises that, which is why this replaces the old
    // "the pin won over --with" test (see specs/cli.md's `hush run` test).
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=work_value", "PROJECT_MARKER=work", "--to", "work-fal"]).code, 0);
      // --no-use: a set made from inside a project is used by it, and this
      // one must stay unused so --use below is what brings it in.
      assert.equal(p.run(["add", "FAL_KEY=personal_value", "PERSONAL_MARKER=mine", "--to", "personal-fal", "--no-use"]).code, 0);
      assert.equal(p.run(["use", "work-fal"]).code, 0);

      const first = JSON.parse(p.run(["export", "--format", "json"]).out) as Record<string, string>;
      assert.equal(first.FAL_KEY, "work_value");
      assert.equal(first.PROJECT_MARKER, "work");
      assert.equal(first.PERSONAL_MARKER, undefined, "a set that is not used yet leaked a key");

      // `--use` on a set the project already uses (or a brand new one, as
      // here) is appended last, so it wins for this run.
      const layered = JSON.parse(p.run(["export", "--format", "json", "--use", "personal-fal"]).out) as Record<string, string>;
      assert.equal(layered.FAL_KEY, "personal_value", "the later set did not win the shared key");
      assert.equal(layered.PROJECT_MARKER, "work", "the earlier layer's own key was dropped, not composed");
      assert.equal(layered.PERSONAL_MARKER, "mine");

      const ran = p.run(["run", "--quiet", "--use", "personal-fal", "--", "sh", "-c", "echo \"${FAL_KEY:-absent}\""]);
      assert.equal(ran.code, 0, ran.out);
      assert.match(ran.out, /redacted:FAL_KEY/, `--use did not reach the child:\n${ran.out}`);
    } finally {
      p.cleanup();
    }
  });

  test("an unpinned run injects nothing from an account", () => {
    // The counterpart: without a pin and without --with, an account's keys must
    // not leak into every command.
    const p = project();
    try {
      p.run(["add", "fal", "--account", "personal", "--vars", "FAL_KEY"], "fal_personal_value\n");
      const names = p.run(["export", "--names"]);
      assert.ok(!names.out.includes("FAL_KEY"), `an unpinned account was injected:\n${names.out}`);
    } finally {
      p.cleanup();
    }
  });
});

describe("hush export / use / run — the rest of the CLI gaps", () => {
  test("an exported .env is written mode 0600, even over an existing world-readable file", () => {
    // writeFileSync only applies a mode when it creates the file, so exporting
    // over a stray .env left at 0644 would keep 0644 — every account on the box
    // can then read every credential.
    const p = project();
    try {
      const out = join(p.root, ".env.generated");
      writeFileSync(out, "STALE=1\n", { mode: 0o644 });
      chmodSync(out, 0o644);
      assert.equal((statSync(out).mode & 0o777).toString(8), "644", "the fixture is not world-readable");

      const r = p.run(["export", "--out", ".env.generated"]);
      assert.equal(r.code, 0, r.out);
      assert.equal((statSync(out).mode & 0o777).toString(8), "600", "the exported file is readable by others");
      assert.match(r.out, /Parse it, don't source it/, "the sourcing hazard is not mentioned");

      // Writing plaintext credentials into the repo and not excluding them is
      // exactly how a .env gets committed — which is the thing hush exists to
      // stop. The entry is added whether or not a .gitignore was there already.
      const ignorePath = join(p.root, ".gitignore");
      assert.ok(existsSync(ignorePath), "no .gitignore was created for the exported secrets");
      assert.ok(
        readFileSync(ignorePath, "utf8").split(/\r?\n/).includes(".env.generated"),
        "the exported file was not added to .gitignore",
      );
      assert.match(r.out, /added \.env\.generated to \.gitignore/);

      // And it is not added twice when you export again.
      assert.equal(p.run(["export", "--out", ".env.generated"]).code, 0);
      const lines = readFileSync(ignorePath, "utf8").split(/\r?\n/).filter((l) => l === ".env.generated");
      assert.equal(lines.length, 1, "the .gitignore entry was duplicated on a second export");
    } finally {
      p.cleanup();
    }
  });

  test("`hush use` refuses a set that does not exist, and `fal=acme` aliases to `fal/acme`", () => {
    // Using a typo silently means every later `hush run` quietly injects
    // nothing, and the failure surfaces somewhere else entirely. `hush use`
    // now names sets directly and records them in .hush/envs.json, not
    // .hush/use.json — the pre-unification "pin a service=account" model this
    // test used to cover, per the alias table in specs/cli.md.
    const p = project();
    try {
      p.run(["add", "fal", "--account", "personal", "--vars", "FAL_KEY"], "fal-value\n");

      const bad = p.run(["use", "fal=typo"]);
      assert.equal(bad.code, 1, `a non-existent set was used:\n${bad.out}`);
      assert.match(bad.out, /"fal=typo" is deprecated/, "the alias was not translated with a deprecation notice");
      assert.match(bad.out, /No set called "fal\/typo"/);
      assert.match(bad.out, /fal\/personal/, "the message does not say what is available");
      assert.ok(!existsSync(join(p.root, ".hush", "envs.json")), "it wrote the bad link anyway");

      const good = p.run(["use", "fal=personal"]);
      assert.equal(good.code, 0, good.out);
      assert.match(good.out, /"fal=personal" is deprecated/);
      const links = JSON.parse(readFileSync(join(p.root, ".hush", "envs.json"), "utf8")) as { use: string[] };
      assert.deepEqual(links.use, ["fal/personal"]);
    } finally {
      p.cleanup();
    }
  });

  test("`hush run` exits with the child's status", () => {
    // CI reads the exit code and nothing else. Reporting 0 for a failed command
    // turns a red build green.
    const p = project();
    try {
      assert.equal(p.run(["run", "--quiet", "--", "sh", "-c", "exit 0"]).code, 0);
      assert.equal(p.run(["run", "--quiet", "--", "sh", "-c", "exit 3"]).code, 3, "a failing child reported success");
      assert.equal(p.run(["run", "--quiet", "--", "sh", "-c", "exit 42"]).code, 42);
      // A child killed by a signal exits with code null; 128+n is the convention.
      assert.equal(p.run(["run", "--quiet", "--", "sh", "-c", "kill -TERM $$"]).code, 143);
    } finally {
      p.cleanup();
    }
  });

  test("a vault that has gone backwards is reported before anything else runs", () => {
    // A rolled-back vault decrypts perfectly — authentication says nothing about
    // freshness — so the only thing standing between a revoked member's old copy
    // and full access is this warning.
    const p = project();
    try {
      p.run(["ls"]); // trust on first use records generation 1
      const other = generateIdentity();
      p.run(["team", "add", "colleague", encodePub(other.pub)]);
      p.run(["team", "rm", "colleague", "--yes"]); // generation 2
      p.run(["ls"]); // watermark now 2

      // Restore the old copy, the way a force-push would.
      const path = join(p.root, ".hush", "vault.json");
      const raw = JSON.parse(readFileSync(path, "utf8")) as { dek: { generation: number } };
      raw.dek.generation = 1;
      writeFileSync(path, JSON.stringify(raw, null, 2));

      const out = p.run(["ls"]).out;
      assert.match(out, /ROLLBACK/, `no rollback warning:\n${out}`);
      assert.match(out, /gone BACKWARDS/);
      assert.match(out, /treat every secret in it as compromised/);
    } finally {
      p.cleanup();
    }
  });

  test("hush init makes the vault unmergeable and keeps local state out of git", () => {
    // A three-way merge of two vaults produces valid JSON with a data key from
    // one branch and values sealed under another: unopenable, and it looks fine.
    // And the identity file must never be committable.
    const p = project();
    try {
      const proj = mkdtempSync(join(tmpdir(), "hush-init-"));
      const env = { ...process.env, HUSH_HOME: p.home, HUSH_NO_NUDGE: "1", HUSH_NO_KEYCHAIN: "1", NO_COLOR: "1" };
      const r = spawnSync(process.execPath, [CLI, "init", "gitattrs"], { cwd: proj, env, encoding: "utf8" });
      assert.equal(r.status, 0, (r.stdout ?? "") + (r.stderr ?? ""));

      const attrs = readFileSync(join(proj, ".hush", ".gitattributes"), "utf8");
      assert.match(attrs, /^vault\.json -merge$/m, "git may line-merge the vault");
      assert.match(attrs, /^use\.json -merge$/m);
      assert.ok(!/-diff/.test(attrs), "the diff is how a reviewer notices a new recipient");

      const ignored = readFileSync(join(proj, ".hush", ".gitignore"), "utf8").split(/\r?\n/);
      for (const entry of ["identity", "audit.log", "pending/", "*.local.json"]) {
        assert.ok(ignored.includes(entry), `.hush/.gitignore does not exclude ${entry}`);
      }
      rmSync(proj, { recursive: true, force: true });
    } finally {
      p.cleanup();
    }
  });
});
