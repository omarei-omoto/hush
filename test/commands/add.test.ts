/**
 * `hush add` in every shape, and the warnings it gives.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { Vault } from "../../src/vault.ts";
import { join } from "node:path";
import { writeFileSync, readFileSync, existsSync } from "node:fs";
import { project } from "../helpers/cli.ts";

describe("hush add", () => {
  test("a value piped in one line per variable is stored", () => {
    const p = project();
    try {
      const r = p.run(["add", "twilio", "--account", "main"], "AC_sid_value\nauth_token_value\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /stored 2 value/);

      // `hush accounts` is now a deprecated alias for `hush ls`, which never
      // prints a machine-readable per-account shape — read the vault directly.
      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      const twilio = vault.sets().find((s) => s.name === "twilio/main");
      assert.deepEqual(twilio?.keys.sort(), ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"]);
    } finally {
      p.cleanup();
    }
  });

  test("with no terminal and nothing piped it fails rather than reporting success", () => {
    // It used to print "nothing entered, nothing changed" and exit 0, so a CI
    // job that checked the exit code believed the credential had been stored.
    const p = project();
    try {
      const r = p.run(["add", "gemini", "--account", "team"]);
      assert.equal(r.code, 1, `expected failure, got:\n${r.out}`);
      assert.match(r.out, /no value arrived on stdin/);
      assert.match(r.out, /GEMINI_API_KEY/, "the message does not say what to pipe");

      // And nothing was written.
      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.equal(vault.hasSet("gemini/team"), false, "a set was created despite the failure");
    } finally {
      p.cleanup();
    }
  });

  test("a partial write says which variables were left unset", () => {
    const p = project();
    try {
      const r = p.run(["add", "twilio", "--account", "half"], "AC_sid_only\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /Left unset: TWILIO_AUTH_TOKEN/);
      assert.match(r.out, /stored 1 value/);
    } finally {
      p.cleanup();
    }
  });
});

describe("exposure warnings", () => {
  test("a value too short to mask is called out when it is stored", () => {
    const p = project();
    try {
      const r = p.run(["add", "PIN=1234", "--as", "Short", "--project"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /PIN is 4 character\(s\)/);
      assert.match(r.out, /will not mask a value that short/);
    } finally {
      p.cleanup();
    }
  });

  test("a value long enough to mask is not warned about", () => {
    const p = project();
    try {
      const r = p.run(["add", "TOKEN=long-enough-value", "--as", "Fine", "--project"]);
      assert.equal(r.code, 0, r.out);
      assert.doesNotMatch(r.out, /character\(s\)/);
    } finally {
      p.cleanup();
    }
  });

  test("the warning at import time is one line naming every short key", () => {
    const p = project();
    try {
      const file = join(p.root, "short.json");
      writeFileSync(file, JSON.stringify({ PIN: "1234", CODE: "12", TOKEN: "long-enough" }));
      const r = p.run(["import", file, "--as", "Mixed", "--project", "--format", "json"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /2 value\(s\) are shorter than 5 characters/);
      assert.match(r.out, /PIN, CODE/);
      assert.doesNotMatch(r.out, /TOKEN/, "a long enough value was named in the warning");
    } finally {
      p.cleanup();
    }
  });

  test("a secret value in the command line is called out, by key and not by value", () => {
    const p = project();
    try {
      // The value is in argv rather than in the environment, which is what `ps`
      // would show to every other user on the machine.
      const r = p.run(["run", "--", "echo", "sk_live_cli"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /the value of STRIPE_SECRET_KEY appears in the command line/);
      assert.match(r.out, /ps shows/);
      // The warning names the key; the output still masks the value.
      assert.match(r.out, /\[redacted:STRIPE_SECRET_KEY\]/);
    } finally {
      p.cleanup();
    }
  });

  test("an argument that merely mentions a key does not warn", () => {
    const p = project();
    try {
      const r = p.run(["run", "--", "echo", "STRIPE_SECRET_KEY"]);
      assert.equal(r.code, 0, r.out);
      assert.doesNotMatch(r.out, /appears in the command line/);
    } finally {
      p.cleanup();
    }
  });
});

// ===========================================================================
// The new command surface: add / use / run+pass-through / dev / ls / rm.
// See specs/cli.md — each test below corresponds to a bullet in its
// "Tests" section.
// ===========================================================================

describe("hush add <file>", () => {
  test("--as --library creates the set in the library; --project puts it in the project", () => {
    const p = project();
    try {
      assert.equal(p.run(["global", "--create"]).code, 0);
      writeFileSync(join(p.root, ".env.x"), "FAL_KEY=libval\n");

      const lib = p.run(["add", ".env.x", "--as", "Work fal", "--library"]);
      assert.equal(lib.code, 0, lib.out);
      const library = Vault.open(join(p.home, "vaults", "global", "vault.json"));
      const libSet = library.sets().find((s) => s.name === "work-fal");
      assert.ok(libSet, `no "work-fal" in the library: ${library.sets().map((s) => s.name).join(", ")}`);
      assert.equal(libSet!.label, "Work fal");
      assert.deepEqual(libSet!.keys, ["FAL_KEY"]);
      const project_ = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.equal(project_.hasSet("work-fal"), false, "--library also wrote the project vault");

      const proj = p.run(["add", ".env.x", "--as", "Work fal", "--project"]);
      assert.equal(proj.code, 0, proj.out);
      const project2 = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.ok(project2.hasSet("work-fal"), "--project did not create the set in the project vault");
    } finally {
      p.cleanup();
    }
  });

  test("non-TTY with no --as exits 1 and stores nothing", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.y"), "SOME_KEY=v\n");
      const r = p.run(["add", ".env.y"]);
      assert.equal(r.code, 1, `expected failure, got:\n${r.out}`);
      assert.match(r.out, /--as/);

      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.deepEqual(vault.sets().map((s) => s.name), ["default"], "a set was created despite the failure");
    } finally {
      p.cleanup();
    }
  });
});

describe("hush add KEY=value", () => {
  test("--to <set> adds to it; with no --to, non-TTY lands in project default and prints the tip", () => {
    const p = project();
    try {
      const named = p.run(["add", "FAL_KEY=v", "--to", "work-fal"]);
      assert.equal(named.code, 0, named.out);
      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.ok(vault.hasSet("work-fal") && vault.has("work-fal", "FAL_KEY"), "FAL_KEY did not land in work-fal");

      const bare = p.run(["add", "K=v"]);
      assert.equal(bare.code, 0, bare.out);
      assert.match(bare.out, /--to <set>/, `no --to tip in:\n${bare.out}`);
      const vault2 = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.ok(vault2.has("default", "K"), "K did not land in default");
    } finally {
      p.cleanup();
    }
  });
});

describe("hush add <service>", () => {
  test('--as "Personal fal" stores FAL_KEY in personal-fal from one piped line', () => {
    const p = project();
    try {
      const r = p.run(["add", "fal", "--as", "Personal fal"], "one_line_fal_value\n");
      assert.equal(r.code, 0, r.out);
      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      const set = vault.sets().find((s) => s.name === "personal-fal");
      assert.ok(set, `no "personal-fal" among: ${vault.sets().map((s) => s.name).join(", ")}`);
      assert.deepEqual(set!.keys, ["FAL_KEY"]);
    } finally {
      p.cleanup();
    }
  });

  test("--account x is a deprecated alias that produces fal/x and prints a notice", () => {
    const p = project();
    try {
      const r = p.run(["add", "fal", "--account", "x"], "aliased_value\n");
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /--account is deprecated/);
      const vault = Vault.open(join(p.root, ".hush", "vault.json"));
      assert.ok(vault.hasSet("fal/x"), `--account did not create "fal/x": ${vault.sets().map((s) => s.name).join(", ")}`);
    } finally {
      p.cleanup();
    }
  });
});

// The library is reachable from every add/rm form, not only `add <file>`:
// "save things into the global environment" has to work for one value, for a
// service, and in reverse.
describe("the library from add KEY=value, add <service> and rm", () => {
  const withLibrary = (p: ReturnType<typeof project>) => {
    assert.equal(p.run(["global", "--create"]).code, 0);
    writeFileSync(join(p.root, ".env.x"), "FAL_KEY=libval\n");
    const r = p.run(["add", ".env.x", "--as", "Work fal", "--library"]);
    assert.equal(r.code, 0, r.out);
  };
  const libraryVault = (p: ReturnType<typeof project>) => Vault.open(join(p.home, "vaults", "global", "vault.json"));
  const projectVault = (p: ReturnType<typeof project>) => Vault.open(join(p.root, ".hush", "vault.json"));

  // Bites: a --to taken literally dies on the space in "Work fal"; a --to that
  // only ever targets the project writes a same-named copy there instead.
  test("add KEY=value --to reaches a library set by its label or its slug, with no flag", () => {
    const p = project();
    try {
      withLibrary(p);
      const byLabel = p.run(["add", "EXTRA_KEY=v1", "--to", "Work fal"]);
      assert.equal(byLabel.code, 0, byLabel.out);
      assert.ok(libraryVault(p).has("work-fal", "EXTRA_KEY"), "the key did not land in the library set");
      assert.equal(projectVault(p).hasSet("work-fal"), false, "a copy of the set appeared in the project");

      const bySlug = p.run(["add", "OTHER_KEY=v2", "--to", "work-fal"]);
      assert.equal(bySlug.code, 0, bySlug.out);
      assert.ok(libraryVault(p).has("work-fal", "OTHER_KEY"));
    } finally {
      p.cleanup();
    }
  });

  test("add KEY=value --to <new name> --library creates it there; a new name alone lands in the project", () => {
    const p = project();
    try {
      withLibrary(p);
      const lib = p.run(["add", "K=v", "--to", "Brand new", "--library"]);
      assert.equal(lib.code, 0, lib.out);
      assert.ok(libraryVault(p).has("brand-new", "K"), "--library did not create the set in the library");
      const proj = p.run(["add", "K=v", "--to", "Also new"]);
      assert.equal(proj.code, 0, proj.out);
      assert.ok(projectVault(p).has("also-new", "K"), "a new name did not default to the project");
      assert.equal(libraryVault(p).hasSet("also-new"), false);
    } finally {
      p.cleanup();
    }
  });

  // Bites: a service form that only knows the project vault stores the
  // prompted value there and never touches the library.
  test("add <service> --library stores the prompted values in the library", () => {
    const p = project();
    try {
      withLibrary(p);
      const r = p.run(["add", "fal", "--as", "Personal fal", "--library"], "piped-fal-value\n");
      assert.equal(r.code, 0, r.out);
      assert.ok(libraryVault(p).has("personal-fal", "FAL_KEY"), "FAL_KEY is not in the library set");
      assert.equal(projectVault(p).hasSet("personal-fal"), false, "the set was created in the project instead");
      assert.ok(!r.out.includes("piped-fal-value"), "the value was echoed");
    } finally {
      p.cleanup();
    }
  });

  test("rm KEY --from a library set trims it; rm <set> --yes removes a library set", () => {
    const p = project();
    try {
      withLibrary(p);
      assert.equal(p.run(["add", "EXTRA_KEY=v1", "--to", "work-fal"]).code, 0);
      const key = p.run(["rm", "EXTRA_KEY", "--from", "work-fal"]);
      assert.equal(key.code, 0, key.out);
      assert.equal(libraryVault(p).has("work-fal", "EXTRA_KEY"), false, "the key is still in the library set");
      assert.ok(libraryVault(p).hasSet("work-fal"), "trimming a key removed the whole set");

      const set = p.run(["rm", "work-fal", "--yes"]);
      assert.equal(set.code, 0, set.out);
      assert.equal(libraryVault(p).hasSet("work-fal"), false, "the library set is still there");
    } finally {
      p.cleanup();
    }
  });
});

// The quick start is "hush add .env --as Dev" then "hush npm run dev". A set the
// project does not use is not injected, so making a set from inside a project
// has to make the project use it — or the second line silently does nothing.
describe("a set made from inside a project is used by it", () => {
  const links = (p: ReturnType<typeof project>): string[] => {
    const file = join(p.hushDir, "envs.json");
    if (!existsSync(file)) return [];
    return (JSON.parse(readFileSync(file, "utf8")) as { use: string[] }).use;
  };

  // Bites: without the link, the run below injects nothing and prints no marker.
  test("add <file> --as makes the project use the new set, so the next run injects it", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.x"), "FAL_KEY=quickstartvalue\n");
      const r = p.run(["add", ".env.x", "--as", "Dev", "--project"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /now uses dev/, r.out);
      assert.deepEqual(links(p), ["dev"]);
      const run = p.run(["sh", "-c", "echo $FAL_KEY"]);
      assert.match(run.out, /\[redacted:FAL_KEY\]/, "the new set was not injected:\n" + run.out);
      assert.ok(!run.out.includes("quickstartvalue"), "a live value leaked");
    } finally {
      p.cleanup();
    }
  });

  test("--no-use opts out, and an already-used set keeps its place", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.x"), "FAL_KEY=v\n");
      assert.equal(p.run(["add", ".env.x", "--as", "Later", "--project", "--no-use"]).code, 0);
      assert.deepEqual(links(p), [], "--no-use still linked the set");
      assert.equal(p.run(["use", "later"]).code, 0);
      writeFileSync(join(p.root, ".env.y"), "OTHER=v\n");
      assert.equal(p.run(["add", ".env.y", "--as", "Other", "--project"]).code, 0);
      assert.equal(p.run(["add", ".env.x", "--as", "Later", "--project", "--overwrite"]).code, 0);
      assert.deepEqual(links(p), ["later", "other"], "re-adding to a used set moved it");
    } finally {
      p.cleanup();
    }
  });

  // Bites: a KEY=value that creates a set has its own success path too.
  test("add KEY=value --to <new set> does the same; adding to an existing set changes nothing", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "K=v", "--to", "fresh"]).code, 0);
      assert.deepEqual(links(p), ["fresh"]);
      assert.equal(p.run(["use", "--not", "fresh"]).code, 0);
      assert.equal(p.run(["add", "K2=v", "--to", "fresh"]).code, 0);
      assert.deepEqual(links(p), [], "adding to an existing set re-linked it");
    } finally {
      p.cleanup();
    }
  });

  // Bites: the alias forwarding to cmdAddKeyValue without "no-use" links prod.
  test("the deprecated hush set --env keeps its old meaning: stored, not used", () => {
    const p = project();
    try {
      assert.equal(p.run(["set", "PROD_KEY", "--env", "prod"], "v\n").code, 0);
      assert.deepEqual(links(p), [], "hush set --env made the project use the env");
    } finally {
      p.cleanup();
    }
  });

  // Bites: the service form has its own success path; forgetting the link
  // there leaves "hush add fal" followed by "hush dev" running without FAL_KEY.
  test("add <service> --as does the same", () => {
    const p = project();
    try {
      const r = p.run(["add", "fal", "--as", "Work fal", "--project"], "piped-value\n");
      assert.equal(r.code, 0, r.out);
      assert.deepEqual(links(p), ["work-fal"]);
    } finally {
      p.cleanup();
    }
  });
});
