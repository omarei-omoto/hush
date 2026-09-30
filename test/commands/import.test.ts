/**
 * `hush import`, end to end.
 */
import { test, describe } from "node:test";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import assert from "node:assert/strict";
import { project } from "../helpers/cli.ts";

describe("hush import", () => {
  const SECRET = "sk_live_adopted_1234567890";

  function jsonFile(p: ReturnType<typeof project>, name: string, body: unknown): string {
    const path = join(p.root, name);
    writeFileSync(path, JSON.stringify(body));
    return path;
  }

  test("a JSON export becomes a set, and the values are not printed", () => {
    const p = project();
    try {
      const file = jsonFile(p, "doppler.json", { API_KEY: SECRET, PORT: 3000, DEBUG: true });
      const r = p.run(["import", file, "--as", "Prod", "--project", "--format", "json"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /imported 3 secret\(s\) as Prod/);
      assert.doesNotMatch(r.out, new RegExp(SECRET), "the import printed a value");

      // The names are listed, and one value round-trips.
      assert.match(p.run(["ls", "prod"]).out, /API_KEY/);
      const got = p.run(["get", "API_KEY", "--yes", "--use", "prod"]);
      assert.match(got.out, new RegExp(SECRET));
      // Numbers and booleans arrive as the strings an environment holds.
      assert.match(p.run(["get", "PORT", "--yes", "--use", "prod"]).out, /3000/);
    } finally {
      p.cleanup();
    }
  });

  test("reads from stdin, which is how a provider's CLI is piped in", () => {
    const p = project();
    try {
      const r = p.run(["import", "-", "--as", "Piped", "--project", "--format", "json"], JSON.stringify({ PIPED_KEY: "v" }));
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /imported 1 secret\(s\) as Piped/);
      assert.match(p.run(["ls", "piped"]).out, /PIPED_KEY/);
    } finally {
      p.cleanup();
    }
  });

  test("--format 1password reads an op item", () => {
    const p = project();
    try {
      const item = { title: "Stripe", fields: [{ label: "secret key", value: SECRET }] };
      const r = p.run(["import", "-", "--as", "Work", "--project", "--format", "1password"], JSON.stringify(item));
      assert.equal(r.code, 0, r.out);
      assert.match(p.run(["ls", "work"]).out, /SECRET_KEY/);
    } finally {
      p.cleanup();
    }
  });

  test("--dry-run lists what would be stored and writes nothing", () => {
    const p = project();
    try {
      const file = jsonFile(p, "dry.json", { DRY_KEY: SECRET });
      const r = p.run(["import", file, "--as", "Dry", "--dry-run", "--format", "json"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /1 secret\(s\) would be stored/);
      assert.match(r.out, /DRY_KEY/);
      assert.match(r.out, /Nothing was written/);
      assert.doesNotMatch(r.out, new RegExp(SECRET));
      // It really did not write: the key cannot be fetched afterwards.
      assert.equal(p.run(["get", "DRY_KEY", "--yes"]).code, 1, "a dry run stored something");
    } finally {
      p.cleanup();
    }
  });

  test("a name is required, and its absence says so rather than guessing", () => {
    const p = project();
    try {
      const file = jsonFile(p, "unnamed.json", { A: "1" });
      const r = p.run(["import", file, "--format", "json"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /Give the set a name/);
    } finally {
      p.cleanup();
    }
  });

  test("an unknown format is refused, naming the ones that exist", () => {
    const p = project();
    try {
      const file = jsonFile(p, "x.json", { A: "1" });
      const r = p.run(["import", file, "--as", "X", "--format", "vault"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /Unknown --format "vault".*dotenv, json, 1password/s);
    } finally {
      p.cleanup();
    }
  });

  test("notes about skipped and collided fields reach the user", () => {
    const p = project();
    try {
      const file = jsonFile(p, "messy.json", { GOOD: "1", VENDOR: { nested: true } });
      const r = p.run(["import", file, "--as", "Messy", "--project", "--format", "json"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /skipped VENDOR/);
      assert.match(r.out, /imported 1 secret\(s\)/);
    } finally {
      p.cleanup();
    }
  });

  test("with no --as it asks for a name rather than guessing", () => {
    const p = project();
    try {
      const file = join(p.root, "unnamed2.json");
      writeFileSync(file, JSON.stringify({ A: "1" }));
      const r = p.run(["import", file, "--format", "json"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /Give the set a name/);
    } finally {
      p.cleanup();
    }
  });
});
