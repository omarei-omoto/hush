/**
 * `hush adopt` — reading another tool's export.
 *
 * The parsers are forgiving about the shapes they recognise and loud about the
 * ones they do not, because the failure mode that matters is a *silent* partial
 * import: sixty secrets in, fifty-eight stored, nobody notices.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { normalizeKey, parseImport } from "../src/import.ts";

describe("normalizeKey", () => {
  test("turns a label into a variable name", () => {
    assert.equal(normalizeKey("Client Secret"), "CLIENT_SECRET");
    assert.equal(normalizeKey("api-key"), "API_KEY");
    assert.equal(normalizeKey("  db.password  "), "DB_PASSWORD");
    assert.equal(normalizeKey("a -- b"), "A_B");
  });

  test("repairs a leading digit rather than dropping the value", () => {
    assert.equal(normalizeKey("2fa seed"), "_2FA_SEED");
  });

  test("returns null when nothing usable is left", () => {
    assert.equal(normalizeKey(""), null);
    assert.equal(normalizeKey("   "), null);
    assert.equal(normalizeKey("!!!"), null);
  });
});

describe("json", () => {
  test("reads a flat object, including numbers and booleans", () => {
    const { values, notes } = parseImport('{"API_KEY":"sk-1","PORT":3000,"DEBUG":true}', "json", "x.json");
    assert.deepEqual(values, { API_KEY: "sk-1", PORT: "3000", DEBUG: "true" });
    assert.deepEqual(notes, []);
  });

  test("unwraps the AWS Secrets Manager envelope", () => {
    const wrapper = JSON.stringify({ SecretString: JSON.stringify({ API_KEY: "sk-1" }) });
    assert.deepEqual(parseImport(wrapper, "json", "aws").values, { API_KEY: "sk-1" });
  });

  test("a nested value is reported, not stringified into a variable", () => {
    const { values, notes } = parseImport('{"GOOD":"1","VENDOR":{"a":1}}', "json", "x.json");
    assert.deepEqual(values, { GOOD: "1" });
    assert.equal(notes.length, 1);
    assert.match(notes[0], /skipped VENDOR/);
  });

  test("a repeated key keeps the last value and says so", () => {
    const { values, notes } = parseImport('{"A":"1","a":"2"}', "json", "x.json");
    assert.deepEqual(values, { A: "2" });
    assert.match(notes.join("\n"), /A appears more than once/);
  });

  test("an array is refused, and points at the format that takes one", () => {
    assert.throws(() => parseImport("[]", "json", "x.json"), /pass --format 1password/);
  });

  test("invalid JSON names the file", () => {
    assert.throws(() => parseImport("{nope", "json", "secrets.json"), /secrets\.json is not valid JSON/);
  });

  test("empty input is refused rather than silently read as zero secrets", () => {
    assert.throws(() => parseImport("   ", "json", "stdin"), /stdin is empty/);
  });
});

describe("1password", () => {
  const item = (title: string, fields: unknown[]) => ({ title, fields });

  test("reads the label of each string field", () => {
    const text = JSON.stringify(
      item("Stripe", [
        { label: "secret key", value: "sk_live_x" },
        { label: "publishable key", value: "pk_live_y" },
      ]),
    );
    assert.deepEqual(parseImport(text, "1password", "op").values, {
      SECRET_KEY: "sk_live_x",
      PUBLISHABLE_KEY: "pk_live_y",
    });
  });

  test("falls back to the field id when there is no label", () => {
    const text = JSON.stringify(item("X", [{ id: "credential", value: "v" }]));
    assert.deepEqual(parseImport(text, "1password", "op").values, { CREDENTIAL: "v" });
  });

  test("a list of items merges, with collisions reported", () => {
    const text = JSON.stringify([
      item("One", [{ label: "api key", value: "first" }]),
      item("Two", [{ label: "api key", value: "second" }, { label: "token", value: "t" }]),
    ]);
    const { values, notes } = parseImport(text, "1password", "op");
    assert.deepEqual(values, { API_KEY: "second", TOKEN: "t" });
    assert.match(notes.join("\n"), /API_KEY appears more than once/);
  });

  test("non-string values (an OTP, a file) are skipped and counted", () => {
    const text = JSON.stringify(
      item("Login", [
        { label: "one-time password", value: { totp: "123456" } },
        { label: "password", value: "hunter2" },
      ]),
    );
    const { values, notes } = parseImport(text, "1password", "op");
    assert.deepEqual(values, { PASSWORD: "hunter2" });
    assert.match(notes.join("\n"), /skipped 1 field/);
  });

  test("nothing usable is an error naming the command that produces the input", () => {
    assert.throws(
      () => parseImport(JSON.stringify(item("Empty", [])), "1password", "op"),
      /No string fields found.*op item get/s,
    );
    assert.throws(() => parseImport('{"foo":1}', "1password", "op"), /No string fields found/);
  });
});

describe("dotenv", () => {
  test("delegates to the same parser `hush add <file>` uses", () => {
    const { values } = parseImport('API_KEY=sk-1\n# comment\nDB="quoted value"\n', "dotenv", ".env");
    assert.deepEqual(values, { API_KEY: "sk-1", DB: "quoted value" });
  });

  // The shared parser keys a map, so a repeated name is overwritten. Doing that
  // in silence is the exact failure this module exists to prevent: one of the
  // two values never makes it into the vault and nothing says which.
  test("a repeated key keeps the later value and names the collision", () => {
    const { values, notes } = parseImport(
      "API_KEY=first\nOTHER=1\nAPI_KEY=second\n",
      "dotenv",
      ".env",
    );
    assert.deepEqual(values, { API_KEY: "second", OTHER: "1" });
    assert.equal(notes.length, 1);
    assert.match(notes[0], /API_KEY appears more than once in \.env; the later value wins/);
  });

  test("one line per repeated key, and nothing when there is no repetition", () => {
    const clean = parseImport("A=1\nB=2\n", "dotenv", ".env");
    assert.deepEqual(clean.notes, []);
    const messy = parseImport("A=1\nA=2\nA=3\n", "dotenv", ".env");
    assert.equal(messy.values.A, "3");
    assert.equal(messy.notes.length, 2);
  });
});
