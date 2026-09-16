/**
 * `.env.schema` — the only place in hush that looks at a value's *shape*.
 *
 * Two properties are load-bearing and are asserted directly rather than
 * incidentally: a failure never prints a value, and validation can be scoped to
 * the keys actually in play, so a production rule cannot block a dev command.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { parseSchema, validate, unsensitive, describeProblems } from "../src/schema.ts";

/**
 * A credential-shaped value that no scanner can read as a real one.
 *
 * The rule under test here is "starts with sk-", so nothing about this needs to
 * look like a Stripe key — and GitHub's push protection blocks a long base62
 * run after `sk_live_`, which is the correct behaviour for a value that does.
 * The runs either side of the hyphens stay short on purpose.
 */
const VALUE = "sk_live_PLACEHOLDER-not-a-real-key-0123";

describe("parseSchema", () => {
  test("reads the directives above a key", () => {
    const rules = parseSchema(`
# @required @type=url
API_URL=

# @type=string(startsWith=sk-) @required
STRIPE_SECRET_KEY=
`);
    assert.equal(rules.length, 2);
    assert.deepEqual(rules[0], { key: "API_URL", required: true, sensitive: true, type: { name: "url" } });
    assert.equal(rules[1].key, "STRIPE_SECRET_KEY");
    assert.deepEqual(rules[1].type, { name: "string", startsWith: "sk-" });
  });

  test("directives on separate lines accumulate on the same key", () => {
    const rules = parseSchema("# @required\n# @type=port\nPORT=\n");
    assert.deepEqual(rules[0], { key: "PORT", required: true, sensitive: true, type: { name: "port" } });
  });

  test("@sensitive=false is recorded; an absent @sensitive means sensitive", () => {
    const rules = parseSchema("# @sensitive=false\nAPP_ENV=development\n\nPLAIN=\n");
    assert.equal(rules[0].sensitive, false);
    assert.equal(rules[1].sensitive, true);
  });

  test("enum values and length bounds are parsed", () => {
    const [e] = parseSchema("# @type=enum(development, preview, production)\nAPP_ENV=\n");
    assert.deepEqual(e.type, { name: "enum", values: ["development", "preview", "production"] });
    const [s] = parseSchema("# @type=string(minLength=8, maxLength=64)\nK=\n");
    assert.deepEqual(s.type, { name: "string", minLength: 8, maxLength: 64 });
  });

  test("@pattern compiles to a RegExp", () => {
    const [r] = parseSchema("# @pattern=^[A-Za-z0-9_]+$\nK=\n");
    assert.ok(r.pattern instanceof RegExp);
    assert.equal(r.pattern!.test("abc_123"), true);
  });

  test("the placeholder value after = is ignored, not stored", () => {
    const rules = parseSchema("# @required\nNODE_ENV=development\n");
    assert.deepEqual(rules, [{ key: "NODE_ENV", required: true, sensitive: true }]);
  });

  test("directives hush does not enforce are ignored, and do not wait for a key", () => {
    // An @env-spec file may carry things hush has no opinion about, including
    // at the end, without being rejected as malformed.
    const rules = parseSchema("# @type=url\nAPI_URL=\n\n# @description=Some words about things\n");
    assert.equal(rules.length, 1);
  });

  test("a directive attached to nothing is reported rather than silently dropped", () => {
    assert.throws(() => parseSchema("# @required\n"), /not attached to any variable/);
  });

  test("an unknown type is refused, naming the known ones", () => {
    assert.throws(() => parseSchema("# @type=json\nK=\n"), /unknown @type "json"/);
  });

  test("an invalid regular expression is refused, naming the line", () => {
    assert.throws(() => parseSchema("# @pattern=[unclosed\nK=\n"), /line 1.*not a valid regular expression/);
  });

  test("an unknown @type argument is refused", () => {
    assert.throws(() => parseSchema("# @type=string(minimum=3)\nK=\n"), /unknown @type argument "minimum"/);
  });

  test("lines that are not .env-shaped are left alone", () => {
    const rules = parseSchema("just a sentence\n\n# a comment\n# @required\nREAL_KEY=\n");
    assert.deepEqual(rules.map((r) => r.key), ["REAL_KEY"]);
  });
});

describe("validate", () => {
  const rules = parseSchema(`
# @required @type=url
API_URL=

# @type=string(startsWith=sk-)
STRIPE_SECRET_KEY=

# @type=port
PORT=

# @type=enum(development, production)
NODE_ENV=
`);

  test("a missing required key is a problem, by name", () => {
    const problems = validate({ STRIPE_SECRET_KEY: "sk-abc" }, rules, ["API_URL", "STRIPE_SECRET_KEY"]);
    assert.equal(problems.length, 1);
    assert.equal(problems[0].key, "API_URL");
    assert.match(problems[0].why, /is required and has no value/);
  });

  test("an empty string does not satisfy @required", () => {
    const problems = validate({ API_URL: "" }, rules, ["API_URL"]);
    assert.equal(problems.length, 1);
    assert.match(problems[0].why, /required/);
  });

  test("each type passes and fails as documented", () => {
    const ok = validate(
      { API_URL: "https://x.test/v1", STRIPE_SECRET_KEY: "sk-live", PORT: "3000", NODE_ENV: "production" },
      rules,
    );
    assert.deepEqual(ok, []);

    assert.match(validate({ API_URL: "not a url" }, rules, ["API_URL"])[0].why, /not a URL/);
    assert.match(validate({ API_URL: "ftp://x.test" }, rules, ["API_URL"])[0].why, /rather than http\(s\)/);
    assert.match(
      validate({ STRIPE_SECRET_KEY: "pk-live" }, rules, ["STRIPE_SECRET_KEY"])[0].why,
      /does not start with "sk-"/,
    );
    assert.match(validate({ PORT: "70000" }, rules, ["PORT"])[0].why, /not a port/);
    assert.match(validate({ PORT: "abc" }, rules, ["PORT"])[0].why, /not a port/);
    assert.match(validate({ NODE_ENV: "staging" }, rules, ["NODE_ENV"])[0].why, /not one of/);
  });

  test("boolean, number and email accept and reject the obvious things", () => {
    const r = parseSchema("# @type=boolean\nB=\n# @type=number\nN=\n# @type=email\nE=\n");
    assert.deepEqual(validate({ B: "yes", N: "-12.5", E: "a@b.co" }, r), []);
    assert.match(validate({ B: "maybe" }, r, ["B"])[0].why, /not a boolean/);
    assert.match(validate({ N: "1e6" }, r, ["N"])[0].why, /not a number/);
    assert.match(validate({ E: "nope" }, r, ["E"])[0].why, /not an email/);
  });

  test("only the keys in play are checked", () => {
    // The point: a broken production secret must not block a dev command that
    // never touches it.
    const problems = validate({ API_URL: "nonsense", STRIPE_SECRET_KEY: "sk-ok" }, rules, ["STRIPE_SECRET_KEY"]);
    assert.deepEqual(problems, []);
  });

  test("with no key filter, everything the schema declares is checked", () => {
    const problems = validate({}, rules);
    assert.equal(problems.length, 1, "the required key should be the only finding");
    assert.equal(problems[0].key, "API_URL");
  });

  test("a failure message never contains the value", () => {
    const problems = validate({ STRIPE_SECRET_KEY: VALUE }, rules, ["STRIPE_SECRET_KEY"]);
    assert.equal(problems.length, 1);
    const line = describeProblems(problems)[0];
    assert.doesNotMatch(line, new RegExp(VALUE.slice(0, 12)));
    // It does say how long it was, which is how you spot a truncated paste.
    assert.match(line, new RegExp(`${VALUE.length} characters`));
  });
});

describe("unsensitive", () => {
  test("returns exactly the keys marked @sensitive=false", () => {
    const rules = parseSchema("# @sensitive=false\nAPP_ENV=\n\nSECRET=\n\n# @sensitive=false\nLOG_LEVEL=\n");
    assert.deepEqual(unsensitive(rules), ["APP_ENV", "LOG_LEVEL"]);
  });
});
