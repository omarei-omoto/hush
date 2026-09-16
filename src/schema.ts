/**
 * `.env.schema` — what a variable is allowed to look like.
 *
 * The most common real-world failure is not a leak, it is a wrong value: the
 * test key in the production set, a truncated paste, a key whose prefix the SDK
 * checks before it will talk to the API. Nothing else in hush looks at a value's
 * *shape*; this is the part that does.
 *
 * The syntax is deliberately `@env-spec`'s, the one Varlock reads, so a team
 * that already has a `.env.schema` gets validation here without rewriting it:
 *
 *     # @required @type=url
 *     API_URL=
 *
 *     # @type=string(startsWith=sk-) @required
 *     STRIPE_SECRET_KEY=
 *
 *     # @type=enum(development, preview, production) @sensitive=false
 *     APP_ENV=development
 *
 * The placeholder after `=` is ignored: the vault is where values come from, so
 * hush reads this file for *rules* and never for values. (That is also why
 * `@default` is deliberately not implemented — an injected default would make
 * "the vault is the source of truth" quietly false.)
 *
 * Two rules shape everything here:
 *
 *   - The schema holds no values, so it is safe to commit and safe to show an
 *     agent. That is the whole reason the format exists.
 *   - A failure message names the key, the rule, and the length. Never the
 *     value, never a prefix of it, never a hash of it.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { ValidationError, isValidKeyName } from "./vault.ts";

export type TypeName = "string" | "number" | "boolean" | "url" | "port" | "email" | "enum";

export interface TypeSpec {
  name: TypeName;
  /** `string(startsWith=…)` */
  startsWith?: string;
  minLength?: number;
  maxLength?: number;
  /** `enum(a, b, c)` */
  values?: string[];
}

export interface Rule {
  key: string;
  required: boolean;
  /** `@sensitive=false` takes this key out of the redactor. */
  sensitive: boolean;
  type?: TypeSpec;
  pattern?: RegExp;
}

export interface Problem {
  key: string;
  why: string;
}

const SCHEMA_FILE = ".env.schema";

// --------------------------------------------------------------- parsing

/**
 * One `@name` or `@name=value` at a time.
 *
 * A value is a quoted string, a bare call like `enum(a, b, c)` or
 * `string(minLength=8, maxLength=64)`, or a single space-free token. The
 * call form has to be here because its arguments are comma-and-space
 * separated, and the quoted form exists for the one case that cannot be
 * expressed otherwise: a `@pattern` containing a space or an `@`.
 */
const DIRECTIVE = /@([A-Za-z][A-Za-z0-9_-]*)(?:=(?:"([^"]*)"|'([^']*)'|([^\s@]+\([^)]*\))|([^\s@]+)))?/g;

const TYPE_NAMES: TypeName[] = ["string", "number", "boolean", "url", "port", "email", "enum"];

function parseTypeSpec(raw: string, where: string): TypeSpec {
  const open = raw.indexOf("(");
  const name = (open === -1 ? raw : raw.slice(0, open)).trim() as TypeName;
  if (!TYPE_NAMES.includes(name)) {
    throw new ValidationError(`${where}: unknown @type "${name}". Known: ${TYPE_NAMES.join(", ")}.`);
  }
  const spec: TypeSpec = { name };
  if (open === -1) return spec;

  const inner = raw.slice(open + 1, raw.lastIndexOf(")"));
  if (name === "enum") {
    spec.values = inner
      .split(",")
      .map((s) => s.trim().replace(/^(["'])(.*)\1$/, "$2"))
      .filter(Boolean);
    if (!spec.values.length) throw new ValidationError(`${where}: @type=enum() needs at least one value.`);
    return spec;
  }

  for (const arg of inner.split(",").map((s) => s.trim()).filter(Boolean)) {
    const eq = arg.indexOf("=");
    if (eq === -1) {
      throw new ValidationError(`${where}: @type argument ${JSON.stringify(arg)} needs a value, e.g. startsWith=sk-.`);
    }
    const attr = arg.slice(0, eq).trim();
    const value = arg.slice(eq + 1).trim();
    if (attr === "startsWith") {
      spec.startsWith = value;
    } else if (attr === "minLength" || attr === "maxLength") {
      const n = Number(value);
      if (!Number.isInteger(n) || n < 0) {
        throw new ValidationError(`${where}: ${attr}=${JSON.stringify(value)} is not a whole number of characters.`);
      }
      if (attr === "minLength") spec.minLength = n;
      else spec.maxLength = n;
    } else {
      throw new ValidationError(`${where}: unknown @type argument "${attr}". Known: startsWith, minLength, maxLength.`);
    }
  }
  return spec;
}

/**
 * Parse a `.env.schema` into rules.
 *
 * Directives accumulate on the comment lines above a key and are consumed by
 * it, so a stray directive at the end of the file is reported rather than
 * silently ignored: a rule nobody attaches to is a rule nobody is checking.
 */
export function parseSchema(text: string, where = SCHEMA_FILE): Rule[] {
  const rules: Rule[] = [];
  let pending: Partial<Rule> = {};
  let pendingLine = 0;

  text.split(/\r?\n/).forEach((rawLine, i) => {
    const line = rawLine.trim();
    if (!line) return;

    if (line.startsWith("#")) {
      const body = line.replace(/^#+\s?/, "");
      for (const m of body.matchAll(DIRECTIVE)) {
        const name = m[1];
        const value = m[2] ?? m[3] ?? m[4] ?? m[5];
        const at = `${where} line ${i + 1}`;
        // Directives hush does not enforce (@description, @import, …) are left
        // for the tools that understand them, and do not count as "waiting for
        // a key" — otherwise an @env-spec file ending in a comment block would
        // be rejected as unattached.
        let recognised = true;
        if (name === "required") {
          pending.required = true;
        } else if (name === "sensitive") {
          pending.sensitive = !(value === "false" || value === "0" || value === "no");
        } else if (name === "type") {
          if (!value) throw new ValidationError(`${at}: @type needs a value, e.g. @type=url.`);
          pending.type = parseTypeSpec(value, at);
        } else if (name === "pattern") {
          if (!value) throw new ValidationError(`${at}: @pattern needs a regular expression.`);
          try {
            pending.pattern = new RegExp(value);
          } catch (e) {
            throw new ValidationError(
              `${at}: @pattern=${value} is not a valid regular expression (${(e as Error).message}).`,
            );
          }
        } else {
          recognised = false;
        }
        if (recognised) pendingLine = i + 1;
      }
      return;
    }

    // A real assignment: the key these directives belong to.
    const eq = line.indexOf("=");
    const key = (eq === -1 ? line : line.slice(0, eq)).trim();
    if (eq === -1 || !isValidKeyName(key)) return; // not .env-shaped; not ours
    rules.push({
      key,
      required: pending.required === true,
      sensitive: pending.sensitive !== false,
      ...(pending.type ? { type: pending.type } : {}),
      ...(pending.pattern ? { pattern: pending.pattern } : {}),
    });
    pending = {};
    pendingLine = 0;
  });

  if (pendingLine) {
    throw new ValidationError(
      `${where} line ${pendingLine}: these directives are not attached to any variable. ` +
        `Put them directly above a KEY=.`,
    );
  }
  return rules;
}

// ------------------------------------------------------------- validating

/** Where a rule failed, and why. Never what the value was. */
function check(rule: Rule, value: string): string | null {
  const held = `it is ${value.length} character${value.length === 1 ? "" : "s"}`;

  if (rule.type) {
    const t = rule.type;
    const isInt = /^-?\d+$/.test(value);
    switch (t.name) {
      case "string":
        if (t.startsWith && !value.startsWith(t.startsWith)) {
          return `does not start with ${JSON.stringify(t.startsWith)} (${held})`;
        }
        if (t.minLength !== undefined && value.length < t.minLength) {
          return `is shorter than ${t.minLength} characters (${held})`;
        }
        if (t.maxLength !== undefined && value.length > t.maxLength) {
          return `is longer than ${t.maxLength} characters (${held})`;
        }
        break;
      case "number":
        if (!isInt && !/^-?\d*\.\d+$/.test(value)) return "is not a number";
        break;
      case "boolean":
        if (!["true", "false", "1", "0", "yes", "no"].includes(value.toLowerCase())) {
          return "is not a boolean (true, false, 1, 0, yes, no)";
        }
        break;
      case "url":
        try {
          const u = new URL(value);
          if (u.protocol !== "http:" && u.protocol !== "https:") {
            return `is a ${u.protocol}// URL rather than http(s)`;
          }
        } catch {
          return "is not a URL";
        }
        break;
      case "port": {
        const n = Number(value);
        if (!isInt || !Number.isInteger(n) || n < 1 || n > 65535) {
          return "is not a port (an integer from 1 to 65535)";
        }
        break;
      }
      case "email":
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "is not an email address";
        break;
      case "enum": {
        const allowed = t.values ?? [];
        if (!allowed.includes(value)) {
          return `is not one of ${allowed.map((v) => JSON.stringify(v)).join(", ")}`;
        }
        break;
      }
    }
  }

  if (rule.pattern && !rule.pattern.test(value)) {
    return `does not match /${rule.pattern.source}/ (${held})`;
  }
  return null;
}

/**
 * Check the values hush is about to use against the schema.
 *
 * @param keys Only these are checked. A run should not be blocked by a
 *             violation in a production secret it never touches.
 */
export function validate(secrets: Record<string, string>, rules: Rule[], keys?: string[]): Problem[] {
  const wanted = keys ? new Set(keys) : null;
  const problems: Problem[] = [];
  for (const rule of rules) {
    if (wanted && !wanted.has(rule.key)) continue;
    const value = secrets[rule.key];
    if (value === undefined || value === "") {
      if (rule.required) problems.push({ key: rule.key, why: "is required and has no value in these sets" });
      continue;
    }
    const why = check(rule, value);
    if (why) problems.push({ key: rule.key, why });
  }
  return problems;
}

/** The keys a schema marks as safe to show, so they can be left unmasked. */
export function unsensitive(rules: Rule[]): string[] {
  return rules.filter((r) => !r.sensitive).map((r) => r.key);
}

/**
 * The masking decision belongs to the user, not to the repository.
 *
 * `@sensitive=false` used to be an authority: whatever the project's
 * `.env.schema` said was taken out of the redactor, so a repository (or an
 * agent with ordinary write access to the project) could turn output masking
 * off for a key by writing one line — and hush's whole "the agent can use a
 * value but never read one" claim rests on that mask.
 *
 * So the schema is now a *request*. Only keys the user has named in their own
 * `~/.hush/policy.json` (`unmaskKeys`) are actually left unmasked; everything
 * else the repo asked for is ignored and reported, so a run can say out loud
 * that it is not doing what the project file asked.
 */
export function unsensitiveForOutput(
  rules: Rule[],
  userAllowed: readonly string[],
): { omit: string[]; ignored: string[] } {
  const asked = unsensitive(rules);
  const allowed = new Set(userAllowed);
  return {
    omit: asked.filter((k) => allowed.has(k)),
    ignored: asked.filter((k) => !allowed.has(k)),
  };
}

// --------------------------------------------------------------- loading

export interface Schema {
  path: string;
  rules: Rule[];
}

/** `.env.schema` at the project root, or null when there is none. */
export function loadSchema(root: string): Schema | null {
  const path = join(root, SCHEMA_FILE);
  if (!existsSync(path)) return null;
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return null;
  }
  return { path, rules: parseSchema(text, SCHEMA_FILE) };
}

/** One line per problem, for a human. Names the key and the rule, never a value. */
export function describeProblems(problems: Problem[]): string[] {
  return problems.map((p) => `${p.key} ${p.why}`);
}
