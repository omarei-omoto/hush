/**
 * Getting secrets in, from wherever they already are.
 *
 * `hush add .env` was the only door in, which makes "I have sixty secrets in
 * 1Password" a reason not to try hush at all.
 *
 * This reads *shapes*, not APIs. Every provider worth importing from can
 * already export, so hush reads the export rather than learning fifteen vendor
 * APIs, holding fifteen tokens, and taking fifteen dependencies:
 *
 *     doppler secrets download --format json --no-file | hush import - --as Prod
 *     aws secretsmanager get-secret-value --secret-id x --query SecretString \
 *       --output text | hush import - --as Prod
 *     op item get "Stripe" --format json | hush import - --format 1password --as Work
 *
 * The recipes are the documentation, and none of them is a hush feature that
 * can rot when a vendor changes an endpoint.
 */
import { parseEnvFile } from "./scan.ts";
import { ValidationError, isValidKeyName } from "./vault.ts";

export type ImportFormat = "dotenv" | "json" | "1password";

export const IMPORT_FORMATS: ImportFormat[] = ["dotenv", "json", "1password"];

export interface Imported {
  values: Record<string, string>;
  /** Worth saying out loud: fields skipped, names collided, shapes ignored. */
  notes: string[];
}

/**
 * A label from another tool, turned into a variable name.
 *
 * `Client Secret` has to become `CLIENT_SECRET`; a name that cannot be
 * salvaged (empty, or leading with something that is not a letter) returns null
 * so the caller can report the field instead of writing something unusable.
 */
export function normalizeKey(raw: string): string | null {
  const cleaned = raw
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9_]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "");
  if (!cleaned) return null;
  // A leading digit is not a valid identifier; a leading underscore is the
  // least surprising repair, and keeps the label recognisable in `hush ls`.
  const name = /^[0-9]/.test(cleaned) ? `_${cleaned}` : cleaned;
  return isValidKeyName(name) ? name : null;
}

/** Add a value, noting a collision rather than silently losing one. */
function put(out: Imported, key: string, value: string, where: string): void {
  if (key in out.values) out.notes.push(`${key} appears more than once in ${where}; the later value wins`);
  out.values[key] = value;
}

/** Strings, numbers and booleans become values; anything nested is reported. */
function fromJson(text: string, where: string): Imported {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch (e) {
    throw new ValidationError(`${where} is not valid JSON (${(e as Error).message}).`);
  }

  // AWS Secrets Manager hands back `{"SecretString": "{\"A\":\"1\"}"}`, and the
  // interesting object is one level in. Unwrapping it is the difference between
  // the documented recipe working and needing a second tool.
  if (data && typeof data === "object" && !Array.isArray(data)) {
    const obj = data as Record<string, unknown>;
    const wrapped = ["SecretString", "secret", "Secret"].filter((k) => typeof obj[k] === "string");
    if (Object.keys(obj).length === 1 && wrapped.length === 1) {
      const inner = obj[wrapped[0]] as string;
      if (inner.trim().startsWith("{")) return fromJson(inner, where);
    }
  }

  if (Array.isArray(data)) {
    throw new ValidationError(
      `${where} is a JSON array. hush import expects an object of name to value; ` +
        `if this is a 1Password export, pass --format 1password.`,
    );
  }
  if (!data || typeof data !== "object") {
    throw new ValidationError(`${where} is JSON but not an object of name to value.`);
  }

  const out: Imported = { values: {}, notes: [] };
  for (const [rawKey, rawValue] of Object.entries(data as Record<string, unknown>)) {
    const key = normalizeKey(rawKey);
    if (!key) {
      out.notes.push(`skipped ${JSON.stringify(rawKey)}: not usable as a variable name`);
      continue;
    }
    if (typeof rawValue === "string") {
      put(out, key, rawValue, where);
    } else if (typeof rawValue === "number" || typeof rawValue === "boolean") {
      put(out, key, String(rawValue), where);
    } else {
      // Deliberately not stringified: a nested object is usually a vendor's
      // metadata, and pasting JSON into a variable surprises nobody in a good way.
      out.notes.push(`skipped ${key}: its value is ${rawValue === null ? "null" : typeof rawValue}, not a string`);
    }
  }
  return out;
}

/**
 * `op item get --format json`, one item or a list of them.
 *
 * The shape is nested and vendor-defined, so this reads the one part that is
 * stable: `fields`, each with a `label` (falling back to `id`) and a string
 * `value`. Everything else is skipped and counted.
 */
function from1Password(text: string, where: string): Imported {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch (e) {
    throw new ValidationError(`${where} is not valid JSON (${(e as Error).message}).`);
  }
  const items = Array.isArray(data) ? data : [data];
  const out: Imported = { values: {}, notes: [] };

  let fields = 0;
  let skippedFields = 0;
  for (const item of items) {
    const record = (item ?? {}) as { title?: unknown; fields?: unknown };
    if (!Array.isArray(record.fields)) {
      out.notes.push(`skipped an item with no fields array${typeof record.title === "string" ? ` (${record.title})` : ""}`);
      continue;
    }
    for (const field of record.fields as unknown[]) {
      const f = (field ?? {}) as { label?: unknown; id?: unknown; value?: unknown };
      const label =
        typeof f.label === "string" && f.label ? f.label : typeof f.id === "string" && f.id ? f.id : null;
      if (!label) {
        skippedFields++;
        continue;
      }
      // Only string values: an OTP field's value is an object, and a file
      // field's is metadata rather than the file.
      if (typeof f.value !== "string" || f.value === "") {
        skippedFields++;
        continue;
      }
      const key = normalizeKey(label);
      if (!key) {
        out.notes.push(`skipped field ${JSON.stringify(label)}: not usable as a variable name`);
        continue;
      }
      put(out, key, f.value, where);
      fields++;
    }
  }
  if (!fields) {
    throw new ValidationError(
      `No string fields found in ${where}. Is this the output of \`op item get <item> --format json\`?`,
    );
  }
  if (skippedFields) out.notes.push(`skipped ${skippedFields} field(s) with no usable string value`);
  return out;
}

export function parseImport(text: string, format: ImportFormat, where: string): Imported {
  if (!text.trim()) throw new ValidationError(`${where} is empty.`);
  switch (format) {
    case "dotenv":
      // The same parser `hush add <file>` uses, so the two cannot disagree
      // about what a .env file means.
      {
        const notes: string[] = [];
        const values = parseEnvFile(text, (name) =>
          notes.push(`${name} appears more than once in ${where}; the later value wins`),
        );
        return { values, notes };
      }
    case "json":
      return fromJson(text, where);
    case "1password":
      return from1Password(text, where);
  }
}
