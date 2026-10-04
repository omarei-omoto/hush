/**
 * Argument parsing for every hush command.
 */

// --------------------------------------------------------------- arg parsing

export interface Args {
  _: string[];
  /** Everything after a bare `--`. */
  rest: string[];
  /** A repeated flag (`--with a --with b`) collects into an array. */
  flags: Record<string, string | boolean | string[]>;
}

export function parseArgs(argv: string[]): Args {
  const _: string[] = [];
  // No prototype: a flag is whatever was typed after "--", and `--__proto__`
  // must be a flag like any other rather than a way to reach Object.prototype.
  const flags: Record<string, string | boolean | string[]> = Object.create(null);
  let rest: string[] = [];

  const put = (name: string, value: string | boolean) => {
    const prev = flags[name];
    if (prev === undefined) flags[name] = value;
    else if (Array.isArray(prev)) prev.push(String(value));
    else flags[name] = [String(prev), String(value)];
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") {
      rest = argv.slice(i + 1);
      break;
    }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq !== -1) {
        put(a.slice(2, eq), a.slice(eq + 1));
      } else {
        const name = a.slice(2);
        const next = argv[i + 1];
        if (next && !next.startsWith("-")) {
          put(name, next);
          i++;
        } else {
          put(name, true);
        }
      }
    } else if (a.startsWith("-") && a.length > 1) {
      put(a.slice(1), true);
    } else {
      _.push(a);
    }
  }
  return { _, rest, flags };
}

export const str = (a: Args, name: string, fallback?: string): string | undefined => {
  const v = a.flags[name];
  if (Array.isArray(v)) return v[v.length - 1];
  return typeof v === "string" ? v : fallback;
};

/** A repeatable flag. Also accepts one comma-separated value. */
export const list = (a: Args, name: string): string[] => {
  const v = a.flags[name];
  const raw = Array.isArray(v) ? v : typeof v === "string" ? [v] : [];
  return raw.flatMap((x) => x.split(",")).map((x) => x.trim()).filter(Boolean);
};
/**
 * A repeatable flag whose values must not be split on commas: file paths, and
 * `KEY=value` pairs that may legitimately contain one. `list()` is the right
 * helper for set names and the wrong one for anything path-shaped.
 */
export const repeat = (a: Args, name: string): string[] => {
  const v = a.flags[name];
  return (Array.isArray(v) ? v : typeof v === "string" ? [v] : []).map((x) => x.trim()).filter(Boolean);
};
export const bool = (a: Args, name: string): boolean => a.flags[name] === true || a.flags[name] === "true";
