/**
 * Work out which environment variables a codebase actually needs.
 *
 * This is what makes `hush` able to provision a repo without anyone writing a
 * manifest: read the source, read the example files, take the union.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, extname } from "node:path";

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "out", ".next", ".nuxt", ".svelte-kit",
  "vendor", "target", "__pycache__", ".venv", "venv", "coverage", ".turbo",
  ".cache", "tmp", ".hush", "Pods", ".gradle",
]);

const SCAN_EXT = new Set([
  ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
  ".py", ".rb", ".go", ".rs", ".java", ".kt", ".php", ".cs", ".ex", ".exs",
  ".sh", ".bash", ".zsh", ".yml", ".yaml", ".toml",
]);

const EXAMPLE_FILES = [
  ".env.example", ".env.sample", ".env.template", ".env.schema", ".env.defaults", ".env.dist",
];

const MAX_FILE_BYTES = 512 * 1024;

/** Matchers across the languages people actually put secrets in. */
const PATTERNS: RegExp[] = [
  /process\.env\.([A-Z_][A-Z0-9_]{2,})/g,                       // JS/TS
  /process\.env\[\s*["'`]([A-Z_][A-Z0-9_]{2,})["'`]\s*\]/g,
  /import\.meta\.env\.([A-Z_][A-Z0-9_]{2,})/g,                  // Vite
  /Deno\.env\.get\(\s*["'`]([A-Z_][A-Z0-9_]{2,})["'`]/g,
  /Bun\.env\.([A-Z_][A-Z0-9_]{2,})/g,
  /os\.environ(?:\.get)?[\[(]\s*["']([A-Z_][A-Z0-9_]{2,})["']/g, // Python
  /os\.getenv\(\s*["']([A-Z_][A-Z0-9_]{2,})["']/g,
  /ENV\[\s*["']([A-Z_][A-Z0-9_]{2,})["']\s*\]/g,                 // Ruby
  /os\.Getenv\(\s*"([A-Z_][A-Z0-9_]{2,})"/g,                     // Go
  /std::env::var(?:_os)?\(\s*"([A-Z_][A-Z0-9_]{2,})"/g,          // Rust
  /System\.getenv\(\s*"([A-Z_][A-Z0-9_]{2,})"/g,                 // Java/Kotlin
  /Environment\.GetEnvironmentVariable\(\s*"([A-Z_][A-Z0-9_]{2,})"/g, // C#
  /getenv\(\s*["']([A-Z_][A-Z0-9_]{2,})["']/g,                   // PHP/C
  /\$\{?([A-Z_][A-Z0-9_]{2,})\}?/g,                              // shell / compose (noisy, filtered below)
];

/** Shell-ish `$VAR` matches sweep up a lot of noise; only trust them in env-ish files. */
const SHELL_PATTERN_INDEX = PATTERNS.length - 1;

/** Names that show up everywhere and are supplied by the OS, not by you. */
const AMBIENT = new Set([
  "PATH", "HOME", "USER", "SHELL", "PWD", "OLDPWD", "LANG", "LC_ALL", "TERM",
  "TMPDIR", "TZ", "EDITOR", "HOSTNAME", "CI", "NODE_ENV", "PYTHONPATH",
  "GOPATH", "GOROOT", "JAVA_HOME", "RUST_LOG", "DEBUG", "PORT", "HOST",
  "LOGNAME", "SHLVL", "IFS", "PS1", "RANDOM", "UID", "EUID", "BASH_VERSION",
]);

export interface Usage {
  name: string;
  /** Repo-relative locations, capped for readability. */
  sites: string[];
  /** True when it came from a .env.example-style file rather than source. */
  declared: boolean;
}

function walk(dir: string, root: string, out: string[], depth = 0): void {
  if (depth > 12) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (e.name.startsWith(".") && !e.name.startsWith(".env")) {
      if (e.name !== ".github") continue;
    }
    if (SKIP_DIRS.has(e.name)) continue;
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      walk(full, root, out, depth + 1);
    } else if (e.isFile()) {
      if (SCAN_EXT.has(extname(e.name)) || e.name.startsWith(".env") || e.name === "Dockerfile") {
        try {
          if (statSync(full).size <= MAX_FILE_BYTES) out.push(full);
        } catch {
          /* unreadable, skip */
        }
      }
    }
  }
}

/**
 * Parse a `.env`-shaped file into name -> value. Values are ignored by scan().
 *
 * A repeated key used to be dropped in silence, with the later value quietly
 * winning. Callers that care (imports, `hush add`) pass `onDuplicate` so the
 * person sees which line was discarded.
 */
export function parseEnvFile(
  text: string,
  onDuplicate?: (name: string) => void,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq < 1) continue;
    const name = line.slice(0, eq).replace(/^export\s+/, "").trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) continue;
    let value = line.slice(eq + 1).trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      // Double quotes carry escapes, the way dotenv defines them. Anything
      // written by toEnvFile() must come back byte-identical.
      value = value.slice(1, -1).replace(/\\(.)/g, (_, ch: string) =>
        ch === "n" ? "\n" : ch === "r" ? "\r" : ch === "t" ? "\t" : ch,
      );
    } else if (value.length >= 2 && value.startsWith("'") && value.endsWith("'")) {
      value = value.slice(1, -1); // single quotes are literal
    }
    if (name in out) onDuplicate?.(name);
    out[name] = value;
  }
  return out;
}

export function scanRepo(root: string): Usage[] {
  const files: string[] = [];
  walk(root, root, files);

  const found = new Map<string, Usage>();
  const note = (name: string, site: string, declared: boolean) => {
    if (AMBIENT.has(name)) return;
    const existing = found.get(name);
    if (existing) {
      if (existing.sites.length < 5 && !existing.sites.includes(site)) existing.sites.push(site);
      existing.declared ||= declared;
    } else {
      found.set(name, { name, sites: [site], declared });
    }
  };

  for (const file of files) {
    const rel = file.startsWith(root) ? file.slice(root.length + 1) : file;
    const base = rel.split("/").pop()!;
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }

    if (EXAMPLE_FILES.includes(base)) {
      for (const name of Object.keys(parseEnvFile(text))) note(name, rel, true);
      continue;
    }

    const envish = base.startsWith(".env") || base === "Dockerfile" ||
      /docker-compose|\.ya?ml$|\.sh$|\.bash$/.test(base);

    PATTERNS.forEach((pattern, i) => {
      if (i === SHELL_PATTERN_INDEX && !envish) return;
      pattern.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = pattern.exec(text))) note(m[1], rel, false);
    });
  }

  return [...found.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export interface Reconciliation {
  needed: Usage[];
  satisfied: string[];
  missing: Usage[];
  /** In the vault but not referenced anywhere — candidates for cleanup. */
  unused: string[];
}

export function reconcile(usages: Usage[], vaultKeys: string[]): Reconciliation {
  const have = new Set(vaultKeys);
  const satisfied: string[] = [];
  const missing: Usage[] = [];
  for (const u of usages) {
    if (have.has(u.name)) satisfied.push(u.name);
    else missing.push(u);
  }
  const referenced = new Set(usages.map((u) => u.name));
  const unused = vaultKeys.filter((k) => !referenced.has(k));
  return { needed: usages, satisfied, missing, unused };
}
