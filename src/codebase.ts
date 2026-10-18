/**
 * What a codebase is, for the app's list of projects: its stack, when it was
 * last worked on, and which credentials its code reads. Names and file
 * metadata only — no value, and nothing from a .env, is ever read.
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { looksLikeSecret, scanTree } from "./scan.ts";

export interface CodebaseDetails {
  /** Languages and frameworks, most specific first ("Next.js", "TypeScript", …). */
  stack: string[];
  /** The checked-out branch, when it is a git repository. */
  branch?: string;
  /** When it was last worked on (ISO): the newest of git's own bookkeeping files. */
  active?: string;
  /** Who its git remote "origin" belongs to ("github.com/omoto"), when it has one: for grouping projects. */
  owner?: string;
  /** Credentials its code reads, by name: variables that look like keys, tokens, passwords. */
  credentials: string[];
  /** Every variable its code reads, by name (capped), so a name you keep as a global key counts too. */
  reads: string[];
  /** A plaintext .env sits in the folder. */
  plaintextEnv: boolean;
  /** The scan stopped at its budget, so the list may be incomplete. */
  partial: boolean;
  /** When these details were worked out (ISO). */
  at: string;
}

/** Files that mark the top of a codebase. */
const MARKERS = ["package.json", "pyproject.toml", "requirements.txt", "go.mod", "Cargo.toml", "Gemfile", "composer.json", "deno.json", "pom.xml", "build.gradle", "mix.exs", "pubspec.yaml", "Package.swift"];

/** Is `dir` the top of a codebase: a git repository, or a folder with a project manifest? */
export function isCodebase(dir: string): boolean {
  return existsSync(join(dir, ".git")) || MARKERS.some((m) => existsSync(join(dir, m)));
}

const readText = (path: string, max = 256 * 1024): string => {
  try {
    if (statSync(path).size > max) return "";
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
};

/** JavaScript frameworks, by the dependency that names them. */
const JS_FRAMEWORKS: [string, string][] = [
  ["next", "Next.js"], ["nuxt", "Nuxt"], ["@remix-run/react", "Remix"], ["astro", "Astro"], ["@sveltejs/kit", "SvelteKit"],
  ["expo", "Expo"], ["react-native", "React Native"], ["electron", "Electron"], ["@nestjs/core", "NestJS"],
  ["express", "Express"], ["fastify", "Fastify"], ["hono", "Hono"], ["vue", "Vue"], ["svelte", "Svelte"], ["react", "React"], ["vite", "Vite"],
];

function stackOf(root: string): string[] {
  const stack: string[] = [];
  const pkg = readText(join(root, "package.json"));
  if (pkg) {
    let deps: Record<string, unknown> = {};
    try {
      const j = JSON.parse(pkg) as { dependencies?: Record<string, unknown>; devDependencies?: Record<string, unknown> };
      deps = { ...(j.dependencies ?? {}), ...(j.devDependencies ?? {}) };
    } catch { /* not JSON: still a JavaScript project */ }
    const framework = JS_FRAMEWORKS.find(([dep]) => Object.hasOwn(deps, dep));
    if (framework) stack.push(framework[1]);
    stack.push(Object.hasOwn(deps, "typescript") || existsSync(join(root, "tsconfig.json")) ? "TypeScript" : "JavaScript");
  }
  const py = readText(join(root, "pyproject.toml")) + readText(join(root, "requirements.txt"));
  if (py || existsSync(join(root, "setup.py"))) {
    const f = /\bdjango\b/i.test(py) ? "Django" : /\bfastapi\b/i.test(py) ? "FastAPI" : /\bflask\b/i.test(py) ? "Flask" : null;
    if (f) stack.push(f);
    stack.push("Python");
  }
  if (existsSync(join(root, "go.mod"))) stack.push("Go");
  if (existsSync(join(root, "Cargo.toml"))) stack.push("Rust");
  if (existsSync(join(root, "Gemfile"))) stack.push(/\brails\b/.test(readText(join(root, "Gemfile"))) ? "Rails" : "Ruby");
  if (existsSync(join(root, "composer.json"))) stack.push("PHP");
  if (existsSync(join(root, "deno.json"))) stack.push("Deno");
  if (existsSync(join(root, "pom.xml")) || existsSync(join(root, "build.gradle"))) stack.push("Java");
  if (existsSync(join(root, "mix.exs"))) stack.push("Elixir");
  if (existsSync(join(root, "pubspec.yaml"))) stack.push("Flutter");
  if (existsSync(join(root, "Package.swift"))) stack.push("Swift");
  return [...new Set(stack)];
}

function gitOf(root: string): { branch?: string; active?: string } {
  const git = join(root, ".git");
  if (!existsSync(git)) return {};
  const head = readText(join(git, "HEAD"), 4096).trim();
  const branch = /^ref: refs\/heads\/(.+)$/.exec(head)?.[1];
  let newest = 0;
  for (const f of ["HEAD", "index", "FETCH_HEAD", join("logs", "HEAD")]) {
    try {
      newest = Math.max(newest, statSync(join(git, f)).mtimeMs);
    } catch { /* not there */ }
  }
  const owner = ownerOf(readText(join(git, "config"), 64 * 1024));
  return { ...(branch ? { branch } : {}), ...(newest ? { active: new Date(newest).toISOString() } : {}), ...(owner ? { owner } : {}) };
}

/**
 * The host and owner of the "origin" remote in a git config, from either URL
 * shape: https://github.com/omoto/web.git or git@github.com:omoto/web.git.
 * Never the credentials an https URL can carry.
 */
export function ownerOf(config: string): string | undefined {
  const section = /\[remote "origin"\]([^[]*)/.exec(config)?.[1] ?? "";
  const url = /^\s*url\s*=\s*(\S+)/m.exec(section)?.[1];
  if (!url) return undefined;
  const m = /^(?:[a-z+]+:\/\/)?(?:[^@/]+@)?([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?::\d+)?[:/]+([A-Za-z0-9_.-]+)\/[^/]+?(?:\.git)?\/?$/.exec(url);
  return m ? `${m[1].toLowerCase()}/${m[2]}` : undefined;
}

/**
 * Describe a codebase. The scan is bounded (by default about a second and a
 * few thousand files) so a crawl over many repositories stays quick; a
 * repository bigger than that is marked partial.
 */
export function describeCodebase(root: string, limits = { maxEntries: 8_000, deadlineMs: 900 }): CodebaseDetails {
  const scan = scanTree(root, limits);
  const reads = [...new Set(scan.usages.map((u) => u.name))].sort().slice(0, 300);
  const credentials = reads.filter(looksLikeSecret);
  return {
    stack: stackOf(root),
    ...gitOf(root),
    credentials,
    reads,
    plaintextEnv: existsSync(join(root, ".env")),
    partial: scan.truncated,
    at: new Date().toISOString(),
  };
}
