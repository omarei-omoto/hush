/**
 * The places a key can be sent: each host's own CLI, driven so the value
 * never touches a command line.
 *
 * Every entry here was checked against the CLI itself — its source, and its
 * help as installed or as published — on 2026-10-14, and says where (`checked`).
 * What each one gets wrong if fed carelessly is written down as a rule
 * (`refuses`), and the rules are what make a push exact rather than probably
 * right:
 *
 *   - The value only ever goes to the CLI's standard input. The command line
 *     holds the key's name and where it goes, nothing else; push.ts checks
 *     that before it starts anything.
 *   - A CLI that would change the value on its way in — trimming whitespace,
 *     reading it line by line, a size limit — is not given one it would
 *     change. The value is refused instead, and the reason says why, so what
 *     arrives is always exactly what you keep.
 *   - The installed CLI must prove it is the one these rules describe: its
 *     help must say the things this entry relies on (`proof.mustSay`), and
 *     where behaviour cannot be seen in the help, its version must be at least
 *     the first one checked to behave this way (`proof.minVersion`). Anything
 *     else is refused, with the update to make.
 *
 * Hosts whose CLIs take a secret only as an argument (Netlify, Render,
 * Heroku, Expo EAS, Deno Deploy, …) are deliberately absent: an argument is
 * on the command line, in the process list and in an agent's transcript.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export interface HostOptions {
  /** The name it gets there: the key's own name unless given. */
  name: string;
  /** Which app, Worker, project, repository or store — when the host needs one. */
  target?: string;
  /** Which environment, stage or deployment — when the host has them. */
  env?: string;
  /** Deploy as part of setting it, where the host makes that optional. */
  deploy?: boolean;
}

export interface Host {
  id: string;
  /** "Cloudflare Workers". */
  label: string;
  /** The program, by name. */
  bin: string;
  /** Other names the same program is installed under. */
  alt?: string[];
  /** Also looked for in the project's node_modules/.bin, where a project usually pins it. */
  local?: boolean;
  /** What the installed CLI has to show before it is trusted with a value. */
  proof: {
    /** Arguments that print the help for the command used. */
    help: string[];
    /** Text the help must contain, compared with all whitespace collapsed. */
    mustSay: string[];
    /** The earliest version checked to behave as described, for what help cannot show. */
    minVersion?: { args: string[]; min: string };
  };
  /** The thing it goes into, when there is one. */
  target?: {
    /** "Worker", "app", "repository". */
    noun: string;
    required: boolean;
    /** Read from the project's own files, when they say. */
    detect?: (root: string) => string | null;
  };
  env?: {
    /** "environment", "stage", "deployment". */
    noun: string;
    choices?: string[];
    default?: string;
    required?: boolean;
  };
  /**
   * For a host with separate create and update commands: a command that exits
   * 0 when the key is there already. Its output is never shown — on some hosts
   * it holds the current value.
   */
  exists?: (o: HostOptions) => string[];
  /** The command line: never the value. `exists` says which of create and update. */
  argv: (o: HostOptions & { exists?: boolean }) => string[];
  /** What goes to standard input. */
  stdin: (value: string, o: HostOptions) => string;
  /** Why this value or name cannot be sent here exactly, or null when it can. */
  refuses: (value: string, o: HostOptions) => string | null;
  /** Does setting it deploy: always, never, or when asked (`deploy`). */
  deploys: "always" | "never" | "optional";
  /** One line on what happens next, shown after a push. */
  after: string;
  /** Where each fact above was checked. */
  checked: string[];
}

// ------------------------------------------------------------------ rules

const bytes = (s: string): number => Buffer.byteLength(s, "utf8");

/**
 * The rule every host shares: a value with whitespace at either end, or a
 * carriage return anywhere, is refused. Every CLI below that reads stdin
 * trims or splits somewhere — Wrangler trims trailing whitespace, gh and
 * Encore trailing CR/LF, Fly and glab both ends, Convex one newline, Doppler
 * and Koyeb read line by line — so such a value would arrive changed.
 */
function edges(value: string): string | null {
  if (!value) return "it is empty";
  if (/^\s|\s$/.test(value)) return "it starts or ends with whitespace (a space or a newline), which this host's CLI strips — remove it in hush (Replace value) if it is not meant to be there";
  if (value.includes("\r")) return "it contains a carriage return, which this host's CLI does not keep";
  return null;
}

/** For the few that take every byte as it is: only emptiness, and a size limit. */
function nonEmpty(value: string): string | null {
  return value ? null : "it is empty";
}

const atMost = (limit: number, why: string) => (value: string): string | null =>
  bytes(value) > limit ? `it is ${bytes(value)} bytes, and ${why} takes at most ${limit}` : null;

const first = (...rules: (string | null)[]): string | null => rules.find((r) => r !== null) ?? null;

// ---------------------------------------------------------- project files

const read = (path: string): string | null => {
  try {
    return existsSync(path) ? readFileSync(path, "utf8") : null;
  } catch {
    return null;
  }
};

/** A JSON file, with // and /* comments allowed (wrangler.jsonc). Never a code path: only JSON.parse. */
function jsonc(text: string): unknown {
  let out = "";
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      out += c;
      if (c === "\\") out += text[++i] ?? "";
      else if (c === '"') inString = false;
    } else if (c === '"') {
      inString = true;
      out += c;
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (c === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i++;
    } else out += c;
  }
  // Trailing commas, which wrangler.jsonc allows.
  return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
}

/** A top-level `key = "value"` from a TOML file: the one shape these files use for a name. */
function tomlTop(text: string, key: string): string | null {
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*\[/.test(line)) return null; // a table starts: no longer top level
    const m = new RegExp(`^\\s*${key}\\s*=\\s*(?:"([^"]*)"|'([^']*)')\\s*(?:#.*)?$`).exec(line);
    if (m) return (m[1] ?? m[2]) || null;
  }
  return null;
}

/** The Worker (or Pages project, with `pages`) a Wrangler config names. */
function wranglerName(root: string, pages: boolean): string | null {
  for (const f of ["wrangler.jsonc", "wrangler.json"]) {
    const t = read(join(root, f));
    if (t === null) continue;
    try {
      const j = jsonc(t) as { name?: unknown; pages_build_output_dir?: unknown };
      if (pages !== (typeof j.pages_build_output_dir === "string")) return null;
      return typeof j.name === "string" && j.name ? j.name : null;
    } catch {
      return null;
    }
  }
  const t = read(join(root, "wrangler.toml"));
  if (t === null) return null;
  if (pages !== (tomlTop(t, "pages_build_output_dir") !== null)) return null;
  return tomlTop(t, "name");
}

const NAME_IN_FLY_TOML = (root: string): string | null => {
  const t = read(join(root, "fly.toml"));
  return t === null ? null : tomlTop(t, "app");
};

/** .firebaserc's default project. */
function firebaseProject(root: string): string | null {
  const t = read(join(root, ".firebaserc"));
  if (t === null) return null;
  try {
    const p = (JSON.parse(t) as { projects?: { default?: unknown } }).projects?.default;
    return typeof p === "string" && p ? p : null;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ hosts

const opt = (flag: string, value: string | undefined): string[] => (value ? [flag, value] : []);

export const HOSTS: Host[] = [
  {
    id: "cloudflare",
    label: "Cloudflare Workers",
    bin: "wrangler",
    local: true,
    proof: {
      help: ["secret", "put", "--help"],
      mustSay: ["wrangler secret put", "--name"],
      // The help never mentions stdin. wrangler 3.0.0's bundle (wrangler-dist/cli.js)
      // already reads it when stdin is not a terminal; checked in the published tarball.
      minVersion: { args: ["--version"], min: "3.0.0" },
    },
    target: { noun: "Worker", required: true, detect: (root) => wranglerName(root, false) },
    env: { noun: "Wrangler environment" },
    argv: (o) => ["secret", "put", o.name, "--name", o.target!, ...opt("--env", o.env)],
    stdin: (value) => value,
    // trimTrailingWhitespace() is str.trimEnd() (packages/wrangler/src/utils/std.ts).
    refuses: (value) => edges(value),
    deploys: "always",
    after: "Setting it deploys a new version of the Worker.",
    checked: [
      "help: wrangler 4.151.0 `secret put --help`",
      "https://github.com/cloudflare/workers-sdk/blob/main/packages/wrangler/src/secret/index.ts (isTTY ? prompt : readFromStdin, then trimTrailingWhitespace)",
      "https://registry.npmjs.org/wrangler/-/wrangler-3.0.0.tgz (the same read in 3.0.0)",
    ],
  },
  {
    id: "cloudflare-pages",
    label: "Cloudflare Pages",
    bin: "wrangler",
    local: true,
    proof: {
      help: ["pages", "secret", "put", "--help"],
      mustSay: ["wrangler pages secret put", "--project-name"],
      // The first release with `pages secret put`, found by searching the published
      // tarballs; it reads stdin the same way as `secret put`.
      minVersion: { args: ["--version"], min: "3.49.0" },
    },
    target: { noun: "Pages project", required: true, detect: (root) => wranglerName(root, true) },
    argv: (o) => ["pages", "secret", "put", o.name, "--project-name", o.target!],
    stdin: (value) => value,
    refuses: (value) => edges(value),
    deploys: "never",
    after: "It applies from the Pages project's next deployment.",
    checked: [
      "help: wrangler 4.151.0 `pages secret put --help`",
      "https://github.com/cloudflare/workers-sdk/blob/main/packages/wrangler/src/pages/secret/index.ts",
      "https://registry.npmjs.org/wrangler/-/wrangler-3.49.0.tgz (first release with the command)",
    ],
  },
  {
    id: "vercel",
    label: "Vercel",
    bin: "vercel",
    local: true,
    proof: {
      help: ["env", "add", "--help"],
      // 59.16.0: "--value … otherwise use stdin or the prompt".
      mustSay: ["--force", "--sensitive", "stdin"],
    },
    target: { noun: "project", required: false },
    env: { noun: "environment", choices: ["production", "preview", "development"], default: "production", required: true },
    argv: (o) => [
      "env", "add", o.name, o.env!, "--force",
      // Vercel keeps Development values readable; Sensitive is for Production and Preview.
      ...(o.env === "development" ? [] : ["--sensitive"]),
      ...opt("--project", o.target),
    ],
    stdin: (value) => value,
    refuses: (value) =>
      first(
        edges(value),
        // readStandardInput() keeps only the first chunk that arrives
        // (stdin.once("data")); under 8 KiB it is all in the pipe at once.
        atMost(8192, "Vercel's CLI, which reads only the first chunk of its input,")(value),
      ),
    deploys: "never",
    after: "It applies from the next deployment: redeploy for it to take effect.",
    checked: [
      "help: vercel 59.16.0 `env add --help`",
      "https://github.com/vercel/vercel/blob/main/packages/cli/src/util/input/read-standard-input.ts (first data chunk only)",
      "https://github.com/vercel/vercel/blob/main/packages/cli/src/util/env/validate-env.ts (normalizeStdinEnvValue strips one trailing newline)",
    ],
  },
  {
    id: "convex",
    label: "Convex",
    bin: "convex",
    local: true,
    proof: {
      help: ["env", "set", "--help"],
      mustSay: ["pipe it in via stdin", "--prod"],
      // Setting a value from stdin arrived in 1.27.0.
      minVersion: { args: ["--version"], min: "1.27.0" },
    },
    target: { noun: "deployment", required: false },
    env: { noun: "deployment", choices: ["dev", "prod"], default: "dev" },
    argv: (o) => ["env", "set", o.name, ...(o.target ? ["--deployment", o.target] : o.env === "prod" ? ["--prod"] : [])],
    stdin: (value) => value,
    // readFromStdin() drops one trailing "\n" (npm-packages/convex/src/cli/lib/utils/stdin.ts).
    refuses: (value) => edges(value),
    deploys: "never",
    after: "Convex functions see it right away.",
    checked: [
      "help: convex 1.46.0 `env set --help`",
      "https://github.com/get-convex/convex-backend/blob/main/npm-packages/convex/src/cli/lib/utils/stdin.ts",
      "https://ship.convex.dev/changelog/convex-1-27 (stdin added)",
    ],
  },
  {
    id: "fly",
    label: "Fly.io",
    bin: "fly",
    alt: ["flyctl"],
    proof: {
      help: ["secrets", "import", "--help"],
      mustSay: ["read from stdin as NAME=VALUE pairs", "--stage"],
    },
    target: { noun: "app", required: true, detect: NAME_IN_FLY_TOML },
    argv: (o) => ["secrets", "import", "--app", o.target!, ...(o.deploy ? [] : ["--stage"])],
    // One NAME=VALUE line. The value is written as it is, never quoted:
    // parseSecrets (internal/command/secrets/parser.go) strips a pair of
    // surrounding quotes, starts a multi-line value at """, and cuts at a "#"
    // outside quotes — so a value that could set any of those off is refused.
    stdin: (value, o) => `${o.name}=${value}\n`,
    refuses: (value, o) =>
      first(
        edges(value),
        value.includes("\n") ? "it spans several lines, which Fly's import reads one line at a time" : null,
        value.includes("#") ? "it contains #, which Fly's import can read as the start of a comment" : null,
        /^["']/.test(value) ? "it starts with a quote, which Fly's import strips" : null,
        atMost(60_000 - o.name.length, "one line of Fly's import")(value),
      ),
    deploys: "optional",
    after: "Staged: Machines get it when they next start or deploy, unless you deploy now.",
    checked: [
      "help: fly v0.4.112 `secrets import --help`",
      "https://github.com/superfly/flyctl/blob/master/internal/command/secrets/parser.go",
    ],
  },
  {
    id: "railway",
    label: "Railway",
    bin: "railway",
    proof: {
      // Railway 4.16.1 has neither `variable set` nor --stdin: it is refused, with the update to make.
      help: ["variable", "set", "--help"],
      mustSay: ["--stdin", "--skip-deploys"],
    },
    target: { noun: "service", required: false },
    env: { noun: "environment" },
    argv: (o) => [
      "variable", "set", o.name, "--stdin",
      ...opt("--service", o.target),
      ...opt("--environment", o.env),
      ...(o.deploy ? [] : ["--skip-deploys"]),
    ],
    stdin: (value) => value,
    // read_value_from_stdin trims trailing \n, then trailing \r (src/commands/variable.rs).
    refuses: (value) => edges(value),
    deploys: "optional",
    after: "The service gets it on its next deploy, unless you deploy now.",
    checked: [
      "https://github.com/railwayapp/cli/blob/master/src/commands/variable.rs (variable set KEY --stdin; read_value_from_stdin)",
      "help: railway 4.16.1 lacks `variable set` (checked, refused by the proof)",
    ],
  },
  {
    id: "firebase",
    label: "Firebase Functions",
    bin: "firebase",
    local: true,
    proof: {
      help: ["functions:secrets:set", "--help"],
      mustSay: ['Set to "-" to read the secret data from stdin'],
    },
    target: { noun: "project", required: false, detect: firebaseProject },
    argv: (o) => ["functions:secrets:set", o.name, "--data-file", "-", "--non-interactive", ...opt("--project", o.target)],
    stdin: (value) => value,
    refuses: (value, o) =>
      first(
        nonEmpty(value),
        // ensureValidKey() renames anything else to UPPER_SNAKE_CASE without
        // asking when non-interactive (src/functions/secrets.ts): the secret
        // would arrive under a name you did not choose.
        /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/.test(o.name) ? null : `Firebase would rename ${o.name}: secret names there are UPPER_SNAKE_CASE`,
        atMost(65_536, "Secret Manager")(value),
      ),
    deploys: "never",
    after: "Functions that use it pick up the new version on their next deploy (firebase deploy --only functions).",
    checked: [
      "help: firebase-tools 15.33.0 `functions:secrets:set --help`",
      "https://github.com/firebase/firebase-tools/blob/main/src/utils.ts (readSecretValue: readFileSync(0, \"utf-8\"), exact)",
      "https://github.com/firebase/firebase-tools/blob/main/src/commands/functions-secrets-set.ts (non-interactive: no redeploy)",
    ],
  },
  {
    id: "github",
    label: "GitHub Actions",
    bin: "gh",
    proof: {
      help: ["secret", "set", "--help"],
      mustSay: ["reads from standard input if not specified"],
    },
    target: { noun: "repository (OWNER/REPO)", required: false },
    env: { noun: "GitHub environment" },
    argv: (o) => ["secret", "set", o.name, ...opt("--repo", o.target), ...opt("--env", o.env)],
    stdin: (value) => value,
    // bytes.TrimRight(body, "\r\n") (pkg/cmd/secret/set/set.go).
    refuses: (value, o) =>
      first(
        edges(value),
        /^GITHUB_/i.test(o.name) ? "GitHub does not allow secret names that start with GITHUB_" : null,
        atMost(48 * 1024, "a GitHub secret")(value),
      ),
    deploys: "never",
    after: "Workflows get it from their next run.",
    checked: ["help: gh 2.102.0 `secret set --help`", "https://github.com/cli/cli/blob/trunk/pkg/cmd/secret/set/set.go"],
  },
  {
    id: "gitlab",
    label: "GitLab CI/CD",
    bin: "glab",
    proof: {
      help: ["variable", "set", "--help"],
      mustSay: ["You can pass the variable value from standard input", "--masked"],
    },
    target: { noun: "project (GROUP/PROJECT)", required: false },
    env: { noun: "environment scope" },
    exists: (o) => ["variable", "get", o.name, ...opt("--repo", o.target), ...opt("--scope", o.env)],
    argv: (o) => [
      "variable", o.exists ? "update" : "set", o.name,
      ...opt("--repo", o.target),
      ...opt("--scope", o.env),
    ],
    stdin: (value) => value,
    // GetValue: strings.TrimSpace(io.ReadAll(stdin)) (internal/commands/variable/variableutils/value.go).
    refuses: (value) => edges(value),
    deploys: "never",
    after: "Pipelines get it from their next run.",
    checked: [
      "help: glab 1.120.0 `variable set --help` and `variable update --help`",
      "https://gitlab.com/gitlab-org/cli/-/blob/main/internal/commands/variable/variableutils/value.go",
    ],
  },
  {
    id: "gcloud",
    label: "Google Cloud Secret Manager",
    bin: "gcloud",
    proof: {
      help: ["secrets", "versions", "add", "--help"],
      mustSay: ['Set this to "-" to read the secret data from stdin'],
    },
    target: { noun: "Google Cloud project", required: false },
    exists: (o) => ["secrets", "describe", o.name, ...opt("--project", o.target)],
    argv: (o) =>
      o.exists
        ? ["secrets", "versions", "add", o.name, "--data-file=-", ...opt("--project", o.target)]
        : ["secrets", "create", o.name, "--data-file=-", "--replication-policy=automatic", ...opt("--project", o.target)],
    stdin: (value) => value,
    // console_io.ReadFromFileOrStdin(path, binary=True): every byte, as it is.
    refuses: (value) => first(nonEmpty(value), atMost(65_536, "Secret Manager")(value)),
    deploys: "never",
    after: "It becomes the secret's latest version.",
    checked: [
      "help: Google Cloud SDK 444.0.0 `secrets versions add --help`",
      "googlecloudsdk/command_lib/secrets/util.py ReadFileOrStdin (binary), in the installed SDK",
    ],
  },
  {
    id: "koyeb",
    label: "Koyeb",
    bin: "koyeb",
    proof: {
      help: ["secrets", "create", "--help"],
      mustSay: ["--value-from-stdin"],
    },
    exists: (o) => ["secrets", "get", o.name],
    argv: (o) => ["secrets", o.exists ? "update" : "create", o.name, "--value-from-stdin"],
    stdin: (value) => value,
    // getSecretValue reads lines until the first empty one, joined with "\n" (pkg/koyeb/secrets.go).
    refuses: (value) =>
      first(
        edges(value),
        value.includes("\n\n") ? "it has an empty line, where Koyeb's CLI stops reading" : null,
        value.split("\n").some((l) => bytes(l) > 60_000) ? "it has a line longer than Koyeb's CLI reads" : null,
      ),
    deploys: "never",
    after: "Services that use it get it on their next deploy.",
    checked: ["help: koyeb `secrets create --help` and `secrets update --help`", "https://github.com/koyeb/koyeb-cli/blob/master/pkg/koyeb/secrets.go"],
  },
  {
    id: "fastly",
    label: "Fastly Secret Store",
    bin: "fastly",
    proof: {
      help: ["secret-store-entry", "create", "--help"],
      mustSay: ["--stdin", "--recreate-allow"],
    },
    target: { noun: "secret store ID", required: true },
    argv: (o) => ["secret-store-entry", "create", "--store-id", o.target!, "--name", o.name, "--stdin", "--recreate-allow"],
    stdin: (value) => value,
    // case c.secretSTDIN: buf.ReadFrom(in), every byte (pkg/commands/secretstoreentry/create.go).
    refuses: (value) => first(nonEmpty(value), atMost(64 * 1024, "a Fastly secret")(value)),
    deploys: "never",
    after: "Compute services read it from the store.",
    checked: [
      "https://github.com/fastly/cli/blob/main/pkg/commands/secretstoreentry/create.go",
      "https://www.fastly.com/documentation/reference/cli/secret-store-entry/create/",
    ],
  },
  {
    id: "pulumi",
    label: "Pulumi config",
    bin: "pulumi",
    proof: {
      help: ["config", "set", "--help"],
      mustSay: ["--raw", "When setting the value through stdin", "--secret"],
    },
    target: { noun: "stack", required: false },
    argv: (o) => ["config", "set", "--secret", "--raw", o.name, ...opt("--stack", o.target)],
    stdin: (value) => value,
    // --raw: "do not trim trailing newlines from the value" — the bytes as they are.
    refuses: (value) => nonEmpty(value),
    deploys: "never",
    after: "It goes in the stack's config, encrypted; the next pulumi up uses it.",
    checked: ["https://www.pulumi.com/docs/iac/cli/commands/pulumi_config_set/ (--raw)"],
  },
  {
    id: "sst",
    label: "SST",
    bin: "sst",
    local: true,
    proof: {
      help: ["secret", "set", "--help"],
      mustSay: ["sst secret set StripeSecret < tmp.txt", "--stage"],
    },
    env: { noun: "stage" },
    argv: (o) => ["secret", "set", o.name, ...opt("--stage", o.env)],
    stdin: (value) => value,
    // Not a terminal: every line read and kept, newlines included (cmd/sst/secret.go).
    refuses: (value, o) =>
      first(
        nonEmpty(value),
        /^[A-Z][a-zA-Z0-9_]*$/.test(o.name) ? null : "SST secret names start with a capital letter and hold only letters, digits and _",
      ),
    deploys: "never",
    after: "sst dev picks it up; elsewhere, sst deploy applies it.",
    checked: ["help: sst 4.17.2 `secret set --help`", "https://github.com/anomalyco/sst/blob/dev/cmd/sst/secret.go"],
  },
];

export const hostById = (id: string): Host | undefined => HOSTS.find((h) => h.id === id);

/** Every host whose project files say this folder deploys there, with what they name. */
export function detectHosts(root: string): { id: string; target: string | null }[] {
  const out: { id: string; target: string | null }[] = [];
  for (const h of HOSTS) {
    const target = h.target?.detect?.(root) ?? null;
    if (target) out.push({ id: h.id, target });
  }
  if (existsSync(join(root, ".vercel", "project.json"))) out.push({ id: "vercel", target: null });
  if (existsSync(join(root, "convex.json")) || existsSync(join(root, "convex"))) out.push({ id: "convex", target: null });
  if (existsSync(join(root, "sst.config.ts"))) out.push({ id: "sst", target: null });
  if (existsSync(join(root, "Pulumi.yaml"))) out.push({ id: "pulumi", target: null });
  if (existsSync(join(root, ".github", "workflows"))) out.push({ id: "github", target: null });
  if (existsSync(join(root, ".gitlab-ci.yml"))) out.push({ id: "gitlab", target: null });
  return out;
}

/** "1.27.0" vs "1.46.0": the first version-looking thing in each, compared numerically. */
export function versionAtLeast(text: string, min: string): boolean | null {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(text);
  if (!m) return null;
  const have = m.slice(1, 4).map(Number);
  const want = min.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (have[i] !== want[i]) return have[i] > want[i];
  return true;
}

/** Help text as the proof compares it: no colour codes, whitespace collapsed. */
export const normalHelp = (text: string): string =>
  text.replace(/\u001b\[[0-9;]*m/g, "").replace(/\s+/g, " ");
