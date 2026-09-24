/**
 * The guided first run: what a person who has never used hush should meet.
 *
 * The problem this solves is not a missing feature. It is that arriving at hush
 * means arriving at forty commands, a vocabulary (vault, set, scope, layer) and
 * a README, and none of that is how anyone wants to spend their first five
 * minutes. What they want is: my keys are in a `.env`, make my project work.
 *
 * So the wording and the branches live here, as data and small pure functions,
 * where they can be read and tested without a terminal. The asking and the
 * doing happen in cli.ts's `hush start`, next to the things they call.
 *
 * Two rules held throughout, both from what the audience actually is:
 *
 *   - One question at a time, in words a person would use out loud. No
 *     "scope", no "vault", no "layer" — and where hush's own word is
 *     unavoidable it is glossed in the same sentence.
 *   - Never demand hush's vocabulary to get started. "Keys", "passwords",
 *     "tokens" and "env vars" all mean the same thing here and live in the same
 *     place, so the questions are written so that any of them is a correct
 *     answer.
 */
import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";

/** The names people actually use for the file. All of them are ours. */
const ENV_FILE_NAMES = [".env", ".env.local", ".env.development", ".env.dev", ".env.production"];

/** One choice in a question, as a number the user can type. */
export interface Choice {
  /** What the user types. */
  key: string;
  /** The line itself, in plain words. */
  label: string;
  /** A dimmed aside, e.g. what was found on disk. */
  note?: string;
}

/**
 * The `.env`-shaped files in this folder, most likely first.
 *
 * `.env` before `.env.local` because that is what a person means when they say
 * "it's in the env file".
 */
export function findEnvFiles(root: string): string[] {
  return ENV_FILE_NAMES.filter((name) => existsSync(join(root, name)));
}

/** True when git is already ignoring this path, without shelling out to git. */
export function isGitignored(root: string, name: string): boolean {
  const gi = join(root, ".gitignore");
  if (!existsSync(gi)) return false;
  try {
    // Literal name, or a wildcard that covers it. Deliberately approximate:
    // this only picks which friendly sentence to show, and being wrong costs a
    // dimmed sentence rather than a wrong action.
    return readFileSync(gi, "utf8")
      .split(/\r?\n/)
      .map((l) => l.trim())
      .some((l) => l === name || l === `/${name}` || l === ".env*" || l === ".env.*" || l === "*.local");
  } catch {
    return false;
  }
}

/** The dev command for this folder, if it has a package.json. */
export function detectDevCommand(
  root: string,
  packageManagerFor: (dir: string) => string,
): { pm: string; script: string } | null {
  let dir = root;
  for (;;) {
    const pkg = join(dir, "package.json");
    if (existsSync(pkg)) {
      try {
        const parsed = JSON.parse(readFileSync(pkg, "utf8")) as { scripts?: Record<string, string> };
        // "dev" first, then the two runners people use instead of it.
        const script = ["dev", "start", "serve"].find((s) => parsed.scripts?.[s]);
        if (!script) return null;
        return { pm: packageManagerFor(dir), script };
      } catch {
        return null;
      }
    }
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/** The opening lines. No jargon, and the promise is what happens, not what it is. */
export function openingLines(state: { envFiles: string[] }): string[] {
  const lines = [
    "Let's get this project set up so it can use your keys.",
    "",
    "A few questions, nothing you have to know already.",
  ];
  if (state.envFiles.length) {
    lines.push("");
    lines.push(
      state.envFiles.length === 1
        ? `I can see ${state.envFiles[0]} in this folder.`
        : `I can see ${state.envFiles.join(", ")} in this folder.`,
    );
  }
  return lines;
}

/**
 * "Where are your keys right now?"
 *
 * Ordered by how common the answer is, and worded around what is actually on
 * disk, so the first choice is usually right and pressing enter usually works.
 */
export function keySourceChoices(state: { envFiles: string[]; librarySetCount: number }): Choice[] {
  const choices: Choice[] = [
    {
      key: "1",
      label: state.envFiles.length
        ? `In a file in this folder${state.envFiles.length === 1 ? ` (${state.envFiles[0]})` : ""}`
        : "In a file in this folder (I'll look for one)",
      note: state.envFiles.length ? "the usual case: your .env" : "nothing here yet",
    },
    {
      key: "2",
      label: "In another tool, like 1Password, Doppler or AWS",
      note: "I'll print one command to copy them in",
    },
    {
      key: "3",
      label: "Nowhere yet, I want to add one now",
      note: "I'll ask for the value, hidden",
    },
  ];
  if (state.librarySetCount > 0) {
    choices.push({
      key: "4",
      label: "Already in hush, I just want this project to use them",
      note: `${state.librarySetCount} you made earlier`,
    });
  }
  return choices;
}

/** The one command to copy keys in, per the tool they named. */
export function importRecipe(tool: string, setLabel: string): string | null {
  const t = tool.trim().toLowerCase();
  const as = `--as "${setLabel}"`;
  if (t.includes("doppler")) return `doppler secrets download --format json --no-file | hush import - ${as}`;
  if (t.includes("1password") || t === "op" || t.includes("1pass")) {
    return `op item get "YOUR ITEM" --format json | hush import - --format 1password ${as}`;
  }
  if (t.includes("aws")) {
    return (
      "aws secretsmanager get-secret-value --secret-id YOUR_SECRET --query SecretString \\\n" +
      `  --output text | hush import - ${as}`
    );
  }
  if (t.includes("infisical")) return `infisical secrets --plain | hush import - ${as}`;
  if (t.includes("hashicorp") || t.includes("vault")) {
    return `vault kv get -format=json YOUR/PATH | hush import - --format json ${as}`;
  }
  return null;
}

/**
 * What to say at the end: the commands worth knowing, and the one that proves
 * it worked. Deliberately three. The other thirty-seven are a `hush help --all`
 * away, and listing them here is how a good first run turns back into a wall of
 * text.
 */
export function closingLines(state: { devCommand: { pm: string; script: string } | null }): string[] {
  const runLine = state.devCommand ? "hush dev" : "hush run -- <your command>";
  return [
    "",
    "That's it. The three commands you'll actually use:",
    "",
    `  ${runLine.padEnd(32)}# run your project with the keys`,
    `  ${"hush ls".padEnd(32)}# what's here, and what this folder uses`,
    `  ${"hush start".padEnd(32)}# this again, any time`,
    "",
    "Nothing was written to disk as plain text, and the keys are encrypted in your repo.",
  ];
}
