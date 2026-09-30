#!/usr/bin/env node
/**
 * docs/guide/commands.md, generated from `hush help --all` (src/cli/help.ts),
 * so the reference cannot drift from the program. It had: by the time the
 * README's hand-kept copy moved into the guide, it was missing start, import,
 * request, approvals and more.
 *
 *   node scripts/gen-commands.mjs            write it
 *   node scripts/gen-commands.mjs --check    exit 1 if it is out of date
 *
 * test/consistency.test.ts runs the check.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const target = join(root, "docs", "guide", "commands.md");

export async function commandsPage() {
  const { FULL_HELP } = await import(pathToFileURL(join(root, "src", "cli", "help.ts")).href);
  const plain = FULL_HELP.replace(/\x1b\[[0-9;]*m/g, "")
    .split("\n")
    // The version line changes every release and says nothing a reader needs here.
    .filter((line, i) => !(i === 0 && /^hush \S+ — /.test(line)))
    .join("\n")
    .trim();
  return `# Commands

<!-- Generated from \`hush help --all\` by scripts/gen-commands.mjs. Edit src/cli/help.ts, then run npm run docs:commands. -->

Everything \`hush help --all\` prints. \`hush help\` shows the eight you need most.

\`\`\`
${plain}
\`\`\`
`;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const page = await commandsPage();
  if (process.argv.includes("--check")) {
    if (readFileSync(target, "utf8") !== page) {
      process.stderr.write("docs/guide/commands.md is out of date — run npm run docs:commands\n");
      process.exit(1);
    }
  } else {
    writeFileSync(target, page);
    process.stdout.write("wrote docs/guide/commands.md\n");
  }
}
