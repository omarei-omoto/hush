#!/usr/bin/env node
/**
 * The demo repository (D-2): a project with a committed vault and a *published*
 * test identity, so someone can `git clone`, set one variable, and `hush run`
 * in ten seconds — and see a value go into a program and come out redacted.
 *
 *   node scripts/make-demo.mjs [--out examples/hush-demo]
 *
 * Every value in it is fake, and its identity is public on purpose: it is a
 * key to a vault that holds nothing. The output is committed as
 * examples/hush-demo/ and pushed as its own repository (omarei-omoto/hush-demo)
 * by the maintainer. test/demo.test.ts runs the README's commands against it.
 */
import { mkdirSync, rmSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const { Vault } = await import(join(root, "src", "vault.ts"));
const { generateIdentity, encodeSecret, decodeSecret } = await import(join(root, "src", "crypto.ts"));

const i = process.argv.indexOf("--out");
const out = i === -1 ? join(root, "examples", "hush-demo") : process.argv[i + 1];

// Keep the published identity stable across regenerations: it is in the demo's
// README, in blog posts and in people's shell history.
const idFile = join(out, "DEMO_IDENTITY.txt");
const id = existsSync(idFile) ? decodeSecret(readFileSync(idFile, "utf8").trim()) : generateIdentity();

rmSync(join(out, ".hush"), { recursive: true, force: true });
mkdirSync(join(out, ".hush"), { recursive: true });

const v = Vault.create(join(out, ".hush", "vault.json"), "hush-demo", { name: "demo", pub: id.pub, priv: id.priv });
v.set(id, "default", "DEMO_API_KEY", "demo_live_4f9c2a17e3b8d6051c7e9a2b");
v.set(id, "default", "DATABASE_URL", "postgres://demo:demo-password-not-real@localhost:5432/demo");
v.set(id, "staging", "DEMO_API_KEY", "demo_staging_8b1d5e3f0a9c7264e1b3");
v.save();

writeFileSync(idFile, encodeSecret(id) + "\n");

writeFileSync(
  join(out, "app.js"),
  `// A stand-in for your app: it reads its key from the environment, as real
// code does, and prints it — which is exactly what hush's redaction is for.
const key = process.env.DEMO_API_KEY;
const db = process.env.DATABASE_URL;
if (!key) {
  console.error("DEMO_API_KEY is not set — run this with: hush run -- node app.js");
  process.exit(1);
}
console.log("Calling the demo API with key " + key);
console.log("Connecting to " + db);
console.log("(The key reached the program. It did not reach your terminal.)");
`,
);

writeFileSync(
  join(out, "package.json"),
  JSON.stringify({ name: "hush-demo", private: true, scripts: { dev: "node app.js" } }, null, 2) + "\n",
);

writeFileSync(
  join(out, ".env.schema"),
  `# What each value must look like — hush checks before anything runs.
# @required @type=string(startsWith=demo_)
DEMO_API_KEY=
# @required @type=string(startsWith=postgres://)
DATABASE_URL=
`,
);

writeFileSync(join(out, ".gitignore"), ".env\n.env.*\n!.env.schema\n.hush/audit.log\n.hush/*.local.json\n");

writeFileSync(
  join(out, "README.md"),
  `# hush demo

A project whose secrets are in the repo, encrypted, with [hush](https://github.com/omarei-omoto/hush).
Ten seconds from clone to a run:

\`\`\`bash
git clone https://github.com/omarei-omoto/hush-demo && cd hush-demo
export HUSH_IDENTITY="$(cat DEMO_IDENTITY.txt)"    # the demo's key — public on purpose, see below
hush run -- node app.js
\`\`\`

\`\`\`
Calling the demo API with key [redacted:DEMO_API_KEY]
Connecting to [redacted:DATABASE_URL]
(The key reached the program. It did not reach your terminal.)
\`\`\`

\`app.js\` printed the real key; hush replaced it on the way out. Then try:

\`\`\`bash
hush ls                          # the sets this project has (names, never values)
hush run --use staging -- node app.js   # the same program, the staging key
hush dev                         # package.json's dev script, same thing
cat .hush/vault.json             # what is committed: ciphertext and public keys
hush verify                      # everything decrypts, and it is the vault you accepted
hush install-mcp                 # then ask your coding agent to run the app
\`\`\`

Your agent gets tools that can *use* \`DEMO_API_KEY\` and never read it. Ask it
"what is the demo API key?" and watch it say it cannot tell you.

## About DEMO_IDENTITY.txt

It is the private key that opens this vault, published so the demo works
without setup. **Never do this with a real project.** Your own key stays on your
machine (\`hush id --create\` puts it in the OS keychain), and a teammate gets
access with \`hush team add\` — no key is ever shared. Every value in this
vault is fake.

Install hush: \`curl -fsSL https://raw.githubusercontent.com/omarei-omoto/hush/main/scripts/install.sh | sh\`,
\`brew install omarei-omoto/tap/hush\`, or \`npm i -g @omarei/hush\`.
`,
);

process.stdout.write(`demo → ${out}\n`);
