#!/usr/bin/env node
/**
 * The `hush` entry point.
 *
 * Node >= 22.6 strips the types in src/ and runs them directly — except for any
 * file under node_modules, where it refuses. So an installed copy importing
 * src/ threw ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING and every single
 * command failed; `npm run build` emits dist/, and the published tarball ships
 * it.
 *
 * Which one to use is decided by that same distinction, not by "is dist there".
 * Preferring dist whenever it existed broke the development loop in the other
 * direction: `npm link` puts a symlink in node_modules pointing back at the
 * checkout, so a built dist/ left lying around would quietly shadow every edit
 * to src/ until someone remembered to rebuild.
 */
import { existsSync } from "node:fs";
import { dirname, join, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// The real path, so a symlinked bin resolves to wherever it actually lives.
const here = dirname(fileURLToPath(import.meta.url));
const installed = here.split(sep).includes("node_modules");

const built = join(here, "..", "dist", "cli.js");
const source = join(here, "..", "src", "cli.ts");

const entry = installed || !existsSync(source) ? built : source;
await import(pathToFileURL(entry).href);
