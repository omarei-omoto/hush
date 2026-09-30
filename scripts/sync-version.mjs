#!/usr/bin/env node
/**
 * Run by `npm version` (package.json "version" script): carry package.json's
 * new version into the two other places that state it — src/version.ts (what
 * `hush --version` prints) and server.json (the MCP registry listing). The
 * release workflow refuses a tag that disagrees with any of the three.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const { version } = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

const versionTs = join(root, "src", "version.ts");
writeFileSync(versionTs, readFileSync(versionTs, "utf8").replace(/VERSION = "[^"]+"/, `VERSION = "${version}"`));

const serverJson = join(root, "server.json");
const server = JSON.parse(readFileSync(serverJson, "utf8"));
server.version = version;
for (const p of server.packages ?? []) if (p.registryType === "npm") p.version = version;
writeFileSync(serverJson, JSON.stringify(server, null, 2) + "\n");

process.stdout.write(`version ${version} → src/version.ts, server.json\n`);
