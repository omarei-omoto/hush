/**
 * `hush scan --transcripts` — your real secrets, word for word, in coding
 * agents' saved conversations.
 *
 * Looks for three things: values in your hush vaults, plaintext keys from
 * agents' config files, and strings shaped like a provider's key that hush has
 * never seen. Reports names, places and dates — never a hush value, and only a
 * masked preview of the rest.
 *
 * Read-only by design. It does not edit, redact or delete a conversation:
 * those files belong to the agents, and a tool that rewrites them should be a
 * separate, deliberate step.
 */
import { availableParallelism, homedir } from "node:os";
import { existsSync } from "node:fs";
import { type Args, bool, str } from "../cli/args.ts";
import { ctxLoose } from "../cli/context.ts";
import { bold, cyan, die, dim, green, info, out, red, warn } from "../cli/output.ts";
import { Vault, locateProject, namedVaultPath } from "../vault.ts";
import { loadIdentity } from "../identity.ts";
import { globalVaultPath, namedVaults } from "../library.ts";
import { credentialLike } from "../agent-configs.ts";
import { agentConfigSecrets } from "./scan-agents.ts";
import { preview } from "../redact.ts";
import { CATALOG, rotationUrl } from "../services.ts";
import {
  MIN_NEEDLE, listTranscripts, scanTranscripts, tokenService, transcriptSources, variants,
  type TranscriptFile,
} from "../transcripts.ts";

interface Known {
  /** Variable names it is stored under, e.g. STRIPE_SECRET_KEY. */
  keys: string[];
  /** Where it lives, for a person: "library · Stripe Live", "Codex config". */
  places: string[];
  source: "hush" | "config";
  value: string;
}

const tilde = (p: string): string => {
  const h = homedir();
  return p.startsWith(h + "/") ? "~" + p.slice(h.length) : p;
};

const gb = (n: number): string => (n >= 1e9 ? `${(n / 1e9).toFixed(1)} GB` : `${Math.max(1, Math.round(n / 1e6))} MB`);

const day = (ms: number): string => new Date(ms).toISOString().slice(0, 10);

/** `30d`, `12h`, `2w`, or a date. */
export function parseSince(s: string, now = Date.now()): number {
  const rel = /^(\d+)\s*([hdw])$/.exec(s.trim());
  if (rel) return now - Number(rel[1]) * { h: 3600e3, d: 86400e3, w: 7 * 86400e3 }[rel[2] as "h" | "d" | "w"];
  const t = Date.parse(s);
  if (Number.isNaN(t)) die(`--since takes 30d, 12h, 2w or a date, not "${s}".`);
  return t;
}

/** Every value in every vault this machine can read, credentials only. */
function hushValues(warnings: string[]): Known[] {
  const id = loadIdentity();
  if (!id) {
    warnings.push("no hush identity on this machine, so your vaults were not searched for");
    return [];
  }
  const paths = new Set<string>();
  const loc = locateProject(process.cwd());
  if (loc?.hasVault) paths.add(loc.vaultPath);
  if (existsSync(globalVaultPath())) paths.add(globalVaultPath());
  for (const n of namedVaults()) paths.add(namedVaultPath(n));

  const out: Known[] = [];
  for (const path of paths) {
    let v: Vault;
    try {
      v = Vault.open(path);
    } catch (e) {
      warnings.push(`skipped ${tilde(path)}: ${(e as Error).message.split("\n")[0]}`);
      continue;
    }
    if (!v.canRead(id)) continue;
    for (const s of v.sets()) {
      for (const key of s.keys) {
        let value: string;
        try {
          value = v.get(id, s.name, key);
        } catch {
          continue; // a set this member was not given
        }
        if (value.length < MIN_NEEDLE || !credentialLike(key, value)) continue;
        out.push({ keys: [key], places: [`${v.data.name} · ${s.label || s.name}`], source: "hush", value });
      }
    }
  }
  return out;
}

function configValues(root: string): Known[] {
  return agentConfigSecrets(root)
    .filter(({ finding }) => finding.value.length >= MIN_NEEDLE)
    .map(({ agent, finding }) => ({
      keys: [finding.name],
      places: [`${agent} config${finding.server ? ` (${finding.server})` : ""}`],
      source: "config" as const,
      value: finding.value,
    }));
}

/** One entry per distinct value: the same key in three sets is one finding. */
function merge(all: Known[]): Known[] {
  const byValue = new Map<string, Known>();
  for (const k of all) {
    const have = byValue.get(k.value);
    if (!have) byValue.set(k.value, { ...k, keys: [...k.keys], places: [...k.places] });
    else {
      for (const x of k.keys) if (!have.keys.includes(x)) have.keys.push(x);
      for (const x of k.places) if (!have.places.includes(x)) have.places.push(x);
      if (k.source === "hush") have.source = "hush";
    }
  }
  return [...byValue.values()];
}

interface Seen {
  files: { file: TranscriptFile; count: number }[];
}

const rotateFor = (serviceLabelOrKey: string): string | null =>
  rotationUrl(serviceLabelOrKey) ??
  Object.values(CATALOG).find((c) => c.label === serviceLabelOrKey)?.rotate ??
  null;

export async function cmdScanTranscripts(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  const sinceRaw = str(a, "since");
  const since = sinceRaw ? parseSince(sinceRaw) : 0;
  const json = bool(a, "json");
  const verbose = bool(a, "verbose");

  const files = listTranscripts(transcriptSources(process.env), since);
  const total = files.reduce((n, f) => n + f.size, 0);
  const agents = [...new Set(files.map((f) => f.agent))];

  const warnings: string[] = [];
  const known = merge([...hushValues(warnings), ...configValues(loose.root)]);
  const needles: Buffer[] = [];
  const owner: number[] = [];
  known.forEach((k, i) => {
    for (const v of variants(k.value)) {
      const b = Buffer.from(v, "utf8");
      if (b.length < MIN_NEEDLE) continue;
      needles.push(b);
      owner.push(i);
    }
  });

  const threads = Math.max(1, Math.min(8, Number(str(a, "threads")) || availableParallelism() - 1));
  const tty = Boolean(process.stderr.isTTY) && !json;
  let lastDraw = 0;
  const started = Date.now();
  const results = await scanTranscripts(files, needles, {
    threads,
    onProgress: (doneBytes) => {
      if (!tty || Date.now() - lastDraw < 200) return;
      lastDraw = Date.now();
      process.stderr.write(`\r  reading conversations… ${Math.floor((doneBytes / Math.max(1, total)) * 100)}% of ${gb(total)}   `);
    },
  });
  if (tty) process.stderr.write("\r" + " ".repeat(60) + "\r");
  const seconds = ((Date.now() - started) / 1000).toFixed(1);

  // Fold the per-file hits into per-secret findings.
  const fileOf = new Map(files.map((f) => [f.path, f]));
  const seenKnown = new Map<number, Seen>();
  const seenTokens = new Map<string, Seen>();
  const knownValues = new Set(known.map((k) => k.value));
  for (const [path, hits] of results) {
    const file = fileOf.get(path)!;
    const perKnown = new Map<number, number>();
    for (const [needle, count] of hits.needles) perKnown.set(owner[needle], (perKnown.get(owner[needle]) ?? 0) + count);
    for (const [k, count] of perKnown) {
      const s = seenKnown.get(k) ?? { files: [] };
      s.files.push({ file, count });
      seenKnown.set(k, s);
    }
    for (const [token, count] of hits.tokens) {
      if (knownValues.has(token)) continue;
      const s = seenTokens.get(token) ?? { files: [] };
      s.files.push({ file, count });
      seenTokens.set(token, s);
    }
  }

  const describe = (s: Seen) => {
    const latest = Math.max(...s.files.map((f) => f.file.mtimeMs));
    const by = [...new Set(s.files.map((f) => f.file.agent))];
    return { conversations: s.files.length, agents: by, last: day(latest), files: s.files.sort((x, y) => y.file.mtimeMs - x.file.mtimeMs) };
  };

  if (json) {
    return out(JSON.stringify({
      scanned: { files: files.length, bytes: total, agents, since: since ? new Date(since).toISOString() : null, seconds: Number(seconds) },
      warnings,
      found: [...seenKnown].map(([i, s]) => {
        const d = describe(s);
        return {
          source: known[i].source, keys: known[i].keys, places: known[i].places,
          conversations: d.conversations, agents: d.agents, last: d.last,
          files: d.files.map((f) => ({ path: f.file.path, agent: f.file.agent, modified: day(f.file.mtimeMs), count: f.count })),
        };
      }),
      keyShaped: [...seenTokens].map(([t, s]) => {
        const d = describe(s);
        return {
          service: tokenService(t), preview: preview(t), conversations: d.conversations, agents: d.agents, last: d.last,
          files: d.files.map((f) => ({ path: f.file.path, agent: f.file.agent, modified: day(f.file.mtimeMs), count: f.count })),
        };
      }),
    }, null, 2));
  }

  info(`${bold("transcripts")}  ${dim(`${files.length.toLocaleString()} file(s), ${gb(total)} — ${agents.join(", ") || "no agent history found"}${sinceRaw ? ` · since ${day(since)}` : ""} · ${seconds}s`)}`);
  for (const w of warnings) warn(w);
  if (!seenKnown.size && !seenTokens.size) {
    info("");
    info(`  ${green("✓")} none of your secrets, and nothing shaped like a key, in any saved conversation`);
    info(dim(`    looked for ${known.length} value(s) from your vaults and agent configs`));
    return;
  }

  const line = (label: string, where: string, s: Seen) => {
    const d = describe(s);
    info(`    ${red("✗")} ${bold(label)}  ${dim(where)}`);
    info(dim(`        ${d.conversations} conversation file(s) · ${d.agents.join(", ")} · last ${d.last}`));
    if (verbose) for (const f of d.files) info(dim(`          ${tilde(f.file.path)}  ${day(f.file.mtimeMs)}${f.count > 1 ? `  ×${f.count}` : ""}`));
  };
  const section = (title: string, source: Known["source"]) => {
    const rows = [...seenKnown].filter(([i]) => known[i].source === source);
    if (!rows.length) return;
    info("");
    info(`  ${title}`);
    for (const [i, s] of rows) line(known[i].keys.join(", "), known[i].places.join("; "), s);
  };
  section("Your hush values, word for word:", "hush");
  section("Keys from your agents' config files:", "config");
  if (seenTokens.size) {
    info("");
    info("  Other strings shaped like a key (hush has never seen these):");
    for (const [t, s] of seenTokens) line(`${tokenService(t)}  ${preview(t)}`, "", s);
  }

  info("");
  info("  Each of these went to the model provider with the conversation, and is still");
  info(`  on disk in the files above${verbose ? "" : ` (${cyan("--verbose")} lists them)`}. Replace each key at its provider:`);
  const urls = new Map<string, string>();
  for (const [i] of seenKnown) for (const k of known[i].keys) {
    const u = rotateFor(k);
    if (u) urls.set(k, u);
  }
  for (const [t] of seenTokens) {
    const svc = tokenService(t);
    const u = rotateFor(svc);
    if (u) urls.set(svc, u);
  }
  for (const [k, u] of urls) info(`    ${k.padEnd(22)} ${cyan(u)}`);
  if (!urls.size) info(dim("    (hush knows no replacement page for these — use the provider's dashboard)"));
  info("");
  info(dim("  Nothing was changed: hush only read these files."));
}
