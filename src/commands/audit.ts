/**
 * `hush audit` — the local log, and a check that nothing was edited out of it.
 */
import { existsSync, readFileSync } from "node:fs";
import { join, basename } from "node:path";
import { locateProject } from "../vault.ts";
import { verifyAudit, withoutChain } from "../audit.ts";
import { type Args, bool, str } from "../cli/args.ts";
import { bold, die, dim, green, info, out, red, shown } from "../cli/output.ts";

/**
 * `hush audit` — the local log of what hush did here, newest last; and
 * `hush audit verify`, which walks its hash chain and names the first line
 * that does not follow from the one above it.
 */
export async function cmdAudit(a: Args): Promise<void> {
  const loc = locateProject(process.cwd());
  if (!loc) die("No hush project here, so no audit log.", "Run it inside a project that uses hush.");
  const sub = a._[0];

  if (sub === "verify") {
    const reports = verifyAudit(loc.hushDir);
    if (bool(a, "json")) {
      out(JSON.stringify(reports, null, 2));
    } else if (!reports.length) {
      info(dim("No audit log here yet."));
    } else {
      for (const r of reports) {
        const name = basename(r.file);
        if (r.breaks.length) {
          info(`${red("✗")} ${name}  ${dim(`${r.lines} line(s); the chain breaks ${r.breaks.length} time(s)`)}`);
          for (const b of r.breaks.slice(0, 10)) info(`    ${red(`line ${b.line}`)}  ${b.why}`);
        } else {
          const extra = [
            r.legacy ? `${r.legacy} written before the log was chained` : "",
            r.unchained.length ? `${r.unchained.length} written while another hush held the log (lines ${r.unchained.slice(0, 5).join(", ")})` : "",
          ].filter(Boolean);
          info(`${green("✓")} ${name}  ${dim(`${r.lines} line(s), each following from the one above` + (extra.length ? `; ${extra.join("; ")}` : ""))}`);
        }
      }
      info("");
      info(dim("  This shows an edit; it cannot prevent one. Anything running as you can rewrite"));
      info(dim("  the whole file, or cut lines off the end, and a chain cannot tell."));
    }
    if (reports.some((r) => r.breaks.length)) process.exitCode = 1;
    return;
  }
  if (sub) die(`Unknown: hush audit ${sub}`, "Try: hush audit, hush audit verify");

  const path = join(loc.hushDir, "audit.log");
  const lines = existsSync(path) ? readFileSync(path, "utf8").split("\n").filter(Boolean) : [];
  const last = Math.max(1, Number(str(a, "last") ?? 20) || 20);
  const entries = lines.slice(-last).map((l) => {
    try {
      return withoutChain(JSON.parse(l) as Record<string, unknown>);
    } catch {
      return { unreadable: l.slice(0, 80) };
    }
  });
  if (bool(a, "json")) return out(JSON.stringify(entries, null, 2));
  if (!entries.length) return info(dim("Nothing logged here yet."));
  for (const e of entries) {
    const { at, actor, action, ...rest } = e as Record<string, unknown>;
    const detail = Object.entries(rest)
      .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
      .join(" ");
    info(`${dim(String(at ?? "").replace("T", " ").slice(0, 19))}  ${String(actor ?? "")}  ${bold(String(action ?? ""))}  ${dim(shown(detail, 160))}`);
  }
}
