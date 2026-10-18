/**
 * `hush doctor` — check this machine's setup, top to bottom.
 *
 * The checks are worked out once, as data (doctorReport), and then either
 * printed as a checklist for a person or, with --json, written out whole for
 * a script or the app. Both show the same checks: names, paths and counts —
 * a public key, never a private one, and never a value.
 */
import { existsSync } from "node:fs";
import { join } from "node:path";
import { Vault, locateProject } from "../vault.ts";
import { loadIdentity, publicKeyOf, hushHome } from "../identity.ts";
import { DEFAULT_POLICY, loadPolicy } from "../mcp.ts";
import { readPolicyFile, policyWeakenings, projectKey } from "../policy.ts";
import { loadSchema, validate, describeProblems } from "../schema.ts";
import { AGENTS, mcpRegistrations } from "../agents.ts";
import { usedSets, composeSets, librarySets, linkNameFor } from "../library.ts";
import { VERSION } from "../version.ts";
import { assess } from "../posture.ts";
import { inspect, pendingChanges, hasProblems } from "../integrity.ts";
import { biometryStatus } from "../biometry.ts";
import { ageAvailable, ageIdentityPath, identityPlugin } from "../age.ts";
import { type Args, bool } from "../cli/args.ts";
import { driverInstalled } from "./merge.ts";
import { agentCredentialCount } from "./scan-agents.ts";
import { keyAges } from "../freshness.ts";
import { bold, cyan, dim, green, info, out, red } from "../cli/output.ts";
import { readIfExists } from "../cli/programs.ts";

/** One line of the checklist. */
export interface DoctorCheck {
  /** Stable, for scripts: "identity", "approval", "policy-floor", … */
  id: string;
  ok: boolean;
  /** What a person reads: "approval required". */
  label: string;
  detail: string;
  /** Lines that belong under it: your public key, what a repo's policy tried to loosen, what a schema refused. */
  notes?: string[];
}

export interface DoctorReport {
  version: string;
  checks: DoctorCheck[];
  /** Where this machine sits on the ladder; absent when there is no project or no identity to judge. */
  posture?: { rung: number; name: string; next: string | null };
}

export function doctorReport(cwd: string = process.cwd()): DoctorReport {
  const checks: DoctorCheck[] = [];
  const report: DoctorReport = { version: VERSION, checks };
  const check = (id: string, ok: boolean, label: string, detail = "", notes?: string[]) => {
    checks.push({ id, ok, label, detail, ...(notes?.length ? { notes } : {}) });
  };

  const id = loadIdentity();
  check("identity", Boolean(id), "identity", id ? id.source : "run `hush id --create`", id ? [publicKeyOf(id)] : undefined);

  const loc = locateProject(cwd);
  check(
    "project",
    Boolean(loc),
    "project",
    !loc
      ? "not set up — run something with hush here, or `hush use <set>`"
      : loc.hasVault
        ? loc.vaultPath
        : `${loc.hushDir}  (no vault yet — uses library sets only)`,
  );
  if (!loc || !id) return report;

  // A folder that only uses library sets has nothing to be a recipient *of*;
  // the checks below that read the vault simply do not apply to it.
  let vault: Vault | null = null;
  if (loc.hasVault) {
    try {
      vault = Vault.open(loc.vaultPath);
    } catch (e) {
      check("vault-readable", false, "vault readable", (e as Error).message);
      return report;
    }
    check("recipient", vault.canRead(id), "you are a recipient", vault.canRead(id) ? `as "${vault.memberName(id)}"` : "ask an admin to `hush team add` you");
    check("members", true, "members", String(vault.members().length));
    if (vault.canRead(id)) {
      const pending = pendingChanges(vault.trustView(vault.dekForReview(id)));
      const bad = hasProblems(pending);
      check(
        "vault-accepted",
        !bad,
        "vault accepted",
        bad
          ? `${pending.added.length ? `${pending.added.length} member(s) nobody here accepted` : "changed since this machine accepted it"} — hush team accept, or hush team reject`
          : pending.firstUse ? "first look — pinned from now on" : "members and key match what this machine accepted",
      );
      // Nothing below should decrypt a vault a person has not accepted.
      if (bad) return report;
    }
  }

  // One vocabulary here too: every set, project and library, marked the way
  // `hush ls` marks it.
  const used = new Set(usedSets(loc.hushDir));
  const projectNames = vault ? vault.sets().map((s) => s.name) : [];
  const libraryNames = librarySets().map((s) => s.name).filter((n) => !projectNames.includes(n));
  check(
    "sets",
    true,
    "sets",
    [
      ...projectNames.map((s) => s + (used.has(s) ? " ●" : "")),
      ...libraryNames.map((s) => s + (used.has(linkNameFor("library", s)) ? " ●" : "")),
    ].join(", "),
  );

  const root = loc.hushDir.replace(/[/\\]\.hush$/, "");
  // Asked of every agent hush knows, not just Claude Code: on a Codex machine
  // the old check looked for `.mcp.json`, did not find it, and told someone with
  // a working setup to run the installer again.
  const registered = mcpRegistrations(root, process.env, readIfExists);
  check(
    "mcp",
    registered.length > 0,
    "MCP registered",
    registered.length
      ? registered.map((x) => `${x.agent.name}: ${x.file}`).join(", ")
      : "run `hush install-mcp`",
  );

  const skills = AGENTS.flatMap((g) =>
    [g.skill.project(root), g.skill.global?.(process.env)].filter((p): p is string => !!p && existsSync(p)),
  );
  check("skill", skills.length > 0, "agent skill", skills.length ? skills.join(", ") : "run `hush install-skill`");

  const plain = agentCredentialCount(root);
  check(
    "agent-configs",
    plain.count === 0,
    "agent configs",
    plain.count ? `${plain.count} plaintext key(s) in ${plain.files} file(s) — hush scan --agents` : "no plaintext keys",
  );

  // What the agent is actually allowed to do, rather than what it could be.
  const policy = loadPolicy(loc.hushDir);
  check(
    "approval",
    policy.requireApproval.length > 0,
    "approval required",
    policy.requireApproval.length ? policy.requireApproval.join(", ") : "nothing is gated — see .hush/policy.json",
  );

  // The floor lives outside the repo on purpose (see policy.ts's
  // mergePolicies), so it is worth spelling out here that it exists at all —
  // and, when the repo tried to loosen something it sets, exactly what got
  // refused rather than leaving that invisible.
  const floorPath = join(hushHome(), "policy.json");
  check(
    "policy-floor",
    existsSync(floorPath),
    "policy floor",
    existsSync(floorPath) ? floorPath : "none — hush secure floor makes one (a copy of the vault opened elsewhere has no policy without it)",
    policyWeakenings(readPolicyFile(floorPath), readPolicyFile(join(loc.hushDir, "policy.json")), DEFAULT_POLICY, projectKey(loc.hushDir)),
  );

  // `.env.schema`, when the project has one. This is the only check anywhere
  // that says whether a value is the *right shape*; everything above is about
  // where it lives and who can read it.
  const schema = loadSchema(root);
  if (!schema) {
    check("schema", true, ".env.schema", "none — add one to have value shapes checked");
  } else {
    let problems: ReturnType<typeof validate> = [];
    try {
      problems = validate(composeSets(vault, id, loc.hushDir, []).secrets, schema.rules);
    } catch {
      /* nothing resolves yet; the set checks above already said so */
    }
    check(
      "schema",
      problems.length === 0,
      ".env.schema",
      problems.length ? `${problems.length} value(s) do not match` : `${schema.rules.length} rule(s)`,
      describeProblems(problems),
    );
  }

  const bio = biometryStatus();
  check(
    "biometry",
    policy.biometry === "required" && bio.available,
    "biometry",
    !bio.available
      ? (bio.reason ?? "unavailable")
      : policy.biometry === "required"
        ? bio.kind
        : `${bio.kind} available, but policy is "${policy.biometry}" — a click still works`,
  );

  // The hardware bridge, only when it is relevant.
  if (ageAvailable()) {
    const agePath = ageIdentityPath();
    const plugin = agePath ? identityPlugin(agePath) : null;
    check("hardware-key", Boolean(plugin), "hardware key", plugin ? `age-plugin-${plugin}` : "age installed, but the identity is a software key");
  }

  // Signed, overdue, exposed: the vault's own state, beyond this machine's.
  if (vault) {
    check("vault-signed", vault.signed, "vault signed", vault.signed ? "only an admin can change who can read it" : "an admin can run hush team sign");
    const ages = keyAges(vault, policy);
    const exposed = ages.filter((k) => k.exposed.length);
    const overdue = ages.filter((k) => k.overdue);
    if (exposed.length) check("exposed", false, "exposed values", `${exposed.length} readable by someone since removed — hush exposed`);
    if (overdue.length) check("rotation", false, "rotation", `${overdue.length} past rotateAfterDays — hush ls --age`);
  }

  // A vault in git merges key by key only where this clone has asked for it.
  if (vault) {
    const merging = driverInstalled(root);
    if (merging !== null) {
      check("merge-driver", merging, "merge driver", merging ? "vault merges go key by key" : "hush merge-driver --install (or hush merge after a conflict)");
    }
  }

  // Loose .env files are the thing hush exists to remove.
  const stray = [".env", ".env.local", ".env.production"].filter((f) => existsSync(join(root, f)));
  check("plaintext-env", stray.length === 0, "no plaintext .env in repo", stray.length ? `found ${stray.join(", ")}` : "");

  // Freshness, and where this machine sits on the ladder.
  const stale = vault ? inspect(vault) : null;
  if (stale) check("freshness", false, "vault freshness", `rolled back to generation ${stale.nowGeneration} — hush verify`);

  const posture = assess(vault, loc.hushDir, root);
  report.posture = { rung: posture.rung, name: posture.name, next: posture.next?.label ?? null };
  return report;
}

export async function cmdDoctor(a: Args): Promise<void> {
  const report = doctorReport();
  if (bool(a, "json")) return out(JSON.stringify(report, null, 2));

  info(bold(`hush ${report.version}`));
  info("");
  for (const c of report.checks) {
    // The sets line says what its ● means.
    const detail = c.id === "sets" ? c.detail + "   ● = used by this project" : c.detail;
    info(`  ${c.ok ? green("✓") : red("✗")} ${c.label}${detail ? dim(`  ${detail}`) : ""}`);
    for (const note of c.notes ?? []) info(`    ${dim(note)}`);
  }
  const p = report.posture;
  if (!p) return;
  info("");
  info(`  ${p.rung === 5 ? green("●".repeat(5)) : green("●".repeat(p.rung)) + dim("○".repeat(5 - p.rung))}  ${bold(`rung ${p.rung} of 5`)} ${dim("— " + p.name)}`);
  if (p.next) info(`    ${dim("next: " + p.next)}  ${cyan("hush secure")}`);
}
