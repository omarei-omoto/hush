/**
 * `hush doctor` — check this machine's setup, top to bottom.
 */
import { existsSync } from "node:fs";
import { join } from "node:path";
import { Vault, locateProject } from "../vault.ts";
import { loadIdentity, publicKeyOf, hushHome } from "../identity.ts";
import { loadPolicy } from "../mcp.ts";
import { readPolicyFile, policyWeakenings } from "../policy.ts";
import { loadSchema, validate, describeProblems } from "../schema.ts";
import { AGENTS, mcpRegistrations } from "../agents.ts";
import { usedSets, composeSets, librarySets, linkNameFor } from "../library.ts";
import { VERSION } from "../version.ts";
import { assess } from "../posture.ts";
import { inspect, pendingChanges, hasProblems } from "../integrity.ts";
import { biometryStatus } from "../biometry.ts";
import { ageAvailable, ageIdentityPath, identityPlugin } from "../age.ts";
import { type Args } from "../cli/args.ts";
import { driverInstalled } from "./merge.ts";
import { bold, cyan, dim, green, info, red } from "../cli/output.ts";
import { readIfExists } from "../cli/programs.ts";

export async function cmdDoctor(_a: Args): Promise<void> {
  const check = (okFlag: boolean, label: string, detail = "") =>
    info(`  ${okFlag ? green("✓") : red("✗")} ${label}${detail ? dim(`  ${detail}`) : ""}`);

  info(bold(`hush ${VERSION}`));
  info("");
  const id = loadIdentity();
  check(Boolean(id), "identity", id ? id.source : "run `hush id --create`");
  if (id) info(`    ${dim(publicKeyOf(id))}`);

  const loc = locateProject(process.cwd());
  check(
    Boolean(loc),
    "project",
    !loc
      ? "not set up — run something with hush here, or `hush use <set>`"
      : loc.hasVault
        ? loc.vaultPath
        : `${loc.hushDir}  (no vault yet — uses library sets only)`,
  );
  if (!loc || !id) return;

  // A folder that only uses library sets has nothing to be a recipient *of*;
  // the checks below that read the vault simply do not apply to it.
  let vault: Vault | null = null;
  if (loc.hasVault) {
    try {
      vault = Vault.open(loc.vaultPath);
    } catch (e) {
      return check(false, "vault readable", (e as Error).message);
    }
    check(vault.canRead(id), "you are a recipient", vault.canRead(id) ? `as "${vault.memberName(id)}"` : "ask an admin to `hush team add` you");
    check(true, "members", String(vault.members().length));
    if (vault.canRead(id)) {
      const pending = pendingChanges(vault.trustView(vault.dekForReview(id)));
      const bad = hasProblems(pending);
      check(
        !bad,
        "vault accepted",
        bad
          ? `${pending.added.length ? `${pending.added.length} member(s) nobody here accepted` : "changed since this machine accepted it"} — hush team accept, or hush team reject`
          : pending.firstUse ? "first look — pinned from now on" : "members and key match what this machine accepted",
      );
      // Nothing below should decrypt a vault a person has not accepted.
      if (bad) return;
    }
  }

  // One vocabulary here too: every set, project and library, marked the way
  // `hush ls` marks it.
  const used = new Set(usedSets(loc.hushDir));
  const projectNames = vault ? vault.sets().map((s) => s.name) : [];
  const libraryNames = librarySets().map((s) => s.name).filter((n) => !projectNames.includes(n));
  check(
    true,
    "sets",
    [
      ...projectNames.map((s) => s + (used.has(s) ? " ●" : "")),
      ...libraryNames.map((s) => s + (used.has(linkNameFor("library", s)) ? " ●" : "")),
    ].join(", ") + dim("   ● = used by this project"),
  );

  const root = loc.hushDir.replace(/[/\\]\.hush$/, "");
  // Asked of every agent hush knows, not just Claude Code: on a Codex machine
  // the old check looked for `.mcp.json`, did not find it, and told someone with
  // a working setup to run the installer again.
  const registered = mcpRegistrations(root, process.env, readIfExists);
  check(
    registered.length > 0,
    "MCP registered",
    registered.length
      ? registered.map((x) => `${x.agent.name}: ${x.file}`).join(", ")
      : "run `hush install-mcp`",
  );

  const skills = AGENTS.flatMap((g) =>
    [g.skill.project(root), g.skill.global?.(process.env)].filter((p): p is string => !!p && existsSync(p)),
  );
  check(skills.length > 0, "agent skill", skills.length ? skills.join(", ") : "run `hush install-skill`");

  // What the agent is actually allowed to do, rather than what it could be.
  const policy = loadPolicy(loc.hushDir);
  check(
    policy.requireApproval.length > 0,
    "approval required",
    policy.requireApproval.length ? policy.requireApproval.join(", ") : "nothing is gated — see .hush/policy.json",
  );

  // The floor lives outside the repo on purpose (see policy.ts's
  // mergePolicies), so it is worth spelling out here that it exists at all —
  // and, when the repo tried to loosen something it sets, exactly what got
  // refused rather than leaving that invisible.
  const floorPath = join(hushHome(), "policy.json");
  check(existsSync(floorPath), "policy floor", existsSync(floorPath) ? floorPath : "none — hush secure floor makes one (a copy of the vault opened elsewhere has no policy without it)");
  const weakenings = policyWeakenings(readPolicyFile(floorPath), readPolicyFile(join(loc.hushDir, "policy.json")));
  for (const w of weakenings) info(`    ${dim(w)}`);

  // `.env.schema`, when the project has one. This is the only check anywhere
  // that says whether a value is the *right shape*; everything above is about
  // where it lives and who can read it.
  const schema = loadSchema(root);
  if (!schema) {
    check(true, ".env.schema", dim("none — add one to have value shapes checked"));
  } else {
    let problems: ReturnType<typeof validate> = [];
    try {
      problems = validate(composeSets(vault, id, loc.hushDir, []).secrets, schema.rules);
    } catch {
      /* nothing resolves yet; the set checks above already said so */
    }
    check(
      problems.length === 0,
      ".env.schema",
      problems.length ? `${problems.length} value(s) do not match` : `${schema.rules.length} rule(s)`,
    );
    for (const line of describeProblems(problems)) info(`    ${dim(line)}`);
  }

  const bio = biometryStatus();
  const enforcing = policy.biometry === "required" && bio.available;
  check(
    enforcing,
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
    check(Boolean(plugin), "hardware key", plugin ? `age-plugin-${plugin}` : "age installed, but the identity is a software key");
  }

  // A vault in git merges key by key only where this clone has asked for it.
  if (vault) {
    const merging = driverInstalled(root);
    if (merging !== null) {
      check(merging, "merge driver", merging ? "vault merges go key by key" : "hush merge-driver --install (or hush merge after a conflict)");
    }
  }

  // Loose .env files are the thing hush exists to remove.
  const stray = [".env", ".env.local", ".env.production"].filter((f) => existsSync(join(root, f)));
  check(stray.length === 0, "no plaintext .env in repo", stray.length ? `found ${stray.join(", ")}` : "");

  // Freshness, and where this machine sits on the ladder.
  const stale = vault ? inspect(vault) : null;
  if (stale) check(false, "vault freshness", `rolled back to generation ${stale.nowGeneration} — hush verify`);

  const posture = assess(vault, loc.hushDir, root);
  info("");
  info(`  ${posture.rung === 5 ? green("●".repeat(5)) : green("●".repeat(posture.rung)) + dim("○".repeat(5 - posture.rung))}  ${bold(`rung ${posture.rung} of 5`)} ${dim("— " + posture.name)}`);
  if (posture.next) info(`    ${dim("next: " + posture.next.label)}  ${cyan("hush secure")}`);
}
