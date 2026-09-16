/**
 * Policy checks shared by every surface that can act on the vault.
 *
 * These lived only inside mcp.ts, which meant they governed the MCP tools and
 * nothing else — an agent with a Bash tool could call `hush get`, `hush export`
 * or `hush run` directly and walk around every one of them. cli.ts now calls
 * these same functions before doing the equivalent thing, so a policy written
 * once in .hush/policy.json holds regardless of which surface an agent uses.
 *
 * DEFAULT_POLICY and loadPolicy stay in mcp.ts (see test/consistency.test.ts's
 * "the default policy is not retyped anywhere") — this file only holds the
 * checks that read an already-loaded Policy, the merge that builds one, and
 * the approval-scope helpers both surfaces share.
 */
import { readFileSync } from "node:fs";
import { ttlLabel } from "./dialogs.ts";
import { ValidationError } from "./vault.ts";
import type { Policy } from "./mcp.ts";

export function checkEnv(policy: Policy, env: string): void {
  if (policy.allowEnvs.length && !policy.allowEnvs.includes(env)) {
    throw new ValidationError(`Policy forbids agent access to environment "${env}".`);
  }
}

/**
 * allowEnvs has to cover service-account scopes too. Checking only the base
 * environment let an agent pinned to "dev" pull any account it liked, including
 * a production one, by naming it in `accounts`.
 */
export function checkScopes(policy: Policy, scopes: string[]): void {
  if (!policy.allowEnvs.length) return;
  for (const s of scopes) {
    // A library layer is spelled "<vault>:<set>". The policy names sets the
    // way the person does, so the plain name is what allowEnvs is matched on
    // as well — a set name cannot contain ":" (see assertScopeName), so the
    // part after the last one is always the set.
    const plain = s.slice(s.lastIndexOf(":") + 1);
    if (!policy.allowEnvs.includes(s) && !policy.allowEnvs.includes(plain)) {
      throw new ValidationError(`Policy forbids agent access to "${s}". Allowed: ${policy.allowEnvs.join(", ")}.`);
    }
  }
}

export function checkCommand(policy: Policy, command: string): void {
  const base = command.split("/").pop() ?? command;
  if (policy.denyCommands.includes(base)) {
    throw new ValidationError(
      `Refused: "${base}" can read the whole injected environment and write it somewhere ` +
        `redaction cannot see, so it is denied by default. Put the work in a script and run ` +
        `that instead, or ask the human to add "${base}" to unsafeAllowCommands in ` +
        `.hush/policy.json if they accept the risk.`,
    );
  }
  if (policy.allowCommands.length && !policy.allowCommands.includes(base)) {
    throw new ValidationError(
      `Refused: "${base}" is not in policy.allowCommands (${policy.allowCommands.join(", ")}).`,
    );
  }
}

/**
 * Does this host match the policy's allow list?
 *
 * An empty list means "no host restriction", the same way an empty
 * allowCommands means "no command restriction" — the list only ever narrows.
 *
 * An entry may carry a port (`localhost:3000`), in which case the whole
 * `host:port` has to match, or may be bare (`api.stripe.com`), in which case
 * it matches on hostname whatever the port. `*.example.com` matches a
 * subdomain but never the apex: a wildcard should not quietly widen to the
 * registered domain someone else's tenant lives on.
 */
export function hostAllowed(patterns: string[], hostname: string, host: string): boolean {
  if (!patterns.length) return true;
  const h = hostname.toLowerCase();
  const hp = host.toLowerCase();
  return patterns.some((raw) => {
    const p = raw.trim().toLowerCase();
    if (!p) return false;
    if (p.startsWith("*.")) {
      const suffix = p.slice(1); // ".example.com"
      return h.endsWith(suffix) && h.length > suffix.length;
    }
    return p.includes(":") ? hp === p : h === p;
  });
}

/**
 * The host half of the gate for `hush request`.
 *
 * `checkCommand` cannot express this: the "command" being run is hush's own
 * fetch, so the thing an agent actually picks is the destination. Without a
 * host check, a set that is allowed for `api.stripe.com` is equally allowed
 * for an attacker's collector.
 */
export function checkHost(policy: Policy, url: URL): void {
  if (hostAllowed(policy.allowHosts, url.hostname, url.host)) return;
  throw new ValidationError(
    `Policy forbids requests to "${url.host}". Allowed: ${policy.allowHosts.join(", ")}.`,
  );
}

/**
 * The grant key an "Allow 15 min" approval for a request is cached under.
 *
 * Same idea as runScope, with the host in the command's place: a grant made
 * for one destination must not authorise the same sets going somewhere else,
 * because that is the whole shape of the attack this gate exists to stop.
 */
export function requestScope(policy: Policy, host: string, layers: string[]): string {
  // A JSON array, not a ":"-joined string: a host may carry ":" (host:port)
  // and a library layer always does ("<vault>:<set>"), so the joined form was
  // not injective — two different (host, sets) pairs produced one key and one
  // approval covered both.
  return policy.approvalScope === "sets"
    ? JSON.stringify(["request", layers])
    : JSON.stringify(["request", host, layers]);
}

/** The request-shaped sibling of approvalCoverageLine(). */
export function requestCoverageLine(policy: Policy, host: string, layers: string[]): string {
  const sets = layers.join(", ") || "(none)";
  const what = policy.approvalScope === "sets" ? "any host" : host;
  return `${ttlLabel(policy.approvalTtlSeconds)} covers:  ${what} with ${sets}`;
}

/** Same rule checkCommand() uses: the part after the last "/", not the whole invocation. */
const basenameOf = (command: string): string => command.split("/").pop() ?? command;

/**
 * The grant key an "Allow 15 min" approval is cached under.
 *
 * Before this, both surfaces scoped a run grant to the sets alone
 * (`run:<sets>`), so approving one command for 15 minutes silently approved
 * every other allowed command too, for as long as the grant lasted — a user
 * who clicked "Allow 15 min" for `./deploy.sh` had no way to know that also
 * covered `curl` for the next 15 minutes. Naming the command in the scope
 * closes that: a grant now matches only the same basename with the same sets,
 * unless a policy opts back into the wider shape with `approvalScope: "sets"`.
 */
export function runScope(policy: Policy, command: string, layers: string[]): string {
  // Same reasoning as requestScope(): a command basename may itself contain
  // ":" and a library layer always does, so `run:${basename}:${sets}` let
  // ("npm", ["global:work-fal"]) and ("./npm:global", ["work-fal"]) share one
  // key, and an "Allow 15 min" grant approved for the first pair answered the
  // second with no dialog.
  return policy.approvalScope === "sets"
    ? JSON.stringify(["run", layers])
    : JSON.stringify(["run", basenameOf(command), layers]);
}

/**
 * The line added to an approval's detail so a human knows exactly what the
 * session button buys — named with the policy's real TTL, the same label the
 * button itself carries.
 */
export function approvalCoverageLine(policy: Policy, command: string, layers: string[]): string {
  const sets = layers.join(", ") || "(none)";
  const what = policy.approvalScope === "sets" ? "any command" : basenameOf(command);
  return `${ttlLabel(policy.approvalTtlSeconds)} covers:  ${what} with ${sets}`;
}

/** Read a policy file (floor or repo), tolerating "missing" and "not valid JSON" alike as "nothing to add". */
export function readPolicyFile(path: string): Partial<Policy> {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as Partial<Policy>;
  } catch {
    return {};
  }
}

const union = (...lists: (string[] | undefined)[]): string[] => [...new Set(lists.flatMap((l) => l ?? []))];
const intersect = (a: string[], b: string[]): string[] => b.filter((x) => a.includes(x));

const BIOMETRY_RANK: Record<Policy["biometry"], number> = { off: 0, preferred: 1, required: 2 };
const SCOPE_RANK: Record<Policy["approvalScope"], number> = { sets: 0, command: 1 };

/**
 * `effective = mergePolicies(DEFAULT_POLICY, userFloor, repoPolicy)`.
 *
 * `floor` comes from `~/.hush/policy.json` — outside the repo, so an agent
 * with write access to the project cannot touch it. `repo` comes from the
 * project's `.hush/policy.json`. The rule for every field is the same idea
 * applied differently depending on what "tighter" means for that field: the
 * repo may narrow what the floor allows, or add to what it requires, but it
 * can never widen or drop below what the floor already settled.
 *
 * Passing `{}` for `floor` (no floor file, or one that does not mention a
 * given field) reproduces today's two-way `{...DEFAULT_POLICY, ...repo}`
 * merge for every field except `unsafeAllowCommands` — see its own comment
 * for why that one field is deliberately not "empty floor means no opinion".
 */
export function mergePolicies(base: Policy, floor: Partial<Policy>, repo: Partial<Policy>): Policy {
  // "Narrow, not widen" fields: allowCommands/allowEnvs have always treated an
  // empty list as "no restriction", so a floor that does not set one leaves
  // the repo's own choice untouched — exactly today's behaviour.
  const narrow = (field: "allowCommands" | "allowEnvs" | "allowHosts"): string[] => {
    const floorList = floor[field];
    const repoList = repo[field];
    // An absent or empty floor is "no opinion": the repo's own list applies
    // untouched, exactly the two-way merge this replaces.
    if (!floorList?.length) return repoList ?? base[field];
    // Repo silence must inherit the floor, not the built-in empty list. The
    // old `repo[field] ?? base[field]` fell back to `[]`, and an empty list
    // means "no restriction" at every consumer, so a repo that said nothing
    // widened the floor to nothing — the exact inversion the floor exists to
    // prevent, and the shape hush's own setup writes.
    if (!repoList?.length) return floorList;
    const overlap = intersect(floorList, repoList);
    // An empty overlap cannot be represented — `[]` reads as "no restriction"
    // — so a repo list that lies entirely outside the floor is ignored as a
    // whole, which is what policyWeakenings() already reports.
    return overlap.length ? overlap : floorList;
  };

  const denyCommandsUnion = union(base.denyCommands, floor.denyCommands, repo.denyCommands);
  // Unlike allowCommands/allowEnvs, an empty (or absent) unsafeAllowCommands
  // has always meant "nothing exempted" — the safe, default state — so there
  // is no passthrough exception here: an entry only survives when BOTH the
  // floor and the repo name it. That is the whole point of the floor —
  // without it, a repo file alone could reopen any command in denyCommands by
  // itself, which is exactly the hole this feature closes.
  const unsafeAllowCommands = intersect(floor.unsafeAllowCommands ?? [], repo.unsafeAllowCommands ?? []);
  const denyCommands = denyCommandsUnion.filter((c) => !unsafeAllowCommands.includes(c));

  // Numeric ceilings: the floor caps how large the value may be, defaulting to
  // "no cap" when unset so an absent floor changes nothing.
  const ceiling = (field: "maxRunMs" | "approvalTtlSeconds"): number =>
    Math.min(repo[field] ?? base[field], floor[field] ?? Infinity);

  const biometryRepo = repo.biometry ?? base.biometry;
  const biometryFloor = floor.biometry ?? "off";
  const biometry = BIOMETRY_RANK[biometryFloor] > BIOMETRY_RANK[biometryRepo] ? biometryFloor : biometryRepo;

  const scopeRepo = repo.approvalScope ?? base.approvalScope;
  const scopeFloor = floor.approvalScope ?? "sets";
  const approvalScope = SCOPE_RANK[scopeFloor] > SCOPE_RANK[scopeRepo] ? scopeFloor : scopeRepo;

  return {
    allowCommands: narrow("allowCommands"),
    allowHosts: narrow("allowHosts"),
    denyCommands,
    unsafeAllowCommands,
    allowEnvs: narrow("allowEnvs"),
    denyKeys: union(base.denyKeys, floor.denyKeys, repo.denyKeys),
    maxRunMs: ceiling("maxRunMs"),
    // Union of floor and repo, with repo falling back to the base default when
    // unset — the same "repo can override the default outright" behaviour
    // loadPolicy has always had, except the floor's own requirements are never
    // among the things an unset-vs-empty repo value can drop.
    requireApproval: union(floor.requireApproval, repo.requireApproval ?? base.requireApproval),
    approvalTtlSeconds: ceiling("approvalTtlSeconds"),
    // A longer wait is not a weakening, so the repo's own choice always wins.
    approvalTimeoutSeconds: repo.approvalTimeoutSeconds ?? floor.approvalTimeoutSeconds ?? base.approvalTimeoutSeconds,
    biometry,
    approvalScope,
    // The unmask list is the user's own decision, so only the floor can set
    // it: a repository must not be able to talk hush out of masking a value
    // it can write a file about. See unsensitiveForOutput() in schema.ts.
    unmaskKeys: floor.unmaskKeys ?? [],
  };
}

/**
 * Human-readable lines for `hush doctor`: one per place the repo's
 * policy.json asked for something the user's floor refused. Empty when the
 * repo asks for nothing wider than the floor allows (including when there is
 * no floor at all, in which case nothing is ever refused).
 */
export function policyWeakenings(floor: Partial<Policy>, repo: Partial<Policy>): string[] {
  const lines: string[] = [];

  const droppedFromUnsafe = (repo.unsafeAllowCommands ?? []).filter((c) => !(floor.unsafeAllowCommands ?? []).includes(c));
  if (droppedFromUnsafe.length) {
    lines.push(`policy.json asks for unsafeAllowCommands: ${droppedFromUnsafe.join(", ")} — ignored, below your floor`);
  }

  const narrowFields = {
    allowCommands: "allowCommands",
    allowEnvs: "allowEnvs",
    allowHosts: "allowHosts",
  } as const;
  for (const field of Object.keys(narrowFields) as (keyof typeof narrowFields)[]) {
    const floorList = floor[field];
    const repoList = repo[field];
    if (!floorList?.length) continue;
    if (repoList && !repoList.length) {
      lines.push(`policy.json asks for an empty ${field} — ignored, your floor's list (${floorList.join(", ")}) applies`);
      continue;
    }
    if (!repoList?.length) continue;
    const dropped = repoList.filter((x) => !floorList.includes(x));
    if (dropped.length === repoList.length) {
      lines.push(
        `policy.json asks for ${field}: ${dropped.join(", ")} — none are inside your floor, ` +
          `so your floor's list (${floorList.join(", ")}) applies`,
      );
    } else if (dropped.length) {
      lines.push(`policy.json asks for ${field}: ${dropped.join(", ")} — ignored, outside your floor`);
    }
  }

  if (repo.requireApproval) {
    const dropped = (floor.requireApproval ?? []).filter((a) => !repo.requireApproval!.includes(a));
    if (dropped.length) lines.push(`policy.json drops requireApproval: ${dropped.join(", ")} — ignored, your floor requires it`);
  }

  if (repo.denyKeys) {
    const dropped = (floor.denyKeys ?? []).filter((k) => !repo.denyKeys!.includes(k));
    if (dropped.length) lines.push(`policy.json drops denyKeys: ${dropped.join(", ")} — ignored, your floor requires it`);
  }

  for (const field of ["maxRunMs", "approvalTtlSeconds"] as const) {
    const floorValue = floor[field];
    const repoValue = repo[field];
    if (floorValue !== undefined && repoValue !== undefined && repoValue > floorValue) {
      lines.push(`policy.json asks for ${field}: ${repoValue} — ignored, above your floor of ${floorValue}`);
    }
  }

  if (floor.biometry && repo.biometry && BIOMETRY_RANK[repo.biometry] < BIOMETRY_RANK[floor.biometry]) {
    lines.push(`policy.json asks for biometry: ${repo.biometry} — ignored, below your floor of ${floor.biometry}`);
  }

  if (floor.approvalScope && repo.approvalScope && SCOPE_RANK[repo.approvalScope] < SCOPE_RANK[floor.approvalScope]) {
    lines.push(`policy.json asks for approvalScope: ${repo.approvalScope} — ignored, below your floor of ${floor.approvalScope}`);
  }

  return lines;
}
