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
 * checks that read an already-loaded Policy.
 */
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
    if (!policy.allowEnvs.includes(s)) {
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
