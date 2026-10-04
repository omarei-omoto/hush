/**
 * Write a test's policy the way it now has to live (review F4): what turns an
 * approval off, or lowers the fingerprint or grant settings, is this
 * machine's choice and goes in the floor (`~/.hush/policy.json`, here the
 * test's HUSH_HOME), the approvals keyed by the project; everything else is
 * the repository's `.hush/policy.json`.
 */
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export function writePolicies(home: string, root: string, policy: Record<string, unknown>): void {
  const { requireApproval, biometry, approvalScope, ...repo } = policy;
  const floorPath = join(home, "policy.json");
  const floor = existsSync(floorPath) ? JSON.parse(readFileSync(floorPath, "utf8")) : {};
  if (biometry !== undefined) floor.biometry = biometry;
  if (approvalScope !== undefined) floor.approvalScope = approvalScope;
  if (requireApproval !== undefined) {
    floor.projects = { ...(floor.projects ?? {}), [realpathSync(root)]: { requireApproval } };
  }
  mkdirSync(home, { recursive: true });
  writeFileSync(floorPath, JSON.stringify(floor, null, 2) + "\n");
  mkdirSync(join(root, ".hush"), { recursive: true });
  writeFileSync(join(root, ".hush", "policy.json"), JSON.stringify(repo, null, 2) + "\n");
}

/** This machine's choice of approvals for one project, in the floor only — the repository's file is left alone. */
export function localApprovals(home: string, root: string, requireApproval: string[]): void {
  const floorPath = join(home, "policy.json");
  const floor = existsSync(floorPath) ? JSON.parse(readFileSync(floorPath, "utf8")) : {};
  floor.projects = { ...(floor.projects ?? {}), [realpathSync(root)]: { requireApproval } };
  mkdirSync(home, { recursive: true });
  writeFileSync(floorPath, JSON.stringify(floor, null, 2) + "\n");
}

/** What the floor says this machine requires approval for in `root`. */
export function localApprovalsOf(home: string, root: string): string[] | undefined {
  const floorPath = join(home, "policy.json");
  if (!existsSync(floorPath)) return undefined;
  return JSON.parse(readFileSync(floorPath, "utf8")).projects?.[realpathSync(root)]?.requireApproval;
}
