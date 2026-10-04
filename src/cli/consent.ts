/**
 * A person's yes to something hard to undo — deleting a .env, rewriting an
 * agent's config — asked where only a person can answer.
 *
 * On a terminal it is a y/N question. Without one (an agent's shell, a
 * script) it is a hush dialog on the person's screen: the same channel
 * approvals use, which the agent that ran the command cannot click. `--yes`
 * stands in only where no dialog can be shown at all (headless CI), so an
 * agent on a desktop cannot answer for the person by adding a flag.
 */
import { randomBytes } from "node:crypto";
import { approvalPromptAvailable, requestApproval } from "../approval.ts";
import { askLine } from "./prompts.ts";
import { dim } from "./output.ts";

export async function consent(
  question: string,
  opts: { hushDir: string; detail?: string[]; yes?: boolean },
): Promise<boolean> {
  if (process.stdin.isTTY) {
    const ans = (await askLine(`${question} ${dim("[y/N]")} `)).trim().toLowerCase();
    return ans === "y" || ans === "yes";
  }
  if (approvalPromptAvailable()) {
    const ap = await requestApproval(opts.hushDir, {
      action: "setup",
      summary: question,
      detail: opts.detail ?? [],
      // Fresh every time: one yes is never remembered for the next question.
      scope: `consent:${randomBytes(8).toString("hex")}`,
      ttlSeconds: 0,
      sessionGrant: false,
      biometry: "off",
    });
    return ap.decision === "once" || ap.decision === "session";
  }
  // --yes stands in for a person only on a machine that has no way to ask
  // one. When the prompt is missing because the environment switched it off,
  // the switch must not make the answer easier: it used to turn an agent's own
  // --yes into the person's.
  if (process.env.HUSH_NO_DIALOG === "1" || process.env.HUSH_BIOMETRY === "off") return false;
  return opts.yes === true;
}
