/**
 * The page `hush ui` serves: one self-contained document, no network, no
 * dependencies. It lives apart from the server (ui.ts) so each can be read on
 * its own.
 *
 * It is organised around what a person came to do, in the order they came to
 * do it:
 *
 *   - Project: does my app have what it needs to run? The code is scanned for
 *     the variables it reads, and each is shown as provided (and by which set)
 *     or missing (with an Add button). Below that, the sets a run gets, in the
 *     order they apply, with every key visible and the one that wins marked.
 *   - Library: the catalog of your own sets. Nothing in it reaches a project
 *     until the project adds it.
 *   - Team, Agent, Activity: who can decrypt, what an agent must ask for, and
 *     what happened, in sentences.
 *
 * Two rules hold everywhere:
 *
 *   - No value reaches this page unless the person clicks Reveal, which goes
 *     through the same approval as `hush get`. Everything else is a masked
 *     preview built server-side.
 *   - The DOM is built with h(), which only ever sets textContent and
 *     attributes. Nothing assigns HTML built from data, so nothing a vault,
 *     a dropped file or the audit log contains can become markup.
 *
 * This is a String.raw template: the script inside it must not use backticks
 * or the dollar-brace sequence.
 */
import { STYLES } from "./ui/styles.ts";
import { FOUNDATIONS } from "./ui/foundations.ts";
import { ACTIONS } from "./ui/actions.ts";
import { SECTIONS } from "./ui/sections.ts";
import { AGENT } from "./ui/agent.ts";
import { IMPORT } from "./ui/import.ts";

/** The whole document, in order. */
export const PAGE = STYLES + FOUNDATIONS + ACTIONS + SECTIONS + AGENT + IMPORT;
