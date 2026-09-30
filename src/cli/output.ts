/**
 * Terminal output: colour, the one-line helpers, and dying with a message.
 */
import { safeText, withoutControls } from "../vault.ts";

// ------------------------------------------------------------------- output

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
export const bold = c("1");
export const dim = c("2");
export const red = c("31");
export const green = c("32");
export const yellow = c("33");
export const cyan = c("36");

export const out = (s = ""): void => void process.stdout.write(s + "\n");

/** Indent every line of a multi-line block, so a pasted snippet stays aligned. */
export const indent = (s: string, pad: string): string => pad + s.split("\n").join("\n" + pad);
export const info = (s: string): void => out(s);
export const warn = (s: string): void => void process.stderr.write(yellow(`! ${withoutControls(s)}`) + "\n");

/**
 * A vault-supplied name on its way to the terminal. Set names are an identity,
 * not free text, so they are kept intact for lookups and only scrubbed where
 * they are printed: an ANSI sequence in a name would otherwise repaint the
 * lines above it rather than show up as part of the name.
 */
export const shown = (name: string, max = 80): string => safeText(name, max) ?? "<unprintable>";

export function die(message: string, hint?: string): never {
  // An error message can carry text from a vault file or another program;
  // none of it gets to drive the terminal.
  process.stderr.write(red(`✗ ${withoutControls(message)}`) + "\n");
  if (hint) process.stderr.write(dim(`  ${withoutControls(hint)}`) + "\n");
  process.exit(1);
}
