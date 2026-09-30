/**
 * Asking the person at the terminal: hidden values, visible lines, yes/no.
 */
import { createInterface } from "node:readline";
import { dim } from "../cli/output.ts";

// ------------------------------------------------------------------ prompts

/** Piped stdin is read once, then served one line per prompt. */
let pipedLines: string[] | null = null;

function readAllStdin(): Promise<string> {
  return new Promise((res) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (d) => (data += d));
    process.stdin.on("end", () => res(data));
  });
}

/**
 * @param whole  Take everything piped in as one value.
 *
 * Multi-variable flows (`hush add aws`) read one line per prompt, but a single
 * secret must not be split: `cat key.pem | hush set PRIVATE_KEY` was silently
 * storing only "-----BEGIN PRIVATE KEY-----".
 */
export async function promptSecret(label: string, whole = false): Promise<string> {
  if (!process.stdin.isTTY) {
    if (whole && pipedLines === null) {
      return (await readAllStdin()).replace(/\r?\n$/, "");
    }
    if (pipedLines === null) {
      pipedLines = (await readAllStdin()).split(/\r?\n/);
      if (pipedLines.at(-1) === "") pipedLines.pop();
    }
    return pipedLines.shift() ?? "";
  }
  return new Promise((res) => {
    process.stderr.write(`${label}: `);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    let value = "";
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") {
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdin.removeListener("data", onData);
          process.stderr.write("\n");
          return res(value);
        }
        if (ch === "\u0003") { // Ctrl-C
          process.stdin.setRawMode(false);
          process.stderr.write("\n");
          process.exit(130);
        }
        if (ch === "\u007f" || ch === "\b") { // backspace
          value = value.slice(0, -1);
          continue;
        }
        value += ch;
      }
    };
    process.stdin.on("data", onData);
  });
}

// A throw between setRawMode(true) and the handler would otherwise leave the
// user's terminal with no echo and no line editing after hush exits.
process.on("exit", () => {
  if (process.stdin.isTTY && process.stdin.isRaw) {
    try { process.stdin.setRawMode(false); } catch { /* already gone */ }
  }
});

export function confirm(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) return Promise.resolve(false);
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((res) =>
    rl.question(`${question} ${dim("[y/N]")} `, (a) => {
      rl.close();
      res(/^y(es)?$/i.test(a.trim()));
    }),
  );
}

/**
 * A single visible line of input, echoed as typed — unlike `promptSecret`,
 * which hides input and is for values that must never appear on screen. Only
 * ever called once the caller has confirmed `process.stdin.isTTY`, so there is
 * no non-TTY branch here to silently do the wrong thing.
 */
export function promptLine(label: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((res) =>
    rl.question(label, (a) => {
      rl.close();
      res(a.trim());
    }),
  );
}

/**
 * A visible line of input, usable over a pipe as well as a real terminal —
 * unlike `promptLine`, which every existing call site only ever reaches after
 * checking `process.stdin.isTTY`. The setup dialogue (below) has to be
 * answerable non-interactively too, for HUSH_INTERACTIVE=1 tests to drive it.
 *
 * A fresh `readline.Interface` per question — what `promptLine` does — only
 * ever sees the first line piped in: a non-TTY stdin typically arrives as one
 * buffered chunk, and a closed Interface does not hand the unread remainder to
 * the next one. Reusing `promptSecret`'s `pipedLines` buffer sidesteps that by
 * reading the whole pipe once and serving it back one line per call.
 */
export async function askLine(label: string): Promise<string> {
  if (process.stdin.isTTY) return promptLine(label);
  // promptLine's `rl.question(label, …)` writes the label as part of asking;
  // reading pipedLines directly bypasses readline entirely, so the question
  // has to be written out here or a piped run of the dialogue would apply
  // each answer to a question nobody — human or test assertion — ever saw.
  process.stderr.write(label);
  if (pipedLines === null) {
    pipedLines = (await readAllStdin()).split(/\r?\n/);
    if (pipedLines.at(-1) === "") pipedLines.pop();
  }
  return (pipedLines.shift() ?? "").trim();
}
