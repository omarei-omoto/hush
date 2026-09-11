/**
 * Run a command with secrets in its environment and nothing on disk.
 *
 * Secrets exist only in the child's process environment. Output is streamed
 * through the redactor, so a program that helpfully echoes its own config
 * cannot put a live credential in your terminal, your CI log, or an agent's
 * transcript.
 */
import { spawn } from "node:child_process";
import { Redactor } from "./redact.ts";
import { isValidKeyName } from "./vault.ts";

export interface RunOptions {
  cwd?: string;
  /** Secrets to inject. */
  secrets: Record<string, string>;
  /** Pass through the parent environment too. Default true. */
  inherit?: boolean;
  /** Mask secret values in the child's output. Default true. Never disable for agents. */
  redact?: boolean;
  /** Collect output instead of streaming it to this process's stdio. */
  capture?: boolean;
  timeoutMs?: number;
}

/** Enough of the table to report the conventional 128+n exit status. */
const SIGNAL_NUMBERS: Record<string, number> = {
  SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGKILL: 9, SIGTERM: 15, SIGPIPE: 13,
};

export interface RunResult {
  code: number;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  redactions: number;
  timedOut: boolean;
}

export function runWithSecrets(
  command: string,
  args: string[],
  opts: RunOptions,
): Promise<RunResult> {
  const redact = opts.redact !== false;
  const outRedactor = new Redactor(redact ? opts.secrets : {});
  const errRedactor = new Redactor(redact ? opts.secrets : {});

  // Strip the whole HUSH_* namespace from what we inherit. Leaking any one of
  // HUSH_IDENTITY, HUSH_IDENTITY_FILE, HUSH_AGE_IDENTITY, HUSH_VAULT or
  // HUSH_HOME lets the child re-open the vault and read every other secret,
  // which defeats the point of injecting only what it needs.
  const inherited: NodeJS.ProcessEnv = opts.inherit === false ? {} : { ...process.env };
  for (const key of Object.keys(inherited)) {
    if (key.startsWith("HUSH_")) delete inherited[key];
  }

  // Secrets are merged after the strip, so a vault entry deliberately named
  // HUSH_* is still delivered — that is the user's call, not ambient config.
  const env: NodeJS.ProcessEnv = { ...inherited, ...opts.secrets, HUSH_ACTIVE: "1" };

  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: opts.cwd ?? process.cwd(),
      env,
      // stdout/stderr are always piped so the redactor can see them; only the
      // destination differs between capture and stream mode.
      stdio: ["inherit", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let redactions = 0;
    let timedOut = false;

    const countMasks = (after: string) => {
      redactions += (after.match(/\[redacted:/g) ?? []).length;
      return after;
    };

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");

    child.stdout.on("data", (chunk: string) => {
      const safe = countMasks(outRedactor.push(chunk));
      if (opts.capture) stdout += safe;
      else process.stdout.write(safe);
    });
    child.stderr.on("data", (chunk: string) => {
      const safe = countMasks(errRedactor.push(chunk));
      if (opts.capture) stderr += safe;
      else process.stderr.write(safe);
    });

    const timer = opts.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          child.kill("SIGKILL");
        }, opts.timeoutMs)
      : null;

    // Pass signals on to the child. Without this, killing hush left the child
    // running — still holding every injected credential — and orphaned it.
    const forwarded: NodeJS.Signals[] = ["SIGINT", "SIGTERM", "SIGHUP"];
    const onSignal = (sig: NodeJS.Signals) => () => {
      try {
        child.kill(sig);
      } catch {
        /* already gone */
      }
    };
    const handlers = forwarded.map((sig) => [sig, onSignal(sig)] as const);
    for (const [sig, handler] of handlers) process.on(sig, handler);
    const unhook = () => {
      for (const [sig, handler] of handlers) process.off(sig, handler);
    };

    child.on("error", (err) => {
      if (timer) clearTimeout(timer);
      unhook();
      reject(err);
    });

    child.on("close", (code, signal) => {
      if (timer) clearTimeout(timer);
      unhook();
      const tailOut = countMasks(outRedactor.flush());
      const tailErr = countMasks(errRedactor.flush());
      if (opts.capture) {
        stdout += tailOut;
        stderr += tailErr;
      } else {
        if (tailOut) process.stdout.write(tailOut);
        if (tailErr) process.stderr.write(tailErr);
      }
      // A child killed by a signal exits with code null. Reporting that as 0
      // told callers and CI that an interrupted command had succeeded.
      const exit = code ?? (signal ? 128 + (SIGNAL_NUMBERS[signal] ?? 1) : 0);
      resolvePromise({ code: exit, signal, stdout, stderr, redactions, timedOut });
    });
  });
}

/** Render secrets as a `.env` file body, for the escape hatch that needs a real file. */
export function toEnvFile(secrets: Record<string, string>, header?: string): string {
  const lines = header ? [`# ${header}`, ""] : [];
  for (const [k, v] of Object.entries(secrets).sort(([a], [b]) => a.localeCompare(b))) {
    // Newer vaults reject these on write; an older one may still contain them.
    if (!isValidKeyName(k)) {
      lines.push(`# skipped ${JSON.stringify(k)}: not a valid variable name`);
      continue;
    }
    // The escaping here must be exactly what parseEnvFile() undoes, or a value
    // cannot survive export -> import. A multi-line secret (a PEM key, say)
    // becomes one physical line with \n escapes, keeping the format
    // line-oriented for every other tool that reads .env files.
    const needsQuote = /[\s#"'$`\\]/.test(v) || v === "";
    const quoted =
      '"' +
      v
        .replace(/\\/g, "\\\\")
        .replace(/"/g, '\\"')
        .replace(/\n/g, "\\n")
        .replace(/\r/g, "\\r") +
      '"';
    lines.push(`${k}=${needsQuote ? quoted : v}`);
  }
  return lines.join("\n") + "\n";
}

/**
 * POSIX single-quoting. Inside single quotes the shell expands nothing at all,
 * and the only character that needs handling is the quote itself: close the
 * quoted run, emit an escaped quote, reopen.
 */
const shellQuote = (v: string): string => "'" + v.replaceAll("'", "'\\''") + "'";

/**
 * Render as `export K=V` for `eval "$(hush export --shell)"`.
 *
 * This output is fed straight to `eval` by the shell hook, so BOTH halves are a
 * code-execution surface, and only one of them used to be handled.
 *
 * Names are filtered, never escaped: there is no safe way to `export` something
 * that is not an identifier.
 *
 * Values are single-quoted. They used to go through `JSON.stringify`, which
 * produces a *double*-quoted string — and inside double quotes a shell still
 * expands dollar signs, backticks and backslashes. A secret whose value was a
 * command substitution therefore ran that command on every machine whose shell
 * hook loaded the vault: on every teammate's machine, the moment they changed
 * directory into the repo. Writing a value is something any member can do, so
 * this turned "can add a secret" into "can run code as everyone".
 */
export function toShellExports(secrets: Record<string, string>): string {
  return (
    Object.entries(secrets)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) =>
        isValidKeyName(k)
          ? `export ${k}=${shellQuote(v)}`
          : `# skipped ${JSON.stringify(k)}: not a valid variable name`,
      )
      .join("\n") + "\n"
  );
}
