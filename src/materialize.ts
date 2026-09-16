/**
 * Credentials that are a file, not a string.
 *
 * A whole class of tooling does not read the environment for a secret; it
 * reads a *path*:
 *
 *     GOOGLE_APPLICATION_CREDENTIALS=/path/service-account.json
 *     KUBECONFIG=/path/config
 *     ~/.docker/config.json, a .p12 keystore, a client certificate
 *
 * Before this, the only way to feed one was `hush export`, which writes every
 * value in the vault to disk in plaintext and leaves it there — the problem
 * this project exists to avoid, offered as the solution.
 *
 * So hush writes the one file a command asked for, hands the child the *path*,
 * and removes it again. Two rules keep it from becoming a way around the reveal
 * gate:
 *
 *   - The file is created with `wx`, so an existing path is a refusal rather
 *     than a write through it. That is what makes a planted symlink fail closed
 *     instead of pointing the credential somewhere else.
 *   - There is no MCP tool for it. A caller that can materialise a value to a
 *     path *and* read that path has read the value, which is precisely what the
 *     agent surface is built not to allow.
 */
import { mkdtempSync, openSync, writeFileSync, closeSync, unlinkSync, rmdirSync, statSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { tmpdir, homedir } from "node:os";
import { ValidationError, isValidKeyName } from "./vault.ts";

/** One `--materialize` request: which secret, and where it should land. */
export interface MaterializeSpec {
  key: string;
  /** An explicit path, or null to let hush choose a private one. */
  path: string | null;
}

export interface Materialized {
  /** Extra environment for the child: `KEY` -> the path, never the value. */
  env: Record<string, string>;
  /** The paths that were written, for the approval dialog and the audit log. */
  written: string[];
  /** Remove every file this call created. Safe to run twice. */
  cleanup: () => void;
}

/**
 * `KEY` or `KEY=/path`.
 *
 * No `=` means "you choose": a private directory, so the common case does not
 * need the caller to invent a safe path, and does not put a predictable name in
 * a world-writable directory.
 */
export function parseMaterializeSpec(raw: string): MaterializeSpec {
  const at = raw.indexOf("=");
  const key = (at === -1 ? raw : raw.slice(0, at)).trim();
  if (!key) throw new ValidationError(`Bad --materialize "${raw}". Use --materialize KEY or --materialize KEY=/path.`);
  if (!isValidKeyName(key)) {
    throw new ValidationError(
      `--materialize ${JSON.stringify(key)}: that is not a valid variable name, so it cannot be the key of a secret.`,
    );
  }
  if (at === -1) return { key, path: null };
  const path = raw.slice(at + 1).trim();
  if (!path) return { key, path: null };
  return { key, path };
}

/** A leading `~` is the user's home; anything else is taken as written. */
function expandHome(path: string): string {
  if (path === "~") return homedir();
  if (path.startsWith("~/")) return join(homedir(), path.slice(2));
  return path;
}

/**
 * What each spec will do, for the approval dialog — with no filesystem effect.
 *
 * Kept separate from materialize() so the human is asked *before* any plaintext
 * is written, and so the check that each named secret exists happens before a
 * dialog rather than after it.
 */
export function describeMaterialize(specs: MaterializeSpec[], secrets: Record<string, string>): string[] {
  return specs.map((spec) => {
    if (secrets[spec.key] === undefined) {
      throw new ValidationError(
        `--materialize ${spec.key}: no such secret in the sets being used. ` +
          `Use hush ls <set> to see the names that exist.`,
      );
    }
    const where = spec.path === null ? "a private temporary path" : expandHome(spec.path);
    return `${spec.key} -> ${where}`;
  });
}

/** True when the mode says anyone on the machine may write here. */
function worldWritable(path: string): boolean {
  try {
    return (statSync(path).mode & 0o002) !== 0;
  } catch {
    return false;
  }
}

/**
 * Write each requested secret to its path and return the environment the child
 * should get.
 *
 * All or nothing: if the second file cannot be written, the first is removed
 * again rather than left on disk with a command that never ran.
 *
 * @param onWarn  Called for a condition worth saying out loud but not refusing
 *                over, e.g. a world-writable destination directory.
 */
export function materialize(
  specs: MaterializeSpec[],
  secrets: Record<string, string>,
  onWarn: (message: string) => void = () => {},
): Materialized {
  const env: Record<string, string> = {};
  const written: string[] = [];
  const dirs: string[] = [];

  const cleanup = (): void => {
    for (const path of written.splice(0)) {
      try {
        unlinkSync(path);
      } catch {
        /* already gone, or never created */
      }
    }
    for (const dir of dirs.splice(0)) {
      try {
        rmdirSync(dir);
      } catch {
        /* not empty, or already gone */
      }
    }
  };

  try {
    for (const spec of specs) {
      const value = secrets[spec.key];
      if (value === undefined) {
        // Naming the key is the whole value of the message: it is nearly always
        // a set the caller forgot to pass, not a missing secret.
        throw new ValidationError(
          `--materialize ${spec.key}: no such secret in the sets being used. ` +
            `Use hush ls <set> to see the names that exist.`,
        );
      }

      let target: string;
      if (spec.path === null) {
        const dir = mkdtempSync(join(tmpdir(), "hush-"));
        chmodSync(dir, 0o700);
        dirs.push(dir);
        target = join(dir, spec.key.toLowerCase());
      } else {
        target = expandHome(spec.path);
      }

      // A directory is never a destination; without this the failure would be
      // EISDIR from deep inside an open() call.
      let isDir = false;
      try {
        isDir = statSync(target).isDirectory();
      } catch {
        isDir = false;
      }
      if (isDir) {
        throw new ValidationError(`--materialize ${spec.key}=${target}: that is a directory, not a file.`);
      }

      if (spec.path !== null) {
        const parent = target.slice(0, target.lastIndexOf("/")) || ".";
        if (worldWritable(parent)) {
          onWarn(
            `${parent} is world-writable, so the file hush writes there can be read by other users ` +
              `while ${spec.key} runs. Prefer --materialize ${spec.key} with no path.`,
          );
        }
      }

      // "wx": fail if anything is already at this path. A symlink planted
      // there is a refusal, not a write through to wherever it points.
      let fd: number;
      try {
        fd = openSync(target, "wx", 0o600);
      } catch (e) {
        const code = (e as { code?: string }).code;
        if (code === "EEXIST") {
          throw new ValidationError(
            `--materialize ${spec.key}=${target}: something is already there. hush will not overwrite it ` +
              `(and will not follow a symlink placed at that path).`,
          );
        }
        throw new ValidationError(`--materialize ${spec.key}=${target}: ${(e as Error).message}`);
      }

      try {
        writeFileSync(fd, value);
      } finally {
        closeSync(fd);
      }
      written.push(target);
      env[spec.key] = target;
    }
  } catch (e) {
    cleanup();
    throw e;
  }

  return { env, written, cleanup };
}
