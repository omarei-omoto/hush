/**
 * `--materialize` — writing one credential to a path, and taking it away again.
 *
 * The refusal cases matter as much as the happy path: the whole reason this is
 * gated as a reveal is that it puts plaintext somewhere the caller chose, so
 * "will not overwrite" and "will not follow a symlink" are load-bearing.
 */
import { test, describe, after } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync, existsSync, readFileSync, statSync, symlinkSync, writeFileSync, chmodSync, rmSync,
} from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";

import { parseMaterializeSpec, describeMaterialize, materialize } from "../src/materialize.ts";

const dirs: string[] = [];
function scratch(): string {
  const d = mkdtempSync(join(tmpdir(), "hush-mat-test-"));
  dirs.push(d);
  return d;
}

after(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("parseMaterializeSpec", () => {
  test("KEY alone means hush chooses the path", () => {
    assert.deepEqual(parseMaterializeSpec("GOOGLE_APPLICATION_CREDENTIALS"), {
      key: "GOOGLE_APPLICATION_CREDENTIALS",
      path: null,
    });
  });

  test("KEY=path pins the path, including one containing =", () => {
    assert.deepEqual(parseMaterializeSpec("KUBECONFIG=/tmp/a=b/config"), {
      key: "KUBECONFIG",
      path: "/tmp/a=b/config",
    });
  });

  test("KEY= with nothing after it is the same as KEY alone", () => {
    assert.deepEqual(parseMaterializeSpec("KUBECONFIG="), { key: "KUBECONFIG", path: null });
  });

  test("a key that is not a variable name is refused by name", () => {
    assert.throws(() => parseMaterializeSpec("not a key=/tmp/x"), /not a valid variable name/);
    assert.throws(() => parseMaterializeSpec("=/tmp/x"), /Bad --materialize/);
  });
});

describe("describeMaterialize", () => {
  test("names each secret and where it would go, without writing anything", () => {
    const target = join(scratch(), "sa.json");
    const lines = describeMaterialize([{ key: "GCP_SA", path: target }], { GCP_SA: "{}" });
    assert.deepEqual(lines, [`GCP_SA -> ${target}`]);
    assert.equal(existsSync(target), false, "describing wrote a file");
  });

  test("says so when hush is choosing the path", () => {
    const lines = describeMaterialize([{ key: "GCP_SA", path: null }], { GCP_SA: "{}" });
    assert.match(lines[0], /GCP_SA -> a private temporary path/);
  });

  test("a key that is not in the sets is refused before any dialog", () => {
    assert.throws(() => describeMaterialize([{ key: "NOPE", path: null }], {}), /no such secret/);
  });
});

describe("materialize", () => {
  test("writes the value to an explicit path at 0600, and hands back the path", () => {
    const target = join(scratch(), "sa.json");
    const files = materialize([{ key: "GCP_SA", path: target }], { GCP_SA: '{"a":1}' });
    try {
      assert.equal(readFileSync(target, "utf8"), '{"a":1}');
      assert.equal(statSync(target).mode & 0o777, 0o600, "the file is not 0600");
      assert.deepEqual(files.env, { GCP_SA: target });
      assert.deepEqual(files.written, [target]);
    } finally {
      files.cleanup();
    }
    assert.equal(existsSync(target), false, "cleanup left the file behind");
  });

  test("with no path, it uses a 0700 directory and removes the directory too", () => {
    const files = materialize([{ key: "KUBECONFIG", path: null }], { KUBECONFIG: "apiVersion: v1" });
    const path = files.env.KUBECONFIG;
    const dir = path.slice(0, path.lastIndexOf("/"));
    try {
      assert.equal(readFileSync(path, "utf8"), "apiVersion: v1");
      assert.equal(statSync(path).mode & 0o777, 0o600);
      assert.equal(statSync(dir).mode & 0o777, 0o700, "the temporary directory is not 0700");
      assert.match(dir, /hush-/);
    } finally {
      files.cleanup();
    }
    assert.equal(existsSync(path), false, "cleanup left the file behind");
    assert.equal(existsSync(dir), false, "cleanup left the directory behind");
  });

  test("refuses to overwrite an existing file, and leaves it alone", () => {
    const target = join(scratch(), "existing");
    writeFileSync(target, "ORIGINAL");
    assert.throws(
      () => materialize([{ key: "K", path: target }], { K: "NEW" }),
      /something is already there/,
    );
    assert.equal(readFileSync(target, "utf8"), "ORIGINAL");
  });

  test("refuses a planted symlink and does not write through it", () => {
    // The attack "wx" exists for: point the path at a file the attacker wants
    // overwritten, and let the write follow the link.
    const dir = scratch();
    const real = join(dir, "real.txt");
    const link = join(dir, "link.json");
    writeFileSync(real, "ORIGINAL");
    symlinkSync(real, link);

    assert.throws(() => materialize([{ key: "K", path: link }], { K: "NEW" }), /already there/);
    assert.equal(readFileSync(real, "utf8"), "ORIGINAL", "the symlink was followed");
  });

  test("refuses a directory as the target", () => {
    const dir = scratch();
    assert.throws(() => materialize([{ key: "K", path: dir }], { K: "v" }), /that is a directory/);
  });

  test("a missing key fails and takes back the file it already wrote", () => {
    const target = join(scratch(), "first.json");
    assert.throws(
      () => materialize(
        [{ key: "FIRST", path: target }, { key: "MISSING", path: null }],
        { FIRST: "one" },
      ),
      /--materialize MISSING: no such secret in the sets being used/,
    );
    assert.equal(existsSync(target), false, "the first file was left behind after a later failure");
  });

  test("cleanup is safe to run more than once", () => {
    const target = join(scratch(), "once.json");
    const files = materialize([{ key: "K", path: target }], { K: "v" });
    files.cleanup();
    files.cleanup();
    assert.equal(existsSync(target), false);
  });

  test("warns when the destination directory is world-writable", () => {
    const dir = scratch();
    chmodSync(dir, 0o777);
    const warnings: string[] = [];
    const files = materialize([{ key: "K", path: join(dir, "x") }], { K: "v" }, (m) => warnings.push(m));
    try {
      assert.equal(warnings.length, 1);
      assert.match(warnings[0], /world-writable/);
      assert.match(warnings[0], /--materialize K with no path/, "the warning does not say what to do instead");
    } finally {
      files.cleanup();
    }
  });

  test("a leading ~ is the home directory", () => {
    const files = materialize([{ key: "K", path: "~/hush-materialize-test-does-not-exist" }], { K: "v" });
    try {
      assert.equal(files.env.K, join(homedir(), "hush-materialize-test-does-not-exist"));
    } finally {
      files.cleanup();
    }
  });
});
