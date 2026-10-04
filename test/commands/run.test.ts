/**
 * `hush run`, `hush dev`, pass-through and `--materialize`.
 */
import { test, describe } from "node:test";
import { join, dirname } from "node:path";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync, chmodSync } from "node:fs";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { project } from "../helpers/cli.ts";

describe("hush run and .env.schema", () => {
  function echoScript(p: ReturnType<typeof project>, body = 'echo "val=$STRIPE_SECRET_KEY"'): string {
    const path = join(p.root, "echo.sh");
    writeFileSync(path, `#!/bin/sh\n${body}\n`);
    chmodSync(path, 0o755);
    return "./echo.sh";
  }

  test("a value of the wrong shape stops the run before anything is spawned", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.schema"), "# @type=string(startsWith=pk-)\nSTRIPE_SECRET_KEY=\n");
      const r = p.run(["run", "--", echoScript(p)]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /STRIPE_SECRET_KEY does not start with "pk-"/);
      assert.match(r.out, /\.env\.schema rejected 1 value/);
      assert.doesNotMatch(r.out, /val=/, "the command ran despite the schema");
    } finally {
      p.cleanup();
    }
  });

  test("a schema that accepts the value does not get in the way", () => {
    const p = project();
    try {
      // The fixture value is sk_live_cli, so the accepted prefix is sk_.
      writeFileSync(join(p.root, ".env.schema"), "# @type=string(startsWith=sk_)\nSTRIPE_SECRET_KEY=\n");
      const r = p.run(["run", "--", echoScript(p)]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /\[redacted:STRIPE_SECRET_KEY\]/);
    } finally {
      p.cleanup();
    }
  });

  test("--no-validate runs anyway, because it is the user's own schema", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.schema"), "# @type=string(startsWith=pk-)\nSTRIPE_SECRET_KEY=\n");
      const r = p.run(["run", "--no-validate", "--", echoScript(p)]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /\[redacted:STRIPE_SECRET_KEY\]/);
    } finally {
      p.cleanup();
    }
  });

  test("a repo-supplied @sensitive=false cannot unmask a value on its own", () => {
    // The masking decision is the user's, not the repository's. Before this,
    // one line in a committed .env.schema took a key out of the redactor, so a
    // repo (or an agent with repo write access) could read a value it was only
    // supposed to be able to use.
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.schema"), "# @sensitive=false\nSTRIPE_SECRET_KEY=\n");
      const r = p.run(["run", "--", echoScript(p)]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /\[redacted:STRIPE_SECRET_KEY\]/, "a repo-supplied @sensitive=false unmasked a value");
      assert.match(r.out, /asks to leave STRIPE_SECRET_KEY unmasked/);
    } finally {
      p.cleanup();
    }
  });

  test("the user's own floor can allow an unmask", () => {
    // The bit still exists for what it was for: NODE_ENV=production showing as
    // [redacted:…] on every line is how people learn to ignore the mask.
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.schema"), "# @sensitive=false\nSTRIPE_SECRET_KEY=\n");
      writeFileSync(join(p.home, "policy.json"), JSON.stringify({ unmaskKeys: ["STRIPE_SECRET_KEY"] }));
      // The project asks for no approvals, so the run itself is not gated; the
      // floor's unmaskKeys is the thing under test, not the approval path.
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: [] }));
      const r = p.run(["run", "--", echoScript(p)]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /val=sk_live_cli/, "the user's own unmaskKeys entry was ignored");
      assert.doesNotMatch(r.out, /redacted/);
    } finally {
      p.cleanup();
    }
  });

  test("a schema violation in a key this run never uses does not block it", () => {
    const p = project();
    try {
      writeFileSync(
        join(p.root, ".env.schema"),
        "# @type=string(startsWith=sk_)\nSTRIPE_SECRET_KEY=\n\n# @type=url @required\nPROD_ONLY=\n",
      );
      const r = p.run(["run", "--", echoScript(p)]);
      assert.equal(r.code, 0, r.out);
    } finally {
      p.cleanup();
    }
  });

  test("doctor reports the schema, and names the values that do not match", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.schema"), "# @type=string(startsWith=pk-)\nSTRIPE_SECRET_KEY=\n");
      const r = p.run(["doctor"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /\.env\.schema\s+1 value\(s\) do not match/);
      assert.match(r.out, /STRIPE_SECRET_KEY does not start with "pk-"/);
      assert.doesNotMatch(r.out, /sk_live_cli/, "doctor printed the value");
    } finally {
      p.cleanup();
    }
  });

  test("a malformed schema is an error with a line number, not a silent no-op", () => {
    const p = project();
    try {
      writeFileSync(join(p.root, ".env.schema"), "# @type=url\n# @required\n");
      const r = p.run(["run", "--", echoScript(p)]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /not attached to any variable/);
    } finally {
      p.cleanup();
    }
  });
});

describe("pass-through", () => {
  test("an unrecognised command on PATH runs through hush run, injected and redacted", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=passthroughvalue"]).code, 0);
      const r = p.run(["sh", "-c", "echo $FAL_KEY"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /\[redacted:FAL_KEY\]/, r.out);
      assert.ok(!r.out.includes("passthroughvalue"), "a live value leaked");
    } finally {
      p.cleanup();
    }
  });

  test("`hush ls` is never /bin/ls: a known command always wins over pass-through", () => {
    const p = project();
    try {
      const r = p.run(["ls"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /YOUR LIBRARY/);
      assert.match(r.out, /THIS PROJECT/);
      assert.ok(!/\.hush\b/.test(r.out), "looked like a directory listing, not hush's ls");
    } finally {
      p.cleanup();
    }
  });

  test("an unknown, non-existent command exits 1 with Unknown command", () => {
    const p = project();
    try {
      const r = p.run(["definitely-not-a-real-command-xyz"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /Unknown command/);
    } finally {
      p.cleanup();
    }
  });
});

describe("hush dev", () => {
  // node, npm, pnpm and yarn all live under the same directory as the running
  // node binary on a typical nvm install; bun does not. Restricting PATH to
  // that directory plus the base system bins (for `sh`, which npm's own
  // script runner shells out to) gives every test a real npm and a
  // guaranteed-absent bun, deterministically, rather than depending on what
  // happens to be installed on whichever machine runs the suite.
  const NODE_BIN_DIR = `${dirname(process.execPath)}:/usr/bin:/bin`;

  test("no lockfile runs the script via npm, injected and redacted", () => {
    const p = project({ PATH: NODE_BIN_DIR });
    try {
      assert.equal(p.run(["add", "FAL_KEY=devkeyvalue"]).code, 0);
      writeFileSync(
        join(p.root, "package.json"),
        JSON.stringify({ scripts: { dev: "sh -c 'echo DEV $FAL_KEY'" } }),
      );
      const r = p.run(["dev"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /DEV/);
      assert.match(r.out, /\[redacted:FAL_KEY\]/, r.out);
    } finally {
      p.cleanup();
    }
  });

  test("no lockfile picks npm specifically, not just whichever package manager is on PATH", () => {
    // A fake npm ahead of the real one on PATH proves *which* program was
    // picked — pnpm and yarn can both run a plain npm script perfectly well
    // with no lockfile of their own, so a test that only checks the script
    // ran would pass identically whichever one hush chose.
    const fakeBin = mkdtempSync(join(tmpdir(), "hush-fake-npm-"));
    writeFileSync(join(fakeBin, "npm"), '#!/bin/sh\necho FAKE_NPM_INVOKED "$@"\n', { mode: 0o755 });
    const p = project({ PATH: `${fakeBin}:${NODE_BIN_DIR}` });
    try {
      writeFileSync(join(p.root, "package.json"), JSON.stringify({ scripts: { dev: "true" } }));
      const r = p.run(["dev"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /FAKE_NPM_INVOKED run dev/, `npm was not the program invoked:\n${r.out}`);
    } finally {
      rmSync(fakeBin, { recursive: true, force: true });
      p.cleanup();
    }
  });

  test("a bun.lock with no bun on PATH names bun in the error", () => {
    const p = project({ PATH: NODE_BIN_DIR });
    try {
      writeFileSync(join(p.root, "package.json"), JSON.stringify({ scripts: { dev: "true" } }));
      writeFileSync(join(p.root, "bun.lock"), "");
      const r = p.run(["dev"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /bun/);
    } finally {
      p.cleanup();
    }
  });

  test("no package.json suggests hush run --", () => {
    const p = project({ PATH: NODE_BIN_DIR });
    try {
      const r = p.run(["dev"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /hush run --/);
    } finally {
      p.cleanup();
    }
  });
});

describe("pass-through by path", () => {
  // Bites: an onPath() that only walks PATH never finds "./dev.sh", so the
  // most natural thing to type after `hush` is "Unknown command".
  test("hush ./script.sh runs a script by relative path, injected and redacted", () => {
    const p = project();
    try {
      assert.equal(p.run(["add", "FAL_KEY=pathvalue"]).code, 0);
      writeFileSync(join(p.root, "dev.sh"), "#!/bin/sh\necho $FAL_KEY\n", { mode: 0o755 });
      const r = p.run(["./dev.sh"]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /\[redacted:FAL_KEY\]/, r.out);
      assert.ok(!r.out.includes("pathvalue"), "a live value leaked");
    } finally {
      p.cleanup();
    }
  });
});

describe("hush run --materialize", () => {
  /**
   * A script rather than `node -e`: with a policy file present the interpreter
   * deny list applies, and the documented way through it is a script, which is
   * also what a real project would have.
   */
  function script(p: ReturnType<typeof project>): string {
    const path = join(p.root, "show.sh");
    writeFileSync(path, '#!/bin/sh\necho "path=$STRIPE_SECRET_KEY"\ncat "$STRIPE_SECRET_KEY"\n');
    chmodSync(path, 0o755);
    return "./show.sh";
  }

  test("the child gets the path, the file holds the value, and it is gone afterwards", () => {
    const p = project();
    try {
      const r = p.run(["run", "--materialize", "STRIPE_SECRET_KEY", "--", script(p)]);
      assert.equal(r.code, 0, r.out);
      // The child saw a path, not the value...
      const shown = r.out.match(/path=(\S+)/);
      assert.ok(shown, `the script never printed the path:\n${r.out}`);
      assert.match(shown[1], /hush-/);
      // ...and the value stays masked in the output, because the key remained
      // in the redaction set even though it left the environment.
      assert.doesNotMatch(r.out, /service_account/, "reading the file leaked the value into output");
      assert.match(r.out, /\[redacted:STRIPE_SECRET_KEY\]/);
      assert.equal(existsSync(shown[1]), false, "the materialised file outlived the command");
    } finally {
      p.cleanup();
    }
  });

  test("the file is removed even when the child fails", () => {
    const p = project();
    try {
      const path = join(p.root, "boom.sh");
      writeFileSync(path, '#!/bin/sh\necho "path=$STRIPE_SECRET_KEY"\nexit 3\n');
      chmodSync(path, 0o755);
      const r = p.run(["run", "--materialize", "STRIPE_SECRET_KEY", "--", "./boom.sh"]);
      assert.equal(r.code, 3, r.out);
      const shown = r.out.match(/path=(\S+)/);
      assert.ok(shown, r.out);
      assert.equal(existsSync(shown[1]), false, "a failed command left the credential on disk");
    } finally {
      p.cleanup();
    }
  });

  test("an explicit path is used as given, and refused if something is there", () => {
    const p = project();
    try {
      const target = join(p.root, "sa.json");

      const ok = p.run(["run", "--materialize", `STRIPE_SECRET_KEY=${target}`, "--", script(p)]);
      assert.equal(ok.code, 0, ok.out);
      assert.equal(existsSync(target), false, "the explicit file was not cleaned up");

      writeFileSync(target, "DO NOT TOUCH");
      const clash = p.run(["run", "--materialize", `STRIPE_SECRET_KEY=${target}`, "--", script(p)]);
      assert.equal(clash.code, 1, clash.out);
      assert.match(clash.out, /something is already there/);
      assert.equal(readFileSync(target, "utf8"), "DO NOT TOUCH", "an existing file was overwritten");
    } finally {
      p.cleanup();
    }
  });

  test("a key that is not in the sets is refused before anything runs", () => {
    const p = project();
    try {
      const r = p.run(["run", "--materialize", "NOPE", "--", script(p)]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /--materialize NOPE: no such secret/);
      assert.doesNotMatch(r.out, /path=/, "the command ran anyway");
    } finally {
      p.cleanup();
    }
  });

  test("materialising is gated on reveal, not on run", () => {
    // The whole design decision: this writes plaintext to a path the caller
    // chose, so it needs the approval `hush get` needs, not the one `hush run`
    // needs. A policy that gates only `run` must not be enough.
    const p = project();
    try {
      writeFileSync(
        join(p.hushDir, "policy.json"),
        JSON.stringify({ requireApproval: ["reveal"], approvalTimeoutSeconds: 1 }),
      );
      const r = p.run(["run", "--materialize", "STRIPE_SECRET_KEY", "--", script(p)]);
      assert.equal(r.code, 1, `a reveal-gated materialise ran unattended:\n${r.out}`);
      assert.doesNotMatch(r.out, /path=/, "the command ran despite the reveal gate");
    } finally {
      p.cleanup();
    }
  });

  test("with no gate at all, it runs unattended like any other run", () => {
    // The other direction of the same decision, so the gate cannot silently
    // become "everything" or "nothing".
    const p = project();
    try {
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: [] }));
      const r = p.run(["run", "--materialize", "STRIPE_SECRET_KEY", "--", script(p)]);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /path=/);
    } finally {
      p.cleanup();
    }
  });
});

describe("hush run --no-redact (review F7)", () => {
  test("turning masking off is gated like a reveal, even where plain runs are not", () => {
    const p = project();
    try {
      const path = join(p.root, "show.sh");
      writeFileSync(path, '#!/bin/sh\necho "value=$STRIPE_SECRET_KEY"\n');
      chmodSync(path, 0o755);
      writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: ["reveal"], approvalTimeoutSeconds: 1 }));
      const masked = p.run(["run", "--", "./show.sh"]);
      assert.equal(masked.code, 0, masked.out);
      assert.match(masked.out, /value=\[redacted:STRIPE_SECRET_KEY\]/);
      const unmasked = p.run(["run", "--no-redact", "--", "./show.sh"]);
      assert.notEqual(unmasked.code, 0, `--no-redact ran with nobody asked:\n${unmasked.out}`);
      assert.doesNotMatch(unmasked.out, /value=/, "the command ran despite the gate");
    } finally {
      p.cleanup();
    }
  });
});

describe("a run leaves no value on disk", () => {
  // The invariant ARCHITECTURE.md names: the value exists in the child's
  // environment and hush's memory, and nowhere a file could hold it. The child
  // itself looks — while the run is live, which is when a temp file would exist
  // — through the project, HUSH_HOME and anything new in the temp directory.
  test("while the command runs, no file under the project, HUSH_HOME or tmp holds the value", () => {
    const p = project();
    try {
      const probe = join(p.root, "probe.mjs");
      writeFileSync(
        probe,
        `import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
const value = process.env.STRIPE_SECRET_KEY;
if (!value) { console.log("no value injected"); process.exit(2); }
const since = Number(process.argv[2]);
let hits = 0, looked = 0;
function walk(dir, onlyNew) {
  let names = [];
  try { names = readdirSync(dir); } catch { return; }
  for (const name of names) {
    const path = join(dir, name);
    let st;
    try { st = statSync(path); } catch { continue; }
    if (st.isDirectory()) { if (!onlyNew || st.mtimeMs >= since) walk(path, onlyNew); continue; }
    if (onlyNew && st.mtimeMs < since) continue;
    if (st.size > 1 << 20 || path === ${JSON.stringify(probe)}) continue;
    looked++;
    try { if (readFileSync(path).includes(value)) hits++; } catch {}
  }
}
for (const d of process.argv.slice(3, -1)) walk(d, false);
walk(process.argv.at(-1), true);
console.log("looked=" + looked + " hits=" + hits);
`,
      );
      const r = p.run(["run", "--", process.execPath, probe, String(Date.now() - 1000), p.root, p.home, tmpdir()]);
      assert.equal(r.code, 0, r.out);
      const m = /looked=(\d+) hits=(\d+)/.exec(r.out);
      assert.ok(m, r.out);
      assert.ok(Number(m[1]) > 0, "the probe looked at nothing");
      assert.equal(m[2], "0", "a file on disk holds the injected value during the run");
    } finally {
      p.cleanup();
    }
  });
});
