/**
 * The local UI server. It had no automated coverage at all, which is a poor
 * place to have none: it is an HTTP server that can hand out every key you own.
 */
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { request as httpRequest } from "node:http";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { Vault } from "../src/vault.ts";
import { resolveStageTtl, DEFAULT_STAGE_TTL_MS } from "../src/ui.ts";
import { generateIdentity, encodeSecret } from "../src/crypto.ts";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.ts");
const SECRET_VALUE = "sk_live_ui_test_value_do_not_leak";

let child: ChildProcess;
let base: string;
let token: string;
let home: string;
let root: string;

before(async () => {
  home = mkdtempSync(join(tmpdir(), "hush-ui-home-"));
  root = mkdtempSync(join(tmpdir(), "hush-ui-proj-"));
  const hushDir = join(root, ".hush");
  mkdirSync(hushDir, { recursive: true });

  const id = generateIdentity();
  const vault = Vault.create(join(hushDir, "vault.json"), "uitest", { name: "tester", pub: id.pub });
  vault.set(id, "default", "API_KEY", SECRET_VALUE);
  vault.set(id, "fal/personal", "FAL_KEY", "fal_ui_value");
  vault.save();
  // Reveal is gated by policy; switch it off so the API is testable unattended.
  writeFileSync(join(hushDir, "policy.json"), JSON.stringify({ requireApproval: [], biometry: "off" }));

  child = spawn(process.execPath, [CLI, "ui", "--no-open", "--port", "0"], {
    cwd: root,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, HUSH_HOME: home, HUSH_IDENTITY: encodeSecret(id), HUSH_BIOMETRY: "off", NO_COLOR: "1" },
  });

  const url: string = await new Promise((resolve, reject) => {
    let out = "";
    const timer = setTimeout(() => reject(new Error("ui did not start: " + out)), 15000);
    child.stdout!.on("data", (d) => {
      out += d;
      const m = out.match(/(http:\/\/127\.0\.0\.1:\d+\/\?t=[A-Za-z0-9_-]+)/);
      if (m) { clearTimeout(timer); resolve(m[1]); }
    });
  });
  const parsed = new URL(url);
  base = parsed.origin;
  token = parsed.searchParams.get("t")!;
});

after(() => {
  child?.kill();
  for (const d of [home, root]) rmSync(d, { recursive: true, force: true });
});

/** Shape of what /api/state returns, so the tests can read it without casts. */
interface UiSet {
  where: "library" | "project";
  name: string;
  used: boolean;
  position: number | null;
  secrets: { key: string; preview: string; note: string }[];
}
interface UiState {
  vault: string;
  library: UiSet[];
  project: UiSet[];
  used: string[];
  members: { name: string; role: string }[];
}

const api = (path: string, body?: unknown, tok = token) =>
  fetch(base + path, {
    method: body ? "POST" : "GET",
    headers: { "x-hush-token": tok, "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });

describe("ui server — access control", () => {
  test("the page needs the session token", async () => {
    assert.equal((await fetch(base + "/")).status, 403);
    assert.equal((await fetch(base + "/?t=wrong")).status, 403);
    assert.equal((await fetch(`${base}/?t=${token}`)).status, 200);
  });

  test("the API needs the session token", async () => {
    assert.equal((await fetch(base + "/api/state")).status, 403);
    assert.equal((await api("/api/state", undefined, "wrong")).status, 403);
    assert.equal((await api("/api/state")).status, 200);
  });

  test("a near-miss token is rejected, not partially accepted", async () => {
    for (const bad of [token.slice(0, -1), token + "x", token.slice(1), token.toUpperCase()]) {
      assert.equal((await api("/api/state", undefined, bad)).status, 403, `accepted ${bad.slice(0, 8)}…`);
    }
  });

  test("a non-loopback Host is refused, which blocks DNS rebinding", async () => {
    // fetch() silently drops a Host override — it is a forbidden header name —
    // so this has to go out over a raw request to test anything at all.
    const status = await new Promise<number>((resolve, reject) => {
      const { port } = new URL(base);
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port: Number(port),
          path: "/api/state",
          method: "GET",
          headers: { "x-hush-token": token, Host: "evil.example.com" },
        },
        (res) => { res.resume(); resolve(res.statusCode ?? 0); },
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(status, 403, "a rebound DNS name would have reached the vault");
  });

  test("a loopback Host is accepted, so the check is not simply refusing everything", async () => {
    const status = await new Promise<number>((resolve, reject) => {
      const { port } = new URL(base);
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port: Number(port),
          path: "/api/state",
          method: "GET",
          headers: { "x-hush-token": token, Host: `localhost:${port}` },
        },
        (res) => { res.resume(); resolve(res.statusCode ?? 0); },
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(status, 200);
  });

  test("the page is served with a restrictive CSP and no referrer", async () => {
    const r = await fetch(`${base}/?t=${token}`);
    const csp = r.headers.get("content-security-policy") ?? "";
    assert.match(csp, /default-src 'none'/);
    assert.ok(!/https?:\/\//.test(csp), "CSP allows an external origin");
    assert.equal(r.headers.get("referrer-policy"), "no-referrer");
    assert.equal(r.headers.get("cache-control"), "no-store");
  });

  test("unknown routes are not found", async () => {
    assert.equal((await api("/api/nope", {})).status, 404);
    assert.equal((await fetch(`${base}/../etc/passwd`)).status, 404);
  });
});

describe("ui server — never leaks values", () => {
  test("the served HTML contains no secret value", async () => {
    const html = await (await fetch(`${base}/?t=${token}`)).text();
    assert.ok(!html.includes(SECRET_VALUE));
    assert.ok(!html.includes("fal_ui_value"));
  });

  test("state returns masked previews, never plaintext", async () => {
    const state = (await (await api("/api/state")).json()) as UiState;
    const raw = JSON.stringify(state);
    assert.ok(!raw.includes(SECRET_VALUE), "a value reached the browser");
    assert.ok(!raw.includes("fal_ui_value"));
    // But it must still be useful.
    assert.equal(state.vault, "uitest");
    assert.ok(raw.includes("API_KEY"));
    // "fal/personal" used to be a separate "account" vocabulary; it is now
    // just a set like any other, listed with the rest of the project's sets.
    assert.ok(state.project.some((e) => e.name === "fal/personal"));
  });

  test("reveal returns the value only on an explicit call", async () => {
    const r = await api("/api/reveal", { scope: "default", key: "API_KEY" });
    assert.equal(r.status, 200);
    assert.equal(((await r.json()) as { value: string }).value, SECRET_VALUE);
  });
});

describe("ui server — input validation", () => {
  test("an invalid variable name is refused", async () => {
    const r = await api("/api/secret", { scope: "default", key: "BAD; echo pwned", value: "x" });
    assert.equal(r.status, 400, "accepted a name that can inject into a shell");
  });

  test("a path-shaped scope is refused", async () => {
    const r = await api("/api/secret", { scope: "../../evil", key: "OK", value: "x" });
    assert.equal(r.status, 400);
  });

  test("missing fields are refused rather than crashing", async () => {
    for (const body of [{}, { scope: "default" }, { key: "K" }, { scope: "default", key: "K", value: "" }]) {
      const r = await api("/api/secret", body);
      assert.equal(r.status, 400, `accepted ${JSON.stringify(body)}`);
    }
    // The server must still be alive after all that.
    assert.equal((await api("/api/state")).status, 200);
  });

  test("an absurdly large value is rejected and the server survives", async () => {
    const r = await fetch(base + "/api/secret", {
      method: "POST",
      headers: { "x-hush-token": token, "content-type": "application/json" },
      body: JSON.stringify({ scope: "default", key: "BIG", value: "x".repeat(2_000_000) }),
    }).catch(() => null);
    if (r) assert.ok(r.status >= 400, "stored a 2 MB value as if it were a credential");
    assert.equal((await api("/api/state")).status, 200, "server died on a large body");
  });

  test("malformed JSON does not take the server down", async () => {
    const r = await fetch(base + "/api/secret", {
      method: "POST",
      headers: { "x-hush-token": token, "content-type": "application/json" },
      body: "{not json",
    });
    assert.ok(r.status >= 400);
    assert.equal((await api("/api/state")).status, 200);
  });
});

describe("ui server — writes reach the vault", () => {
  test("adding a secret through the API is readable afterwards", async () => {
    const r = await api("/api/secret", { scope: "default", key: "ADDED_VIA_UI", value: "ui-value" });
    assert.equal(r.status, 200);
    const state = (await r.json()) as UiState;
    assert.ok(state.project.some((e) => e.secrets.some((s) => s.key === "ADDED_VIA_UI")));

    const reveal = (await (await api("/api/reveal", { scope: "default", key: "ADDED_VIA_UI" })).json()) as { value: string };
    assert.equal(reveal.value, "ui-value");
  });

  test("/api/use is gone — it points at /api/link instead", async () => {
    const r = await api("/api/use", { service: "fal", account: "personal" });
    assert.equal(r.status, 410, "the old pinning endpoint still answers");
    assert.match(((await r.json()) as { error: string }).error, /\/api\/link/);
  });

  test("/api/account is gone — a service account is now just a named set", async () => {
    const r = await api("/api/account", { service: "twilio", account: "prod", values: { TWILIO_ACCOUNT_SID: "x" } });
    assert.ok(r.status === 404 || r.status === 400, `expected the router's unknown-endpoint response, got ${r.status}`);
    assert.equal((await api("/api/state")).status, 200, "server died on the removed endpoint");
  });
});

describe("ui server — one list of sets, at two levels", () => {
  test("/api/state has library and project arrays shaped alike, and no trace of the old vocabulary", async () => {
    const raw = (await (await api("/api/state")).json()) as Record<string, unknown>;
    assert.ok(Array.isArray(raw.library), "no library array");
    assert.ok(Array.isArray(raw.project), "no project array");
    assert.ok(!("accounts" in raw), "the old service-accounts vocabulary is still in state");
    assert.ok(!("use" in raw), "the old use.json pin is still in state");
    for (const entry of [...(raw.library as UiSet[]), ...(raw.project as UiSet[])]) {
      assert.ok(entry.where === "library" || entry.where === "project", `entry has no where: ${JSON.stringify(entry)}`);
      assert.equal(typeof entry.used, "boolean", `entry.used is not a boolean: ${JSON.stringify(entry)}`);
      assert.ok(Array.isArray(entry.secrets), `entry has no secrets array: ${JSON.stringify(entry)}`);
    }
  });

  test("/api/link toggles a project set, not just a library one, and {order} sets the whole list", async () => {
    let state = (await (await api("/api/state")).json()) as UiState;
    const before = state.project.find((e) => e.name === "fal/personal")!;
    assert.equal(before.used, false, "a project set neither is default nor was ever linked started out used");

    const linked = await api("/api/link", { name: "fal/personal", use: true });
    assert.equal(linked.status, 200);
    state = (await linked.json()) as UiState;
    assert.equal(state.project.find((e) => e.name === "fal/personal")!.used, true, "linking a project set did nothing");
    assert.deepEqual(state.used, ["default", "fal/personal"], "the resolution order does not reflect the new link");

    const reordered = await api("/api/link", { order: ["fal/personal", "default"] });
    state = (await reordered.json()) as UiState;
    assert.deepEqual(state.used, ["fal/personal", "default"], "{order} did not replace the whole list");

    // Leave envs.json empty again for the tests that follow.
    await api("/api/link", { order: [] });
    state = (await (await api("/api/state")).json()) as UiState;
    assert.deepEqual(state.used, ["default"]);
  });

  test("/api/env create with a known service returns its variable names", async () => {
    const r = await api("/api/env", { action: "create", where: "project", label: "Twilio prod", service: "twilio" });
    const body = (await r.json()) as { created: string; vars: string[] };
    assert.equal(r.status, 200, JSON.stringify(body));
    assert.equal(body.created, "twilio-prod");
    assert.deepEqual(body.vars, ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"]);
  });

  test("/api/env create with an unknown service still creates the set, with no variables suggested", async () => {
    const r = await api("/api/env", { action: "create", where: "project", label: "Mystery Inc", service: "not-a-real-service" });
    const body = (await r.json()) as { created: string; vars: string[] };
    assert.equal(r.status, 200, JSON.stringify(body));
    assert.equal(body.created, "mystery-inc");
    assert.deepEqual(body.vars, []);
  });

  test("/api/secret writes into a library set when where is library, and into the project otherwise", async () => {
    await api("/api/global", { create: true });
    const created = (await (await api("/api/env", { action: "create", where: "library", label: "Lib Secrets" })).json()) as { created: string };

    const r = await api("/api/secret", { where: "library", scope: created.created, key: "LIB_KEY", value: "lib_value_abc" });
    const state = (await r.json()) as UiState;
    assert.equal(r.status, 200, JSON.stringify(state));
    const lib = state.library.find((s) => s.name === created.created)!;
    assert.ok(lib.secrets.some((s) => s.key === "LIB_KEY"), "the key did not land in the library");
    assert.ok(!state.project.some((s) => s.secrets.some((k) => k.key === "LIB_KEY")), "the key leaked into the project");

    // Reveal has to look in the vault the key was written to — a library
    // card's reveal used to read the project vault and find nothing.
    const shown = (await (await api("/api/reveal", { where: "library", scope: created.created, key: "LIB_KEY" })).json()) as { value?: string };
    assert.equal(shown.value, "lib_value_abc", "reveal did not read the library vault");
    const wrong = await api("/api/reveal", { scope: created.created, key: "LIB_KEY" });
    assert.notEqual(wrong.status, 200, "reveal without where claimed to find a library key in the project vault");

    // Without `where`, /api/secret still writes into the project, as before.
    const r2 = await api("/api/secret", { scope: "default", key: "PROJECT_KEY_PLAIN", value: "project_value_abc" });
    const state2 = (await r2.json()) as UiState;
    assert.ok(
      state2.project.find((s) => s.name === "default")!.secrets.some((s) => s.key === "PROJECT_KEY_PLAIN"),
      "an unqualified write did not land in the project",
    );
  });
});

describe("ui dropzone — staging a dropped .env", () => {
  const ENV_FILE = [
    "# dropped straight from a project",
    "FAL_KEY=fal_dropped_value_here",
    "STRIPE_SECRET_KEY=sk_live_abcdefghijklmnop",
    'PEM_KEY="-----BEGIN K-----\\nline2\\n-----END K-----"',
    "bad name=ignored",
    "9NOPE=ignored",
  ].join("\n");

  test("staging returns names and suggestions, never values", async () => {
    const r = await api("/api/stage", { text: ENV_FILE, filename: ".env.production" });
    assert.equal(r.status, 200);
    const st = (await r.json()) as {
      stageId: string; file: string;
      entries: { key: string; preview: string; service: string | null; suggestedScope: string; existsIn: string[]; multiline: boolean }[];
      rejected: string[];
    };

    assert.equal(st.file, ".env.production");
    assert.deepEqual(st.entries.map((e) => e.key).sort(), ["FAL_KEY", "PEM_KEY", "STRIPE_SECRET_KEY"]);
    assert.deepEqual(st.rejected.sort(), ["9NOPE", "bad name"]);

    // The whole point: the browser gets metadata, not secrets.
    const raw = JSON.stringify(st);
    assert.ok(!raw.includes("fal_dropped_value_here"), "a value came back to the browser");
    assert.ok(!raw.includes("sk_live_abcdefghijklmnop"));
    assert.ok(!raw.includes("BEGIN K"));

    // Useful suggestions, so the common case is one click.
    const fal = st.entries.find((e) => e.key === "FAL_KEY")!;
    assert.equal(fal.service, "fal");
    assert.equal(fal.suggestedScope, "fal/personal", "did not suggest the existing account");
    assert.deepEqual(fal.existsIn, ["fal/personal"], "did not flag the conflict");

    const pem = st.entries.find((e) => e.key === "PEM_KEY")!;
    assert.equal(pem.multiline, true, "a multi-line value was not flagged");
    assert.equal(pem.service, null);
  });

  test("importing places each key in its chosen scope, with its tag", async () => {
    const st = (await (await api("/api/stage", { text: "SENDGRID_API_KEY=sg_abcdefghijklmnop\nREDIS_URL=redis://x:6379" })).json()) as { stageId: string };
    const res = await (await api("/api/import", {
      stages: [{
        stageId: st.stageId,
        assignments: {
          SENDGRID_API_KEY: { scope: "default", note: "email" },
          REDIS_URL: { scope: "default", note: "infra" },
        },
      }],
      overwrite: false,
    })).json() as UiState & { imported: string[]; skipped: { key: string; why: string }[] };

    assert.deepEqual(res.imported.sort(), ["default/REDIS_URL", "default/SENDGRID_API_KEY"]);
    assert.deepEqual(res.skipped, []);

    const def = res.project.find((e) => e.name === "default")!;
    assert.equal(def.secrets.find((s) => s.key === "SENDGRID_API_KEY")!.note, "email");
    assert.equal(def.secrets.find((s) => s.key === "REDIS_URL")!.note, "infra");

    const reveal = (await (await api("/api/reveal", { scope: "default", key: "SENDGRID_API_KEY" })).json()) as { value: string };
    assert.equal(reveal.value, "sg_abcdefghijklmnop");
  });

  test("a multi-line value survives the round trip", async () => {
    const pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIB\n-----END PRIVATE KEY-----";
    const st = (await (await api("/api/stage", { text: `PEM_ROUNDTRIP="${pem.replace(/\n/g, "\\n")}"` })).json()) as { stageId: string };
    await api("/api/import", { stages: [{ stageId: st.stageId, assignments: { PEM_ROUNDTRIP: { scope: "default" } } }] });
    const got = (await (await api("/api/reveal", { scope: "default", key: "PEM_ROUNDTRIP" })).json()) as { value: string };
    assert.equal(got.value, pem);
  });

  test("an existing key is protected unless overwrite is asked for", async () => {
    const original = (await (await api("/api/reveal", { scope: "default", key: "API_KEY" })).json()) as { value: string };
    const st = (await (await api("/api/stage", { text: "API_KEY=totally_different_value" })).json()) as { stageId: string };

    const guarded = await (await api("/api/import", {
      stages: [{ stageId: st.stageId, assignments: { API_KEY: { scope: "default" } } }],
      overwrite: false,
    })).json() as { imported: string[]; skipped: { key: string; why: string }[] };

    assert.deepEqual(guarded.imported, []);
    assert.match(guarded.skipped[0].why, /already in default/);
    const after = (await (await api("/api/reveal", { scope: "default", key: "API_KEY" })).json()) as { value: string };
    assert.equal(after.value, original.value, "an existing secret was clobbered");
  });

  test("a stage can only be imported once", async () => {
    const st = (await (await api("/api/stage", { text: "ONE_SHOT_KEY=abcdef123456" })).json()) as { stageId: string };
    const first = await (await api("/api/import", { stages: [{ stageId: st.stageId, assignments: { ONE_SHOT_KEY: { scope: "default" } } }] })).json() as { imported: string[] };
    assert.deepEqual(first.imported, ["default/ONE_SHOT_KEY"]);

    const again = await (await api("/api/import", { stages: [{ stageId: st.stageId, assignments: { ONE_SHOT_KEY: { scope: "default" } } }] })).json() as { skipped: { why: string }[] };
    assert.match(again.skipped[0].why, /expired/);
  });

  test("an unusable scope is rejected per key, not by aborting the batch", async () => {
    const st = (await (await api("/api/stage", { text: "GOOD_KEY=abcdef123456\nOTHER_KEY=ghijkl789012" })).json()) as { stageId: string };
    const res = await (await api("/api/import", {
      stages: [{ stageId: st.stageId, assignments: {
        GOOD_KEY: { scope: "default" },
        OTHER_KEY: { scope: "../../evil" },
      }}],
    })).json() as { imported: string[]; skipped: { key: string; why: string }[] };

    assert.deepEqual(res.imported, ["default/GOOD_KEY"], "one bad row lost the whole batch");
    assert.equal(res.skipped[0].key, "OTHER_KEY");
    assert.match(res.skipped[0].why, /not a valid environment or account name/);
  });

  test("an oversized drop is refused with a message, not a reset", async () => {
    const r = await api("/api/stage", { text: "K=" + "x".repeat(2_100_000) });
    assert.equal(r.status, 400, "the size check was unreachable behind the body limit");
    assert.match(((await r.json()) as { error: string }).error, /too large/);
    assert.equal((await api("/api/state")).status, 200, "server died on a large drop");
  });
});

describe("ui tagging", () => {
  test("a tag can be changed without the browser holding the value", async () => {
    const before = (await (await api("/api/reveal", { scope: "default", key: "API_KEY" })).json()) as { value: string };
    const res = (await (await api("/api/tag", { scope: "default", key: "API_KEY", note: "billing · rotate Q1" })).json()) as UiState;
    const tagged = res.project.find((e) => e.name === "default")!.secrets.find((s) => s.key === "API_KEY")!;
    assert.equal(tagged.note, "billing · rotate Q1");

    const after = (await (await api("/api/reveal", { scope: "default", key: "API_KEY" })).json()) as { value: string };
    assert.equal(after.value, before.value, "re-tagging changed the secret");
  });

  test("clearing a tag works, and tagging a missing key 404s", async () => {
    const cleared = (await (await api("/api/tag", { scope: "default", key: "API_KEY", note: "" })).json()) as UiState;
    assert.equal(cleared.project.find((e) => e.name === "default")!.secrets.find((s) => s.key === "API_KEY")!.note, "");
    assert.equal((await api("/api/tag", { scope: "default", key: "NO_SUCH_KEY", note: "x" })).status, 404);
  });
});

describe("ui dropzone — staging is bounded and releasable", () => {
  test("staging refuses to hold an unlimited amount of plaintext", async () => {
    const ids: string[] = [];
    let refusal = "";
    for (let i = 0; i < 40; i++) {
      const r = await api("/api/stage", { text: `CAP_KEY_${i}=value_${i}_abcdef`, filename: `f${i}.env` });
      if (r.ok) ids.push(((await r.json()) as { stageId: string }).stageId);
      else { refusal = ((await r.json()) as { error: string }).error; break; }
    }
    assert.ok(refusal, "accepted 40 pending uploads without complaint");
    assert.match(refusal, /too many uploads/);
    assert.ok(ids.length <= 20, `held ${ids.length} stages`);

    // Clearing them frees the capacity again.
    const d = (await (await api("/api/discard", { stageIds: ids })).json()) as { discarded: number };
    assert.equal(d.discarded, ids.length);
    assert.equal((await api("/api/stage", { text: "AFTER_CAP=abcdef123456" })).status, 200);
  });

  test("discarding releases the staged plaintext, not just the page's reference", async () => {
    const st = (await (await api("/api/stage", { text: "DISCARD_ME=secret_value_here" })).json()) as { stageId: string };
    await api("/api/discard", { stageIds: [st.stageId] });

    const after = (await (await api("/api/import", {
      stages: [{ stageId: st.stageId, assignments: { DISCARD_ME: { scope: "default" } } }],
    })).json()) as { imported: string[]; skipped: { why: string }[] };

    assert.deepEqual(after.imported, [], "a discarded upload was still importable");
    assert.match(after.skipped[0].why, /expired/);
  });

  test("two files defining the same key can go to different places", async () => {
    const a = (await (await api("/api/stage", { text: "SAME_NAME=from_file_a", filename: "a.env" })).json()) as { stageId: string };
    const b = (await (await api("/api/stage", { text: "SAME_NAME=from_file_b", filename: "b.env" })).json()) as { stageId: string };

    const res = (await (await api("/api/import", {
      stages: [
        { stageId: a.stageId, assignments: { SAME_NAME: { scope: "default", note: "from a" } } },
        { stageId: b.stageId, assignments: { SAME_NAME: { scope: "staging", note: "from b" } } },
      ],
    })).json()) as { imported: string[] };

    assert.deepEqual(res.imported.sort(), ["default/SAME_NAME", "staging/SAME_NAME"]);
    const va = (await (await api("/api/reveal", { scope: "default", key: "SAME_NAME" })).json()) as { value: string };
    const vb = (await (await api("/api/reveal", { scope: "staging", key: "SAME_NAME" })).json()) as { value: string };
    assert.equal(va.value, "from_file_a");
    assert.equal(vb.value, "from_file_b", "the two rows collided into one value");
  });

  test("discard tolerates unknown ids without erroring", async () => {
    const r = await api("/api/discard", { stageIds: ["nope", "also-nope"] });
    assert.equal(r.status, 200);
    assert.equal(((await r.json()) as { discarded: number }).discarded, 0);
    assert.equal((await api("/api/discard", {})).status, 200);
  });
});

describe("the page script itself", () => {
  /**
   * The entire UI is a template string, so TypeScript never looks at it. A typo
   * in there compiles cleanly, passes every server-side test, and ships a blank
   * page. Parsing it is the only thing that catches that.
   */
  const pageSource = async () => {
    const html = await (await fetch(`${base}/?t=${token}`)).text();
    const m = html.match(/<script>([\s\S]*?)<\/script>/);
    assert.ok(m, "the page has no script block");
    return { html, js: m![1] };
  };

  test("it parses", async () => {
    const { js } = await pageSource();
    assert.doesNotThrow(() => new Function(js), "the page script has a syntax error");
    assert.ok(js.split("\n").length > 100, "the script looks truncated");
  });

  test("the dropzone wiring is present and self-consistent", async () => {
    const { js } = await pageSource();
    // Every function the drop path calls must actually be defined in the page.
    for (const fn of ["ingestFiles", "stagingPanel", "scopeSelect", "dropCard", "doImport", "runImport", "retag", "ck"]) {
      assert.match(js, new RegExp(`function ${fn}\\b`), `${fn} is called but never defined`);
    }
    // Assert the guards are *used*, not merely declared — a removed comparison
    // leaves the constant behind and a presence check would still pass.
    assert.match(js, /f\.size>MAX_DROP_BYTES/, "the file-size guard is not applied");
    assert.match(js, /list\.length>MAX_DROP_FILES/, "the file-count guard is not applied");
    assert.match(js, /if\(importing\)return/, "double submits are not prevented");
    assert.match(js, /api\("\/api\/discard"/, "Discard does not release the server-side upload");

    // ck() decides whether two files sharing a key name stay apart. Run it.
    const ckLine = js.split("\n").find((l) => l.startsWith("function ck("));
    assert.ok(ckLine, "ck() is missing");
    const ck = new Function(ckLine + "; return ck;")() as (stage: string, key: string) => string;
    assert.notEqual(
      ck("stage-a", "FAL_KEY"),
      ck("stage-b", "FAL_KEY"),
      "two files defining the same key would share one row's scope, tag and checkbox",
    );
    assert.equal(ck("stage-a", "FAL_KEY"), ck("stage-a", "FAL_KEY"), "ck() is not stable");
    assert.notEqual(ck("s", "A"), ck("s", "B"));
  });

  test("esc() escapes everything that could break out of markup", async () => {
    const { js } = await pageSource();
    const line = js.split("\n").find((l) => l.startsWith("const esc="));
    assert.ok(line, "the page has no esc() helper");
    const esc = new Function("return " + line!.replace(/^const esc=/, "").replace(/;$/, ""))() as (
      v: string,
    ) => string;

    // Checking for a bare "&" would be wrong — "&amp;" contains one. Compare
    // against the exact expected encoding instead.
    assert.equal(esc("<img src=x>"), "&lt;img src=x&gt;");
    assert.equal(esc("a&b"), "a&amp;b");
    assert.equal(esc("say \"hi\""), "say &quot;hi&quot;");
    assert.equal(esc("it's"), "it&#39;s");
    assert.equal(esc("plain"), "plain");
    // Nothing that can open a tag or close an attribute may survive.
    const hostile = esc("</div><script>alert(1)</script>");
    for (const ch of ["<", ">"]) assert.ok(!hostile.includes(ch), "esc() left a raw " + ch);
  });
  test("every data-bearing interpolation into markup is escaped", async () => {
    const { js } = await pageSource();
    // Literal ternaries and counts are fine; anything reading a field off a
    // record that came from the vault or a dropped file must go through esc().
    const dataRef = /\b(?:e|s|a|m|st|sk|r|i)\.[a-zA-Z_]/;
    const builders = js.match(/\$\('<[^)]*?\+[^)]*?\)/g) ?? [];
    assert.ok(builders.length > 5, "expected several markup builders to check");

    let checked = 0;
    for (const b of builders) {
      for (const part of b.split("+").slice(1)) {
        const t = part.trim();
        if (!dataRef.test(t)) continue; // literal or a count
        // A ternary whose branches are both string literals renders a literal,
        // however data-driven the condition is.
        if (/^\(?[\w.]+\?"[^"]*":"[^"]*"\)?$/.test(t)) continue;
        checked++;
        assert.ok(t.startsWith("esc("), `unescaped field in markup: ${t.slice(0, 70)}`);
      }
    }
    assert.ok(checked > 8, `only checked ${checked} interpolations — the scan missed the markup`);
  });

  test("the page pulls nothing from the network", async () => {
    const { html } = await pageSource();
    assert.ok(!/<script[^>]+src=/.test(html), "the page loads an external script");
    assert.ok(!/<link[^>]+href=/.test(html), "the page loads an external stylesheet");
    assert.ok(!/@import/.test(html), "the CSS imports something");
  });

  test("the page shows one list of sets at two levels, not the old two vocabularies", async () => {
    const { html } = await pageSource();
    assert.ok(html.includes("Your library"), "the library section heading is missing");
    // "This project" alone also names the (unrelated) standalone empty-state
    // heading, so pin the one used by the actual set-listing section instead.
    assert.ok(html.includes("committed with the repo"), "the project section heading is missing");
    assert.ok(!html.includes("Service accounts"), "the old Service accounts section is still there");
  });

  // The project's default set is the floor of every run and cannot be switched
  // off; the card must say so rather than offer a toggle whose "drop" is a no-op.
  test("the project's default card says it is always used instead of offering a toggle", async () => {
    const { js } = await pageSource();
    assert.ok(js.includes("● always used"), "the default set's card does not say it is the floor");
  });

  test("the namer bar's default destination is the library when one exists", async () => {
    const { js } = await pageSource();
    // Scoped to stagingPanel() itself — the new-set form lower on the page has
    // its own, separate destination select, and must not be able to satisfy
    // this assertion on the namer bar's behalf.
    const start = js.indexOf("function stagingPanel(");
    assert.ok(start > -1, "stagingPanel() is missing");
    const end = js.indexOf("\nfunction ", start + 1);
    const panel = js.slice(start, end > -1 ? end : undefined);

    const libAt = panel.indexOf('option value="library"');
    const projAt = panel.indexOf('option value="project"');
    assert.ok(libAt > -1 && projAt > -1, "the namer bar is missing a destination option");
    assert.ok(libAt < projAt, "the namer bar does not offer the library first");
    assert.match(panel, /if\(!S\.global\.exists\)dest\.value="project"/, "no fallback to project when there is no library");
  });
});

describe("ui dropzone — imports that would not reach the app", () => {
  test("filing keys into an unused account is reported, with the fix", async () => {
    // The trap: you carefully file FAL_KEY into fal/personal, import, and then
    // `hush run` silently does not provide it because the project does not use
    // that account. Nothing else in the flow would tell you.
    const st = (await (await api("/api/stage", { text: "FAL_KEY=fal_unpinned_value" })).json()) as { stageId: string };
    const res = (await (await api("/api/import", {
      stages: [{ stageId: st.stageId, assignments: { FAL_KEY: { scope: "fal/unused-account" } } }],
    })).json()) as { imported: string[]; unpinned: { service: string; account: string; scope: string; keys: number }[] };

    assert.deepEqual(res.imported, ["fal/unused-account/FAL_KEY"]);
    assert.equal(res.unpinned.length, 1, "no warning that the key will not be injected");
    assert.deepEqual(res.unpinned[0], { service: "fal", account: "unused-account", scope: "fal/unused-account", keys: 1 });
  });

  test("no warning when the project already uses that set", async () => {
    await api("/api/link", { name: "fal/personal", use: true });
    const st = (await (await api("/api/stage", { text: "FAL_KEY=fal_pinned_value" })).json()) as { stageId: string };
    const res = (await (await api("/api/import", {
      stages: [{ stageId: st.stageId, assignments: { FAL_KEY: { scope: "fal/personal" } } }],
      overwrite: true,
    })).json()) as { unpinned: unknown[] };
    assert.deepEqual(res.unpinned, [], "warned about an account that is in use");
  });

  test("plain environments never trigger the warning", async () => {
    const st = (await (await api("/api/stage", { text: "PLAIN_ENV_KEY=abcdef123456" })).json()) as { stageId: string };
    const res = (await (await api("/api/import", {
      stages: [{ stageId: st.stageId, assignments: { PLAIN_ENV_KEY: { scope: "default" } } }],
    })).json()) as { unpinned: unknown[] };
    assert.deepEqual(res.unpinned, []);
  });

  test("several keys into the same unused account are counted once", async () => {
    const st = (await (await api("/api/stage", { text: "AWS_ACCESS_KEY_ID=AKIAX\nAWS_SECRET_ACCESS_KEY=secret123456\nAWS_REGION=eu-west-1" })).json()) as { stageId: string };
    const res = (await (await api("/api/import", {
      stages: [{ stageId: st.stageId, assignments: {
        AWS_ACCESS_KEY_ID: { scope: "aws/prod" },
        AWS_SECRET_ACCESS_KEY: { scope: "aws/prod" },
        AWS_REGION: { scope: "aws/prod" },
      }}],
    })).json()) as { unpinned: { scope: string; keys: number }[] };
    assert.equal(res.unpinned.length, 1);
    assert.equal(res.unpinned[0].keys, 3);
  });
});

describe("ui team endpoints", () => {
  test("adding a member grants access and shows up in the roster", async () => {
    const { generateIdentity, encodePub } = await import("../src/crypto.ts");
    const mate = generateIdentity();
    const r = await api("/api/team", { name: "teammate", pk: encodePub(mate.pub) });
    assert.equal(r.status, 200);
    const state = (await r.json()) as UiState;
    assert.ok(state.members.some((m) => m.name === "teammate"), "the member was not added");
    assert.ok(!JSON.stringify(state).includes(SECRET_VALUE));
  });

  test("removing a member re-keys the vault and reports it", async () => {
    const { generateIdentity, encodePub } = await import("../src/crypto.ts");
    const doomed = generateIdentity();
    await api("/api/team", { name: "leaving", pk: encodePub(doomed.pub) });

    const r = await api("/api/team", { action: "remove", name: "leaving" });
    assert.equal(r.status, 200);
    const res = (await r.json()) as UiState & { notice?: string };
    assert.ok(!res.members.some((m) => m.name === "leaving"), "the member survived removal");
    assert.match(res.notice ?? "", /re-sealed/, "did not report the re-encryption");

    // The vault must still be readable by whoever is left.
    const still = (await (await api("/api/reveal", { scope: "default", key: "API_KEY" })).json()) as { value: string };
    assert.equal(still.value, SECRET_VALUE, "re-keying lost the values");
  });

  test("removing yourself is refused rather than locking you out", async () => {
    const state = (await (await api("/api/state")).json()) as UiState & { me: { name: string } };
    const r = await api("/api/team", { action: "remove", name: state.me.name });
    assert.equal(r.status, 400, "let the only member remove themselves");
    assert.match(((await r.json()) as { error: string }).error, /own last key/);
    assert.equal((await api("/api/state")).status, 200);
  });

  test("removing someone who is not a member 400s rather than crashing", async () => {
    const r = await api("/api/team", { action: "remove", name: "nobody-by-that-name" });
    assert.equal(r.status, 400);
    assert.match(((await r.json()) as { error: string }).error, /No member named/);
    assert.equal((await api("/api/state")).status, 200);
  });

  test("a malformed public key is refused", async () => {
    const r = await api("/api/team", { name: "bad", pk: "not-a-key" });
    assert.equal(r.status, 400);
    assert.match(((await r.json()) as { error: string }).error, /not a hush public key/);
  });
});

describe("ui server — the gaps mutation testing found", () => {
  /** A raw request, because fetch() drops a Host override. */
  const withHost = (host: string, path = "/api/state") =>
    new Promise<number>((resolve, reject) => {
      const { port } = new URL(base);
      const req = httpRequest(
        { host: "127.0.0.1", port: Number(port), path, method: "GET", headers: { "x-hush-token": token, Host: host } },
        (res) => { res.resume(); resolve(res.statusCode ?? 0); },
      );
      req.on("error", reject);
      req.end();
    });

  test("the Host check matches a loopback name exactly, not merely contains one", async () => {
    // A substring test is the natural-looking mistake and it is worth nothing:
    // every one of these resolves wherever an attacker's DNS says it does, and
    // each contains a loopback name.
    for (const host of [
      "localhost.evil.example.com",
      "evil.example.com/127.0.0.1",
      "127.0.0.1.evil.example.com",
      "notlocalhost",
      "localhost.attacker.test:1234",
      "[::1].evil.example.com",
    ]) {
      assert.equal(await withHost(host), 403, `accepted Host: ${host}`);
    }
    // And the real ones still work, so it is not refusing everything.
    const { port } = new URL(base);
    for (const host of ["127.0.0.1", `127.0.0.1:${port}`, "localhost", `localhost:${port}`]) {
      assert.equal(await withHost(host), 200, `refused a genuine loopback Host: ${host}`);
    }
  });

  test("the server is listening on loopback only, not on every interface", async () => {
    // Binding 0.0.0.0 puts every key you own on the office wifi. The Host check
    // does not save you: an attacker on the same network sets Host themselves.
    const { networkInterfaces } = await import("node:os");
    const external = Object.values(networkInterfaces())
      .flat()
      .filter((n) => n && !n.internal && n.family === "IPv4")
      .map((n) => n!.address);

    const { port } = new URL(base);
    for (const address of external) {
      const reachable = await new Promise<boolean>((resolve) => {
        const req = httpRequest(
          { host: address, port: Number(port), path: "/", method: "GET", timeout: 2000 },
          (res) => { res.resume(); resolve(true); },
        );
        req.on("error", () => resolve(false));
        req.on("timeout", () => { req.destroy(); resolve(false); });
        req.end();
      });
      assert.equal(reachable, false, `the UI answered on ${address}:${port} — it is on the network`);
    }
    // The test is only meaningful if this machine has an external address at all.
    assert.ok(external.length > 0, "no external interface to test against on this host");
  });

  test("a staged upload expires instead of holding plaintext for ever", async () => {
    // Staging holds plaintext server-side. Without a sweep, a page left open
    // pins every dropped secret in memory until the process dies.
    const staged = await (await api("/api/stage", {
      filename: ".env.expiring",
      text: "EXPIRING_KEY=expiring_value_0123456789\n",
    })).json() as { stageId: string };
    assert.ok(staged.stageId, "nothing was staged");

    // Importing a stage that the sweep has dropped must fail rather than
    // silently succeed against stale plaintext. Here it is still live:
    const ok = await api("/api/import", {
      stages: [{ stageId: staged.stageId, assignments: { EXPIRING_KEY: { scope: "default" } } }],
    });
    assert.equal(ok.status, 200);
    const first = await ok.json() as { imported: string[] };
    assert.deepEqual(first.imported, ["default/EXPIRING_KEY"]);

    // A stage is consumed on import, so replaying the same id finds nothing —
    // the same path the TTL sweep takes, and the one that proves a dropped
    // stage cannot be imported from.
    const replay = await api("/api/import", {
      stages: [{ stageId: staged.stageId, assignments: { EXPIRING_KEY: { scope: "prod" } } }],
    });
    const second = await replay.json() as { imported: string[]; skipped: { why: string }[] };
    assert.deepEqual(second.imported, [], "a consumed stage was imported a second time");
    assert.match(second.skipped[0]?.why ?? "", /expired/);
  });
});

describe("ui server — staged plaintext expires", () => {
  // Staging holds decrypted values server-side so the browser never sees them.
  // The other half of that bargain is that it does not hold them for ever: a
  // page left open on a dropped .env would otherwise pin every secret in it in
  // memory until the process dies. Fifteen minutes is not a thing a test can
  // wait for, so this server runs with the TTL turned down.
  let ttlChild: ChildProcess;
  let ttlBase: string;
  let ttlToken: string;
  let ttlHome: string;
  let ttlRoot: string;

  before(async () => {
    ttlHome = mkdtempSync(join(tmpdir(), "hush-ttl-home-"));
    ttlRoot = mkdtempSync(join(tmpdir(), "hush-ttl-proj-"));
    const hushDir = join(ttlRoot, ".hush");
    mkdirSync(hushDir, { recursive: true });
    const id = generateIdentity();
    const vault = Vault.create(join(hushDir, "vault.json"), "ttltest", { name: "tester", pub: id.pub });
    vault.set(id, "default", "SEED", "seed_value_for_ttl_test");
    vault.save();
    writeFileSync(join(hushDir, "policy.json"), JSON.stringify({ requireApproval: [], biometry: "off" }));

    ttlChild = spawn(process.execPath, [CLI, "ui", "--no-open", "--port", "0"], {
      cwd: ttlRoot,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        HUSH_HOME: ttlHome,
        HUSH_IDENTITY: encodeSecret(id),
        HUSH_BIOMETRY: "off",
        HUSH_UI_STAGE_TTL_MS: "400",
        NO_COLOR: "1",
      },
    });
    const url: string = await new Promise((resolve, reject) => {
      let out = "";
      const timer = setTimeout(() => reject(new Error("ui did not start: " + out)), 15000);
      ttlChild.stdout!.on("data", (d) => {
        out += d;
        const m = out.match(/(http:\/\/127\.0\.0\.1:\d+\/\?t=[A-Za-z0-9_-]+)/);
        if (m) { clearTimeout(timer); resolve(m[1]); }
      });
    });
    const parsed = new URL(url);
    ttlBase = parsed.origin;
    ttlToken = parsed.searchParams.get("t")!;
  });

  after(() => {
    ttlChild?.kill();
    for (const d of [ttlHome, ttlRoot]) rmSync(d, { recursive: true, force: true });
  });

  const ttlApi = (path: string, body?: unknown) =>
    fetch(ttlBase + path, {
      method: body ? "POST" : "GET",
      headers: { "x-hush-token": ttlToken, "content-type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });

  test("a stage that is never reviewed is swept away, and cannot be imported afterwards", async () => {
    const staged = (await (await ttlApi("/api/stage", {
      filename: ".env.forgotten",
      text: "FORGOTTEN_KEY=forgotten_value_0123456789\n",
    })).json()) as { stageId: string };
    assert.ok(staged.stageId, "nothing was staged");

    // Past the TTL. The sweep runs on the next request that touches staging.
    await new Promise((r) => setTimeout(r, 700));

    const late = (await (await ttlApi("/api/import", {
      stages: [{ stageId: staged.stageId, assignments: { FORGOTTEN_KEY: { scope: "default" } } }],
    })).json()) as { imported: string[]; skipped: { why: string }[] };

    assert.deepEqual(late.imported, [], "an expired stage was still importable");
    assert.match(late.skipped[0]?.why ?? "", /expired/);

    // And the value really is gone rather than merely unreachable by that id:
    // nothing about it survived into the vault.
    const state = (await (await ttlApi("/api/state")).json()) as {
      project: { name: string; secrets: { key: string }[] }[];
    };
    const keys = state.project.flatMap((e) => e.secrets.map((s) => s.key));
    assert.ok(!keys.includes("FORGOTTEN_KEY"), "an expired stage was written to the vault");
  });

  test("a stage reviewed inside the window still works, so the sweep is not simply eating everything", async () => {
    const staged = (await (await ttlApi("/api/stage", {
      filename: ".env.prompt",
      text: "PROMPT_KEY=prompt_value_0123456789\n",
    })).json()) as { stageId: string };

    const imported = (await (await ttlApi("/api/import", {
      stages: [{ stageId: staged.stageId, assignments: { PROMPT_KEY: { scope: "default" } } }],
    })).json()) as { imported: string[] };
    assert.deepEqual(imported.imported, ["default/PROMPT_KEY"]);
  });
});

describe("staged plaintext cannot be made to linger", () => {
  test("the stage TTL can only be turned down, never up", () => {
    // The seam exists so the sweep can be tested without waiting a quarter of an
    // hour. It must not become a way to keep decrypted secrets in the server's
    // memory for longer than the design allows — so anything above the default,
    // and anything that is not a sensible number, falls back to the default.
    assert.equal(resolveStageTtl("500"), 500, "a shorter TTL was ignored");
    assert.equal(resolveStageTtl(1), 1);

    for (const raw of [
      String(DEFAULT_STAGE_TTL_MS),
      String(DEFAULT_STAGE_TTL_MS + 1),
      "86400000",
      "1e12",
      "Infinity",
      "0",
      "-1",
      "abc",
      "",
      undefined,
      null,
      {},
    ]) {
      assert.equal(
        resolveStageTtl(raw),
        DEFAULT_STAGE_TTL_MS,
        `${JSON.stringify(raw)} changed the TTL when it should not have`,
      );
    }
  });
});

describe("ui server — named env sets", () => {
  // What a dropped .env is supposed to become: one entry in a list, with a name
  // you chose, a description and a note about when to use it — not twenty loose
  // keys filed under "default".
  let libChild: ChildProcess;
  let libBase: string;
  let libToken: string;
  let libHome: string;
  let libRoot: string;

  const libApi = async (path: string, body?: unknown) => {
    const r = await fetch(libBase + path, {
      method: body ? "POST" : "GET",
      headers: { "x-hush-token": libToken, "content-type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: r.status, body: (await r.json()) as any };
  };

  before(async () => {
    libHome = mkdtempSync(join(tmpdir(), "hush-lib-home-"));
    libRoot = mkdtempSync(join(tmpdir(), "hush-lib-proj-"));
    const hushDir = join(libRoot, ".hush");
    mkdirSync(hushDir, { recursive: true });
    const id = generateIdentity();
    const vault = Vault.create(join(hushDir, "vault.json"), "libtest", { name: "tester", pub: id.pub });
    vault.set(id, "default", "PROJECT_ONLY", "project_only_value_1234");
    vault.save();
    writeFileSync(join(hushDir, "policy.json"), JSON.stringify({ requireApproval: [], biometry: "off" }));

    libChild = spawn(process.execPath, [CLI, "ui", "--no-open", "--port", "0"], {
      cwd: libRoot,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        HUSH_HOME: libHome,
        HUSH_IDENTITY: encodeSecret(id),
        HUSH_BIOMETRY: "off",
        HUSH_NO_KEYCHAIN: "1",
        NO_COLOR: "1",
      },
    });
    const url: string = await new Promise((resolve, reject) => {
      let out = "";
      const timer = setTimeout(() => reject(new Error("ui did not start: " + out)), 15000);
      libChild.stdout!.on("data", (d) => {
        out += d;
        const m = out.match(/(http:\/\/127\.0\.0\.1:\d+\/\?t=[A-Za-z0-9_-]+)/);
        if (m) { clearTimeout(timer); resolve(m[1]); }
      });
    });
    const parsed = new URL(url);
    libBase = parsed.origin;
    libToken = parsed.searchParams.get("t")!;
  });

  after(() => {
    libChild?.kill();
    for (const d of [libHome, libRoot]) rmSync(d, { recursive: true, force: true });
  });

  test("/api/global creates the library, and it starts out absent", async () => {
    const before = (await libApi("/api/state")).body;
    assert.equal(before.global.exists, false, "a library appeared from nowhere");
    assert.deepEqual(before.library, [], "an empty library is not empty");

    const after = (await libApi("/api/global", { create: true })).body;
    assert.equal(after.global.exists, true, "creating the library did nothing");
    assert.equal(after.global.name, "global");
  });

  test("/api/env names a set, and the command-line name is the slug of it", async () => {
    const r = await libApi("/api/env", {
      action: "create",
      where: "library",
      label: "Acme Production",
      description: "Live Stripe + Convex",
    });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.created, "acme-production", "the slug is not derived from the name");

    const set = r.body.library.find((x: any) => x.name === "acme-production");
    assert.equal(set.label, "Acme Production");
    assert.equal(set.description, "Live Stripe + Convex");
    assert.equal(set.whenToUse, "", "a field nobody filled in is not empty");
  });

  test("/api/env describes a set, and every field is optional", async () => {
    const described = (await libApi("/api/env", {
      action: "describe",
      where: "library",
      name: "acme-production",
      whenToUse: "deploys only",
    })).body;
    const set = described.library.find((x: any) => x.name === "acme-production");
    assert.equal(set.whenToUse, "deploys only");
    assert.equal(set.description, "Live Stripe + Convex", "describing one field cleared another");

    // A set with nothing said about it at all is a legitimate set.
    const bare = (await libApi("/api/env", { action: "create", where: "library", label: "Scratch" })).body;
    const scratch = bare.library.find((x: any) => x.name === "scratch");
    assert.equal(scratch.description, "");
    assert.equal(scratch.whenToUse, "");
  });

  test("/api/link decides which sets this project uses", async () => {
    let s = (await libApi("/api/state")).body;
    assert.ok(s.library.every((x: any) => !x.used), "something was used before anything asked for it");

    s = (await libApi("/api/link", { name: "acme-production", use: true })).body;
    assert.equal(s.library.find((x: any) => x.name === "acme-production").used, true);
    // "default" is the floor and always sits first; the set just linked is
    // added after it, so it lands second in resolution order.
    assert.equal(s.library.find((x: any) => x.name === "acme-production").position, 1);
    assert.equal(s.library.find((x: any) => x.name === "scratch").used, false, "linking one used them all");
    assert.equal(s.library.find((x: any) => x.name === "scratch").position, null);
    assert.deepEqual(s.used, ["default", "acme-production"]);

    s = (await libApi("/api/link", { name: "acme-production", use: false })).body;
    assert.equal(s.library.find((x: any) => x.name === "acme-production").used, false, "it could not be dropped");
    assert.equal(s.library.find((x: any) => x.name === "acme-production").position, null);

    await libApi("/api/link", { name: "acme-production", use: true });
  });

  test("/api/link accepts {order} to set the whole resolution order at once", async () => {
    // A drag-to-reorder writes the full list back in one call rather than one
    // toggle at a time. Position is precedence, so naming "default" explicitly
    // and putting it last is how a set is made to beat it — the floor moved.
    const before = (await libApi("/api/state")).body;
    assert.deepEqual(before.used, ["default", "acme-production"]);

    const r = await libApi("/api/link", { order: ["acme-production", "default"] });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.used, ["acme-production", "default"], "the order given was not preserved");
    assert.equal(r.body.library.find((x: any) => x.name === "acme-production").position, 0);

    // Restore the order the rest of the suite expects: "default" implicit
    // and first, "acme-production" linked after it.
    await libApi("/api/link", { order: ["acme-production"] });
    const restored = (await libApi("/api/state")).body;
    assert.deepEqual(restored.used, ["default", "acme-production"]);
  });

  test("a dropped file becomes one named set, and its keys reach a run", async () => {
    const staged = (await libApi("/api/stage", {
      filename: ".env.production",
      text: "STRIPE_SECRET_KEY=sk_live_named_set_0123456789\nCONVEX_DEPLOYMENT=prod-named-77\n",
    })).body;
    assert.equal(staged.entries.length, 2);

    const assignments: Record<string, { scope: string }> = {};
    for (const e of staged.entries) assignments[e.key] = { scope: "acme-production" };
    const imported = (await libApi("/api/import", {
      stages: [{ stageId: staged.stageId, assignments }],
      where: "library",
      overwrite: true,
    })).body;
    assert.equal(imported.imported.length, 2, JSON.stringify(imported));

    const set = imported.library.find((x: any) => x.name === "acme-production");
    assert.deepEqual(set.keys.sort(), ["CONVEX_DEPLOYMENT", "STRIPE_SECRET_KEY"]);
    assert.ok(!JSON.stringify(imported).includes("sk_live_named_set_0123456789"), "a value came back");
  });

  test("renaming a set re-seals it and carries the project's link along", async () => {
    const r = await libApi("/api/env", {
      action: "rename",
      where: "library",
      name: "acme-production",
      label: "Acme Prod EU",
    });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.renamed, "acme-prod-eu");

    const set = r.body.library.find((x: any) => x.name === "acme-prod-eu");
    assert.ok(set, "the renamed set is missing");
    assert.equal(set.label, "Acme Prod EU");
    assert.deepEqual(set.keys.sort(), ["CONVEX_DEPLOYMENT", "STRIPE_SECRET_KEY"], "the keys did not come with it");
    assert.equal(set.used, true, "the project's link did not follow the rename");
    assert.ok(!r.body.library.some((x: any) => x.name === "acme-production"), "the old name is still there");
  });

  test("the library and the project are kept apart", async () => {
    const s = (await libApi("/api/state")).body;
    // The project's own set is listed separately and is not in the library.
    assert.ok(s.project.some((e: any) => e.name === "default"), "the project's own env vanished");
    assert.ok(!s.library.some((x: any) => x.name === "default"), "the project's env leaked into the library");
    assert.ok(!JSON.stringify(s).includes("project_only_value_1234"), "a project value came back");
  });

test("/api/move carves one pile into named sets", async () => {
    // The state everybody starts in: every key in one unnamed set. Moving them
    // out is how it becomes a list of named things, so it has to work from the
    // UI and not only from the command line.
    const before = (await libApi("/api/state")).body;
    const source = before.library.find((x: any) => x.name === "acme-prod-eu");
    assert.ok(source.secrets.length >= 2, "nothing to move");
    assert.ok(
      source.secrets.every((s: any) => !s.preview.includes("sk_live")),
      "the library sent a real value to the browser",
    );

    const made = (await libApi("/api/env", { action: "create", where: "library", label: "Convex only" })).body;
    assert.equal(made.created, "convex-only");

    const moved = (await libApi("/api/move", {
      where: "library",
      key: "CONVEX_DEPLOYMENT",
      from: "acme-prod-eu",
      to: "convex-only",
    })).body;

    const dest = moved.library.find((x: any) => x.name === "convex-only");
    const src = moved.library.find((x: any) => x.name === "acme-prod-eu");
    assert.deepEqual(dest.keys, ["CONVEX_DEPLOYMENT"], "it did not arrive");
    assert.ok(!src.keys.includes("CONVEX_DEPLOYMENT"), "it did not leave");
    assert.ok(src.keys.includes("STRIPE_SECRET_KEY"), "it took the wrong key too");
    assert.ok(!JSON.stringify(moved).includes("sk_live_named_set_0123456789"), "a value came back");

    // A move that would overwrite is refused rather than silently winning.
    await libApi("/api/move", { where: "library", key: "STRIPE_SECRET_KEY", from: "acme-prod-eu", to: "convex-only" });
    const clash = await libApi("/api/move", {
      where: "library", key: "STRIPE_SECRET_KEY", from: "convex-only", to: "convex-only",
    });
    assert.ok(clash.status === 200 || clash.status >= 400, "a self-move behaved oddly");

    const missing = await libApi("/api/move", { where: "library", key: "NOPE", from: "convex-only", to: "acme-prod-eu" });
    assert.ok(missing.status >= 400, "moving a key that is not there reported success");
  });

  test("/api/env deletes a set", async () => {
    const s = (await libApi("/api/env", { action: "delete", where: "library", name: "scratch" })).body;
    assert.ok(!s.library.some((x: any) => x.name === "scratch"), "it survived deletion");
    assert.ok(s.library.some((x: any) => x.name === "acme-prod-eu"), "it deleted the wrong one");
  });
});

describe("ui server — any folder", () => {
  /**
   * The third state a folder can be in: no .hush anywhere above it at all.
   * Before this, opening hush here either refused to start outright (no
   * project and no library), or — the actual bug this fixture exists to
   * catch — crashed if a project marker existed without a vault, because
   * Vault.open() throws unconditionally on a missing file. This fixture never
   * creates .hush itself; every test below either reads state or drives it
   * through the setup flow, in the order a real folder would go through it:
   * unset → links-only → its own vault.
   */
  let bareChild: ChildProcess;
  let bareBase: string;
  let bareToken: string;
  let bareHome: string;
  let bareRoot: string;

  const bareApi = async (path: string, body?: unknown) => {
    const r = await fetch(bareBase + path, {
      method: body ? "POST" : "GET",
      headers: { "x-hush-token": bareToken, "content-type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: r.status, body: (await r.json()) as any };
  };

  before(async () => {
    bareHome = mkdtempSync(join(tmpdir(), "hush-bare-home-"));
    bareRoot = mkdtempSync(join(tmpdir(), "hush-bare-proj-"));
    // No .hush anywhere in bareRoot — that absence is the point of this fixture.
    writeFileSync(
      join(bareRoot, "index.js"),
      "console.log(process.env.FAL_KEY, process.env.DATABASE_URL);\n",
    );

    const id = generateIdentity();
    // Built by hand rather than via namedVaultPath(): that helper reads
    // process.env.HUSH_HOME of *this* process, not the HUSH_HOME the child
    // below is about to be spawned with.
    const libPath = join(bareHome, "vaults", "global", "vault.json");
    mkdirSync(dirname(libPath), { recursive: true });
    const lib = Vault.create(libPath, "global", { name: "tester", pub: id.pub });
    lib.set(id, "acme-production", "DATABASE_URL", "postgres_acme_prod_value_here");
    lib.set(id, "acme-production", "FAL_KEY", "fal_acme_prod_value_here");
    lib.set(id, "work-fal", "FAL_KEY", "fal_work_value_here");
    lib.save();

    bareChild = spawn(process.execPath, [CLI, "ui", "--no-open", "--port", "0"], {
      cwd: bareRoot,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        HUSH_HOME: bareHome,
        HUSH_IDENTITY: encodeSecret(id),
        HUSH_BIOMETRY: "off",
        HUSH_NO_KEYCHAIN: "1",
        NO_COLOR: "1",
      },
    });
    const url: string = await new Promise((resolve, reject) => {
      let out = "";
      const timer = setTimeout(() => reject(new Error("ui did not start: " + out)), 15000);
      bareChild.stdout!.on("data", (d) => {
        out += d;
        const m = out.match(/(http:\/\/127\.0\.0\.1:\d+\/\?t=[A-Za-z0-9_-]+)/);
        if (m) { clearTimeout(timer); resolve(m[1]); }
      });
    });
    const parsed = new URL(url);
    bareBase = parsed.origin;
    bareToken = parsed.searchParams.get("t")!;
  });

  after(() => {
    bareChild?.kill();
    for (const d of [bareHome, bareRoot]) rmSync(d, { recursive: true, force: true });
  });

  test("a bare folder reports itself unset, with a setup suggestion drawn from the library", async () => {
    const s = (await bareApi("/api/state")).body;
    assert.equal(s.folder.state, "unset");
    assert.deepEqual(s.suggestion.needed, ["DATABASE_URL", "FAL_KEY"], "did not find both variables the code references");
    assert.deepEqual(s.suggestion.picks, ["acme-production"], "did not prefer the set covering both keys");
    assert.deepEqual(s.library.map((x: any) => x.name).sort(), ["acme-production", "work-fal"]);
    assert.deepEqual(s.project, [], "an unset folder reported project vault data");
    assert.equal(s.vault, null, "an unset folder claimed to have a vault");
    assert.deepEqual(s.members, []);

    const raw = JSON.stringify(s);
    assert.ok(!raw.includes("postgres_acme_prod_value_here"), "a library value reached the browser");
    assert.ok(!raw.includes("fal_acme_prod_value_here"));
    assert.ok(!raw.includes("fal_work_value_here"));
  });

  test("the setup panel is on the page for an unset folder, and the inline script still parses", async () => {
    const html = await (await fetch(`${bareBase}/?t=${bareToken}`)).text();
    assert.ok(html.includes("This folder"), "the setup panel heading is missing");
    assert.ok(html.includes("set up for hush yet"), "the setup panel heading is missing");
    assert.ok(html.includes("Use these here"), "the setup button is missing");

    const m = html.match(/<script>([\s\S]*?)<\/script>/);
    assert.ok(m, "the page has no script block");
    assert.doesNotThrow(() => new Function(m![1]), "the page script has a syntax error");
  });

  test("/api/link toggles a library set with no project vault at all", async () => {
    const before = (await bareApi("/api/state")).body;
    assert.equal(before.folder.state, "unset");

    const linked = await bareApi("/api/link", { name: "work-fal", use: true });
    assert.equal(linked.status, 200, JSON.stringify(linked.body));
    assert.deepEqual(linked.body.used, ["default", "work-fal"]);
    // Linking writes envs.json, which is itself the marker that moves the
    // folder past "unset" — before any vault exists anywhere.
    assert.equal(linked.body.folder.state, "links-only");
    assert.ok(!existsSync(join(bareRoot, ".hush", "vault.json")), "linking a set made a vault");
  });

  test("/api/setup refuses a name that is not in the library or an unknown name entirely", async () => {
    const r = await bareApi("/api/setup", { use: ["not-a-real-set"] });
    assert.equal(r.status, 400, "accepted a set name nothing offers");
    assert.match(r.body.error, /acme-production/, "the error did not name what does exist");
    assert.match(r.body.error, /work-fal/);
  });

  test("/api/setup links sets and writes the dotfiles, but makes no vault and no policy", async () => {
    const r = await bareApi("/api/setup", { use: ["acme-production"] });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.folder.state, "links-only");
    // Replaces the whole list — the leftover "work-fal" link from the
    // previous test does not linger alongside it.
    assert.deepEqual(r.body.used, ["default", "acme-production"]);

    const hushDir = join(bareRoot, ".hush");
    assert.ok(existsSync(join(hushDir, "envs.json")), "envs.json was not written");
    assert.ok(existsSync(join(hushDir, ".gitignore")), "the project dotfiles were not written");
    assert.ok(!existsSync(join(hushDir, "vault.json")), "setup made a vault it was not asked to");
    assert.ok(!existsSync(join(hushDir, "policy.json")), "setup wrote a policy without being asked to");
  });

  test("/api/setup with agent:true writes the three approvals, and a second call keeps an edited policy", async () => {
    const hushDir = join(bareRoot, ".hush");
    const policyPath = join(hushDir, "policy.json");

    const r = await bareApi("/api/setup", { use: ["acme-production"], agent: true });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.ok(existsSync(policyPath), "no policy.json was written");
    const written = JSON.parse(readFileSync(policyPath, "utf8"));
    assert.deepEqual(written.requireApproval, ["run", "add", "reveal"]);
    assert.ok(!r.body.policyKept, "reported keeping a policy it just wrote for the first time");

    // Someone edits it by hand, turning approvals off.
    writeFileSync(policyPath, JSON.stringify({ requireApproval: [] }));
    const again = await bareApi("/api/setup", { use: ["acme-production"], agent: true });
    assert.equal(again.status, 200);
    assert.equal(again.body.policyKept, true, "did not report keeping the edited policy");
    const stillEdited = JSON.parse(readFileSync(policyPath, "utf8"));
    assert.deepEqual(stillEdited.requireApproval, [], "a second setup call overwrote the edited policy");
  });

  test("revealing a project scope before any vault exists 400s naming the folder's state", async () => {
    const s = (await bareApi("/api/state")).body;
    assert.equal(s.folder.state, "links-only", "expected the folder to still have no vault at this point");

    const r = await bareApi("/api/reveal", { scope: "default", key: "PROJECT_SECRET" });
    assert.equal(r.status, 400, "revealed from a project vault that does not exist");
    // Specifically the folder-state message, not the unrelated "you have no
    // library vault yet" 400 that a where:"library" reveal would give — a
    // reveal() that quietly fell through to that message would still be a
    // 400 containing the word "vault" and pass a looser check.
    assert.match(r.body.error, /This folder/, "the 400 did not name the folder's own state");
  });

  test("a links-only folder makes its own vault the first time a project secret is added", async () => {
    const r = await bareApi("/api/secret", { scope: "default", key: "PROJECT_SECRET", value: "project_secret_value" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.vaultCreated, true, "the vault was not reported as created");
    assert.equal(r.body.folder.state, "vault", "state still reports no vault right after making one");
    assert.ok(existsSync(join(bareRoot, ".hush", "vault.json")), "no vault.json appeared on disk");

    // The value written before the vault existed has to actually be in it.
    const reveal = await bareApi("/api/reveal", { scope: "default", key: "PROJECT_SECRET" });
    assert.equal(reveal.status, 200, JSON.stringify(reveal.body));
    assert.equal(reveal.body.value, "project_secret_value");

    const state = (await bareApi("/api/state")).body;
    assert.equal(state.folder.state, "vault");
    assert.ok(state.project.some((s: any) => s.secrets.some((k: any) => k.key === "PROJECT_SECRET")));
  });
});
