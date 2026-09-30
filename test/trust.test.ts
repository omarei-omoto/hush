/**
 * V-1: a vault replaced by someone who is not a member.
 *
 * The vault file is committed and readable by anyone with the repository, and
 * every member's public key is in it. So anyone who can get a change to
 * `.hush/vault.json` merged — without being a member — can mint a new data key,
 * wrap it for every existing member *and* for themselves, and seal whatever
 * values they like. Before pinning, every member's hush opened that vault
 * without a word: planted values were injected, the next secret anyone added
 * was sealed to a key the attacker holds, and `hush verify` was all green.
 *
 * These tests drive the real CLI with one HUSH_HOME per person, which is what
 * makes them people: pins live in each person's own ~/.hush.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync, spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, copyFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { Vault } from "../src/vault.ts";
import {
  generateIdentity, encodeSecret, encodePub, decodePub, fingerprint, newDek, wrapDek, sealValue, dekCommit,
  type Identity,
} from "../src/crypto.ts";
import { recordTrusted, pendingChanges, acceptPending, hasProblems } from "../src/integrity.ts";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.ts");

interface Person {
  name: string;
  id: Identity;
  home: string;
  pk: string;
  run: (args: string[], opts?: { cwd?: string; input?: string; env?: NodeJS.ProcessEnv }) => { out: string; code: number };
}

function person(name: string, defaultCwd: () => string): Person {
  const id = generateIdentity();
  const home = mkdtempSync(join(tmpdir(), `hush-trust-${name}-`));
  const run: Person["run"] = (args, opts = {}) => {
    const r = spawnSync(process.execPath, [CLI, ...args], {
      cwd: opts.cwd ?? defaultCwd(),
      env: {
        ...process.env,
        HOME: home,
        HUSH_HOME: home,
        HUSH_IDENTITY: encodeSecret(id),
        HUSH_NO_KEYCHAIN: "1",
        HUSH_BIOMETRY: "off",
        HUSH_NO_DIALOG: "1",
        HUSH_NO_NUDGE: "1",
        NO_COLOR: "1",
        USER: name,
        ...opts.env,
      },
      encoding: "utf8",
      input: opts.input,
      stdio: [opts.input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
    return { out: (r.stdout ?? "") + (r.stderr ?? ""), code: r.status ?? 1 };
  };
  return { name, id, home, pk: encodePub(id.pub), run };
}

/** Alice's project, with Alice as the founding admin and a couple of real values. */
function team() {
  const root = mkdtempSync(join(tmpdir(), "hush-trust-proj-"));
  const scratch = mkdtempSync(join(tmpdir(), "hush-trust-scratch-"));
  mkdirSync(join(root, ".hush"), { recursive: true });
  const alice = person("alice", () => root);
  const mallory = person("mallory", () => scratch);
  const bob = person("bob", () => root);
  const vaultPath = join(root, ".hush", "vault.json");

  const v = Vault.create(vaultPath, "acme", { name: "alice", pub: alice.id.pub });
  v.set(alice.id, "default", "STRIPE_KEY", "sk_live_REAL_ALICE_VALUE");
  v.set(alice.id, "default", "API_BASE", "https://api.stripe.com");
  v.save();

  /**
   * What Mallory can do with nothing but the committed file: build a brand-new
   * vault wrapped for every member listed in it, plus Mallory, holding values
   * Mallory chose, and put it where the real one was.
   */
  const takeOver = (opts: { addSelf?: boolean; keepId?: boolean; generation?: number } = {}): void => {
    const real = JSON.parse(readFileSync(vaultPath, "utf8"));
    const generation = opts.generation ?? real.dek.generation + 1;
    const dek = newDek();
    const wraps: Record<string, unknown> = {};
    const recipients: Record<string, unknown> = {};
    // Every listed member gets a wrap: their public keys are right there.
    for (const [fp, r] of Object.entries(real.recipients) as [string, { pk: string }][]) {
      wraps[fp] = wrapDek(dek, decodePub(r.pk));
      recipients[fp] = r;
    }
    if (opts.addSelf ?? true) {
      const fp = fingerprint(mallory.id.pub);
      wraps[fp] = wrapDek(dek, mallory.id.pub);
      recipients[fp] = { name: "mallory", pk: mallory.pk, role: "admin", addedAt: new Date().toISOString(), type: "x25519" };
    }
    const seal = (key: string, value: string) => ({
      ...sealValue(dek, "default", key, value, generation),
      gen: generation, v: 2, updatedAt: new Date().toISOString(), updatedBy: "alice",
    });
    const forged = {
      scheme: real.scheme,
      id: opts.keepId === false ? "vlt_" + "f".repeat(16) : real.id,
      name: real.name,
      createdAt: real.createdAt,
      dek: { generation, wraps },
      recipients,
      envs: {
        default: {
          STRIPE_KEY: seal("STRIPE_KEY", "sk_live_REAL_ALICE_VALUE_placeholder"),
          API_BASE: seal("API_BASE", "https://evil.example"),
        },
      },
    };
    writeFileSync(vaultPath, JSON.stringify(forged, null, 2) + "\n");
  };

  return {
    root, scratch, vaultPath, alice, mallory, bob, takeOver,
    cleanup: () => {
      for (const d of [root, scratch, alice.home, mallory.home, bob.home]) rmSync(d, { recursive: true, force: true });
    },
  };
}

const runPrint = ["run", "--", process.execPath, "-e", "process.stdout.write('API_BASE=' + process.env.API_BASE)"];

describe("V-1: a vault rebuilt by a non-member is refused", () => {
  test("the reproduction: planted values are not injected, a new secret is not sealed to the attacker, verify fails", () => {
    const t = team();
    // Alice has used the vault before, as any real member has.
    assert.equal(t.alice.run(["verify"]).code, 0);
    assert.match(t.alice.run(runPrint).out, /API_BASE=\[redacted:API_BASE\]/);

    t.takeOver({ addSelf: true });

    const ran = t.alice.run(runPrint);
    assert.notEqual(ran.code, 0, "hush ran a command with a vault a non-member rebuilt:\n" + ran.out);
    assert.doesNotMatch(ran.out, /API_BASE=/, "the command ran");
    assert.match(ran.out, /hush team accept/, "the refusal does not say how to proceed:\n" + ran.out);

    const added = t.alice.run(["add", "NEW_SECRET=alice-new-secret-value", "--to", "default"]);
    assert.notEqual(added.code, 0, "a new secret was sealed into the rebuilt vault:\n" + added.out);

    // The proof that matters: whatever Alice did, Mallory cannot read it.
    copyFileSync(t.vaultPath, join(t.scratch, "stolen.json"));
    const stolen = Vault.open(join(t.scratch, "stolen.json"));
    assert.ok(!stolen.has("default", "NEW_SECRET"), "NEW_SECRET reached a vault the attacker can open");

    const got = t.alice.run(["get", "API_BASE", "--yes"]);
    assert.notEqual(got.code, 0);
    assert.doesNotMatch(got.out, /evil\.example/);

    const verify = t.alice.run(["verify"]);
    assert.notEqual(verify.code, 0, "verify passed a rebuilt vault:\n" + verify.out);
    assert.match(verify.out, /mallory|not accepted|changed/i);
    t.cleanup();
  });

  test("the attacker is listed as not accepted in team ls, under whatever name they picked", () => {
    const t = team();
    t.alice.run(["verify"]);
    t.takeOver({ addSelf: true });
    const ls = t.alice.run(["team", "ls"]);
    assert.match(ls.out, /not accepted/, ls.out);
    t.cleanup();
  });

  test("same vault id, same generation, a different data key: refused outright", () => {
    const t = team();
    t.alice.run(["verify"]);
    t.takeOver({ addSelf: false, keepId: true, generation: 1 });
    const ran = t.alice.run(runPrint);
    assert.notEqual(ran.code, 0, ran.out);
    assert.doesNotMatch(ran.out, /API_BASE=/);
    assert.match(ran.out, /data key/i, ran.out);
    t.cleanup();
  });

  test("a project whose vault id changed underneath it is refused", () => {
    const t = team();
    t.alice.run(["verify"]);
    t.takeOver({ addSelf: false, keepId: false });
    const ran = t.alice.run(runPrint);
    assert.notEqual(ran.code, 0, ran.out);
    assert.match(ran.out, /different vault|replaced/i, ran.out);
    t.cleanup();
  });

  test("the pins hold when the vault is reached through HUSH_VAULT instead of the project", () => {
    const t = team();
    t.alice.run(["verify"]);
    t.takeOver({ addSelf: true, keepId: true, generation: 2 });
    const copy = join(t.scratch, "copy.json");
    copyFileSync(t.vaultPath, copy);
    const ran = t.alice.run(["get", "API_BASE", "--yes"], { cwd: t.scratch, env: { HUSH_VAULT: copy } });
    assert.notEqual(ran.code, 0, ran.out);
    assert.doesNotMatch(ran.out, /evil\.example/);
    t.cleanup();
  });
});

describe("V-1: accepting covers exactly what was shown", () => {
  test("a member added between being shown and being accepted is not accepted with them", () => {
    const home = mkdtempSync(join(tmpdir(), "hush-trust-unit-"));
    const prev = process.env.HUSH_HOME;
    process.env.HUSH_HOME = home;
    try {
      const owner = generateIdentity();
      const path = join(home, "v.json");
      const v = Vault.create(path, "unit", { name: "owner", pub: owner.pub });
      recordTrusted(v.trustView(v.dekForReview(owner)));

      v.addRecipient(owner, "dave", encodePub(generateIdentity().pub));
      v.save();
      const shown = pendingChanges(v.trustView(v.dekForReview(owner)));
      assert.deepEqual(shown.added.map((a) => a.name), ["dave"]);

      // Someone slips another member in while the person is reading the prompt.
      v.addRecipient(owner, "eve", encodePub(generateIdentity().pub));
      v.save();
      const view = v.trustView(v.dekForReview(owner));
      assert.throws(() => acceptPending(view, shown), /changed again/);
      assert.deepEqual(
        pendingChanges(view).added.map((a) => a.name).sort(),
        ["dave", "eve"],
        "a refused accept recorded something anyway",
      );

      acceptPending(view, pendingChanges(view));
      assert.equal(hasProblems(pendingChanges(view)), false);
    } finally {
      if (prev === undefined) delete process.env.HUSH_HOME;
      else process.env.HUSH_HOME = prev;
      rmSync(home, { recursive: true, force: true });
    }
  });

  test("the key commitment reveals nothing and changes with the key, the vault and the generation", () => {
    const a = newDek();
    const b = newDek();
    const c = dekCommit(a, "vlt_x", 1);
    assert.match(c, /^[0-9a-f]{32}$/);
    assert.ok(!a.toString("hex").includes(c) && !c.includes(a.toString("hex").slice(0, 8)));
    assert.equal(dekCommit(a, "vlt_x", 1), c, "not deterministic");
    assert.notEqual(dekCommit(b, "vlt_x", 1), c);
    assert.notEqual(dekCommit(a, "vlt_y", 1), c);
    assert.notEqual(dekCommit(a, "vlt_x", 2), c);
  });
});

describe("V-1: the MCP server refuses too", () => {
  test("an agent's tools cannot use a rebuilt vault, and are told a person has to accept it", async () => {
    const t = team();
    t.alice.run(["verify"]);
    t.takeOver({ addSelf: true });
    writeFileSync(join(t.root, ".hush", "policy.json"), JSON.stringify({ requireApproval: [], biometry: "off" }));

    const replies = await new Promise<{ id: number; result?: { content?: { text?: string }[]; isError?: boolean } }[]>(
      (resolve) => {
        const child = spawn(process.execPath, [CLI, "mcp"], {
          cwd: t.root,
          stdio: ["pipe", "pipe", "pipe"],
          env: {
            ...process.env, HOME: t.alice.home, HUSH_HOME: t.alice.home, HUSH_IDENTITY: encodeSecret(t.alice.id),
            HUSH_NO_KEYCHAIN: "1", HUSH_BIOMETRY: "off", HUSH_NO_DIALOG: "1", NO_COLOR: "1",
          },
        });
        let out = "";
        child.stdout.on("data", (d) => (out += d));
        child.stdin.on("error", () => {});
        child.on("exit", () =>
          resolve(out.split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l))),
        );
        const call = (id: number, name: string, args: Record<string, unknown>) =>
          JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
        child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize", params: {} }) + "\n");
        child.stdin.write(call(1, "hush_describe_secret", { key: "API_BASE" }) + "\n");
        child.stdin.write(call(2, "hush_run", { command: "npm", args: ["--version"] }) + "\n");
        child.stdin.end();
      },
    );
    for (const id of [1, 2]) {
      const r = replies.find((x) => x.id === id);
      const text = r?.result?.content?.[0]?.text ?? "";
      assert.ok(r?.result?.isError, `tool ${id} used a rebuilt vault:\n${text}`);
      assert.match(text, /team accept/, text);
      assert.doesNotMatch(text, /evil\.example|htt/, text);
    }
    t.cleanup();
  });
});

describe("V-1: the app refuses too, and still loads", () => {
  test("no masked preview of a rebuilt vault, a banner naming the change, and writes answered 409", async () => {
    const t = team();
    t.alice.run(["verify"]);
    t.takeOver({ addSelf: true });
    const child = spawn(process.execPath, [CLI, "ui", "--no-open", "--port", "0"], {
      cwd: t.root,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env, HOME: t.alice.home, HUSH_HOME: t.alice.home, HUSH_IDENTITY: encodeSecret(t.alice.id),
        HUSH_NO_KEYCHAIN: "1", HUSH_BIOMETRY: "off", HUSH_NO_DIALOG: "1", NO_COLOR: "1",
      },
    });
    try {
      const link: string = await new Promise((resolve, reject) => {
        let out = "";
        const timer = setTimeout(() => reject(new Error("ui did not start: " + out)), 15000);
        child.stdout!.on("data", (d) => {
          out += d;
          const m = out.match(/(http:\/\/127\.0\.0\.1:\d+\/[#?]t=[A-Za-z0-9_-]+)/);
          if (m) { clearTimeout(timer); resolve(m[1]); }
        });
      });
      const u = new URL(link.replace("/#t=", "/?t="));
      const token = u.searchParams.get("t")!;
      const api = (path: string, body?: unknown) =>
        fetch(u.origin + path, {
          method: body === undefined ? "GET" : "POST",
          headers: { "x-hush-token": token, "content-type": "application/json" },
          body: body === undefined ? undefined : JSON.stringify(body),
        });

      const res = await api("/api/state");
      assert.equal(res.status, 200, "the page failed to load at all");
      const raw = await res.text();
      const state = JSON.parse(raw) as { trust: string[] | null; project: { secrets: unknown[] }[] };
      assert.ok(state.trust?.some((l) => /mallory/.test(l)), raw.slice(0, 400));
      assert.ok(state.project.every((s) => s.secrets.length === 0), "a preview of a rebuilt vault reached the page");
      assert.doesNotMatch(raw, /evil|sk_live/);

      const write = await api("/api/secret", { scope: "default", key: "NEW_ONE", value: "should-not-land" });
      assert.equal(write.status, 409, await write.text());
    } finally {
      child.kill();
      t.cleanup();
    }
  });
});

describe("V-1: ordinary team changes keep working", () => {
  test("members this machine added, removals seen from elsewhere, and a first look are all accepted", () => {
    const t = team();
    assert.equal(t.alice.run(["team", "add", "bob", t.bob.pk]).code, 0);
    // Alice added Bob herself: no question for Alice.
    assert.match(t.alice.run(runPrint).out, /API_BASE=\[redacted:API_BASE\]/);
    // Bob's first look at the vault is trust on first use.
    assert.match(t.bob.run(runPrint).out, /API_BASE=\[redacted:API_BASE\]/);

    // A removal Bob did not make: accepted, it only takes access away.
    const carol = generateIdentity();
    assert.equal(t.alice.run(["team", "add", "carol", encodePub(carol.pub)]).code, 0);
    assert.equal(t.alice.run(["team", "rm", "carol"]).code, 0);
    assert.match(t.bob.run(runPrint).out, /API_BASE=\[redacted:API_BASE\]/);
    t.cleanup();
  });

  test("in a signed vault, a member an admin added is accepted, and said", () => {
    const t = team();
    t.alice.run(["team", "add", "bob", t.bob.pk]);
    t.bob.run(["verify"]);
    const dave = generateIdentity();
    t.alice.run(["team", "add", "dave", encodePub(dave.pub)]);

    const ran = t.bob.run(runPrint);
    assert.equal(ran.code, 0, ran.out);
    assert.match(ran.out, /API_BASE=\[redacted:API_BASE\]/);
    assert.match(ran.out, /alice changed who can read this vault: added dave \(signed\)/, ran.out);
    assert.doesNotMatch(t.bob.run(runPrint).out, /added dave/, "the notice repeats");
    t.cleanup();
  });

  test("in an unsigned (v2) vault, a member someone else added is refused until accepted, then works", () => {
    const t = team();
    // A v2 vault with Alice as admin and Bob as a member — built in-process and
    // stripped of its signature before anyone's hush has seen it signed.
    const v = Vault.open(t.vaultPath);
    v.addRecipient(t.alice.id, "bob", t.bob.pk);
    v.save();
    const data = JSON.parse(readFileSync(t.vaultPath, "utf8"));
    data.scheme = "hush/v2";
    delete data.signature;
    for (const r of Object.values(data.recipients) as { spk?: string }[]) delete r.spk;
    writeFileSync(t.vaultPath, JSON.stringify(data, null, 2));
    t.alice.run(["verify"]);
    t.bob.run(["verify"]);

    // Bob is a member, not an admin: his addition is not signed.
    const dave = generateIdentity();
    const added = t.bob.run(["team", "add", "dave", encodePub(dave.pub)]);
    assert.equal(added.code, 0, added.out);
    assert.equal(JSON.parse(readFileSync(t.vaultPath, "utf8")).scheme, "hush/v2", "a member's change signed the vault");

    const refused = t.alice.run(runPrint);
    assert.notEqual(refused.code, 0, refused.out);
    assert.match(refused.out, /dave/, "the refusal does not name who was added:\n" + refused.out);

    const noTty = t.alice.run(["team", "accept"]);
    assert.notEqual(noTty.code, 0, "accept went through with nobody asked:\n" + noTty.out);

    const accepted = t.alice.run(["team", "accept", "--yes"]);
    assert.equal(accepted.code, 0, accepted.out);
    assert.match(accepted.out, /dave/);
    assert.match(t.alice.run(runPrint).out, /API_BASE=\[redacted:API_BASE\]/);
    t.cleanup();
  });

  test("a rotation by someone else is accepted and said once", () => {
    const t = team();
    t.alice.run(["team", "add", "bob", t.bob.pk]);
    t.bob.run(["verify"]);
    assert.equal(t.alice.run(["rotate"]).code, 0);
    const first = t.bob.run(runPrint);
    assert.match(first.out, /API_BASE=\[redacted:API_BASE\]/, first.out);
    assert.match(first.out, /rotated/i, "a rotation by someone else went unmentioned:\n" + first.out);
    const second = t.bob.run(runPrint);
    assert.doesNotMatch(second.out, /rotated/i, "the rotation notice repeats:\n" + second.out);
    t.cleanup();
  });

  test("team reject explains how to undo it and changes nothing", () => {
    const t = team();
    t.alice.run(["verify"]);
    t.takeOver({ addSelf: true });
    const r = t.alice.run(["team", "reject"]);
    assert.match(r.out, /git/, r.out);
    assert.notEqual(t.alice.run(runPrint).code, 0, "reject accepted the change");
    t.cleanup();
  });
});
