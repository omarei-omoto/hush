/**
 * F-6: how old each value is, which are overdue, and which were readable by
 * someone who has since been removed.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { Vault } from "../src/vault.ts";
import { generateIdentity, encodePub, encodeSecret } from "../src/crypto.ts";
import { keyAges, describeAge } from "../src/freshness.ts";
import { mergePolicies, rotationDaysFor } from "../src/policy.ts";
import { DEFAULT_POLICY } from "../src/mcp.ts";
import { rotationUrl } from "../src/services.ts";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.ts");

function vaultWithTwo() {
  const dir = mkdtempSync(join(tmpdir(), "hush-fresh-"));
  const owner = generateIdentity();
  const sam = generateIdentity();
  const v = Vault.create(join(dir, "vault.json"), "f", { name: "owner", pub: owner.pub, priv: owner.priv });
  v.set(owner, "default", "STRIPE_SECRET_KEY", "sk_live_before_sam_left");
  v.set(owner, "default", "OTHER", "other-value-here");
  v.addRecipient(owner, "sam", encodePub(sam.pub));
  v.save();
  return { dir, owner, sam, v, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

describe("F-6: exposure after a member leaves", () => {
  test("team rm marks every value they could read; setting it again clears it; moving it does not", () => {
    const t = vaultWithTwo();
    const { exposed } = t.v.removeRecipient(t.owner, "sam");
    assert.equal(exposed, 2);
    assert.deepEqual(t.v.data.envs.default.STRIPE_SECRET_KEY.exposed, ["sam"]);

    t.v.set(t.owner, "default", "STRIPE_SECRET_KEY", "sk_live_rotated_after");
    assert.equal(t.v.data.envs.default.STRIPE_SECRET_KEY.exposed, undefined, "a new value is still marked");

    t.v.ensureEnvExists("prod");
    t.v.moveSecret(t.owner, "OTHER", "default", "prod");
    assert.deepEqual(t.v.data.envs.prod.OTHER.exposed, ["sam"], "moving a value hid that it was seen");
    t.cleanup();
  });

  test("hush exposed lists them with where to replace each, and never a value", () => {
    const t = vaultWithTwo();
    t.v.removeRecipient(t.owner, "sam");
    t.v.save();
    const home = mkdtempSync(join(tmpdir(), "hush-fresh-home-"));
    const r = spawnSync(process.execPath, [CLI, "exposed"], {
      cwd: t.dir,
      env: { ...process.env, HOME: home, HUSH_HOME: home, HUSH_VAULT: join(t.dir, "vault.json"), HUSH_IDENTITY: encodeSecret(t.owner), HUSH_NO_KEYCHAIN: "1", NO_COLOR: "1", HUSH_NO_NUDGE: "1" },
      encoding: "utf8",
    });
    const out = r.stdout + r.stderr;
    assert.match(out, /STRIPE_SECRET_KEY/);
    assert.match(out, /readable by sam/);
    assert.match(out, /dashboard\.stripe\.com\/apikeys/);
    assert.doesNotMatch(out, /sk_live_before/);
    rmSync(home, { recursive: true, force: true });
    t.cleanup();
  });
});

describe("F-6: rotateAfterDays", () => {
  test("keys past the limit are overdue, per set or with a default", () => {
    const t = vaultWithTwo();
    const old = new Date(Date.now() - 100 * 86_400_000).toISOString();
    t.v.data.envs.default.STRIPE_SECRET_KEY.updatedAt = old;
    const ages = keyAges(t.v, { rotateAfterDays: { "*": 90 } });
    const stripe = ages.find((k) => k.key === "STRIPE_SECRET_KEY")!;
    assert.equal(stripe.overdue, true);
    assert.equal(stripe.days, 100);
    assert.equal(ages.find((k) => k.key === "OTHER")!.overdue, false);
    assert.equal(keyAges(t.v, { rotateAfterDays: { prod: 30 } }).some((k) => k.overdue), false, "a limit for another set applied");
    assert.equal(keyAges(t.v, null).some((k) => k.overdue), false);
    assert.equal(describeAge(100), "3 months");
    t.cleanup();
  });

  test("a floor can ask to be told sooner than a repository, never later", () => {
    const merged = mergePolicies(DEFAULT_POLICY, { rotateAfterDays: 30 }, { rotateAfterDays: { "*": 90, dev: 10 } });
    assert.equal(rotationDaysFor(merged, "prod"), 30);
    assert.equal(rotationDaysFor(merged, "dev"), 10);
    const none = mergePolicies(DEFAULT_POLICY, {}, {});
    assert.equal(rotationDaysFor(none, "prod"), null);
  });

  test("rotation links exist for the credentials people rotate most, and not for a database URL", () => {
    assert.match(rotationUrl("OPENAI_API_KEY")!, /^https:\/\//);
    assert.match(rotationUrl("AWS_SECRET_ACCESS_KEY")!, /^https:\/\//);
    assert.equal(rotationUrl("DATABASE_URL"), null);
    assert.equal(rotationUrl("SOMETHING_UNKNOWN"), null);
  });

  test("hush ls --age prints ages and flags, and hush level mentions overdue and exposed values", () => {
    const t = vaultWithTwo();
    t.v.removeRecipient(t.owner, "sam");
    t.v.data.envs.default.OTHER.updatedAt = new Date(Date.now() - 400 * 86_400_000).toISOString();
    t.v.save();
    const home = mkdtempSync(join(tmpdir(), "hush-fresh-home-"));
    writeFileSync(join(home, "policy.json"), JSON.stringify({ rotateAfterDays: 90 }));
    const env = { ...process.env, HOME: home, HUSH_HOME: home, HUSH_VAULT: join(t.dir, "vault.json"), HUSH_IDENTITY: encodeSecret(t.owner), HUSH_NO_KEYCHAIN: "1", NO_COLOR: "1", HUSH_NO_NUDGE: "1" };
    const ls = spawnSync(process.execPath, [CLI, "ls", "default", "--age"], { cwd: t.dir, env, encoding: "utf8" });
    assert.match(ls.stdout, /OTHER\s+13 months\s+overdue \(limit 90 days\)\s+exposed to sam/);
    const level = spawnSync(process.execPath, [CLI, "level"], { cwd: t.dir, env, encoding: "utf8" });
    assert.match(level.stdout, /readable by someone since removed/);
    assert.match(level.stdout, /past your rotateAfterDays/);
    rmSync(home, { recursive: true, force: true });
    t.cleanup();
  });
});
