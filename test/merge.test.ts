/**
 * F-1: the vault merge.
 *
 * The core check is differential: every pair of operations — one on each
 * branch — is applied to real vaults and to a plaintext model, and the merged
 * vault must decrypt to exactly what a key-by-key three-way merge of the model
 * says, with the same keys in conflict. Nothing about how the merge is written
 * is assumed; only what a person would expect the merged vault to hold.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Vault, type VaultFile } from "../src/vault.ts";
import { generateIdentity, encodePub, type Identity } from "../src/crypto.ts";
import { mergeVaults } from "../src/merge.ts";
import { verifyHeader } from "../src/header.ts";

const owner = generateIdentity();
const leaving = generateIdentity();
const joiners: Record<string, Identity> = { ours: generateIdentity(), theirs: generateIdentity() };
const scopedIds: Record<string, Identity> = { ours: generateIdentity(), theirs: generateIdentity() };

type Model = { values: Map<string, string>; members: Set<string> };

function baseVault(): { data: VaultFile; model: Model } {
  const dir = mkdtempSync(join(tmpdir(), "hush-merge-"));
  const v = Vault.create(join(dir, "vault.json"), "m", { name: "owner", pub: owner.pub });
  const values: Record<string, string> = {
    "default/KEY_C": "c-base",
    "default/KEY_D": "d-base",
    "default/KEY_M": "m-base",
    "default/KEEP": "keep-base",
    "staging/S1": "s1-base",
  };
  for (const [k, val] of Object.entries(values)) {
    const [env, key] = k.split("/");
    v.set(owner, env, key, val);
  }
  v.addRecipient(owner, "remove-me", encodePub(leaving.pub));
  // Saved, as it would be in a repository: a v3 vault is signed on save.
  v.save();
  const data = JSON.parse(readFileSync(join(dir, "vault.json"), "utf8")) as VaultFile;
  rmSync(dir, { recursive: true, force: true });
  return { data, model: { values: new Map(Object.entries(values)), members: new Set(["owner", "remove-me"]) } };
}

type Op = { name: string; rotates: boolean; apply: (v: Vault, m: Model, side: string) => void };

const OPS: Op[] = [
  { name: "add", rotates: false, apply: (v, m, side) => { v.set(owner, "default", `NEW_${side.toUpperCase()}`, `new-${side}`); m.values.set(`default/NEW_${side.toUpperCase()}`, `new-${side}`); } },
  { name: "change", rotates: false, apply: (v, m, side) => { v.set(owner, "default", "KEY_C", `c-${side}`); m.values.set("default/KEY_C", `c-${side}`); } },
  { name: "delete", rotates: false, apply: (v, m) => { v.delete("default", "KEY_D"); m.values.delete("default/KEY_D"); } },
  {
    name: "rename set", rotates: false,
    apply: (v, m, side) => {
      v.renameEnv(owner, "staging", `stage-${side}`);
      for (const [k, val] of [...m.values]) {
        if (k.startsWith("staging/")) { m.values.delete(k); m.values.set(`stage-${side}/${k.slice(8)}`, val); }
      }
    },
  },
  {
    name: "move key", rotates: false,
    apply: (v, m) => {
      v.moveSecret(owner, "KEY_M", "default", "staging");
      m.values.set("staging/KEY_M", m.values.get("default/KEY_M")!);
      m.values.delete("default/KEY_M");
    },
  },
  { name: "rotate", rotates: true, apply: (v) => { v.rotate(owner); } },
  { name: "team add", rotates: false, apply: (v, m, side) => { v.addRecipient(owner, `add-${side}`, encodePub(joiners[side].pub)); m.members.add(`add-${side}`); } },
  { name: "team rm", rotates: true, apply: (v, m) => { v.removeRecipient(owner, "remove-me"); m.members.delete("remove-me"); } },
  {
    // A scoped member for "staging": the set gets a key of its own (hush/v3).
    name: "grant set", rotates: false,
    apply: (v, m, side) => {
      v.addRecipient(owner, `scoped-${side}`, encodePub(scopedIds[side].pub), "member", { sets: ["staging"] });
      m.members.add(`scoped-${side}`);
    },
  },
];

/** An independent, obviously-correct three-way merge of the plaintext model. */
function modelMerge(o: Model, a: Model, b: Model): { values: Map<string, string>; conflicts: string[]; members: Set<string> } {
  const keys = new Set([...o.values.keys(), ...a.values.keys(), ...b.values.keys()]);
  const values = new Map<string, string>();
  const conflicts: string[] = [];
  for (const k of keys) {
    const [va, vb, vo] = [a.values.get(k), b.values.get(k), o.values.get(k)];
    let r: string | undefined;
    if (va === vb) r = va;
    else if (va === vo) r = vb;
    else if (vb === vo) r = va;
    else { conflicts.push(k); r = va; }
    if (r !== undefined) values.set(k, r);
  }
  const members = new Set<string>();
  for (const n of new Set([...o.members, ...a.members, ...b.members])) {
    const [ia, ib, io] = [a.members.has(n), b.members.has(n), o.members.has(n)];
    if (ia === ib ? ia : ia === io ? ib : ia) members.add(n);
  }
  return { values, members, conflicts: conflicts.sort() };
}

const clone = (m: Model): Model => ({ values: new Map(m.values), members: new Set(m.members) });

function flatten(v: Vault, id: Identity): Map<string, string> {
  const out = new Map<string, string>();
  for (const env of v.envNames()) for (const [k, val] of Object.entries(v.materialize(id, env))) out.set(`${env}/${k}`, val);
  return out;
}

describe("F-1: merging two branches of a vault", () => {
  for (const opA of OPS) {
    for (const opB of OPS) {
      test(`ours: ${opA.name}  ·  theirs: ${opB.name}`, () => {
        const base = baseVault();
        const ours = Vault.fromData("ours", JSON.parse(JSON.stringify(base.data)));
        const theirs = Vault.fromData("theirs", JSON.parse(JSON.stringify(base.data)));
        const mA = clone(base.model);
        const mB = clone(base.model);
        opA.apply(ours, mA, "ours");
        opB.apply(theirs, mB, "theirs");

        const r = mergeVaults(base.data, ours.data, theirs.data, owner);

        if (opA.rotates && opB.rotates) {
          assert.ok(r.structural, "two rotations were merged instead of refused");
          assert.match(r.structural!, /both branches changed the vault key/);
          return;
        }
        assert.equal(r.structural, undefined, r.structural);
        const expected = modelMerge(base.model, mA, mB);

        const merged = Vault.fromData("merged", r.data!);
        assert.deepEqual(
          Object.fromEntries([...flatten(merged, owner)].sort()),
          Object.fromEntries([...expected.values].sort()),
          "the merged vault does not hold what a three-way merge of the values says",
        );
        assert.deepEqual(r.conflicts.map((c) => `${c.set}/${c.key}`).sort(), expected.conflicts);
        assert.deepEqual(merged.members().map((m) => m.name).sort(), [...expected.members].sort());

        // Every member can open it, and nobody else is wrapped in.
        for (const [side, id] of Object.entries(joiners)) {
          if (expected.members.has(`add-${side}`)) {
            assert.ok(merged.canRead(id), `add-${side} is listed but cannot decrypt`);
            flatten(merged, id);
          }
        }
        assert.equal(merged.canRead(leaving), expected.members.has("remove-me"), "a removed member can still decrypt");
        assert.deepEqual(merged.staleValues(), [], "a value was left under an older key");
        if (merged.signed) assert.ok(verifyHeader(r.data!).ok, `the merged vault is not validly signed: ${JSON.stringify(verifyHeader(r.data!))}`);
        // A scoped member reads their set and nothing else.
        for (const [side, sid] of Object.entries(scopedIds)) {
          if (!expected.members.has(`scoped-${side}`) || !merged.hasSet("staging") || !merged.isRestricted("staging")) continue;
          assert.ok(merged.canReadSet(sid, "staging"), `scoped-${side} cannot read the set they were given`);
          assert.ok(!merged.canReadSet(sid, "default"), `scoped-${side} can read a set they were not given`);
          merged.materialize(sid, "staging");
        }
        assert.deepEqual(merged.unlistedWraps(), [], "a key wrap belongs to no listed member");

        // Nothing a merge reports carries a value.
        const reported = JSON.stringify({ c: r.conflicts, n: r.notes, s: r.structural });
        for (const val of new Set([...mA.values.values(), ...mB.values.values()])) {
          assert.ok(!reported.includes(val), `a value reached the merge report: ${val}`);
        }
      });
    }
  }
});

describe("F-1: without an identity", () => {
  test("branches that share a key merge byte for byte", () => {
    const base = baseVault();
    const ours = Vault.fromData("o", JSON.parse(JSON.stringify(base.data)));
    const theirs = Vault.fromData("t", JSON.parse(JSON.stringify(base.data)));
    ours.set(owner, "default", "A_ONLY", "a-only-value");
    theirs.set(owner, "default", "B_ONLY", "b-only-value");
    const r = mergeVaults(base.data, ours.data, theirs.data, null);
    assert.equal(r.structural, undefined);
    const merged = Vault.fromData("m", r.data!);
    assert.equal(merged.get(owner, "default", "A_ONLY"), "a-only-value");
    assert.equal(merged.get(owner, "default", "B_ONLY"), "b-only-value");
  });

  test("a rotation on one branch is refused rather than half-merged", () => {
    const base = baseVault();
    const ours = Vault.fromData("o", JSON.parse(JSON.stringify(base.data)));
    const theirs = Vault.fromData("t", JSON.parse(JSON.stringify(base.data)));
    ours.rotate(owner);
    theirs.set(owner, "default", "B_ONLY", "b-only-value");
    const r = mergeVaults(base.data, ours.data, theirs.data, null);
    assert.ok(r.structural, "merged without being able to tell a re-seal from a change");
    assert.equal(r.data, undefined, "a half-merged vault was produced");
  });

  test("an identity that is not a member is the same as none", () => {
    const base = baseVault();
    const ours = Vault.fromData("o", JSON.parse(JSON.stringify(base.data)));
    const theirs = Vault.fromData("t", JSON.parse(JSON.stringify(base.data)));
    ours.rotate(owner);
    theirs.set(owner, "default", "B_ONLY", "b-only-value");
    assert.ok(mergeVaults(base.data, ours.data, theirs.data, generateIdentity()).structural);
  });
});

describe("F-1: refusals", () => {
  test("two different vaults are never merged", () => {
    const a = baseVault();
    const b = baseVault();
    const r = mergeVaults(a.data, a.data, b.data, owner);
    assert.match(r.structural ?? "", /different vaults/);
  });

  test("a conflict records both sides sealed under the merged key, never in the clear", () => {
    const base = baseVault();
    const ours = Vault.fromData("o", JSON.parse(JSON.stringify(base.data)));
    const theirs = Vault.fromData("t", JSON.parse(JSON.stringify(base.data)));
    theirs.rotate(owner);
    ours.set(owner, "default", "KEY_C", "ours-says");
    theirs.set(owner, "default", "KEY_C", "theirs-says");
    const r = mergeVaults(base.data, ours.data, theirs.data, owner);
    assert.equal(r.conflicts.length, 1);
    const merged = Vault.fromData("m", r.data!);
    // theirs' entry, as recorded, opens under the merged vault's key.
    merged.data.envs.default.KEY_C = r.conflicts[0].theirs.entry!;
    assert.equal(merged.get(owner, "default", "KEY_C"), "theirs-says");
    assert.ok(!JSON.stringify(r.conflicts).includes("says"));
  });
});
