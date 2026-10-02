/**
 * `hush tailnet`: hush writes its grants into a tailnet policy file and takes
 * them out again, touching nothing else. A fake Tailscale API stands in for
 * the real one; every key and address here is made up.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  grantSnippet, hushGrants, insertGrant, lineDiff, newGrantId, removeGrant, validDestination, validPrincipal,
  type HushGrant,
} from "../src/tailnet-policy.ts";
import { policyApi } from "../src/tailscale-api.ts";
import { stripJsonc } from "../src/agents.ts";
import { bareFolder } from "./helpers/cli.ts";

const POLICY = `// Our tailnet. Edited by hand; keep the comments.
{
\t// people
\t"groups": {"group:eng": ["a@example.com", "b@example.com",],},
\t"grants": [
\t\t// everyone may reach everything (for now)
\t\t{"src": ["*"], "dst": ["*"], "ip": ["*"]},
\t],
\t/* ssh rules */ "ssh": [],
}
`;
const grant = (over: Partial<HushGrant> = {}): HushGrant => ({
  id: newGrantId(), src: ["sam@example.com"], dst: ["100.64.0.5"], port: 8788, sets: ["staging"], ...over,
});

test("a grant goes in, and comes out, leaving every other byte of the file as it was", () => {
  const g = grant();
  const withIt = insertGrant(POLICY, g);
  assert.ok(withIt.includes("// people") && withIt.includes("/* ssh rules */") && withIt.includes("(for now)"));
  assert.deepEqual(hushGrants(withIt).map((x) => [x.id, x.src, x.dst, x.port, x.sets]), [[g.id, g.src, g.dst, 8788, ["staging"]]]);
  const parsed = JSON.parse(stripJsonc(withIt)) as { grants: unknown[] };
  assert.equal(parsed.grants.length, 2, "the existing grant was lost");
  assert.equal(removeGrant(withIt, g.id), POLICY);
});

test("a file without grants, or empty, gets a grants list; two hush grants come out one at a time", () => {
  const g1 = grant();
  const g2 = grant({ src: ["group:eng"], sets: ["*"] });
  const noGrants = `{\n\t"acls": [],\n}\n`;
  const one = insertGrant(noGrants, g1);
  const two = insertGrant(one, g2);
  assert.deepEqual(hushGrants(two).map((x) => x.id).sort(), [g1.id, g2.id].sort());
  assert.equal(removeGrant(removeGrant(two, g2.id), g1.id), `{\n\t"grants": [\n\t],\n\t"acls": [],\n}\n`);
  assert.deepEqual(hushGrants(insertGrant("{}", g1)).map((x) => x.id), [g1.id]);
});

test("someone else's grants are never hush's, and a broken file is refused rather than edited", () => {
  const notMine = POLICY.replace(`{"src": ["*"]`, `{"app": {"github.com/omarei-omoto/cap/hush": [{"sets": ["x"], "grant": "not-a-hush-id"}]}, "src": ["*"]`);
  assert.deepEqual(hushGrants(notMine), []);
  assert.throws(() => removeGrant(POLICY, "hush-00000000"), /no grant/);
  assert.throws(() => insertGrant(`{ "grants": [ }`, grant()));
  assert.throws(() => insertGrant(`["not", "an", "object"]`, grant()));
});

test("who and where: logins, groups, tags; a tailnet IP, a tag or a host alias", () => {
  for (const p of ["sam@example.com", "group:eng", "tag:ci", "autogroup:member"]) assert.ok(validPrincipal(p), p);
  for (const p of ["*", "sam", "group:", "evil\"],\"src\":[\"*", "sam@example.com,x@y.z"]) assert.ok(!validPrincipal(p), p);
  for (const d of ["100.64.0.5", "tag:hush", "broker"]) assert.ok(validDestination(d), d);
  for (const d of ["*", "0.0.0.0/0", "8.8.8.8", "100.1.2.3", "10.0.0.1"]) assert.ok(!validDestination(d), d);
});

test("the snippet and the diff read cleanly", () => {
  const g = grant({ id: "hush-0011aabb" });
  assert.match(grantSnippet(g), /^\/\/ hush: sam@example\.com may use staging on the broker \(hush-0011aabb\)\n\{\n\t"src": \["sam@example\.com"\],/);
  const diff = lineDiff(POLICY, insertGrant(POLICY, g));
  assert.ok(diff.split("\n").every((l) => l.startsWith("  ") || l.startsWith("+ ")), "an insert showed a removed line");
  assert.match(diff, /\+ \t\t\/\/ hush: sam@example\.com/);
});

// ------------------------------------------------------------------ the API

function fakeTailscale(policy: { text: string; etag: string; scope?: string }) {
  const seen: { method: string; url: string; auth: string; ifMatch?: string; body: string }[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({ method: req.method!, url: req.url!, auth: String(req.headers.authorization), ifMatch: req.headers["if-match"] as string | undefined, body });
      if (req.url?.endsWith("/oauth/token")) {
        const form = new URLSearchParams(body);
        if (form.get("client_id") !== "kOAUTHid123" || form.get("client_secret") !== "tskey-client-kOAUTHid123-FAKEsecret789") {
          res.writeHead(401);
          return res.end("{}");
        }
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(JSON.stringify({ access_token: "tskey-access-FAKEhour456", token_type: "Bearer", expires_in: 3600, scope: policy.scope ?? "policy_file" }));
      }
      const okAuth = ["Bearer tskey-api-FAKE7Lm02Np93Kr74", "Bearer tskey-access-FAKEhour456"];
      if (!okAuth.includes(String(req.headers.authorization))) {
        res.writeHead(401);
        return res.end("{}");
      }
      if (req.url?.endsWith("/acl/validate")) {
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(body.includes("BAD") ? JSON.stringify({ message: "invalid", data: [{ errors: ["src: BAD is not a user"] }] }) : "{}");
      }
      if (req.method === "GET") {
        res.writeHead(200, { "content-type": "application/hujson", etag: policy.etag });
        return res.end(policy.text);
      }
      if (req.headers["if-match"] !== policy.etag) {
        res.writeHead(412);
        return res.end("{}");
      }
      policy.text = body;
      policy.etag = `"e${Number(policy.etag.slice(2, -1)) + 1}"`;
      res.writeHead(200);
      res.end(body);
    });
  });
  return { server, seen };
}

test("the API client: the key goes in the header only, saves only over the version read, and reports Tailscale's objections", async () => {
  const state = { text: POLICY.replace("(for now)", "(for now) $TAILSCALE_API_KEY stays literal"), etag: '"e1"' };
  const { server, seen } = fakeTailscale(state);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/v2`;
  try {
    const api = policyApi("tskey-api-FAKE7Lm02Np93Kr74", base);
    const { text, etag } = await api.get();
    assert.equal(etag, '"e1"');
    const next = insertGrant(text, grant());
    assert.equal(await api.validate(next), null);
    assert.match(String(await api.validate(next + "BAD")), /BAD is not a user/);
    await api.set(next, etag);
    assert.equal(state.text, next);
    assert.ok(state.text.includes("$TAILSCALE_API_KEY stays literal"), "the policy body was substituted");
    await assert.rejects(api.set(next, '"e1"'), /changed the policy file/);
    await assert.rejects(policyApi("tskey-api-wrong000000000000", base).get(), /refused the API key/);
    assert.ok(seen.every((s) => !s.body.includes("tskey-api-FAKE")), "the key was sent in a body");
  } finally {
    server.close();
  }
});

// ------------------------------------------------------------------ the command

test("without a stored Tailscale key, hush tailnet grant prints the grant to paste and how to let hush do it", () => {
  const b = bareFolder();
  try {
    const r = b.run(["tailnet", "grant", "--to", "sam@example.com", "--sets", "staging", "--dst", "100.64.0.5"]);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /Add this to "grants"/);
    assert.match(r.out, /"src": \["sam@example\.com"\]/);
    assert.match(r.out, /"ip":  \["tcp:8788"\]/);
    assert.match(r.out, /hush add tailscale/);
    const bad = b.run(["tailnet", "grant", "--to", "*", "--sets", "staging", "--dst", "100.64.0.5"]);
    assert.notEqual(bad.code, 0);
  } finally {
    b.cleanup?.();
  }
});

test("with a stored credential: a preview saves nothing, --apply --yes saves exactly the grant, revoke takes it back", async () => {
  const state = { text: POLICY, etag: '"e1"' };
  const { server, seen } = fakeTailscale(state);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/v2`;
  const work = mkdtempSync(join(tmpdir(), "hush-tailnet-"));
  const saved = { home: process.env.HUSH_HOME, id: process.env.HUSH_IDENTITY, cwd: process.cwd(), dialog: process.env.HUSH_NO_DIALOG };
  try {
    const { generateIdentity, encodeSecret } = await import("../src/crypto.ts");
    const { Vault } = await import("../src/vault.ts");
    const { parseArgs } = await import("../src/cli/args.ts");
    const { cmdTailnet } = await import("../src/commands/tailnet.ts");
    const { policyApi: realApi } = await import("../src/tailscale-api.ts");
    const id = generateIdentity();
    process.env.HUSH_HOME = join(work, "home");
    process.env.HUSH_IDENTITY = encodeSecret(id);
    process.env.HUSH_NO_DIALOG = "1";
    mkdirSync(join(work, "home", "vaults", "global"), { recursive: true });
    const lib = Vault.create(join(work, "home", "vaults", "global", "vault.json"), "global", { name: "me", pub: id.pub });
    // Both kinds stored: the OAuth client must win over the broader API token.
    lib.set(id, "tailscale-token", "TAILSCALE_API_KEY", "tskey-api-FAKE7Lm02Np93Kr74");
    lib.set(id, "tailscale", "TAILSCALE_OAUTH_CLIENT_ID", "kOAUTHid123");
    lib.set(id, "tailscale", "TAILSCALE_OAUTH_CLIENT_SECRET", "tskey-client-kOAUTHid123-FAKEsecret789");
    lib.save();
    mkdirSync(join(work, "proj"));
    process.chdir(join(work, "proj"));
    const api = (c: Parameters<typeof realApi>[0], onScope: (s: string[]) => void) => realApi(c, base, undefined, onScope);

    await cmdTailnet(parseArgs(["grant", "--to", "sam@example.com", "--sets", "staging", "--dst", "100.64.0.5"]), { api });
    assert.equal(state.text, POLICY, "a preview saved the file");

    await cmdTailnet(parseArgs(["grant", "--to", "sam@example.com", "--sets", "staging", "--dst", "100.64.0.5", "--apply", "--yes"]), { api });
    const written = hushGrants(state.text);
    assert.equal(written.length, 1);
    assert.equal(removeGrant(state.text, written[0].id), POLICY, "more than the grant changed");

    await cmdTailnet(parseArgs(["revoke", written[0].id, "--apply", "--yes"]), { api });
    assert.equal(state.text, POLICY);
    const policyCalls = seen.filter((x) => !x.url.endsWith("/oauth/token"));
    assert.ok(policyCalls.length >= 4);
    assert.ok(policyCalls.every((x) => x.auth === "Bearer tskey-access-FAKEhour456"), "the API token was used although an OAuth client was stored");
  } finally {
    process.chdir(saved.cwd);
    for (const [k, v] of [["HUSH_HOME", saved.home], ["HUSH_IDENTITY", saved.id], ["HUSH_NO_DIALOG", saved.dialog]] as const) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    server.close();
    rmSync(work, { recursive: true, force: true });
  }
});

test("an OAuth client: its secret goes only to the sign-in, the policy calls use the hour-long token", async () => {
  const state = { text: POLICY, etag: '"e1"', scope: "policy_file devices:core" };
  const { server, seen } = fakeTailscale(state);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/v2`;
  try {
    let scopes: string[] = [];
    const api = policyApi({ kind: "oauth", clientId: "kOAUTHid123", clientSecret: "tskey-client-kOAUTHid123-FAKEsecret789" }, base, "-", (s) => (scopes = s));
    const { text, etag } = await api.get();
    await api.set(insertGrant(text, grant()), etag);
    assert.deepEqual(scopes, ["policy_file", "devices:core"], "the granted scopes were not reported");
    const signIns = seen.filter((x) => x.url.endsWith("/oauth/token"));
    assert.equal(signIns.length, 1, "it signed in more than once for one command");
    assert.match(signIns[0].body, /scope=policy_file/);
    for (const x of seen.filter((x) => !x.url.endsWith("/oauth/token"))) {
      assert.equal(x.auth, "Bearer tskey-access-FAKEhour456");
      assert.ok(!x.body.includes("FAKEsecret789"), "the client secret left the sign-in request");
    }
    await assert.rejects(
      policyApi({ kind: "oauth", clientId: "kOAUTHid123", clientSecret: "wrong-secret-000000000000" }, base).get(),
      /refused the OAuth client/,
    );
  } finally {
    server.close();
  }
});
