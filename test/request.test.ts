/**
 * `hush request` — the substitution surface, the transport rules, and a real
 * round trip against a loopback server.
 *
 * The loopback tests are the ones that matter: they prove the value actually
 * reached the wire *and* that the same value came back masked, which is the
 * whole promise. Everything else pins a rule a later refactor could quietly
 * drop.
 */
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";

import {
  substitute, resolveTargets, parseHeader, isHeaderName, assertHeaderValue,
  assertTransport, isLoopback, prepare, requestWithSecrets, renderRequest,
  requestSummary, requestSecretNames, statusLine,
} from "../src/request.ts";
import { hostAllowed, checkHost } from "../src/policy.ts";
import { DEFAULT_POLICY } from "../src/mcp.ts";

const SECRET = "super-secret-value-here";
const secrets = { API_KEY: SECRET, OTHER: "another-long-secret-value" };

describe("substitute", () => {
  test("replaces $NAME and ${NAME}", () => {
    assert.equal(substitute("Bearer $API_KEY", secrets).out, `Bearer ${SECRET}`);
    assert.equal(substitute("Bearer ${API_KEY}", secrets).out, `Bearer ${SECRET}`);
  });

  test("$$ is a literal dollar sign, not a substitution", () => {
    const s = substitute("cost is $$5 for $API_KEY", secrets);
    assert.equal(s.out, `cost is $5 for ${SECRET}`);
    assert.deepEqual(s.used, ["API_KEY"]);
  });

  test("a name with no value is reported rather than left silently", () => {
    const s = substitute("Bearer $NOPE", secrets);
    assert.equal(s.out, "Bearer $NOPE");
    assert.deepEqual(s.missing, ["NOPE"]);
    assert.deepEqual(s.used, []);
  });

  test("a value inserted by substitution is never rescanned", () => {
    // One pass, so an inserted value cannot cascade into a second replacement.
    assert.equal(substitute("$A", { A: "abc", B: "b" }).out, "abc");
  });

  test("text with no dollar sign is left exactly alone", () => {
    assert.equal(substitute("plain text", secrets).out, "plain text");
  });
});

describe("resolveTargets", () => {
  test("headers are always permitted", () => {
    assert.deepEqual([...resolveTargets(undefined)], ["header"]);
  });

  test("body and query are opt-in, from one comma-separated value or several", () => {
    assert.deepEqual([...resolveTargets(["body"])], ["header", "body"]);
    assert.deepEqual([...resolveTargets(["query,body"])], ["header", "query", "body"]);
  });

  test("an unknown target is refused rather than ignored", () => {
    assert.throws(() => resolveTargets(["headers"]), /Unknown substitution target "headers"/);
  });
});

describe("header parsing", () => {
  test("splits on the first colon so a value may contain one", () => {
    assert.deepEqual(parseHeader("Authorization: Bearer a:b"), ["Authorization", "Bearer a:b"]);
  });

  test("refuses a missing colon", () => {
    assert.throws(() => parseHeader("Authorization Bearer x"), /Bad --header/);
  });

  test("refuses a name that is not a token", () => {
    assert.throws(() => parseHeader("Bad Name: x"), /Bad header name/);
    assert.equal(isHeaderName("Bad Name"), false);
    assert.equal(isHeaderName("X-Api-Key"), true);
  });

  test("refuses a value that would end the header early", () => {
    assert.throws(() => parseHeader("X-A: a\nX-B: b"), /contains a line break/);
    assert.throws(() => assertHeaderValue("X-A", "a\r\nX-B: b"), /contains a line break/);
  });
});

describe("transport rules", () => {
  test("https is always allowed", () => {
    assert.doesNotThrow(() => assertTransport(new URL("https://api.stripe.com/v1"), false));
  });

  test("loopback http is allowed, so a local dev server works", () => {
    assert.equal(isLoopback("127.0.0.1"), true);
    assert.equal(isLoopback("localhost"), true);
    assert.doesNotThrow(() => assertTransport(new URL("http://127.0.0.1:3000/x"), false));
    assert.doesNotThrow(() => assertTransport(new URL("http://localhost:8080/x"), false));
  });

  test("cleartext to a real host is refused, and --insecure overrides it", () => {
    assert.throws(() => assertTransport(new URL("http://api.stripe.com/v1"), false), /cleartext/);
    assert.doesNotThrow(() => assertTransport(new URL("http://api.stripe.com/v1"), true));
  });

  test("a protocol that is not http(s) is refused", () => {
    assert.throws(() => assertTransport(new URL("ftp://example.com/x"), false), /not a supported protocol/);
  });
});

describe("hostAllowed", () => {
  test("an empty list means no restriction", () => {
    assert.equal(hostAllowed([], "anything.example", "anything.example"), true);
  });

  test("a bare entry matches the host on any port", () => {
    assert.equal(hostAllowed(["api.stripe.com"], "api.stripe.com", "api.stripe.com"), true);
    assert.equal(hostAllowed(["api.stripe.com"], "api.stripe.com", "api.stripe.com:8443"), true);
    assert.equal(hostAllowed(["api.stripe.com"], "evil.example", "evil.example"), false);
  });

  test("an entry with a port has to match the port", () => {
    assert.equal(hostAllowed(["localhost:3000"], "localhost", "localhost:3000"), true);
    assert.equal(hostAllowed(["localhost:3000"], "localhost", "localhost:4000"), false);
  });

  test("a wildcard matches a subdomain but never the apex", () => {
    // The apex is where a shared tenant or a takeover lives, so `*.example.com`
    // must not quietly mean `example.com`.
    assert.equal(hostAllowed(["*.example.com"], "api.example.com", "api.example.com"), true);
    assert.equal(hostAllowed(["*.example.com"], "example.com", "example.com"), false);
    assert.equal(hostAllowed(["*.example.com"], "notexample.com", "notexample.com"), false);
  });

  test("matching is case-insensitive", () => {
    assert.equal(hostAllowed(["API.Stripe.com"], "api.stripe.com", "api.stripe.com"), true);
  });

  test("checkHost refuses a host outside the list, naming what is allowed", () => {
    const policy = { ...DEFAULT_POLICY, allowHosts: ["api.stripe.com"] };
    assert.doesNotThrow(() => checkHost(policy, new URL("https://api.stripe.com/v1")));
    assert.throws(
      () => checkHost(policy, new URL("https://collector.evil.example/x")),
      /forbids requests to "collector\.evil\.example".*api\.stripe\.com/,
    );
  });
});

describe("prepare", () => {
  const base = { url: "https://api.example.com/v1/thing", secrets };

  test("substitutes into header values by default", () => {
    const p = prepare({ ...base, headers: [["authorization", "Bearer $API_KEY"]] });
    assert.deepEqual(p.headers[0], ["authorization", `Bearer ${SECRET}`]);
    assert.deepEqual(p.used, ["API_KEY"]);
  });

  test("does not substitute into the body unless asked", () => {
    const p = prepare({ ...base, method: "POST", body: '{"key":"$API_KEY"}' });
    assert.equal(p.body, '{"key":"$API_KEY"}');
    assert.deepEqual(p.used, []);
  });

  test("a $name in an unsubstituted body is not treated as a vault lookup", () => {
    // JSON Schema's own keywords start with a dollar sign, and a body is
    // usually something the *remote* interprets. Refusing this would make
    // `hush request` unusable for any JSON-Schema-shaped payload.
    const schema = '{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"#/$defs/x"}';
    const p = prepare({ ...base, method: "POST", body: schema });
    assert.equal(p.body, schema);
    assert.deepEqual(p.used, []);
  });

  test("$$ writes a literal dollar sign into a header", () => {
    const p = prepare({ ...base, headers: [["x-note", "costs $$5"]] });
    assert.deepEqual(p.headers[0], ["x-note", "costs $5"]);
  });

  test("substitutes into the body when body is named", () => {
    const p = prepare({ ...base, method: "POST", body: '{"key":"$API_KEY"}', substitute: ["body"] });
    assert.equal(p.body, `{"key":"${SECRET}"}`);
    assert.deepEqual(p.used, ["API_KEY"]);
  });

  test("does not substitute into the query unless asked", () => {
    const p = prepare({ ...base, url: "https://api.example.com/v1?k=$API_KEY" });
    assert.equal(p.url.search, "?k=$API_KEY");
  });

  test("substitutes into the query when query is named", () => {
    const p = prepare({ ...base, url: "https://api.example.com/v1?k=$API_KEY", substitute: ["query"] });
    assert.equal(p.url.search, `?k=${SECRET}`);
  });

  test("refuses to put a secret in the URL path, where logs can read it", () => {
    assert.throws(
      () => prepare({ ...base, url: "https://api.example.com/v1/$API_KEY/thing" }),
      /would go in the URL path/,
    );
  });

  test("an unresolvable name is refused, naming it", () => {
    assert.throws(
      () => prepare({ ...base, headers: [["authorization", "Bearer $TYPO"]] }),
      /No such secret in these sets: TYPO/,
    );
  });

  test("defaults to POST when there is a body and GET otherwise", () => {
    assert.equal(prepare({ ...base }).method, "GET");
    assert.equal(prepare({ ...base, body: "{}" }).method, "POST");
    assert.equal(prepare({ ...base, body: "{}", method: "put" }).method, "PUT");
  });

  test("asks for identity encoding unless the caller set one", () => {
    const auto = prepare({ ...base });
    assert.deepEqual(auto.headers.find(([n]) => n === "accept-encoding"), ["accept-encoding", "identity"]);
    const chosen = prepare({ ...base, headers: [["Accept-Encoding", "gzip"]] });
    assert.equal(chosen.headers.filter(([n]) => n.toLowerCase() === "accept-encoding").length, 1);
  });
});

describe("what the approval dialog is shown", () => {
  test("names the method, host and the keys it will send, never a value", () => {
    const input = {
      url: "https://api.stripe.com/v1/refunds",
      method: "POST",
      headers: [["authorization", "Bearer $API_KEY"]] as [string, string][],
      secrets,
    };
    const summary = requestSummary(input, secrets);
    assert.match(summary, /POST api\.stripe\.com\/v1\/refunds/);
    assert.match(summary, /sends API_KEY/);
    assert.doesNotMatch(summary, new RegExp(SECRET));
    assert.deepEqual(requestSecretNames(input, secrets), ["API_KEY"]);
  });
});

// ------------------------------------------------------------ a real socket

let server: Server;
let base = "";

before(async () => {
  server = createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://localhost");
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      if (u.pathname === "/echo-auth") {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end(`auth=${req.headers.authorization ?? ""}`);
      } else if (u.pathname === "/reflect") {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end(`you sent: ${body}`);
      } else if (u.pathname === "/big") {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("x".repeat(500_000));
      } else if (u.pathname === "/same-redirect") {
        res.writeHead(302, { location: "/echo-auth" });
        res.end();
      } else if (u.pathname === "/away-redirect") {
        res.writeHead(302, { location: "https://example.invalid/steal" });
        res.end();
      } else {
        res.writeHead(404, { "content-type": "text/plain" });
        res.end("nope");
      }
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  server.close();
  await once(server, "close");
});

describe("requestWithSecrets", () => {
  test("the value reaches the wire, and comes back masked", async () => {
    const r = await requestWithSecrets({
      url: `${base}/echo-auth`,
      headers: [["authorization", "Bearer $API_KEY"]],
      secrets,
    });
    assert.equal(r.status, 200);
    // The server saw the real value...
    assert.match(r.body, /auth=Bearer \[redacted:API_KEY\]/);
    // ...and the caller never does.
    assert.doesNotMatch(r.body, new RegExp(SECRET));
    assert.deepEqual(r.used, ["API_KEY"]);
    assert.equal(r.redactions, 1);
  });

  test("a secret reflected back in a body is masked too", async () => {
    const r = await requestWithSecrets({
      url: `${base}/reflect`,
      method: "POST",
      body: '{"token":"$API_KEY"}',
      substitute: ["body"],
      secrets,
    });
    assert.equal(r.status, 200);
    assert.match(r.body, /\[redacted:API_KEY\]/);
    assert.doesNotMatch(r.body, new RegExp(SECRET));
  });

  test("an error status is a normal result, not a thrown failure", async () => {
    const r = await requestWithSecrets({ url: `${base}/nope`, secrets });
    assert.equal(r.status, 404);
    assert.equal(r.body, "nope");
  });

  test("the body is capped, and says so", async () => {
    const r = await requestWithSecrets({ url: `${base}/big`, secrets, maxBytes: 1024 });
    assert.equal(r.truncated, true);
    assert.equal(r.body.length, 1024);
  });

  test("a same-host redirect is followed", async () => {
    const r = await requestWithSecrets({
      url: `${base}/same-redirect`,
      headers: [["authorization", "Bearer $API_KEY"]],
      secrets,
    });
    assert.equal(r.status, 200);
    assert.equal(r.redirects, 1);
    assert.match(r.body, /auth=Bearer \[redacted:API_KEY\]/);
  });

  test("a redirect to another host is refused, because it would move the credential", async () => {
    await assert.rejects(
      () => requestWithSecrets({ url: `${base}/away-redirect`, secrets }),
      /redirected to example\.invalid/,
    );
  });

  test("a port with nothing on it is a plain message, not a stack trace", async () => {
    // Bind and release, so the port is real but nothing is listening on it.
    const probe = createServer();
    probe.listen(0, "127.0.0.1");
    await once(probe, "listening");
    const port = (probe.address() as AddressInfo).port;
    probe.close();
    await once(probe, "close");

    await assert.rejects(
      () => requestWithSecrets({ url: `http://127.0.0.1:${port}/x`, secrets, timeoutMs: 5000 }),
      /Nothing listening at 127\.0\.0\.1/,
    );
  });

  test("a blocked port says so, rather than reporting a connection failure", async () => {
    await assert.rejects(
      () => requestWithSecrets({ url: "http://127.0.0.1:1/x", secrets, timeoutMs: 5000 }),
      /port the HTTP stack refuses to connect to/,
    );
  });

  test("the status line reports what happened, and renderRequest puts the body under it", async () => {
    const r = await requestWithSecrets({
      url: `${base}/echo-auth`,
      headers: [["authorization", "Bearer $API_KEY"]],
      secrets,
    });
    assert.match(statusLine(r), /-> 200/);
    assert.match(statusLine(r), /injected API_KEY/);
    const rendered = renderRequest(r, { includeHeaders: true });
    assert.match(rendered, /content-type: text\/plain/);
    assert.match(rendered, /\[redacted:API_KEY\]/);
  });
});
