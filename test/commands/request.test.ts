/**
 * `hush request`.
 */
import { test, describe } from "node:test";
import { createServer, type IncomingMessage } from "node:http";
import { once } from "node:events";
import { type AddressInfo } from "node:net";
import { spawn } from "node:child_process";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { CLI, project } from "../helpers/cli.ts";

describe("hush request", () => {
  /**
   * A loopback server the CLI can actually talk to. http is allowed here
   * without --insecure precisely because it never leaves the machine, which is
   * the rule the transport check encodes.
   *
   * Anything that has to reach it runs through runAsync: the sync runner blocks
   * the test's event loop, so the server living in this same process can never
   * answer and every such call would time out.
   */
  async function withServer(
    handler: (req: IncomingMessage) => { status: number; body: string; headers?: Record<string, string> },
    fn: (base: string, hits: () => string[]) => Promise<void>,
  ): Promise<void> {
    const hits: string[] = [];
    const server = createServer((req, res) => {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", () => {
        hits.push(`${req.method} ${req.url} ${req.headers.authorization ?? ""} ${body}`);
        const out = handler(req);
        res.writeHead(out.status, { "content-type": "text/plain", ...(out.headers ?? {}) });
        res.end(out.body);
      });
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      await fn(base, () => hits);
    } finally {
      server.close();
      await once(server, "close");
    }
  }

  /** The same thing project().run does, without blocking the event loop. */
  function runAsync(p: ReturnType<typeof project>, args: string[]): Promise<{ code: number; out: string }> {
    return new Promise((resolve) => {
      const child = spawn(process.execPath, [CLI, ...args], {
        cwd: p.root,
        env: p.env,
        stdio: ["ignore", "pipe", "pipe"],
      });
      let out = "";
      child.stdout?.on("data", (d) => (out += String(d)));
      child.stderr?.on("data", (d) => (out += String(d)));
      child.on("exit", (code) => resolve({ code: code ?? 1, out }));
    });
  }

  test("the secret reaches the server and comes back masked", async () => {
    await withServer(
      (req) => ({ status: 200, body: `you sent: ${req.headers.authorization ?? ""}` }),
      async (base, hits) => {
        const p = project();
        try {
          const r = await runAsync(p, [
            "request", "POST", `${base}/v1/thing`,
            "--header", "Authorization: Bearer $STRIPE_SECRET_KEY",
          ]);
          assert.equal(r.code, 0, r.out);
          assert.equal(hits().length, 1, "the request never arrived");
          // The wire carried the real value...
          assert.match(hits()[0], /Bearer sk_live_cli/);
          // ...and the caller only ever saw it masked.
          assert.match(r.out, /\[redacted:STRIPE_SECRET_KEY\]/);
          assert.doesNotMatch(r.out, /sk_live_cli/, "the value came back in the output");
        } finally {
          p.cleanup();
        }
      },
    );
  });

  test("a non-2xx is a normal result; --fail turns it into a non-zero exit", async () => {
    await withServer(
      () => ({ status: 404, body: "no such thing" }),
      async (base) => {
        const p = project();
        try {
          const plain = await runAsync(p, ["request", `${base}/missing`]);
          assert.equal(plain.code, 0, "a 404 exit code broke curl-like piping by default");
          assert.match(plain.out, /no such thing/);

          const failed = await runAsync(p, ["request", "--fail", `${base}/missing`]);
          assert.equal(failed.code, 1, "--fail did not set the exit code");
        } finally {
          p.cleanup();
        }
      },
    );
  });

  test("the body is not substituted unless --substitute body says so", async () => {
    await withServer(
      () => ({ status: 200, body: "ok" }),
      async (base, hits) => {
        const p = project();
        try {
          const literal = await runAsync(p, ["request", "POST", `${base}/x`, "--data", "key=$STRIPE_SECRET_KEY"]);
          assert.equal(literal.code, 0, literal.out);
          assert.match(hits()[0], /key=\$STRIPE_SECRET_KEY/, "the body was substituted without being asked");

          const opted = await runAsync(p, [
            "request", "POST", `${base}/x`, "--data", "key=$STRIPE_SECRET_KEY", "--substitute", "body",
          ]);
          assert.equal(opted.code, 0, opted.out);
          assert.match(hits()[1], /key=sk_live_cli/);
        } finally {
          p.cleanup();
        }
      },
    );
  });

  test("cleartext to a real host is refused before anything is sent", () => {
    const p = project();
    try {
      const r = p.run(["request", "http://api.example.com/x", "--header", "Authorization: Bearer $STRIPE_SECRET_KEY"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /cleartext/);
    } finally {
      p.cleanup();
    }
  });

  test("a secret cannot be put in the URL path", () => {
    const p = project();
    try {
      const r = p.run(["request", "https://api.example.com/v1/$STRIPE_SECRET_KEY/x"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /would go in the URL path/);
    } finally {
      p.cleanup();
    }
  });

  test("a placeholder with no matching key is refused, naming it", () => {
    const p = project();
    try {
      const r = p.run(["request", "https://api.example.com/x", "--header", "Authorization: Bearer $TYPO"]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.out, /No such secret in these sets: TYPO/);
    } finally {
      p.cleanup();
    }
  });

  test("a host outside allowHosts is refused, and the server is never contacted", async () => {
    await withServer(
      () => ({ status: 200, body: "ok" }),
      async (base, hits) => {
        const p = project();
        try {
          writeFileSync(
            join(p.hushDir, "policy.json"),
            JSON.stringify({ allowHosts: ["api.stripe.com"], requireApproval: [] }),
          );
          const r = p.run(["request", `${base}/x`, "--header", "Authorization: Bearer $STRIPE_SECRET_KEY"]);
          assert.equal(r.code, 1, r.out);
          assert.match(r.out, /Policy forbids requests to/);
          assert.equal(hits().length, 0, "the request went out despite the host policy");
        } finally {
          p.cleanup();
        }
      },
    );
  });

  test("requireApproval stops the request going out when nothing can ask a human", async () => {
    await withServer(
      () => ({ status: 200, body: "ok" }),
      async (base, hits) => {
        const p = project();
        try {
          writeFileSync(join(p.hushDir, "policy.json"), JSON.stringify({ requireApproval: ["request"] }));
          const r = p.run([
            "request", `${base}/x`, "--header", "Authorization: Bearer $STRIPE_SECRET_KEY",
          ]);
          assert.equal(r.code, 1, r.out);
          // The whole point: a credential did not leave the machine because a
          // human was not there to approve it.
          assert.equal(hits().length, 0, "the gated request was sent anyway");
          assert.ok(!r.out.includes("sk_live_cli"), `the credential leaked into the output:\n${r.out}`);
        } finally {
          p.cleanup();
        }
      },
    );
  });

  // The whole reason `request` is not in approval.ts's on-disk grant set. A
  // forged grants.local.json is a file an agent with ordinary write access to
  // the project can create; for `run` that buys a redacted child process on
  // this machine, but for `request` it would buy a credential sent to whatever
  // host the scope names. So a request grant is never read from disk at all.
  test("a forged grants.local.json cannot pre-authorise a request", async () => {
    await withServer(
      () => ({ status: 200, body: "ok" }),
      async (base, hits) => {
        const p = project();
        try {
          writeFileSync(
            join(p.hushDir, "policy.json"),
            JSON.stringify({ requireApproval: ["request"], approvalTimeoutSeconds: 1 }),
          );
          const host = new URL(base).host;
          // Exactly the scope requestScope() computes for this call.
          writeFileSync(
            join(p.hushDir, "grants.local.json"),
            JSON.stringify({ [`request:${host}:default`]: Date.now() + 60_000 }),
          );

          const r = p.run(["request", `${base}/x`, "--header", "Authorization: Bearer $STRIPE_SECRET_KEY"]);
          assert.equal(r.code, 1, `a forged grant was honoured:\n${r.out}`);
          assert.equal(hits().length, 0, "the request went out on a forged grant");
        } finally {
          p.cleanup();
        }
      },
    );
  });
});
