/**
 * `hush request` — make an HTTP call with a secret substituted inside hush.
 */
import { readFileSync } from "node:fs";
import { audit } from "../vault.ts";
import { requireIdentity } from "../identity.ts";
import { checkScopes, checkHost, requestScope, requestCoverageLine } from "../policy.ts";
import { parseHeader, prepare, requestWithSecrets, renderRequest, requestSummary, statusLine, requestSecretNames, type RequestInput } from "../request.ts";
import { loadSchema, validate, unsensitiveForOutput, describeProblems } from "../schema.ts";
import { composeSets } from "../library.ts";
import { requestApproval } from "../approval.ts";
import { type Args, bool, list, str } from "../cli/args.ts";
import { die, dim, out, red, warn } from "../cli/output.ts";
import { ctxLoose, dieNotSetUp, dieOnApproval, interactiveSetup, isSetUp, policyFor, runSetupDialogue } from "../cli/context.ts";
import { collectExtraSets } from "../cli/sets.ts";

/**
 * The body of `hush request`, from a flag literal or from somewhere else.
 *
 * `@file` exists because the interesting bodies are JSON documents and
 * fixtures, and pasting one into an argv on a shell is how quoting bugs
 * happen. `@-` reads stdin so `hush request ... --data @- <<< "$json"` and
 * `... | hush request --data @-` both work.
 */
function requestBody(a: Args): string | undefined {
  const raw = str(a, "data") ?? str(a, "body") ?? str(a, "json");
  if (raw === undefined) return undefined;
  if (raw === "@-") return readFileSync(0, "utf8");
  if (raw.startsWith("@")) {
    const path = raw.slice(1);
    try {
      return readFileSync(path, "utf8");
    } catch (e) {
      die(`Could not read ${path}: ${(e as Error).message}`);
    }
  }
  return raw;
}

/**
 * `hush request` — make the call here, so the credential is never handed to
 * the caller or to a child process.
 *
 * `hush run` covers a program that already knows how to authenticate itself.
 * This covers the other half: "call this endpoint with my key" when there is
 * no such program, which previously had no answer at all — `curl` is in the
 * deny list precisely because a shell can read the whole injected environment
 * and post it somewhere redaction cannot see. Here the value goes vault ->
 * this process -> the wire, and the response comes back through the redactor.
 *
 *   hush request POST https://api.stripe.com/v1/refunds \
 *     --header 'Authorization: Bearer $STRIPE_KEY' \
 *     --data '{"charge": "ch_123"}'
 */
export async function cmdRequest(a: Args): Promise<void> {
  const loose = ctxLoose(a);
  const id = requireIdentity();

  const rest = a._;
  let method = str(a, "method");
  let target: string | undefined;
  if (rest.length === 1) target = rest[0];
  else if (rest.length === 2) {
    method = method ?? rest[0];
    target = rest[1];
  }
  if (!target) {
    die(
      "Usage: hush request [METHOD] <url> [--header 'Name: value'] [--data body] [--use <set>]",
      "Example: hush request POST https://api.stripe.com/v1/refunds --header 'Authorization: Bearer $STRIPE_KEY'",
    );
  }
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) {
    die(`Not a URL: ${target}`, `Did you mean https://${target}?`);
  }

  let parsed: URL;
  try {
    parsed = new URL(target);
  } catch {
    die(`Not a URL: ${target}`);
  }

  // Same refusal `hush run` makes, for the same reason: a folder nobody has
  // told hush about must not quietly send something with nothing injected.
  if (!isSetUp(loose)) {
    if (!interactiveSetup()) dieNotSetUp();
    await runSetupDialogue(loose, a);
  }

  const extra = collectExtraSets(a);
  const { secrets, layers, missing, unreadable, blocked } = composeSets(loose.vault, id, loose.hushDir, extra);
  // A scoped member or CI identity in a project that also uses sets they were
  // never given: skipped, and said, so a missing variable has an explanation.
  if (unreadable.length) process.stderr.write(dim(`hush: not yours to read, skipped: ${unreadable.join(", ")}\n`));
  // A set limited to other folders: skipped, and said, for the same reason.
  for (const b of blocked) warn(`skipped ${b.name}: it is only for ${b.onlyIn.join(", ")}`);

  const policy = policyFor(loose.hushDir);
  if (policy) {
    for (const k of policy.denyKeys) delete secrets[k];
  }

  // The same schema gate as `hush run`, before a request is built or sent.
  const schema = loadSchema(loose.root);
  const { omit: redactOmit, ignored: unmaskIgnored } = schema
    ? unsensitiveForOutput(schema.rules, policy?.unmaskKeys ?? [])
    : { omit: [] as string[], ignored: [] as string[] };
  if (unmaskIgnored.length) {
    warn(
      `.env.schema asks to leave ${unmaskIgnored.join(", ")} unmasked; your floor has not allowed that, so they stay masked`,
    );
  }
  if (schema && !bool(a, "no-validate")) {
    const problems = validate(secrets, schema.rules, Object.keys(secrets));
    if (problems.length) {
      for (const line of describeProblems(problems)) process.stderr.write(red(`✗ ${line}`) + "\n");
      die(
        `.env.schema rejected ${problems.length} value(s); nothing was sent.`,
        "Fix the values, or pass --no-validate to send anyway.",
      );
    }
  }

  const input: RequestInput = {
    url: target,
    method,
    headers: list(a, "header").map(parseHeader),
    body: requestBody(a),
    secrets,
    substitute: list(a, "substitute"),
    insecure: bool(a, "insecure"),
    redactOmit,
    timeoutMs: (() => {
      const raw = str(a, "timeout");
      if (raw === undefined) return policy?.maxRunMs ?? 30_000;
      const n = Number(raw);
      if (!Number.isFinite(n) || n <= 0) die(`Bad --timeout "${raw}". Give milliseconds, e.g. 30000.`);
      return n;
    })(),
  };

  if (policy) {
    // The command check has no analogue here — hush is the client — so the
    // host check takes its place: it is the one thing an agent actually picks.
    checkHost(policy, parsed);
    checkScopes(policy, layers);
    if (policy.requireApproval.includes("request")) {
      // Build the request first, so a bad one (an unresolvable $NAME, a secret
      // in the path, cleartext) is refused without a dialog in the way.
      prepare(input);
      const sends = requestSecretNames(input, secrets);
      const ap = await requestApproval(loose.hushDir, {
        action: "request",
        summary: `Request:  ${requestSummary(input, secrets)}`,
        detail: [
          `Sends:  ${sends.join(", ") || "(no secret)"}`,
          `Using sets:  ${layers.join(", ") || "(none)"}`,
          `Directory:  ${process.cwd()}`,
          requestCoverageLine(policy, parsed.host, layers),
        ],
        scope: requestScope(policy, parsed.host, layers),
        ttlSeconds: policy.approvalTtlSeconds,
        timeoutMs: Math.max(1, policy.approvalTimeoutSeconds) * 1000,
        biometry: policy.biometry,
        // One-shot: a grant cannot outlive this command (approval.ts sessionGrant).
        sessionGrant: false,
      });
      audit(loose.hushDir, { actor: "cli", action: "approval", on: "request", decision: ap.decision, via: ap.via, code: ap.code });
      dieOnApproval(ap, `requesting ${parsed.host}`);
    }
  }

  if (missing.length) {
    warn(`This project uses ${missing.join(", ")}, which your library does not have.`);
  }

  const result = await requestWithSecrets(input).catch((e) => die((e as Error).message));

  if (bool(a, "include")) {
    out(renderRequest(result, { includeHeaders: true }));
  } else if (result.body) {
    process.stdout.write(result.body.endsWith("\n") ? result.body : result.body + "\n");
  }
  // The status line always goes somewhere a human can see it: a 404 with a
  // body that happens to be empty would otherwise look like success.
  if (!bool(a, "quiet")) process.stderr.write(dim(`hush: ${statusLine(result)}\n`));

  audit(loose.hushDir, {
    actor: "cli",
    action: "request",
    url: result.url,
    method: result.method,
    status: result.status,
    layers,
    sent: result.used,
    redactions: result.redactions,
  });

  // curl's shape: a completed response is not a failed command unless asked.
  if (bool(a, "fail") && result.status >= 400) process.exitCode = 1;
}
