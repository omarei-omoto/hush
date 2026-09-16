/**
 * An authenticated HTTP request whose credential the caller never holds.
 *
 * `hush run` covers the case where a program already knows how to make its own
 * call: inject the value into its environment and let it work. It does not
 * cover the case where the caller *is* the thing making the call — an agent
 * that needs to hit an API, or a shell one-liner. Until now the only answer
 * there was `curl`, which is denied outright for exactly that reason.
 *
 * So hush makes the request itself. The flow for a secret is:
 *
 *     vault -> this process's memory -> the header on the wire
 *
 * It is never in a child's environment, never in a file, and never in the
 * output: the response goes through the same streaming redactor `hush run`
 * uses. The caller writes `$STRIPE_KEY` and gets back a response with the
 * value masked.
 *
 * Three properties are deliberately stricter than a proxy would be, and they
 * fall out of being the client rather than intercepting one:
 *
 *   - Nothing is substituted into the URL. A secret can reach a header value,
 *     and optionally a query parameter or a request body, and nowhere else, so
 *     "put the key somewhere it will be reflected back at you" has no target.
 *   - The request is `Accept-Encoding: identity`. A response is only ever
 *     scanned for leaks as plain text, so we decline any encoding that would
 *     make that scan miss something.
 *   - Redirects are not followed across hosts. `fetch`'s default would happily
 *     re-send the Authorization header to whatever `Location` names, which
 *     turns any allowed host into a way to hand the credential to another one.
 */
import { Redactor } from "./redact.ts";
import { ValidationError } from "./vault.ts";

/** Where in the request a `$NAME` may be replaced by its value. */
export type SubstitutionTarget = "header" | "query" | "body";

const VALID_TARGETS: readonly SubstitutionTarget[] = ["header", "query", "body"];

/** Hard ceiling on the response body we will hold in memory and scan. */
const DEFAULT_MAX_BYTES = 256 * 1024;

/** Enough to follow a same-host 301 to a canonical path, not to go wandering. */
const MAX_REDIRECTS = 5;

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

export interface RequestInput {
  url: string;
  method?: string;
  /** Ordered, so a signature that covers header order survives the round trip. */
  headers?: [string, string][];
  body?: string;
  /** The resolved vault contents for this call. */
  secrets: Record<string, string>;
  /**
   * Extra parts of the request, beyond headers, where `$NAME` may be
   * substituted. Headers are always allowed: the caller named them. Anything
   * not named here is left byte-for-byte alone.
   */
  substitute?: string[];
  timeoutMs?: number;
  maxBytes?: number;
  /** Permit cleartext to a non-loopback host. https and loopback are always allowed. */
  insecure?: boolean;
  /**
   * Keys whose values must not be masked in the response. Set from
   * `.env.schema`'s `@sensitive=false`, so the mask keeps meaning something.
   */
  redactOmit?: string[];
}

export interface RequestResult {
  url: string;
  method: string;
  status: number;
  statusText: string;
  headers: [string, string][];
  body: string;
  /** True when the body was longer than maxBytes and was cut. */
  truncated: boolean;
  /** How many secret occurrences the response had, which were masked. */
  redactions: number;
  /** Which secrets were actually substituted into the request. */
  used: string[];
  redirects: number;
}

export interface Substitution {
  out: string;
  used: string[];
  missing: string[];
}

/**
 * `$NAME`, `${NAME}`, and `$$` for a literal dollar sign.
 *
 * A name with no value is reported rather than left alone: a header that reads
 * `Bearer $STRIPE_KEY` because the vault has no such key is a request that
 * silently goes out wrong, and the failure is far away from the cause.
 */
const VAR = /\$(\$|\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g;

export function substitute(text: string, secrets: Record<string, string>): Substitution {
  const used: string[] = [];
  const missing: string[] = [];
  const out = text.replace(VAR, (whole, flag, braced, bare) => {
    if (flag === "$") return "$";
    const name: string = braced ?? bare;
    const value = secrets[name];
    if (value === undefined) {
      if (!missing.includes(name)) missing.push(name);
      return whole;
    }
    if (!used.includes(name)) used.push(name);
    return value;
  });
  return { out, used, missing };
}

/** Turn `--substitute header,query` into a validated set. Headers are always in. */
export function resolveTargets(raw: string[] | undefined): Set<SubstitutionTarget> {
  const out = new Set<SubstitutionTarget>(["header"]);
  for (const item of raw ?? []) {
    for (const part of item.split(",").map((s) => s.trim()).filter(Boolean)) {
      if (!VALID_TARGETS.includes(part as SubstitutionTarget)) {
        throw new ValidationError(
          `Unknown substitution target "${part}". Choose from: ${VALID_TARGETS.join(", ")}.`,
        );
      }
      out.add(part as SubstitutionTarget);
    }
  }
  return out;
}

/**
 * A field name is a token (RFC 9110).
 *
 * Checked on its own rather than by re-parsing a joined `Name: value` string,
 * because that re-parse is itself a smuggling path: a name of `X: Y` splits at
 * its own colon and quietly becomes two different headers. The MCP surface
 * takes names and values as separate arguments, so it has to validate them
 * separately.
 */
export function isHeaderName(name: string): boolean {
  return /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(name);
}

/** Reject a value that would end the header early. */
export function assertHeaderValue(name: string, value: string): void {
  if (/[\r\n]/.test(value)) {
    throw new ValidationError(`Header ${name} contains a line break.`);
  }
}

/** `Name: value` (curl's shape), split on the first colon so values may contain one. */
export function parseHeader(raw: string): [string, string] {
  const at = raw.indexOf(":");
  if (at <= 0) throw new ValidationError(`Bad --header "${raw}". Expected "Name: value".`);
  const name = raw.slice(0, at).trim();
  const value = raw.slice(at + 1).trim();
  if (!isHeaderName(name)) throw new ValidationError(`Bad header name ${JSON.stringify(name)}.`);
  assertHeaderValue(name, value);
  return [name, value];
}

export function isLoopback(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "::1" ||
    hostname === "[::1]" ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)
  );
}

/**
 * Refuse to put a live credential on the wire in cleartext.
 *
 * Loopback is the exception: nothing leaves the machine, and `hush request`
 * against a local dev server is the obvious thing to want. Everything else has
 * to be https unless the caller says `--insecure` and means it.
 */
export function assertTransport(u: URL, insecure: boolean): void {
  if (u.protocol === "https:") return;
  if (u.protocol !== "http:") {
    throw new ValidationError(`Refused: "${u.protocol}//" is not a supported protocol. Use https.`);
  }
  if (isLoopback(u.hostname)) return;
  if (insecure) return;
  throw new ValidationError(
    `Refused: http://${u.host} would send the credential in cleartext. ` +
      `Use https, or pass --insecure if this really is a trusted network.`,
  );
}

/** The method, uppercased, defaulting to GET (POST when there is a body). */
function deriveMethod(method: string | undefined, hasBody: boolean): string {
  const m = (method ?? (hasBody ? "POST" : "GET")).trim().toUpperCase();
  if (!/^[A-Z]+$/.test(m)) throw new ValidationError(`Bad method ${JSON.stringify(method)}.`);
  return m;
}

export interface Prepared {
  url: URL;
  method: string;
  headers: [string, string][];
  body: string | undefined;
  used: string[];
}

/**
 * Substitute everything, then report. Split out from the network call so the
 * substitution surface can be tested without a socket.
 */
export function prepare(input: RequestInput): Prepared {
  let url: URL;
  try {
    url = new URL(input.url);
  } catch {
    throw new ValidationError(`Not a URL: ${JSON.stringify(input.url)}`);
  }
  assertTransport(url, input.insecure === true);

  const targets = resolveTargets(input.substitute);
  const secrets = input.secrets;
  const used: string[] = [];
  const missing: string[] = [];

  const absorb = (s: Substitution): string => {
    for (const n of s.used) if (!used.includes(n)) used.push(n);
    for (const n of s.missing) if (!missing.includes(n)) missing.push(n);
    return s.out;
  };

  // The URL itself is never substituted: a secret in a hostname or a path is a
  // secret in a log line, a proxy, and a Referer. Only the query is offered,
  // and only when asked for.
  //
  // A caller who names a real vault key in the path is refused rather than
  // sent literally: `Bearer $KEY` in a path goes nowhere, and the 404 they get
  // instead does not say why.
  const inPath = substitute(url.pathname, secrets).used;
  if (inPath.length) {
    throw new ValidationError(
      `Refused: ${inPath.join(", ")} would go in the URL path, where every proxy and access log ` +
        `on the way can read it. Put it in a header instead.`,
    );
  }

  if (targets.has("query") && url.search) {
    url.search = absorb(substitute(url.search, secrets));
  }

  const headers: [string, string][] = (input.headers ?? []).map(([name, value]) => [
    name,
    absorb(substitute(value, secrets)),
  ]);
  // Re-checked after substitution, because the value that goes on the wire is
  // the vault's, not the caller's placeholder: a stored PEM or any multi-line
  // blob in a header otherwise fails inside undici with a message quoting the
  // whole secret. This refuses it first, naming the header and not the value.
  for (const [name, value] of headers) assertHeaderValue(name, value);

  let body = input.body;
  if (body !== undefined && targets.has("body")) {
    body = absorb(substitute(body, secrets));
  }
  // A body nobody asked to substitute is left byte-for-byte alone, including
  // any `$name` in it. Bodies are routinely JSON that the *remote* interprets —
  // `{"$schema": …}` is a JSON Schema keyword, not a reference to a secret — so
  // treating every dollar sign there as a vault lookup would refuse perfectly
  // ordinary requests. Headers are different: they are where a secret is meant
  // to go in this design, so a name that does not resolve there is a typo worth
  // stopping for.

  if (missing.length) {
    throw new ValidationError(
      `No such ${missing.length === 1 ? "secret" : "secrets"} in these sets: ${missing.join(", ")}. ` +
        `Use hush_list_sets to see the names that exist, check the $NAME spelling, ` +
        `or write $$NAME for a literal dollar sign.`,
    );
  }

  const method = deriveMethod(input.method, body !== undefined);

  // Compression would hide a reflected secret from the redactor, which can
  // only scan what it can read. Ask for identity unless the caller overrode it.
  if (!headers.some(([n]) => n.toLowerCase() === "accept-encoding")) {
    headers.push(["accept-encoding", "identity"]);
  }

  return { url, method, headers, body, used };
}

/**
 * The errno behind a failed fetch.
 *
 * undici wraps a connection failure in `TypeError: fetch failed` whose `cause`
 * is an AggregateError holding the real error, so reading `cause.code` alone
 * finds nothing and every network problem reads as "fetch failed". This walks
 * one level further, which is where ECONNREFUSED actually lives.
 */
function causeCode(err: unknown): string | undefined {
  const cause = (err as { cause?: unknown } | undefined)?.cause;
  if (!cause) return undefined;
  const direct = (cause as { code?: string }).code;
  if (direct) return direct;
  const nested = (cause as { errors?: unknown[] }).errors;
  if (Array.isArray(nested)) {
    for (const e of nested) {
      const code = (e as { code?: string }).code;
      if (code) return code;
    }
  }
  return undefined;
}

/** The message on the underlying cause, for the failures that carry no errno. */
function causeMessage(err: unknown): string | undefined {
  const cause = (err as { cause?: unknown } | undefined)?.cause;
  const message = (cause as { message?: string } | undefined)?.message;
  return typeof message === "string" ? message : undefined;
}

/** Read at most `maxBytes`, so an enormous response cannot exhaust memory. */
async function readCapped(
  res: Response,
  maxBytes: number,
): Promise<{ text: string; truncated: boolean }> {
  const reader = res.body?.getReader();
  if (!reader) return { text: "", truncated: false };
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    const room = maxBytes - total;
    if (value.byteLength >= room) {
      chunks.push(value.subarray(0, room));
      truncated = true;
      await reader.cancel().catch(() => undefined);
      break;
    }
    chunks.push(value);
    total += value.byteLength;
  }
  return { text: Buffer.concat(chunks).toString("utf8"), truncated };
}

export async function requestWithSecrets(input: RequestInput): Promise<RequestResult> {
  const { url, method, headers, body, used } = prepare(input);
  const started = url.host;
  const insecure = input.insecure === true;
  const timeoutMs = input.timeoutMs ?? 30_000;

  // The redactor is built before the request is attempted, not after: a message
  // from the HTTP stack can quote a request value verbatim (undici's header
  // error names the whole substituted value), and the catch below passes
  // anything it re-throws through it.
  const omit = input.redactOmit ?? [];
  const redactable = omit.length
    ? Object.fromEntries(Object.entries(input.secrets).filter(([k]) => !omit.includes(k)))
    : input.secrets;
  const redactor = new Redactor(redactable);
  const redactText = (s: string): string => {
    const r = new Redactor(redactable);
    return r.push(s) + r.flush();
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let current = url;
  let currentMethod = method;
  let currentBody = body;
  let redirects = 0;
  let res: Response;

  try {
    for (;;) {
      res = await fetch(current, {
        method: currentMethod,
        headers,
        body: currentBody,
        // Manual, so a cross-host Location is a decision rather than a default.
        redirect: "manual",
        signal: controller.signal,
      });

      const location = res.headers.get("location");
      if (!REDIRECT_STATUS.has(res.status) || !location) break;
      if (redirects >= MAX_REDIRECTS) {
        throw new ValidationError(`Gave up after ${MAX_REDIRECTS} redirects from ${started}.`);
      }

      const next = new URL(location, current);
      if (next.host !== started) {
        throw new ValidationError(
          `Refused: ${started} redirected to ${next.host}, which would send the credential to a host ` +
            `you did not name. Call ${next.href} directly if you meant it.`,
        );
      }
      assertTransport(next, insecure);
      redirects++;

      // 303, and 301/302 on a non-GET, mean "stop sending that body".
      if (res.status === 303 || ((res.status === 301 || res.status === 302) && currentMethod !== "GET")) {
        currentMethod = "GET";
        currentBody = undefined;
      }
      current = next;
    }
  } catch (err) {
    if (controller.signal.aborted) {
      throw new ValidationError(`No response from ${started} within ${timeoutMs}ms.`);
    }
    const code = causeCode(err);
    // undici refuses a port on its blocked list before it ever tries to
    // connect, and reports it as a bare "bad port" with no errno at all.
    if (causeMessage(err) === "bad port") {
      throw new ValidationError(`${started} is a port the HTTP stack refuses to connect to.`);
    }
    if (code === "ECONNREFUSED") throw new ValidationError(`Nothing listening at ${started}.`);
    if (code === "ENOTFOUND" || code === "EAI_AGAIN") {
      throw new ValidationError(`Could not resolve ${started}.`);
    }
    if (code && /CERT|TLS|SSL/.test(code)) {
      throw new ValidationError(`TLS verification failed for ${started} (${code}).`);
    }
    // A recognised-but-unmapped errno still beats "fetch failed", which says
    // nothing about which of the several possible causes actually happened.
    if (code) throw new ValidationError(`Request to ${started} failed (${code}).`);
    // Last stop before the caller sees it: no error text leaves this function
    // without going through the same redactor the response body does.
    if (err instanceof Error) err.message = redactText(err.message);
    throw err;
  } finally {
    clearTimeout(timer);
  }

  const maxBytes = input.maxBytes ?? DEFAULT_MAX_BYTES;
  const { text, truncated } = await readCapped(res, maxBytes);

  // Scanned as one string rather than streamed: the body is already bounded
  // above, and a reflected secret is only visible once the whole thing is read.
  const safe = redactText(text);
  const redactions = (safe.match(/\[redacted:/g) ?? []).length;

  const outHeaders: [string, string][] = [];
  // Headers are part of the response, so they go through the same redactor as
  // the body. A destination that echoes a credential into a header (an
  // X-Client-Key, a request-id, a Location, a Set-Cookie) would otherwise put
  // the plaintext into the caller's output, which is the one thing this
  // feature promises never to do.
  res.headers.forEach((value, name) => outHeaders.push([redactor.redact(name), redactor.redact(value)]));

  return {
    url: current.href,
    method: currentMethod,
    status: res.status,
    statusText: res.statusText,
    headers: outHeaders,
    body: safe,
    truncated,
    redactions,
    used,
    redirects,
  };
}

/** One line naming what happened, for stderr and for a tool result's first row. */
export function statusLine(r: RequestResult): string {
  const bits = [`${r.method} ${r.url}`, `-> ${r.status} ${r.statusText}`.trim()];
  if (r.used.length) bits.push(`injected ${r.used.join(", ")}`);
  if (r.redactions) bits.push(`masked ${r.redactions}`);
  if (r.truncated) bits.push("body truncated");
  if (r.redirects) bits.push(`${r.redirects} redirect(s)`);
  return bits.join("  ");
}

/**
 * What a human is shown before this goes out.
 *
 * Built from the *unsubstituted* request, so the dialog shows the placeholders
 * the caller wrote rather than the values about to be sent — the same
 * convention `hush run` follows by naming the command and not the environment.
 */
export function requestSummary(input: RequestInput, secrets: Record<string, string>): string {
  const method = deriveMethod(input.method, input.body !== undefined);
  const names = requestSecretNames(input, secrets);
  const target = (() => {
    try {
      const u = new URL(input.url);
      return `${u.host}${u.pathname}`;
    } catch {
      return input.url;
    }
  })();
  return `${method} ${target}${names.length ? `  (sends ${names.join(", ")})` : ""}`;
}

/**
 * Which secrets this request would actually send, in the order they appear.
 *
 * Used for the approval dialog and the audit line, so both name the same set
 * of keys by the same rule the substitution itself uses.
 */
export function requestSecretNames(input: RequestInput, secrets: Record<string, string>): string[] {
  const names: string[] = [];
  const scan = (s: string) => {
    for (const n of substitute(s, secrets).used) if (!names.includes(n)) names.push(n);
  };
  for (const [, value] of input.headers ?? []) scan(value);
  // The same rule prepare() substitutes by, not a second reading of the raw
  // array: `resolveTargets` splits and trims, so a caller who wrote
  // `substitute: ["body,query"]` gets both targets here too. Reading the array
  // literally here made the dialog say "sends nothing" for a request that did
  // send a secret.
  const targets = resolveTargets(input.substitute);
  if (targets.has("query")) scan(input.url);
  if (targets.has("body") && input.body) scan(input.body);
  return names;
}

/** Render a result the way a caller reads it: status first, then the body. */
export function renderRequest(r: RequestResult, opts: { includeHeaders?: boolean } = {}): string {
  const lines: string[] = [statusLine(r)];
  if (opts.includeHeaders) {
    for (const [name, value] of r.headers) lines.push(`${name}: ${value}`);
  }
  lines.push("");
  if (r.body) lines.push(r.body.replace(/\n$/, ""));
  return lines.join("\n");
}
