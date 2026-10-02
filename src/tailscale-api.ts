/**
 * The few calls hush makes to Tailscale's API: read the tailnet policy file,
 * have Tailscale validate a change, and save it.
 *
 * The API key is a hush secret like any other: it goes into the Authorization
 * header inside requestWithSecrets (request.ts), the same code as hush_request,
 * and is never shown or returned. The policy text is a body that is *not*
 * substituted, so a `$NAME` in someone's policy file stays exactly as written.
 */
import { requestWithSecrets, type RequestResult } from "./request.ts";

export const TAILSCALE_API = "https://api.tailscale.com/api/v2";
export const KEY_NAME = "TAILSCALE_API_KEY";

export interface PolicyApi {
  get(): Promise<{ text: string; etag: string | null }>;
  /** null when Tailscale accepts it, otherwise what it objected to. */
  validate(text: string): Promise<string | null>;
  /** Save, but only over the version read (`etag`): a change made meanwhile is never overwritten. */
  set(text: string, etag: string | null): Promise<void>;
}

const header = (r: RequestResult, name: string): string | null =>
  r.headers.find(([k]) => k.toLowerCase() === name)?.[1] ?? null;

function problem(r: RequestResult, doing: string): string {
  if (r.status === 401 || r.status === 403) return `Tailscale refused the API key while ${doing} (${r.status}). It needs access to the policy file.`;
  let detail = r.body.slice(0, 300);
  try {
    const j = JSON.parse(r.body) as { message?: string; data?: { user?: string; errors?: string[] }[] };
    detail = [j.message, ...(j.data ?? []).flatMap((d) => d.errors ?? [])].filter(Boolean).join("; ") || detail;
  } catch { /* not JSON: the text is the message */ }
  return `Tailscale answered ${r.status} while ${doing}: ${detail}`;
}

/**
 * `base` is a parameter for tests, never configuration: an environment
 * variable that moved the API would be a way to send the key somewhere else.
 */
export function policyApi(apiKey: string, base: string = TAILSCALE_API, tailnet = "-"): PolicyApi {
  const url = `${base}/tailnet/${encodeURIComponent(tailnet)}/acl`;
  const secrets = { [KEY_NAME]: apiKey };
  const auth: [string, string] = ["Authorization", `Bearer $${KEY_NAME}`];
  const call = (u: string, method: string, headers: [string, string][], body?: string) =>
    requestWithSecrets({ url: u, method, headers: [auth, ...headers], body, secrets, maxBytes: 8 << 20, timeoutMs: 30_000 });

  return {
    async get() {
      const r = await call(url, "GET", [["Accept", "application/hujson"]]);
      if (r.status !== 200) throw new Error(problem(r, "reading the policy file"));
      if (r.truncated) throw new Error("the policy file is larger than hush will edit (8 MB)");
      return { text: r.body, etag: header(r, "etag") };
    },
    async validate(text) {
      const r = await call(`${url}/validate`, "POST", [["Content-Type", "application/hujson"]], text);
      if (r.status !== 200) return problem(r, "checking the change");
      try {
        const j = JSON.parse(r.body || "{}") as { message?: string };
        return j.message ? problem(r, "checking the change") : null;
      } catch {
        return null;
      }
    },
    async set(text, etag) {
      const r = await call(url, "POST", [["Content-Type", "application/hujson"], ...(etag ? [["If-Match", etag] as [string, string]] : [])], text);
      if (r.status === 412) throw new Error("someone changed the policy file while hush was working; nothing was saved — run it again");
      if (r.status !== 200) throw new Error(problem(r, "saving the policy file"));
    },
  };
}
