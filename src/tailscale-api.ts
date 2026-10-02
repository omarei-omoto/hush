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
/** An API access token: everything its creator may do, for up to 90 days. */
export const KEY_NAME = "TAILSCALE_API_KEY";
/**
 * An OAuth client limited to the policy file: the recommended credential.
 * hush trades it for an access token that lasts an hour, once per command.
 */
export const OAUTH_ID = "TAILSCALE_OAUTH_CLIENT_ID";
export const OAUTH_SECRET = "TAILSCALE_OAUTH_CLIENT_SECRET";
/** The scope hush asks for, and the only one it needs. */
export const POLICY_SCOPE = "policy_file";

export type TailscaleCredential =
  | { kind: "token"; token: string }
  | { kind: "oauth"; clientId: string; clientSecret: string };

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
export function policyApi(
  credential: TailscaleCredential | string,
  base: string = TAILSCALE_API,
  tailnet = "-",
  onScope?: (granted: string[]) => void,
): PolicyApi {
  const cred: TailscaleCredential = typeof credential === "string" ? { kind: "token", token: credential } : credential;
  const url = `${base}/tailnet/${encodeURIComponent(tailnet)}/acl`;
  const BEARER = "TAILSCALE_ACCESS_TOKEN";
  const auth: [string, string] = ["Authorization", `Bearer $${BEARER}`];

  /**
   * The bearer token for this command: the stored API token as it is, or an
   * OAuth client's secret traded for an hour-long token. The client secret is
   * substituted into the form body of that one request and nowhere else; the
   * token it buys stays in this process.
   */
  let bearer: Promise<string> | null = null;
  const token = (): Promise<string> => {
    if (cred.kind === "token") return Promise.resolve(cred.token);
    bearer ??= (async () => {
      const r = await requestWithSecrets({
        url: `${base}/oauth/token`,
        method: "POST",
        headers: [["Content-Type", "application/x-www-form-urlencoded"]],
        body: `client_id=$${OAUTH_ID}&client_secret=$${OAUTH_SECRET}&grant_type=client_credentials&scope=${POLICY_SCOPE}`,
        substitute: ["body"],
        secrets: { [OAUTH_ID]: cred.clientId, [OAUTH_SECRET]: cred.clientSecret },
        maxBytes: 64 * 1024,
        timeoutMs: 30_000,
      });
      if (r.status !== 200) {
        throw new Error(r.status === 401 || r.status === 403
          ? `Tailscale refused the OAuth client (${r.status}). Check its ID and secret, and that it may edit the policy file.`
          : problem(r, "signing in with the OAuth client"));
      }
      let j: { access_token?: unknown; scope?: unknown };
      try {
        j = JSON.parse(r.body);
      } catch {
        throw new Error("Tailscale's sign-in answer was not JSON");
      }
      if (typeof j.access_token !== "string" || !j.access_token) throw new Error("Tailscale's sign-in answer had no access token");
      if (typeof j.scope === "string") onScope?.(j.scope.split(/\s+/).filter(Boolean));
      return j.access_token;
    })();
    return bearer;
  };

  const call = async (u: string, method: string, headers: [string, string][], body?: string) =>
    requestWithSecrets({
      url: u, method, headers: [auth, ...headers], body,
      secrets: { [BEARER]: await token() },
      maxBytes: 8 << 20, timeoutMs: 30_000,
    });

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
