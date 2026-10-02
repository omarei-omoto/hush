/**
 * `hush ui` — a local web app for managing the vault.
 *
 * Security posture, because this thing holds every key you own:
 *   - binds 127.0.0.1 only, never 0.0.0.0
 *   - a random per-session token is required on every /api call
 *   - the Host header must be loopback, which blocks DNS-rebinding
 *   - values are sent to the browser as masked previews; revealing one is an
 *     explicit click that gets written to the audit log
 *   - no CDN, no external fonts, no third-party JS. Everything is inline.
 */
import { system32 } from "./platform.ts";
import { createServer, type IncomingMessage } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { dirname, join } from "node:path";
import { PAGE } from "./ui-page.ts";
import { locateProject, isValidationError } from "./vault.ts";
import { requireIdentity } from "./identity.ts";
import { isTrustError } from "./integrity.ts";
import { type UiCtx, openProjectVault } from "./ui-state.ts";
import { handleApi, json } from "./ui-api.ts";
import { ensureHelper } from "./biometry.ts";

const TOKEN = randomBytes(24).toString("base64url");

/** Compare against the session token without leaking its prefix through timing. */
function tokenOk(given: unknown): boolean {
  if (typeof given !== "string") return false;
  const a = Buffer.from(given);
  const b = Buffer.from(TOKEN);
  // Length is not secret (it is fixed), but timingSafeEqual requires a match.
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Reject anything that isn't a loopback Host — stops DNS-rebinding attacks. */
function hostIsLocal(req: IncomingMessage): boolean {
  const host = (req.headers.host ?? "").split(":")[0];
  return host === "127.0.0.1" || host === "localhost" || host === "[::1]" || host === "::1";
}

export function serveUi(opts: { port?: number; open?: boolean } = {}): void {
  const proj = locateProject(process.cwd());

  // Three states of "this folder": no .hush anywhere above it (a brand-new
  // folder — the setup panel on the page is how it gets one), one that only
  // links library sets (.hush/envs.json, no vault.json yet), and one with a
  // vault of its own. The first two used to be unreachable here at all: no
  // project meant a hard error unless a library existed, and a links-only
  // project meant Vault.open() throwing on a file that was never supposed to
  // exist yet — the crash this whole feature exists to fix.
  let ctx: UiCtx;
  if (proj) {
    ctx = { vaultPath: proj.vaultPath, hushDir: proj.hushDir, root: dirname(proj.hushDir), defaultEnv: proj.env || "default" };
  } else {
    const root = process.cwd();
    const hushDir = join(root, ".hush");
    ctx = { vaultPath: join(hushDir, "vault.json"), hushDir, root, defaultEnv: "default" };
  }

  // Fail fast rather than after the browser opens — but only against a vault
  // that actually exists; a links-only or brand-new folder has none yet, and
  // that is no longer a reason to refuse to start.
  const id = requireIdentity();
  const existing = openProjectVault(ctx);
  if (existing && !existing.canRead(id)) {
    throw new Error(`Your key is not a recipient of vault "${existing.data.name}".`);
  }

  // The page's first request reports Touch ID status, and on macOS that means
  // compiling the helper (biometry.ts: never trusted from disk, so built once
  // per process). Built here, before the link opens, it costs a second in the
  // terminal instead of a blank page; ensureHelper caches it for the server's
  // life and returns at once on other platforms or with HUSH_BIOMETRY=off.
  ensureHelper();

  const server = createServer(async (req, res) => {
    try {
      if (!hostIsLocal(req)) {
        return json(res, 403, { error: "loopback only" });
      }
      const url = new URL(req.url ?? "/", "http://127.0.0.1");

      if (url.pathname === "/") {
        // The page is code, not data, and carries no token: the token travels
        // in the link's #fragment, which the browser never sends here, and
        // every /api/ call still has to present it. Embedding it in the HTML
        // (and taking it from ?t=) put it in history, sync and access logs.
        const html = PAGE;
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
          // frame-ancestors: no other page may frame this one and trick a
          // click on Reveal or Remove. base-uri/form-action: nothing injected
          // could redirect a relative URL or a form post off this origin.
          "content-security-policy":
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src data:; " +
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
          "referrer-policy": "no-referrer",
          "x-content-type-options": "nosniff",
          "x-frame-options": "DENY",
        });
        return res.end(html);
      }

      if (url.pathname.startsWith("/api/")) {
        if (!tokenOk(req.headers["x-hush-token"])) return json(res, 403, { error: "bad token" });
        try {
          return await handleApi(ctx, req, res, url.pathname);
        } catch (err) {
          // Rejected input is the caller's problem (400); anything else is ours.
          const message = err instanceof Error ? err.message : String(err);
          if (isValidationError(err) || /body too large|invalid JSON/.test(message)) {
            return json(res, 400, { error: message.split("\n")[0] });
          }
          // Not the caller's mistake and not a fault: a person has to accept
          // a change to the vault first. The whole message, which ends with how.
          if (isTrustError(err)) {
            return json(res, 409, { error: message.split("\n").map((l) => l.trim()).filter(Boolean).join(" "), trust: true });
          }
          throw err;
        }
      }

      return json(res, 404, { error: "not found" });
    } catch (err) {
      return json(res, 500, { error: err instanceof Error ? err.message : String(err) });
    }
  });

  const port = opts.port ?? 0;
  server.listen(port, "127.0.0.1", () => {
    const addr = server.address();
    const actual = typeof addr === "object" && addr ? addr.port : port;
    const link = `http://127.0.0.1:${actual}/#t=${TOKEN}`;
    const vaultLine = existing ? `vault: ${existing.data.name}` : "no vault here yet — set this folder up in the browser";
    process.stdout.write(`\n  hush ui  →  ${link}\n\n  ${vaultLine}\n  Ctrl-C to stop.\n\n`);
    if (opts.open !== false) {
      import("node:child_process").then(({ spawn }) => {
        // Windows: rundll32's URL handler keeps the #fragment the token is in;
        // `start` would hand "&" in it to cmd.exe.
        const win = process.platform === "win32" ? system32("rundll32.exe") : null;
        const cmd = process.platform === "darwin" ? "open" : win ?? "xdg-open";
        // A server, a container or an SSH session has no xdg-open. spawn()
        // reports that as an 'error' event, and an unhandled one took the
        // whole server down a moment after it printed the link.
        const args = win ? ["url.dll,FileProtocolHandler", link] : [link];
        const child = spawn(cmd, args, { stdio: "ignore", detached: true, windowsHide: true });
        child.on("error", () => {
          process.stdout.write(`  (could not open a browser here — open the link above yourself)\n\n`);
        });
        child.unref();
      });
    }
  });
}
