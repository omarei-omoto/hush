#!/usr/bin/env node
/**
 * The live app on tryhush.dev's home page: the page `hush ui` serves —
 * unchanged — running in a browser with no hush server behind it.
 *
 * It builds a throwaway world (a home, five projects, keys that are not real),
 * starts the real `hush ui` on it, asks for everything the page reads, and
 * writes the page with those answers inline. A small script in front of the
 * page answers its requests from them; anything that would change something
 * gets a "this is a demo" message instead. Nothing on it is real: the keys are
 * made up here, the folders are renamed to ~/code, and the server only ever
 * listens on 127.0.0.1 for the second it takes to record.
 *
 *   node scripts/build-demo.mjs [website/public/demo/index.html]
 *
 * `npm run build` in website/ runs it after build-docs.mjs, which empties
 * website/public. The output is generated and ignored by git.
 */
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Where the demo's folders appear to be. */
const SHOWN_CODE = "/Users/alex/code";
const SHOWN_HOME = "/Users/alex/.hush";
/** What a write gets: the page shows it as a notice. */
export const DEMO_REFUSAL = "This is a demo on made-up keys, so nothing here changes. Install hush to do this on your own projects.";

const MIN = 60_000;

/** Every key in the demo. None is a real credential: each says it is a demo. */
const LIBRARY = [
  { set: "openai", label: "OpenAI", group: "AI stack", keys: { OPENAI_API_KEY: "sk-proj-hushdemo-not-a-real-key-7Qx2", OPENAI_ORG_ID: "org-hushdemo-4kT9" } },
  { set: "anthropic", label: "Anthropic", group: "AI stack", keys: { ANTHROPIC_API_KEY: "sk-ant-hushdemo-not-a-real-key-Lw8a" } },
  { set: "hugging-face", label: "Hugging Face", group: "AI stack", keys: { HF_TOKEN: "hf_hushdemo_not_a_real_token_3pZ" } },
  { set: "stripe-test", label: "Stripe (test)", group: "Payments", keys: { STRIPE_SECRET_KEY: "sk_test_hushdemo_not_a_real_key_9fGh", STRIPE_WEBHOOK_SECRET: "whsec_hushdemo_not_a_real_secret_2b" } },
  { set: "resend", label: "Resend", keys: { RESEND_API_KEY: "re_hushdemo_not_a_real_key_5mNc" } },
  { set: "sentry", label: "Sentry", keys: { SENTRY_DSN: "https://hushdemo@o0.ingest.sentry.io/0", SENTRY_AUTH_TOKEN: "sntrys_hushdemo_not_a_real_token_8" } },
];

/** The projects: their files (what their code reads), what they get, and when they were last worked on. */
const PROJECTS = [
  {
    dir: "acme/acme-api",
    group: "Acme",
    files: {
      "package.json": JSON.stringify({ name: "acme-api", dependencies: { hono: "4.0.0" }, devDependencies: { typescript: "5.0.0" } }),
      "src/index.ts":
        "const db = process.env.DATABASE_URL;\nconst redis = process.env.REDIS_URL;\nconst jwt = process.env.JWT_SECRET;\n" +
        "const stripe = process.env.STRIPE_SECRET_KEY;\nconst hook = process.env.STRIPE_WEBHOOK_SECRET;\nconst ai = process.env.OPENAI_API_KEY;\nconst dsn = process.env.SENTRY_DSN;\n",
      "wrangler.jsonc": '{ "name": "acme-api", "main": "src/index.ts" }\n',
    },
    own: { DATABASE_URL: "postgres://hushdemo:not-a-real-password@db.internal:5432/acme", REDIS_URL: "redis://hushdemo:not-real@cache.internal:6379", JWT_SECRET: "hushdemo-not-a-real-jwt-secret-0d1e2f" },
    links: ["group:payments", "openai", "sentry"],
    origin: "git@github.com:acme/api.git",
    active: 4 * MIN,
  },
  {
    dir: "acme/acme-web",
    group: "Acme",
    files: {
      "package.json": JSON.stringify({ name: "acme-web", dependencies: { next: "15.0.0", react: "19.0.0" }, devDependencies: { typescript: "5.0.0" } }),
      "app/page.tsx": "process.env.OPENAI_API_KEY;\nprocess.env.RESEND_API_KEY;\nprocess.env.STRIPE_SECRET_KEY;\nprocess.env.SENTRY_DSN;\nprocess.env.NEXT_PUBLIC_SITE_URL;\n",
    },
    links: ["openai", "stripe-test#STRIPE_SECRET_KEY", "sentry"],
    origin: "git@github.com:acme/web.git",
    active: 52 * MIN,
  },
  {
    dir: "acme/acme-mobile",
    group: "Acme",
    files: {
      "package.json": JSON.stringify({ name: "acme-mobile", dependencies: { expo: "52.0.0", "react-native": "0.76.0" } }),
      "app.ts": "process.env.ANTHROPIC_API_KEY;\nprocess.env.EXPO_PUBLIC_API_URL;\n",
    },
    links: ["anthropic"],
    origin: "git@github.com:acme/mobile.git",
    active: 26 * 60 * MIN,
  },
  {
    dir: "side/landing",
    files: {
      "package.json": JSON.stringify({ name: "landing", dependencies: { astro: "5.0.0" } }),
      "src/pages/index.astro": "---\nconst key = import.meta.env.RESEND_API_KEY;\n---\n",
      // A plaintext .env still sitting in the folder: the app offers to take it in.
      ".env": "RESEND_API_KEY=re_hushdemo_not_a_real_key_5mNc\n",
    },
    links: [],
    active: 3 * 24 * 60 * MIN,
  },
  {
    dir: "side/ml-service",
    files: {
      "pyproject.toml": '[project]\nname = "ml-service"\ndependencies = ["fastapi"]\n',
      "app/main.py": 'import os\nkey = os.environ["OPENAI_API_KEY"]\nclaude = os.environ["ANTHROPIC_API_KEY"]\nhf = os.environ["HF_TOKEN"]\n',
    },
    links: ["openai", "anthropic"],
    active: 6 * 24 * 60 * MIN,
  },
];

/**
 * The world, under `base`: a home with the library, the projects, a team on
 * acme-api, a push to Cloudflare, and an hour of activity. Returns what the
 * server needs to start.
 */
export async function buildWorld(base, now = Date.now()) {
  const home = join(base, "home");
  const code = join(base, "code");
  // Everything the server could look at sits in here: no real home is ever read.
  const fakeHome = join(base, "user");
  // Claude Code, connected the way `hush install-mcp` and `hush install-skill` leave it.
  mkdirSync(join(fakeHome, ".claude", "skills", "hush"), { recursive: true });
  writeFileSync(join(fakeHome, ".claude", "skills", "hush", "SKILL.md"), "# hush\n");
  process.env.HUSH_HOME = home;
  process.env.HUSH_NO_KEYCHAIN = "1";

  const src = (m) => import(join(root, "src", m));
  const { generateIdentity, encodeSecret, encodePub } = await src("crypto.ts");
  const { Vault } = await src("vault.ts");
  const { globalVaultName, saveLinks } = await src("library.ts");
  const { rememberProject, setProjectGroup } = await src("projects.ts");
  const { recordPush } = await src("push.ts");
  const { audit } = await src("audit.ts");

  const me = generateIdentity();
  const at = (ago) => new Date(now - ago).toISOString();

  // The library: global keys, filed in groups.
  const libPath = join(home, "vaults", globalVaultName(), "vault.json");
  mkdirSync(dirname(libPath), { recursive: true });
  const lib = Vault.create(libPath, "global", { name: "alex", pub: me.pub, priv: me.priv });
  for (const s of LIBRARY) {
    for (const [k, v] of Object.entries(s.keys)) lib.set(me, s.set, k, v);
    lib.describeEnv(s.set, { label: s.label, ...(s.group ? { group: s.group } : {}) });
  }
  lib.save();
  writeFileSync(join(home, "policy.json"), JSON.stringify({ requireApproval: ["run", "reveal", "push"] }) + "\n");

  const roots = {};
  for (const p of PROJECTS) {
    const dir = join(code, p.dir);
    roots[p.dir] = dir;
    for (const [f, text] of Object.entries(p.files)) {
      mkdirSync(dirname(join(dir, f)), { recursive: true });
      writeFileSync(join(dir, f), text);
    }
    const hushDir = join(dir, ".hush");
    mkdirSync(hushDir, { recursive: true });
    writeFileSync(join(hushDir, "envs.json"), JSON.stringify({ use: [] }) + "\n");
    writeFileSync(join(dir, ".mcp.json"), JSON.stringify({ mcpServers: { hush: { command: "hush", args: ["mcp"] } } }, null, 2) + "\n");
    if (p.own) {
      const v = Vault.create(join(hushDir, "vault.json"), p.dir.split("/").pop(), { name: "alex", pub: me.pub, priv: me.priv });
      for (const [k, val] of Object.entries(p.own)) v.set(me, "default", k, val);
      for (const name of ["sam", "priya"]) v.addRecipient(me, name, encodePub(generateIdentity().pub));
      v.save();
    }
    if (p.links.length) saveLinks(hushDir, p.links, { confirm: true });
    if (p.origin) {
      mkdirSync(join(dir, ".git", "logs"), { recursive: true });
      writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
      writeFileSync(join(dir, ".git", "config"), `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${p.origin}\n`);
    } else {
      mkdirSync(join(dir, ".git"), { recursive: true });
      writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
    }
    // "Last worked on" is the newest of git's own files.
    const when = new Date(now - p.active);
    utimesSync(join(dir, ".git", "HEAD"), when, when);
    rememberProject(dir);
  }
  setProjectGroup(PROJECTS.filter((p) => p.group).map((p) => roots[p.dir]), "Acme");

  // acme-api's key went to its Cloudflare Worker, and has been replaced since: the app suggests sending it again.
  const api = roots["acme/acme-api"];
  recordPush(api, {
    key: "STRIPE_SECRET_KEY",
    host: "cloudflare",
    target: "acme-api",
    at: at(3 * 24 * 60 * MIN),
    source: { where: "library", set: "stripe-test", updatedAt: at(4 * 24 * 60 * MIN) },
  });

  // An hour of activity on acme-api: the agent works, you approve.
  const hushDir = join(api, ".hush");
  const events = [
    [62, { actor: "ui", action: "key.assign", link: "group:payments" }],
    [41, { actor: "mcp", action: "list", set: "default", count: 3 }],
    [40, { actor: "mcp", action: "approval", on: "run", decision: "allow", via: "touchid" }],
    [40, { actor: "mcp", action: "run", command: "npm", args: ["run", "dev"], exit: 0, injected: 9, layers: ["default", "stripe-test", "openai", "sentry"] }],
    [23, { actor: "mcp", action: "request", method: "GET", url: "https://api.stripe.com/v1/customers", status: 200 }],
    [12, { actor: "mcp", action: "approval", on: "run", decision: "deny", via: "dialog" }],
    [6, { actor: "mcp", action: "approval", on: "run", decision: "allow", via: "touchid" }],
    [6, { actor: "mcp", action: "run", command: "npm", args: ["test"], exit: 0, injected: 9, layers: ["default", "stripe-test", "openai", "sentry"] }],
    [2, { actor: "cli", action: "team.add", name: "priya" }],
  ];
  for (const [ago, e] of events) audit(hushDir, { ...e, at: at(ago * MIN) });

  return { home, code, fakeHome, start: api, identity: encodeSecret(me) };
}

/** Start the real `hush ui` on the world; resolves with its address and token. */
function serve(world) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(root, "src", "cli.ts"), "ui", "--port", "0", "--no-open"], {
      cwd: world.start,
      env: {
        // Only node: what the build machine has installed is not part of the demo.
        PATH: dirname(process.execPath),
        HOME: world.fakeHome,
        USERPROFILE: world.fakeHome,
        XDG_CONFIG_HOME: join(world.fakeHome, ".config"),
        HUSH_HOME: world.home,
        HUSH_IDENTITY: world.identity,
        HUSH_NO_KEYCHAIN: "1",
        HUSH_BIOMETRY: "off",
        NO_COLOR: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`hush ui did not start:\n${out}`));
    }, 30_000);
    const read = (b) => {
      out += b;
      const m = /http:\/\/127\.0\.0\.1:(\d+)\/#t=([A-Za-z0-9_-]+)/.exec(out);
      if (m) {
        clearTimeout(timer);
        resolve({ child, base: `http://127.0.0.1:${m[1]}`, token: m[2] });
      }
    };
    child.stdout.on("data", read);
    child.stderr.on("data", read);
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`hush ui exited (${code}):\n${out}`));
    });
  });
}

/**
 * What the page reads, for each project: the reads it makes with GET, and the
 * three it makes with an empty POST body. Keyed "METHOD path project".
 */
async function record(server, roots) {
  const answers = {};
  // The server looks over every project as it starts (stack, what the code
  // reads); what it suggests depends on that, so wait for it to finish.
  for (let tries = 0; ; tries++) {
    const r = await fetch(server.base + "/api/hub", { headers: { "x-hush-token": server.token } });
    if (!(await r.json()).crawl?.running) break;
    if (tries > 300) throw new Error("hush ui was still looking over the projects after a minute");
    await new Promise((ok) => setTimeout(ok, 200));
  }
  const ask = async (method, path, project) => {
    const r = await fetch(server.base + path, {
      method,
      headers: { "x-hush-token": server.token, "content-type": "application/json", ...(project ? { "x-hush-project": project } : {}) },
      body: method === "POST" ? "{}" : undefined,
    });
    const j = await r.json();
    if (!r.ok) throw new Error(`${method} ${path} (${project || "started folder"}): ${r.status} ${j.error}`);
    answers[`${method} ${path} ${project}`] = j;
  };
  await ask("GET", "/api/hub", "");
  for (const project of ["", ...roots]) {
    await ask("GET", "/api/state", project);
    for (const path of ["/api/suggestions", "/api/push-hosts", "/api/audit"]) await ask("POST", path, project);
  }
  return answers;
}

/**
 * Answers the page's requests from what was recorded. Runs before the page's
 * own script. Timestamps move forward by however long ago this was built, so
 * "4 minutes ago" stays four minutes ago.
 */
const SHIM = String.raw`(function(){
  // Light or dark as the site around it is, else as the system is.
  var html=document.documentElement,dark=matchMedia("(prefers-color-scheme: dark)");
  function theme(){
    var t=null;
    try{if(parent!==window)t=parent.document.documentElement.dataset.theme}catch(e){}
    html.dataset.theme=t==="light"||t==="dark"?t:(dark.matches?"dark":"light");
  }
  theme();
  dark.addEventListener("change",theme);
  // Every visit starts where the app does: on the project it opened in, the
  // keys beside it if there is room. (The site shares this storage.)
  try{localStorage.removeItem("hush-keys");localStorage.removeItem("hush-project")}catch(e){}
  try{if(parent!==window)new MutationObserver(theme).observe(parent.document.documentElement,{attributes:true,attributeFilter:["data-theme"]})}catch(e){}
  var D=JSON.parse(document.getElementById("hush-demo").textContent);
  var shift=Date.now()-Date.parse(D.at);
  var ISO=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;
  function fresh(v){
    if(typeof v==="string")return ISO.test(v)?new Date(Date.parse(v)+shift).toISOString():v;
    if(Array.isArray(v))return v.map(fresh);
    if(v&&typeof v==="object"){var o={};for(var k in v)o[k]=fresh(v[k]);return o}
    return v;
  }
  function reply(status,body){return Promise.resolve(new Response(JSON.stringify(body),{status:status,headers:{"content-type":"application/json"}}))}
  var real=window.fetch.bind(window);
  window.fetch=function(input,init){
    var url=new URL(typeof input==="string"?input:input.url,location.href);
    if(url.pathname.indexOf("/api/")!==0)return real(input,init);
    init=init||{};
    var method=init.method||"GET";
    var project=(init.headers&&init.headers["x-hush-project"])||"";
    var read=method==="GET"||init.body==="{}";
    var found=read&&(D.answers[method+" "+url.pathname+" "+project]||D.answers[method+" "+url.pathname+" "]);
    if(found)return reply(200,fresh(found));
    return reply(409,{error:D.refusal});
  };
})();`;

/** The app's dark palette, keyed on a theme the shim sets rather than only on the system's. */
const DARK = "@media (prefers-color-scheme:dark){:root{";
function themed(page) {
  const at = page.indexOf(DARK);
  const end = page.indexOf("}}", at);
  if (at === -1 || end === -1) throw new Error("the app page's dark palette is not where the demo expects it");
  return page.slice(0, at) + ":root[data-theme=dark]{" + page.slice(at + DARK.length, end) + "}" + page.slice(end + 2);
}

/** The page `hush ui` serves, with the recorded answers and the script that serves them. */
export function demoPage(page, answers, at) {
  page = themed(page);
  const data = JSON.stringify({ at, refusal: DEMO_REFUSAL, answers }).replace(/</g, "\\u003c");
  // In a window on the home page the app's scrollbars are clutter (it still
  // scrolls), and the demo's one refusal is a notice, not an error.
  const style = "<style>*{scrollbar-width:none}*::-webkit-scrollbar{display:none}.toast.err{background:var(--ink);color:var(--bg)}</style>";
  const head = `<meta name="robots" content="noindex">${style}<script type="application/json" id="hush-demo">${data}</script><script>${SHIM}</script>`;
  // After the charset, which a browser only looks for in the first kilobyte.
  const charset = '<meta charset="utf-8">';
  if (!page.includes(charset)) throw new Error("the app page has no charset to put the demo's script after");
  return page.replace(charset, charset + head);
}

/** Put the folders where they appear to be, and keep nothing that names this machine. */
function renamed(answers, world) {
  let text = JSON.stringify(answers);
  // As the JSON spells it: a Windows path's backslashes are doubled there.
  const swap = (from, to) => {
    for (const f of new Set([from, realpathSync(from)])) text = text.split(JSON.stringify(f).slice(1, -1)).join(to);
  };
  swap(world.code, SHOWN_CODE);
  swap(world.home, SHOWN_HOME);
  swap(world.fakeHome, "/Users/alex");
  return JSON.parse(text);
}

/**
 * The machine the demo shows is a Mac set up the way `hush start` leaves one,
 * with the key in the macOS Keychain and Touch ID there to ask. The recording
 * ran with the key in an environment variable instead, because a build machine
 * has neither: so the places that say where the key is, and how protected
 * that makes a project, say what they would on that Mac.
 */
function onAMac(answers) {
  for (const a of Object.values(answers)) {
    if (a?.posture?.next?.command === "hush id --create --force") {
      a.posture = {
        rung: 3,
        name: "approved use",
        next: { label: "approval needs your fingerprint, not a click", command: "hush secure --biometry", why: "a click can be made by anything at your unlocked laptop; a fingerprint cannot" },
      };
    }
    if (a?.policy && "biometryAvailable" in a.policy) a.policy.biometryAvailable = true;
    if (typeof a?.platform === "string") a.platform = "darwin";
    for (const s of a?.onboarding?.steps ?? []) if (s.id === "key") s.detail = "on this machine (macOS Keychain)";
  }
  return answers;
}

export async function buildDemo(out) {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "hush-demo-")));
  const saved = { HUSH_HOME: process.env.HUSH_HOME, HUSH_NO_KEYCHAIN: process.env.HUSH_NO_KEYCHAIN };
  let server;
  try {
    const at = new Date().toISOString();
    const world = await buildWorld(base, Date.parse(at));
    server = await serve(world);
    const roots = PROJECTS.map((p) => join(world.code, p.dir));
    const answers = onAMac(renamed(await record(server, roots), world));
    const text = JSON.stringify(answers);
    if (text.includes(base) || text.includes(tmpdir())) throw new Error("a temporary folder's path is still in the demo's data");
    if (/hushdemo-not-a-real|not_a_real/.test(text)) throw new Error("a whole value reached the demo's data: the page should only ever get a preview");
    const { PAGE } = await import(join(root, "src", "ui-page.ts"));
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, demoPage(PAGE, answers, at));
    return { out, answers };
  } finally {
    server?.child.kill();
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    rmSync(base, { recursive: true, force: true });
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const out = process.argv[2] ?? join(root, "website", "public", "demo", "index.html");
  const { answers } = await buildDemo(out);
  process.stdout.write(`the live demo → ${out} (${Object.keys(answers).length} answers)\n`);
}
