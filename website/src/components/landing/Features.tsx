import { useEffect, useState, type MouseEvent, type ReactNode } from "react";
import { useReducedMotion } from "motion/react";

import { AnimatedList } from "../ui/animated-list";
import { BlurFade } from "../ui/blur-fade";
import { Marquee } from "../ui/marquee";
import { NumberTicker } from "../ui/number-ticker";
import { cn } from "../../lib/utils";

/** A card lit from wherever the pointer is. */
function Card({ children, className }: { children: ReactNode; className?: string }) {
  const move = (e: MouseEvent<HTMLDivElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    e.currentTarget.style.setProperty("--x", `${e.clientX - r.left}px`);
    e.currentTarget.style.setProperty("--y", `${e.clientY - r.top}px`);
  };
  return (
    <div
      onMouseMove={move}
      className={cn(
        "group relative flex h-full flex-col overflow-hidden rounded-3xl border border-border bg-card",
        "before:pointer-events-none before:absolute before:inset-0 before:opacity-0 before:transition-opacity before:duration-300 hover:before:opacity-100",
        "before:bg-[radial-gradient(420px_circle_at_var(--x,50%)_var(--y,50%),var(--glow),transparent_70%)]",
        className,
      )}
    >
      {children}
    </div>
  );
}

function Text({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="relative p-6 sm:p-7">
      <h3 className="font-display text-xl font-semibold tracking-[-0.025em]">{title}</h3>
      <p className="mt-2 max-w-md text-[14.5px] leading-relaxed text-ink-2">{children}</p>
    </div>
  );
}

const Code = ({ children }: { children: string }) => <code className="rounded bg-sunken px-1 py-0.5 font-mono text-[0.88em]">{children}</code>;

export function Features() {
  return (
    <section id="features" className="mx-auto max-w-6xl scroll-mt-20 px-4 py-24 sm:px-6 sm:py-32">
      <BlurFade inView>
        <p className="text-center text-[13px] font-semibold tracking-[0.12em] text-ok uppercase">What you get</p>
        <h2 className="mx-auto mt-3 max-w-3xl text-center font-display text-[clamp(2rem,4.6vw,3.4rem)] leading-[1.05] font-semibold tracking-[-0.04em] text-balance">
          Everything a <span className="text-muted-foreground">.env</span> did, without the plaintext.
        </h2>
      </BlurFade>

      <div className="mt-14 grid gap-4 md:grid-cols-3">
        <BlurFade inView className="md:col-span-2">
          <Card>
            <div className="grid h-full md:grid-cols-[1fr_1.1fr]">
              <Text title="The vault is a file in your repo">
                Each value is sealed on its own, with <a className="underline decoration-border-strong underline-offset-4 hover:text-foreground" href="https://age-encryption.org">age</a>'s construction
                rebuilt on <Code>node:crypto</Code>. Key names stay readable, so a diff shows which key changed — never what to. The header is signed, and only an
                admin's signature changes who can read it.
              </Text>
              <VaultFile />
            </div>
          </Card>
        </BlurFade>

        <BlurFade inView delay={0.08}>
          <Card>
            <Text title="Asked first, with your finger">
              Anything that uses a key asks on your own screen — a native dialog, or Touch ID on a Mac. Text in a chat can't click it.
            </Text>
            <TouchId />
          </Card>
        </BlurFade>

        <BlurFade inView delay={0.04}>
          <Card>
            <Text title="Tools your agent can use, not read">
              hush's MCP server gives Claude Code, Codex, Cursor and the rest tools that name a key. None of them returns its value.
            </Text>
            <ToolCalls />
          </Card>
        </BlurFade>

        <BlurFade inView delay={0.08}>
          <Card>
            <Text title="A teammate is one command">
              Everyone has a key pair. Adding someone wraps the vault's key for them; removing them re-encrypts every value and lists what to rotate.
            </Text>
            <Team />
          </Card>
        </BlurFade>

        <BlurFade inView delay={0.12}>
          <Card>
            <Text title="Nothing beside it">
              No server to run, no account to make, nothing in <Code>node_modules</Code>: one binary, or one npm package.
            </Text>
            <Stats />
          </Card>
        </BlurFade>

        <BlurFade inView className="md:col-span-3">
          <Card>
            <div className="grid items-center md:grid-cols-[1fr_1.6fr]">
              <Text title="Send keys where your app runs">
                <Code>hush push</Code> sends a key to {HOSTS.length} hosts through their own CLIs — on stdin, never on a command line — and refuses a value
                a CLI would quietly change. When you replace a key, the app tells you where it still needs to go.{" "}
                <a href="/guide/sending-keys-to-your-hosts/" className="font-medium text-foreground underline decoration-border-strong underline-offset-4 hover:decoration-foreground">
                  How it works
                </a>
              </Text>
              <Hosts />
            </div>
          </Card>
        </BlurFade>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ visuals */

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const cipher = (n: number) => Array.from({ length: n }, () => B64[Math.floor(Math.random() * 64)]).join("");

/** .hush/vault.json, as it is committed: names in the clear, values never. */
function VaultFile() {
  const reduce = useReducedMotion();
  const keys = ["OPENAI_API_KEY", "STRIPE_SECRET_KEY", "DATABASE_URL"];
  const [ct, setCt] = useState(() => keys.map(() => "k6egPny2o9uFHSkiJzcUOWUZ"));
  useEffect(() => {
    if (reduce) return;
    setCt(keys.map(() => cipher(24)));
    const t = setInterval(() => setCt((old) => old.map((c) => (Math.random() < 0.5 ? cipher(24) : c))), 140);
    return () => clearInterval(t);
  }, [reduce]);
  return (
    <div className="relative m-4 mt-0 self-center overflow-hidden rounded-2xl border border-border bg-sunken/60 font-mono text-[12px] leading-[1.75] md:m-5 md:ml-0">
      <div className="flex items-center gap-2 border-b border-border px-4 py-2 text-[11.5px] text-muted-foreground">
        <span className="size-2 rounded-full bg-ok" />
        .hush/vault.json
        <span className="ml-auto rounded bg-ok-soft px-1.5 text-ok">committed</span>
      </div>
      <pre className="overflow-hidden px-4 py-3 text-ink-2" aria-label="An excerpt of a vault file: each key's name, and its value as ciphertext">
        <span className="text-muted-foreground">{'"envs": { "dev": {'}</span>
        {keys.map((k, i) => (
          <span key={k} className="block">
            {"  "}
            <span className="text-foreground">"{k}"</span>
            {": { "}
            <span className="text-muted-foreground">"ct": </span>
            <span className="text-ok">"{ct[i]}…"</span>
            {" },"}
          </span>
        ))}
        <span className="block text-muted-foreground">{"} },"}</span>
        <span className="block text-muted-foreground">
          {'"signature": { "by": '}
          <span className="text-ink-2">"99b889e5…"</span>
          {', "sig": '}
          <span className="text-ink-2">"rzm9ulD4…"</span>
          {" }"}
        </span>
      </pre>
      <div className="pointer-events-none absolute inset-y-0 right-0 w-16 bg-gradient-to-l from-card to-transparent" />
    </div>
  );
}

/** The prompt an approval brings up, waiting on a fingerprint. */
function TouchId() {
  return (
    <div className="relative mx-6 mb-6 mt-auto rounded-2xl border border-border bg-sunken/60 p-5 text-center sm:mx-7 sm:mb-7">
      <div className="relative mx-auto grid size-14 place-items-center rounded-full bg-ok-soft text-ok">
        <span className="absolute inset-0 animate-pulse-ring rounded-full border border-ok" />
        <span className="absolute inset-0 animate-pulse-ring rounded-full border border-ok [animation-delay:1.2s]" />
        <svg viewBox="0 0 24 24" className="size-7" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M12 11c0 3.5-.9 6.5-2.4 8.6M8.6 7.8A5 5 0 0 1 17 11c0 1.2-.1 2.4-.3 3.5M7 11a5 5 0 0 1 .3-1.7M7 14.5c-.2 1.5-.7 2.9-1.4 4M15.6 18a17 17 0 0 0 .7-2.4M12 20.8c.4-.7.8-1.5 1.1-2.3M4.3 8.7A8.5 8.5 0 0 1 20.5 11c0 1-.1 2-.2 3M3.6 12.5c.2-.9.3-1.7.3-2.6M9.6 15.3A15 15 0 0 0 10 11a2 2 0 0 1 4 0c0 .7 0 1.4-.1 2.1" />
        </svg>
      </div>
      <p className="mt-4 text-[13px] font-semibold">hush wants to run npm test</p>
      <p className="mt-1 text-[12px] leading-snug text-muted-foreground">for Claude Code, in acme-api, with 9 keys. Touch ID to allow.</p>
    </div>
  );
}

const CALLS: [string, string][] = [
  ["hush_list_sets", "6 sets · names, never values"],
  ["hush_run npm test", "exit 0 · 9 keys in · output masked"],
  ["hush_request GET api.stripe.com", "200 · hush filled in $STRIPE_KEY"],
  ["hush_push STRIPE_SECRET_KEY", "sent to Cloudflare · you approved"],
];

/** An agent's calls, as they come in. */
function ToolCalls() {
  return (
    <div className="relative mt-auto h-[214px] overflow-hidden px-6 pb-6 sm:px-7">
      <AnimatedList delay={1400} className="gap-2.5">
        {CALLS.map(([call, result]) => (
          <div key={call} className="w-full rounded-xl border border-border bg-sunken/60 px-3.5 py-2.5">
            <div className="truncate font-mono text-[12px] text-foreground">{call}</div>
            <div className="mt-0.5 truncate text-[12px] text-muted-foreground">{result}</div>
          </div>
        ))}
      </AnimatedList>
      <div className="pointer-events-none absolute inset-x-0 bottom-0 h-12 bg-gradient-to-t from-card to-transparent" />
    </div>
  );
}

function Team() {
  const people: [string, string, string][] = [
    ["alex", "admin", "bg-foreground text-background"],
    ["sam", "member", "bg-ok-soft text-ok"],
    ["priya", "member · just now", "bg-sunken text-ink-2"],
  ];
  return (
    <div className="mt-auto px-6 pb-6 sm:px-7 sm:pb-7">
      <div className="rounded-2xl border border-border bg-sunken/60 p-2">
        {people.map(([name, role, tone]) => (
          <div key={name} className="flex items-center gap-3 rounded-xl px-2.5 py-2">
            <span className={cn("grid size-8 place-items-center rounded-full text-[12px] font-semibold uppercase", tone)}>{name.slice(0, 2)}</span>
            <span className="text-[13.5px] font-medium">{name}</span>
            <span className="ml-auto text-[12px] text-muted-foreground">{role}</span>
          </div>
        ))}
      </div>
      <div className="mt-3 truncate font-mono text-[12px] text-muted-foreground">
        <span className="text-ok">$</span> hush team add priya hush_pk_9vRw…
      </div>
    </div>
  );
}

function Stats() {
  return (
    <div className="mt-auto grid grid-cols-3 gap-2 px-6 pb-6 sm:px-7 sm:pb-7">
      {[
        { n: 0, label: "runtime dependencies" },
        { n: 1300, label: "tests, and counting", plus: true },
        { n: 1, label: "file to install" },
      ].map((s) => (
        <div key={s.label} className="rounded-2xl border border-border bg-sunken/60 px-3 py-4">
          <div className="font-display text-[24px] leading-none font-semibold tracking-[-0.04em] whitespace-nowrap">
            <NumberTicker value={s.n} className="text-foreground dark:text-foreground" />
            {s.plus && <span className="text-ok">+</span>}
          </div>
          <div className="mt-2 text-[11.5px] leading-tight text-muted-foreground">{s.label}</div>
        </div>
      ))}
    </div>
  );
}

const HOSTS = [
  "Cloudflare Workers",
  "Cloudflare Pages",
  "Vercel",
  "Convex",
  "Fly.io",
  "Railway",
  "Firebase Functions",
  "GitHub Actions",
  "GitLab CI/CD",
  "Google Cloud Secret Manager",
  "Koyeb",
  "Fastly Secret Store",
  "Pulumi",
  "SST",
];

function Hosts() {
  const chip = (h: string) => (
    <span key={h} className="flex items-center gap-2 rounded-full border border-border bg-sunken/60 px-3.5 py-1.5 text-[13px] whitespace-nowrap text-ink-2">
      <span className="size-1.5 rounded-full bg-ok" />
      {h}
    </span>
  );
  const half = Math.ceil(HOSTS.length / 2);
  return (
    <div className="relative overflow-hidden py-6 md:py-8" aria-label={`Hosts hush push sends to: ${HOSTS.join(", ")}`}>
      <Marquee pauseOnHover className="[--duration:36s] [--gap:0.6rem]">{HOSTS.slice(0, half).map(chip)}</Marquee>
      <Marquee pauseOnHover reverse className="[--duration:40s] [--gap:0.6rem]">{HOSTS.slice(half).map(chip)}</Marquee>
      <div className="pointer-events-none absolute inset-y-0 left-0 w-16 bg-gradient-to-r from-card to-transparent" />
      <div className="pointer-events-none absolute inset-y-0 right-0 w-16 bg-gradient-to-l from-card to-transparent" />
    </div>
  );
}
