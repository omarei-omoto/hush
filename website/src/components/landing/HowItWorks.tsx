import { forwardRef, useRef, type ReactNode } from "react";

import { AnimatedBeam } from "../ui/animated-beam";
import { BlurFade } from "../ui/blur-fade";
import { cn } from "../../lib/utils";

const Node = forwardRef<HTMLDivElement, { children: ReactNode; label: string; note?: string; className?: string }>(({ children, label, note, className }, ref) => (
  <div className="z-10 flex w-24 flex-col items-center gap-2 text-center sm:w-36">
    <div ref={ref} className={cn("grid size-12 place-items-center rounded-2xl border border-border-strong bg-card shadow-sm sm:size-14", className)}>
      {children}
    </div>
    <div className="text-[12px] leading-tight font-semibold sm:text-[13px]">{label}</div>
    {note && <div className="-mt-1 hidden text-[12px] leading-tight text-muted-foreground sm:block">{note}</div>}
  </div>
));
Node.displayName = "Node";

const Mono = ({ children }: { children: string }) => <span className="font-display text-[15px] font-bold tracking-tight sm:text-[17px]">{children}</span>;

export function HowItWorks({ mark }: { mark: string }) {
  const box = useRef<HTMLDivElement>(null);
  const agents = [useRef<HTMLDivElement>(null), useRef<HTMLDivElement>(null), useRef<HTMLDivElement>(null)];
  const hush = useRef<HTMLDivElement>(null);
  const out = [useRef<HTMLDivElement>(null), useRef<HTMLDivElement>(null), useRef<HTMLDivElement>(null)];

  return (
    <section id="how" className="relative mx-auto max-w-6xl scroll-mt-20 px-4 py-24 sm:px-6 sm:py-32">
      <BlurFade inView>
        <p className="text-center text-[13px] font-semibold tracking-[0.12em] text-ok uppercase">How it works</p>
        <h2 className="mx-auto mt-3 max-w-3xl text-center font-display text-[clamp(2rem,4.6vw,3.4rem)] leading-[1.05] font-semibold tracking-[-0.04em] text-balance">
          Your agent asks. You approve. It never sees a value.
        </h2>
      </BlurFade>

      <div ref={box} className="relative mx-auto mt-16 flex max-w-4xl items-center justify-between rounded-3xl border border-border bg-card/40 px-3 py-10 sm:px-10 sm:py-14">
        <div className="flex flex-col gap-8 sm:gap-10">
          <Node ref={agents[0]} label="Claude Code"><Mono>CC</Mono></Node>
          <Node ref={agents[1]} label="Codex"><Mono>Cx</Mono></Node>
          <Node ref={agents[2]} label="Cursor"><Mono>Cu</Mono></Node>
        </div>

        <div className="z-10 flex flex-col items-center gap-3 text-center">
          <div ref={hush} className="relative grid size-20 place-items-center rounded-3xl bg-foreground text-background shadow-[0_0_0_8px_var(--ok-soft),0_20px_60px_-10px_var(--glow)] sm:size-24">
            <span className="absolute inset-0 animate-pulse-ring rounded-3xl border border-ok" />
            <span className="w-11 sm:w-12" dangerouslySetInnerHTML={{ __html: mark }} />
          </div>
          <div className="text-[13px] font-semibold">hush</div>
          <div className="-mt-2 max-w-[9rem] text-[12px] leading-tight text-muted-foreground">asks you first, on your screen</div>
        </div>

        <div className="flex flex-col gap-8 sm:gap-10">
          <Node ref={out[0]} label="npm run dev" note="gets the values">
            <Glyph d="M4 6l5 6-5 6M12 18h8" />
          </Node>
          <Node ref={out[1]} label="api.stripe.com" note="called with the key">
            <Glyph d="M4 12a8 8 0 1 0 16 0a8 8 0 1 0-16 0M4 12h16M12 4c2.2 2.4 3.3 5 3.3 8s-1.1 5.6-3.3 8c-2.2-2.4-3.3-5-3.3-8s1.1-5.6 3.3-8" />
          </Node>
          <Node ref={out[2]} label="Cloudflare" note="sent on stdin">
            <Glyph d="M7 18a4.5 4.5 0 0 1-.6-9A6 6 0 0 1 18 9.5a4 4 0 0 1-.5 8.5z" />
          </Node>
        </div>

        {agents.map((ref, i) => (
          <AnimatedBeam key={`in${i}`} containerRef={box} fromRef={ref} toRef={hush} curvature={(1 - i) * 50} duration={4} delay={i * 0.6} pathColor="var(--muted-foreground)" pathOpacity={0.25} gradientStartColor="var(--ok)" gradientStopColor="var(--ok)" />
        ))}
        {out.map((ref, i) => (
          <AnimatedBeam key={`out${i}`} containerRef={box} fromRef={hush} toRef={ref} curvature={(1 - i) * 50} duration={4} delay={1.6 + i * 0.6} pathColor="var(--muted-foreground)" pathOpacity={0.25} gradientStartColor="var(--foreground)" gradientStopColor="var(--ok)" />
        ))}
      </div>

      <div className="mx-auto mt-14 grid max-w-5xl gap-4 sm:grid-cols-3">
        {STEPS.map((s, i) => (
          <BlurFade key={s.title} inView delay={0.1 * i}>
            <div className="h-full rounded-2xl border border-border bg-card p-6">
              <div className="font-mono text-[12px] text-ok">0{i + 1}</div>
              <h3 className="mt-3 font-display text-lg font-semibold tracking-[-0.02em]">{s.title}</h3>
              <p className="mt-2 text-[14.5px] leading-relaxed text-ink-2">{s.body}</p>
            </div>
          </BlurFade>
        ))}
      </div>
    </section>
  );
}

const Code = ({ children }: { children: string }) => <code className="rounded bg-sunken px-1 py-0.5 font-mono text-[0.88em]">{children}</code>;

const STEPS = [
  {
    title: "Keys live encrypted in your repo",
    body: (
      <>
        <Code>.hush/vault.json</Code> holds ciphertext and public keys, so you commit it. Your own key never leaves your machine — on a
        Mac it is in the Keychain.
      </>
    ),
  },
  {
    title: "Your agent names a key",
    body: (
      <>
        Through hush's MCP tools it runs a command with your keys, calls an API with one, or sends one to a host. No tool ever
        returns a value.
      </>
    ),
  },
  {
    title: "You approve, on your screen",
    body: (
      <>
        A native dialog, or Touch ID — never a message in the chat. The process gets the value; the transcript gets{" "}
        <code className="rounded bg-ok-soft px-1 py-0.5 font-mono text-[0.88em] text-ok">[redacted:KEY]</code>.
      </>
    ),
  },
];

function Glyph({ d }: { d: string }) {
  return (
    <svg viewBox="0 0 24 24" className="size-5 sm:size-6" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={d} />
    </svg>
  );
}
