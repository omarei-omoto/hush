import { useEffect, useState, type ReactNode } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";

import { AnimatedShinyText } from "../ui/animated-shiny-text";
import { BlurFade } from "../ui/blur-fade";
import { FlickeringGrid } from "../ui/flickering-grid";
import { AppWindow } from "./AppWindow";
import { CopyCommand } from "./CopyCommand";
import { Decrypt } from "./Decrypt";

export function Hero({ version }: { version: string }) {
  return (
    <section className="grain relative isolate overflow-hidden pt-28 pb-10 sm:pt-36">
      {/* A field of cells that flicker like a vault being read, fading out from the top. */}
      <div aria-hidden="true" className="absolute inset-x-0 top-0 -z-10 h-[760px] [mask-image:radial-gradient(ellipse_65%_60%_at_50%_0%,#000_30%,transparent_100%)]">
        <FlickeringGrid squareSize={3} gridGap={7} flickerChance={0.12} maxOpacity={0.22} color="rgb(140,138,130)" />
      </div>
      <div aria-hidden="true" className="absolute top-[520px] left-1/2 -z-10 h-[620px] w-[1100px] -translate-x-1/2 rounded-full bg-[radial-gradient(ellipse_at_center,var(--glow),transparent_65%)] blur-2xl" />

      <div className="mx-auto max-w-6xl px-4 text-center sm:px-6">
        <BlurFade delay={0.05}>
          <a
            href="/guide/sending-keys-to-your-hosts/"
            className="group mx-auto inline-flex max-w-full items-center gap-2 rounded-full border border-border bg-card/70 py-1 pr-3 pl-1 text-[13px] backdrop-blur transition hover:border-border-strong"
          >
            <span className="shrink-0 rounded-full bg-foreground px-2 py-0.5 text-[11px] font-semibold whitespace-nowrap text-background">New in {version}</span>
            <AnimatedShinyText className="truncate text-muted-foreground" shimmerWidth={140}>
              hush push sends a key to where your app runs
            </AnimatedShinyText>
            <svg viewBox="0 0 24 24" className="size-3.5 shrink-0 text-muted-foreground transition group-hover:translate-x-0.5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
              <path d="M5 12h14M13 6l6 6-6 6" />
            </svg>
          </a>
        </BlurFade>

        <h1 className="mx-auto mt-7 max-w-5xl font-display text-[clamp(2.3rem,7.2vw,5.4rem)] leading-[1.02] font-semibold tracking-[-0.045em] text-balance">
          <Line delay={0.15}>Secrets your AI agent</Line>
          <Line delay={0.3} className="text-muted-foreground">
            can use but <Decrypt text="never read." delay={1100} />
          </Line>
        </h1>

        <BlurFade delay={0.45} offset={8}>
          <p className="mx-auto mt-6 max-w-2xl text-[17px] leading-relaxed text-ink-2 sm:text-lg">
            Your keys live encrypted in the repo. <code className="rounded-md bg-sunken px-1.5 py-0.5 font-mono text-[0.88em]">hush npm run dev</code> hands them to that one process — your coding
            agent can run it, and only ever sees <code className="rounded-md bg-ok-soft px-1.5 py-0.5 font-mono text-[0.88em] text-ok">[redacted:KEY]</code>. No server, no account, no
            shared password.
          </p>
        </BlurFade>

        <BlurFade delay={0.6} offset={8}>
          <div className="mx-auto mt-9 flex max-w-xl flex-col items-stretch justify-center gap-3 sm:flex-row sm:items-center">
            <a
              href="/guide/setting-up/"
              className="inline-flex h-12 shrink-0 items-center justify-center gap-2 rounded-xl bg-foreground px-6 text-[15px] font-semibold text-background shadow-[0_8px_30px_-8px_var(--glow)] transition hover:opacity-90"
            >
              Get started
              <svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" aria-hidden="true">
                <path d="M5 12h14M13 6l6 6-6 6" />
              </svg>
            </a>
            <CopyCommand command="npm i -g @omarei/hush" className="h-12 sm:w-[300px]" />
          </div>
          <p className="mt-4 text-[13px] text-muted-foreground">
            macOS, Linux and Windows (beta) · zero dependencies · MIT ·{" "}
            <a href="#install" className="underline decoration-border-strong underline-offset-4 hover:text-foreground">
              other ways to install
            </a>
          </p>
        </BlurFade>
      </div>

      <div className="relative mx-auto mt-16 max-w-[1240px] px-4 sm:mt-20 sm:px-6">
        <BlurFade delay={0.75} offset={24} duration={0.7}>
          <AppWindow>
            <ApprovalCard />
            <TranscriptCard />
          </AppWindow>
        </BlurFade>
        <p className="mx-auto mt-6 max-w-xl text-center text-[13px] text-muted-foreground">
          That is the app itself — the page <code className="font-mono">hush ui</code> opens on your machine — running here on made-up keys.
          Suggestions, groups, the agent's activity: click around.
        </p>
      </div>
    </section>
  );
}

/** A line of the heading, rising out of a blur: a span, since a heading holds only text. */
function Line({ children, delay, className }: { children: ReactNode; delay: number; className?: string }) {
  return (
    <motion.span
      initial={{ opacity: 0, y: 10, filter: "blur(8px)" }}
      animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
      transition={{ delay, duration: 0.6, ease: "easeOut" }}
      className={`block ${className ?? ""}`}
    >
      {children}
    </motion.span>
  );
}

/** Card chrome for the two that float over the window. */
const floating = "pointer-events-none absolute z-10 hidden w-[300px] rounded-2xl border border-border-strong bg-card/95 p-4 text-left shadow-2xl backdrop-blur-md lg:block";

/** What you see when your agent asks to run something: a prompt on your own screen, answered with a fingerprint. */
function ApprovalCard() {
  const reduce = useReducedMotion();
  const [approved, setApproved] = useState(false);
  useEffect(() => {
    if (reduce) return;
    let t: ReturnType<typeof setTimeout>;
    const cycle = (next: boolean) => {
      setApproved(next);
      t = setTimeout(() => cycle(!next), next ? 3200 : 2600);
    };
    t = setTimeout(() => cycle(true), 3600);
    return () => clearTimeout(t);
  }, [reduce]);

  return (
    <motion.div
      aria-hidden="true"
      initial={{ opacity: 0, x: -24 }}
      animate={{ opacity: 1, x: 0, y: reduce ? 0 : [0, -6, 0] }}
      transition={{ opacity: { delay: 1.6, duration: 0.6 }, x: { delay: 1.6, duration: 0.6 }, y: { duration: 6, repeat: Infinity, ease: "easeInOut" } }}
      className={`${floating} -left-10 bottom-16 xl:-left-16`}
    >
      <div className="flex items-start gap-3">
        <div className="relative grid size-10 shrink-0 place-items-center rounded-full bg-ok-soft text-ok">
          {!approved && <span className="absolute inset-0 animate-pulse-ring rounded-full border border-ok" />}
          <Fingerprint />
        </div>
        <div className="min-w-0">
          <div className="text-[13px] font-semibold">Claude Code wants to run</div>
          <div className="mt-0.5 font-mono text-[12.5px] text-ink-2">npm run dev</div>
          <div className="mt-1 text-[12px] text-muted-foreground">acme-api · 9 keys</div>
        </div>
      </div>
      <div className="mt-3.5 h-9">
        <AnimatePresence mode="wait" initial={false}>
          {approved ? (
            <motion.div
              key="ok"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              className="flex h-9 items-center justify-center gap-2 rounded-lg bg-ok-soft text-[13px] font-medium text-ok"
            >
              <svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
                <path d="M5 12.5l4.5 4.5L19 7.5" />
              </svg>
              Approved with Touch ID
            </motion.div>
          ) : (
            <motion.div key="ask" initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} className="grid h-9 grid-cols-2 gap-2 text-[13px] font-medium">
              <span className="grid place-items-center rounded-lg border border-border">Deny</span>
              <span className="grid place-items-center rounded-lg bg-foreground text-background">Allow</span>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}

/** What your agent sees of the same run: everything but the values. */
function TranscriptCard() {
  const reduce = useReducedMotion();
  return (
    <motion.div
      aria-hidden="true"
      initial={{ opacity: 0, x: 24 }}
      animate={{ opacity: 1, x: 0, y: reduce ? 0 : [0, 7, 0] }}
      transition={{ opacity: { delay: 2.1, duration: 0.6 }, x: { delay: 2.1, duration: 0.6 }, y: { duration: 7, repeat: Infinity, ease: "easeInOut" } }}
      className={`${floating} -right-10 top-28 w-[330px] xl:-right-16`}
    >
      <div className="mb-2.5 flex items-center gap-2 text-[12px] font-medium text-muted-foreground">
        <span className="size-1.5 rounded-full bg-ok" />
        What your agent sees
      </div>
      <div className="space-y-1 rounded-lg bg-sunken/80 p-3 font-mono text-[12px] leading-relaxed">
        <div className="text-muted-foreground">
          <span className="text-ok">●</span> hush_run <span className="text-foreground">npm run dev</span>
        </div>
        <div className="truncate text-ink-2">
          db: <span className="rounded bg-ok-soft px-1 text-ok">[redacted:DATABASE_URL]</span>
        </div>
        <div className="truncate text-ink-2">
          openai: <span className="rounded bg-ok-soft px-1 text-ok">[redacted:OPENAI_API_KEY]</span>
        </div>
        <div className="text-ink-2">ready on http://localhost:3000</div>
      </div>
    </motion.div>
  );
}

function Fingerprint() {
  return (
    <svg viewBox="0 0 24 24" className="size-5" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 11c0 3.5-.9 6.5-2.4 8.6M8.6 7.8A5 5 0 0 1 17 11c0 1.2-.1 2.4-.3 3.5M7 11a5 5 0 0 1 .3-1.7M7 14.5c-.2 1.5-.7 2.9-1.4 4M15.6 18a17 17 0 0 0 .7-2.4M12 20.8c.4-.7.8-1.5 1.1-2.3M4.3 8.7A8.5 8.5 0 0 1 20.5 11c0 1-.1 2-.2 3M3.6 12.5c.2-.9.3-1.7.3-2.6M9.6 15.3A15 15 0 0 0 10 11a2 2 0 0 1 4 0c0 .7 0 1.4-.1 2.1" />
    </svg>
  );
}
