import { useEffect, useRef, useState, type ReactNode } from "react";
import { AnimatePresence, motion, useReducedMotion, useScroll, useTransform } from "motion/react";

import { BorderBeam } from "../ui/border-beam";

/** The app is laid out for a laptop's window; on a wide screen it is shown at that size, scaled to fit. */
const APP_WIDTH = 1280;
const APP_HEIGHT = 800;
/** Narrower than this, the app gets the window's own width, and lays itself out for a phone. */
const PHONE = 720;

/**
 * The real hush app — the page `hush ui` serves — running in a browser
 * window on made-up keys (scripts/build-demo.mjs builds it into /demo/). It
 * tilts back as it comes up the page, and takes clicks once you ask it to, so
 * scrolling past it scrolls the page rather than the app.
 */
export function AppWindow({ children }: { children?: ReactNode }) {
  const reduce = useReducedMotion();
  const outer = useRef<HTMLDivElement>(null);
  const frame = useRef<HTMLDivElement>(null);
  const [live, setLive] = useState(false);
  const [loaded, setLoaded] = useState(false);
  // Unknown until the window is measured: the app lays itself out once, as it loads.
  const [phone, setPhone] = useState<boolean | null>(null);

  // Scale the app to the window: a CSS variable, so resizing never re-renders.
  useEffect(() => {
    const el = frame.current;
    if (!el) return;
    const fit = () => {
      const w = el.clientWidth;
      el.style.setProperty("--app-scale", String(w / APP_WIDTH));
      setPhone(w < PHONE);
    };
    fit();
    const ro = new ResizeObserver(fit);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const { scrollYProgress } = useScroll({ target: outer, offset: ["start end", "start 0.2"] });
  const rotateX = useTransform(scrollYProgress, [0, 1], [16, 0]);
  const scale = useTransform(scrollYProgress, [0, 1], [0.93, 1]);
  const y = useTransform(scrollYProgress, [0, 1], [40, 0]);

  return (
    <div ref={outer} className="relative [perspective:1800px]">
      <motion.div
        style={reduce ? undefined : { rotateX, scale, y, transformOrigin: "50% 0%" }}
        className="relative rounded-2xl border border-border-strong bg-card shadow-[0_40px_120px_-30px_rgba(0,0,0,0.45),0_0_0_1px_rgba(255,255,255,0.02)] dark:shadow-[0_40px_140px_-30px_rgba(0,0,0,0.9),0_0_80px_-20px_var(--glow)]"
      >
        {/* The browser's own bar: hush ui is a page on your own machine. */}
        <div className="flex h-11 items-center gap-3 rounded-t-2xl border-b border-border bg-sunken/70 px-4">
          <div className="flex gap-1.5" aria-hidden="true">
            <span className="size-3 rounded-full bg-[#ff5f57]" />
            <span className="size-3 rounded-full bg-[#febc2e]" />
            <span className="size-3 rounded-full bg-[#28c840]" />
          </div>
          <div className="mx-auto flex h-7 min-w-0 max-w-sm flex-1 items-center justify-center gap-2 rounded-lg bg-background/80 px-3 font-mono text-[12px] text-muted-foreground">
            <svg viewBox="0 0 24 24" className="size-3.5 shrink-0" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
              <path d="M4 12a8 8 0 1 0 16 0a8 8 0 1 0-16 0M4 12h16M12 4c2.2 2.4 3.3 5 3.3 8s-1.1 5.6-3.3 8c-2.2-2.4-3.3-5-3.3-8s1.1-5.6 3.3-8" />
            </svg>
            <span className="truncate">127.0.0.1:4455</span>
          </div>
          <div className="hidden items-center gap-1.5 rounded-full bg-ok-soft px-2.5 py-1 text-[11px] font-medium text-ok sm:flex">
            <span className="relative flex size-1.5">
              <span className="absolute inline-flex size-full animate-ping rounded-full bg-ok opacity-60" />
              <span className="relative inline-flex size-1.5 rounded-full bg-ok" />
            </span>
            Live demo
          </div>
        </div>

        <div
          ref={frame}
          className="relative overflow-hidden rounded-b-2xl bg-background"
          style={{ height: phone ? 620 : `calc(${APP_HEIGHT}px * var(--app-scale, 0.86))` }}
        >
          {phone !== null && (
            <iframe
              src="/demo/index.html#t=demo-only-not-a-real-token"
              title="The hush app, running in this page on made-up keys"
              onLoad={() => setLoaded(true)}
              tabIndex={live ? 0 : -1}
              className="absolute top-0 left-0 origin-top-left border-0 transition-opacity duration-500"
              style={{
                width: phone ? "100%" : APP_WIDTH,
                height: phone ? "100%" : APP_HEIGHT,
                transform: phone ? undefined : "scale(var(--app-scale, 0.86))",
                opacity: loaded ? 1 : 0,
                pointerEvents: live ? "auto" : "none",
              }}
            />
          )}
          {!loaded && <Skeleton />}

          <AnimatePresence>
            {!live && (
              <motion.button
                type="button"
                onClick={() => setLive(true)}
                exit={{ opacity: 0 }}
                className="group absolute inset-0 flex cursor-pointer items-end justify-center bg-gradient-to-b from-transparent from-55% to-background/70 pb-8"
                aria-label="Try the app: it is the real one, running on made-up keys"
              >
                <span className="flex translate-y-1 items-center gap-2 rounded-full border border-border-strong bg-card/95 px-4 py-2 text-[13px] font-medium text-foreground opacity-90 shadow-lg backdrop-blur transition group-hover:translate-y-0 group-hover:opacity-100">
                  <svg viewBox="0 0 24 24" className="size-4 text-ok" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="M9 9l10.5 4.5-4.5 1.5-1.5 4.5zM4 4l3 3M4 10h2.5M10 4v2.5" />
                  </svg>
                  Click to try it — the real app, on made-up keys
                </span>
              </motion.button>
            )}
          </AnimatePresence>
        </div>
        <BorderBeam size={260} duration={10} borderWidth={1.5} colorFrom="var(--ok)" colorTo="transparent" />
      </motion.div>
      {/* What floats over the window steps aside once you are using the app. */}
      <div className="transition-opacity duration-500" style={{ opacity: live ? 0 : 1 }}>
        {children}
      </div>
    </div>
  );
}

/** The app's outline, while it loads. */
function Skeleton() {
  return (
    <div className="absolute inset-0 grid grid-cols-[19%_1fr_22%]" aria-hidden="true">
      <div className="space-y-3 border-r border-border p-5">
        {[60, 45, 70, 50, 40].map((w, i) => (
          <div key={i} className="h-3 animate-pulse rounded bg-sunken" style={{ width: `${w}%` }} />
        ))}
      </div>
      <div className="space-y-4 p-6">
        <div className="h-6 w-1/3 animate-pulse rounded bg-sunken" />
        <div className="h-24 animate-pulse rounded-xl bg-sunken" />
        <div className="h-40 animate-pulse rounded-xl bg-sunken" />
      </div>
      <div className="space-y-3 border-l border-border p-5">
        {[70, 55, 65, 50].map((w, i) => (
          <div key={i} className="h-3 animate-pulse rounded bg-sunken" style={{ width: `${w}%` }} />
        ))}
      </div>
    </div>
  );
}
