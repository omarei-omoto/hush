import { useState } from "react";
import { motion } from "motion/react";

import { BlurFade } from "../ui/blur-fade";
import { CopyCommand } from "./CopyCommand";

/** The ways to install, as the README gives them. */
const WAYS = [
  { id: "sh", label: "macOS & Linux", command: "curl -fsSL https://raw.githubusercontent.com/omarei-omoto/hush/main/scripts/install.sh | sh", note: "One file, no Node needed. Installs to ~/.local/bin without sudo." },
  { id: "brew", label: "Homebrew", command: "brew install omarei-omoto/tap/hush", note: "The same single-file binary, kept up to date by brew." },
  { id: "npm", label: "npm", command: "npm install -g @omarei/hush", note: "Needs Node 22.6 or newer. Still zero runtime dependencies." },
  { id: "ps", label: "Windows", command: "irm https://raw.githubusercontent.com/omarei-omoto/hush/main/scripts/install.ps1 | iex", note: "Windows is in beta: your key is kept with DPAPI, approvals are a native dialog.", prompt: ">" },
  { id: "scoop", label: "Scoop", command: "scoop install https://github.com/omarei-omoto/hush/releases/latest/download/hush.json", note: "Windows, through Scoop.", prompt: ">" },
];

export function Install() {
  const [at, setAt] = useState(WAYS[0].id);
  const way = WAYS.find((w) => w.id === at) ?? WAYS[0];
  return (
    <section id="install" className="mx-auto max-w-4xl scroll-mt-20 px-4 py-24 sm:px-6 sm:py-28">
      <BlurFade inView>
        <p className="text-center text-[13px] font-semibold tracking-[0.12em] text-ok uppercase">Install</p>
        <h2 className="mx-auto mt-3 max-w-2xl text-center font-display text-[clamp(2rem,4.2vw,3.1rem)] leading-[1.05] font-semibold tracking-[-0.04em] text-balance">
          One file. Then <span className="font-mono text-[0.82em] tracking-[-0.02em]">hush start</span>.
        </h2>
      </BlurFade>

      <BlurFade inView delay={0.1}>
        <div className="mt-12 rounded-3xl border border-border bg-card p-3 sm:p-4">
          <div role="tablist" aria-label="How to install" className="flex gap-1 overflow-x-auto rounded-2xl bg-sunken/70 p-1">
            {WAYS.map((w) => (
              <button
                key={w.id}
                role="tab"
                type="button"
                aria-selected={w.id === at}
                onClick={() => setAt(w.id)}
                className="relative shrink-0 rounded-xl px-3.5 py-2 text-[13px] font-medium whitespace-nowrap text-muted-foreground transition hover:text-foreground aria-selected:text-foreground"
              >
                {w.id === at && <motion.span layoutId="install-tab" className="absolute inset-0 rounded-xl bg-card shadow-sm" transition={{ type: "spring", stiffness: 500, damping: 40 }} />}
                <span className="relative">{w.label}</span>
              </button>
            ))}
          </div>
          <div role="tabpanel" className="px-1 pt-4 pb-1 sm:px-2">
            <CopyCommand key={way.id} command={way.command} prompt={way.prompt ?? "$"} className="bg-background" />
            <p className="mt-3 px-1 text-[13px] text-muted-foreground">{way.note}</p>
          </div>
        </div>
      </BlurFade>

      <BlurFade inView delay={0.15}>
        <p className="mx-auto mt-6 max-w-2xl text-center text-[13.5px] leading-relaxed text-muted-foreground">
          The installer refuses a binary whose sha256 is not the release's, and checks its build provenance when the GitHub CLI is signed in. Then, in your project,{" "}
          <code className="rounded bg-sunken px-1.5 py-0.5 font-mono text-[0.92em] text-foreground">hush start</code> finds your keys, gets them in, and asks whether an AI
          assistant will be near them.
        </p>
      </BlurFade>
    </section>
  );
}
