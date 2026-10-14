import { useState } from "react";
import { AnimatePresence, motion } from "motion/react";

import { cn } from "../../lib/utils";

/** A command to paste, with a button that copies it. */
export function CopyCommand({ command, className, prompt = "$" }: { command: string; className?: string; prompt?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* no clipboard here: the command is on screen to select */
    }
  };
  return (
    <div className={cn("group flex min-w-0 items-center gap-3 rounded-xl border border-border bg-card/80 py-2 pr-2 pl-4 font-mono text-[13px] shadow-sm backdrop-blur", className)}>
      <span className="select-none text-muted-foreground">{prompt}</span>
      <code className="min-w-0 flex-1 truncate text-left text-foreground">{command}</code>
      <button
        type="button"
        onClick={copy}
        aria-label={copied ? "Copied" : `Copy: ${command}`}
        className="relative grid size-8 shrink-0 place-items-center rounded-lg text-muted-foreground transition hover:bg-sunken hover:text-foreground"
      >
        <AnimatePresence mode="wait" initial={false}>
          {copied ? (
            <motion.svg key="ok" initial={{ scale: 0.5, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.5, opacity: 0 }} viewBox="0 0 24 24" className="size-4 text-ok" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M5 12.5l4.5 4.5L19 7.5" />
            </motion.svg>
          ) : (
            <motion.svg key="copy" initial={{ scale: 0.5, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.5, opacity: 0 }} viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <rect x="9" y="9" width="11" height="11" rx="2.5" />
              <path d="M5 15V6.5A2.5 2.5 0 0 1 7.5 4H15" />
            </motion.svg>
          )}
        </AnimatePresence>
      </button>
    </div>
  );
}
