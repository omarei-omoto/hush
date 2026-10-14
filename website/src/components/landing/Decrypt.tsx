import { useEffect, useState } from "react";
import { useReducedMotion } from "motion/react";

import { cn } from "../../lib/utils";

/** What ciphertext looks like: the base64 a vault holds. */
const GLYPHS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const glyph = () => GLYPHS[Math.floor(Math.random() * GLYPHS.length)];

/** `text` with everything past `done` characters still scrambled. */
const scrambled = (text: string, done: number) =>
  [...text].map((c, i) => (c === " " || i < done ? c : glyph())).join("");

/**
 * Text that arrives as ciphertext and decrypts, left to right. The real text
 * holds the space, so nothing around it moves while it does; readers and
 * search engines get the real text throughout.
 */
export function Decrypt({ text, delay = 700, duration = 1300, className }: { text: string; delay?: number; duration?: number; className?: string }) {
  const reduce = useReducedMotion();
  const [shown, setShown] = useState<string | null>(null);

  useEffect(() => {
    if (reduce) return;
    let frame = 0;
    let start = 0;
    setShown(scrambled(text, 0));
    // Ciphertext churns while it waits, then gives way one character at a time.
    const churn = setInterval(() => setShown(scrambled(text, 0)), 70);
    const begin = setTimeout(() => {
      clearInterval(churn);
      const step = (now: number) => {
        start ||= now;
        const p = Math.min((now - start) / duration, 1);
        setShown(p < 1 ? scrambled(text, Math.floor(p * text.length)) : null);
        if (p < 1) frame = requestAnimationFrame(step);
      };
      frame = requestAnimationFrame(step);
    }, delay);
    return () => {
      clearInterval(churn);
      clearTimeout(begin);
      cancelAnimationFrame(frame);
    };
  }, [text, delay, duration, reduce]);

  return (
    <span className={cn("relative inline-block whitespace-nowrap", className)}>
      {/* Transparent rather than hidden, so a screen reader still reads it. */}
      <span className={shown === null ? undefined : "opacity-0"}>{text}</span>
      {shown !== null && (
        <span aria-hidden="true" className="absolute inset-0 overflow-hidden text-ok">
          {shown}
        </span>
      )}
    </span>
  );
}
