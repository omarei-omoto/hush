import { AnimatedSpan, Terminal, TypingAnimation } from "../ui/terminal";
import { BlurFade } from "../ui/blur-fade";

/** A command, typed. */
const Cmd = ({ children }: { children: string }) => <TypingAnimation duration={38} className="text-[13px] text-foreground">{children}</TypingAnimation>;
/** What it printed: hush's own output, from a real run. */
const Out = ({ children, ok }: { children: React.ReactNode; ok?: boolean }) => (
  <AnimatedSpan className={`text-[13px] ${ok ? "text-ok" : "text-muted-foreground"}`}>{children}</AnimatedSpan>
);

const STEPS: [string, string][] = [
  ["hush init acme", "A vault in .hush/vault.json: ciphertext and public keys, safe to commit."],
  ["hush add .env --as Dev", "Your existing secrets, encrypted, as a set. Then delete the .env."],
  ["hush npm run dev", "The keys go into that one process, never onto disk. Its output is masked."],
  ["hush team add sam hush_pk_…", "Commit, and Sam can decrypt. No server, no invite email."],
  ["hush team rm sam", "Re-keys the vault, re-seals every value, and lists what to rotate."],
];

export function Commands() {
  return (
    <section className="relative border-y border-border bg-card/40">
      <div className="mx-auto grid max-w-6xl items-center gap-12 px-4 py-24 sm:px-6 sm:py-28 lg:grid-cols-[1fr_1.15fr]">
        <BlurFade inView className="min-w-0">
          <p className="text-[13px] font-semibold tracking-[0.12em] text-ok uppercase">In your terminal</p>
          <h2 className="mt-3 font-display text-[clamp(2rem,4.2vw,3.1rem)] leading-[1.05] font-semibold tracking-[-0.04em] text-balance">
            Five commands. Then it gets out of the way.
          </h2>
          <ol className="mt-8 space-y-4">
            {STEPS.map(([cmd, what]) => (
              <li key={cmd} className="grid grid-cols-[auto_1fr] gap-x-3">
                <span className="mt-1.5 size-1.5 rounded-full bg-ok" />
                <div>
                  <code className="font-mono text-[13.5px] font-medium">{cmd}</code>
                  <p className="mt-0.5 text-[14.5px] leading-relaxed text-ink-2">{what}</p>
                </div>
              </li>
            ))}
          </ol>
          <p className="mt-8 text-[14.5px] text-ink-2">
            Or skip all five: <code className="rounded bg-sunken px-1.5 py-0.5 font-mono text-[0.9em]">hush start</code> finds your keys, asks a few questions,
            and sets the project up — or{" "}
            <a href="/guide/setting-up/" className="font-medium text-foreground underline decoration-border-strong underline-offset-4 hover:decoration-foreground">
              let your coding agent do it
            </a>
            .
          </p>
        </BlurFade>

        <BlurFade inView delay={0.15} className="min-w-0">
          <Terminal title="~/code/acme — zsh" className="max-h-none max-w-none bg-card shadow-2xl">
            <Cmd>$ hush init acme</Cmd>
            <Out ok>✓ vault acme created at .hush/vault.json</Out>
            <Out>{"  This file is safe to commit — it holds only ciphertext and public keys."}</Out>
            <Cmd>$ hush add .env --as Dev</Cmd>
            <Out ok>✓ stored 2 secret(s) as Dev (dev) in this project</Out>
            <Cmd>$ hush npm run dev</Cmd>
            <Out>hush: using default, dev</Out>
            <Out>
              <span className="text-ink-2">
                connecting with <span className="rounded bg-ok-soft px-1 text-ok">[redacted:OPENAI_API_KEY]</span>
              </span>
            </Out>
            <Cmd>$ hush team add sam hush_pk_1xMq…</Cmd>
            <Out ok>✓ sam can now decrypt this vault</Out>
            <Out>{"  commit .hush/vault.json and they are in — no server, no invite email"}</Out>
            <Cmd>$ hush team rm sam</Cmd>
            <Out ok>✓ removed sam</Out>
            <Out>{"  new key generation 2; re-sealed 2 value(s)"}</Out>
          </Terminal>
        </BlurFade>
      </div>
    </section>
  );
}
