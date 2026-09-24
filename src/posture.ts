/**
 * The security ladder.
 *
 * hush works at every rung, including the bottom one. That is deliberate: a
 * tool that refuses to run until you buy a YubiKey gets uninstalled, and the
 * person goes back to a plaintext `.env`. The lesson from passkeys and 2FA is
 * that adoption comes from making the next rung one command, showing it at a
 * moment that already has the user's attention, and then getting out of the way.
 *
 * So: never block, never nag on a timer, and weight the nudge by what the vault
 * actually holds. "Your key is a file on disk" is ignorable. "Five people can
 * read three live payment keys, and your key is a file on disk" is not.
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { Vault } from "./vault.ts";
import { loadIdentity, hushHome } from "./identity.ts";
import { biometryStatus } from "./biometry.ts";
import { identityPlugin, ageIdentityPath, ageAvailable } from "./age.ts";
import { loadPolicy } from "./mcp.ts";
import { globalVaultExists } from "./library.ts";

export type Rung = 0 | 1 | 2 | 3 | 4 | 5;

export interface Check {
  rung: Rung;
  id: string;
  /** Present tense, what this rung gives you. */
  label: string;
  pass: boolean;
  /** Shown when it fails: what to actually do. */
  command?: string;
  /** Shown when it fails: why it is worth doing. */
  why?: string;
  /**
   * The failure stated as a short noun phrase, for one-line nudges. Written out
   * per check rather than derived from `label`, because negating a label with
   * string surgery produces things like "plaintext .env left in the project is
   * not set up".
   */
  gap: string;
}

export interface Risk {
  /** 0 = nothing sensitive, 3 = this vault would ruin someone's week. */
  weight: number;
  reasons: string[];
}

export interface Posture {
  rung: Rung;
  name: string;
  checks: Check[];
  next: Check | null;
  risk: Risk;
}

const RUNG_NAMES: Record<Rung, string> = {
  0: "unprotected",
  1: "encrypted",
  2: "keychain-backed",
  3: "approved use",
  4: "biometric",
  5: "hardware-backed",
};

/** Key names that usually mean money, infrastructure, or customer data. */
const HIGH_VALUE = [
  /^STRIPE_(SECRET|LIVE)/i,
  /^AWS_SECRET_ACCESS_KEY$/i,
  /LIVE_KEY$/i,
  /^.*PRIVATE_KEY$/i,
  /^DATABASE_URL$/i,
  /^.*_PRODUCTION_.*$/i,
  /^TWILIO_AUTH_TOKEN$/i,
  /^GITHUB_TOKEN$/i,
  /^.*ROOT.*(TOKEN|KEY|PASSWORD)$/i,
  /SERVICE_ROLE_KEY$/i,
];

/**
 * Judge risk from names and shape only — never by decrypting. Reading values
 * here would make a hardware key prompt just to render a hint.
 */
export function assessRisk(vault: Vault): Risk {
  const reasons: string[] = [];
  let weight = 0;

  const allKeys = vault.envNames().flatMap((e) => vault.list(e).map((i) => i.key));
  const valuable = [...new Set(allKeys.filter((k) => HIGH_VALUE.some((re) => re.test(k))))];
  if (valuable.length) {
    weight += valuable.length >= 3 ? 2 : 1;
    reasons.push(
      `${valuable.length} high-value secret${valuable.length > 1 ? "s" : ""} (${valuable.slice(0, 3).join(", ")}${valuable.length > 3 ? "…" : ""})`,
    );
  }

  const members = vault.members().length;
  if (members > 1) {
    weight += members >= 5 ? 2 : 1;
    reasons.push(`${members} people can decrypt this vault`);
  }

  const prodEnvs = vault.envNames().filter((e) => /prod|live|production/i.test(e));
  if (prodEnvs.length) {
    weight += 1;
    reasons.push(`a production environment (${prodEnvs.join(", ")})`);
  }

  return { weight: Math.min(weight, 3), reasons };
}

export function assess(vault: Vault | null, hushDir: string | null, projectRoot: string | null): Posture {
  const id = loadIdentity();
  const policy = hushDir ? loadPolicy(hushDir) : null;
  const bio = biometryStatus();

  // Rung 5: the private key is non-extractable, held by hardware via an age plugin.
  const agePath = ageAvailable() ? ageIdentityPath() : null;
  const hardware = Boolean(agePath && identityPlugin(agePath));

  const strayEnv = projectRoot
    ? [".env", ".env.local", ".env.production"].filter((f) => existsSync(join(projectRoot, f)))
    : [];

  const checks: Check[] = [
    {
      rung: 1,
      id: "vault",
      gap: "your secrets are not encrypted",
      label: "secrets are encrypted at rest",
      // A folder that only uses library sets has no vault of its own, and its
      // secrets are every bit as encrypted — the library is a vault too. Without
      // this, the model the README recommends was nudged with "your secrets are
      // not encrypted".
      pass: Boolean(vault) || globalVaultExists(),
      command: "hush init",
      why: "a plaintext .env is readable by every process you run",
    },
    {
      rung: 1,
      id: "no-plaintext",
      gap: "a plaintext .env is still on disk",
      label: "no plaintext .env left in the project",
      pass: strayEnv.length === 0,
      // `hush import` needs --as; the old hint failed with "Give the set a name."
      // Keys already in the set are skipped, so this is safe to re-run.
      command: `hush add ${strayEnv[0] ?? ".env"} --as Dev && rm ${strayEnv[0] ?? ".env"}`,
      why: strayEnv.length ? `${strayEnv.join(", ")} still on disk, so the vault is not the only copy` : undefined,
    },
    {
      rung: 2,
      id: "keychain",
      gap: "your key is a loose file on disk",
      label: "your key is in the OS keychain, not a loose file",
      pass: Boolean(id && (id.source === "macOS Keychain" || hardware)),
      command: "hush id --create --force",
      why: "a file at ~/.hush/identity is copied by any backup or sync client",
    },
    {
      rung: 3,
      id: "approval",
      gap: "credentials can be used without your approval",
      label: "using a credential needs your approval",
      pass: Boolean(policy?.requireApproval.includes("run")),
      command: 'set "requireApproval": ["run","add","reveal","request"] in .hush/policy.json',
      why: "otherwise an agent can use your keys without you seeing it happen",
    },
    {
      rung: 4,
      id: "biometry",
      gap: "approval is a click, not a fingerprint",
      label: "approval needs your fingerprint, not a click",
      pass: policy?.biometry === "required" && bio.available,
      command: bio.available ? 'hush secure --biometry' : "hush biometry setup",
      why: "a click can be made by anything at your unlocked laptop; a fingerprint cannot",
    },
    {
      rung: 5,
      id: "hardware",
      gap: "your key can be copied off this machine",
      label: "your key cannot be copied off this machine",
      pass: hardware,
      command: "hush secure --hardware",
      why: "until this rung, anything running as you can read the vault without asking",
    },
  ];

  // Your rung is the highest one where everything up to it passes — a checklist,
  // so you cannot skip a step and claim the badge for a later one.
  let rung: Rung = 0;
  for (const r of [1, 2, 3, 4, 5] as Rung[]) {
    if (checks.filter((c) => c.rung <= r).every((c) => c.pass)) rung = r;
    else break;
  }

  const next = checks.find((c) => !c.pass) ?? null;
  return {
    rung,
    name: RUNG_NAMES[rung],
    checks,
    next,
    risk: vault ? assessRisk(vault) : { weight: 0, reasons: [] },
  };
}

// ---------------------------------------------------------------- nudging

interface NudgeState {
  lastNudge?: string;
  snoozedUntil?: string;
  lastRung?: number;
}

const stateFile = (): string => join(hushHome(), "state.json");

function readState(): NudgeState {
  try {
    return JSON.parse(readFileSync(stateFile(), "utf8")) as NudgeState;
  } catch {
    return {};
  }
}

function writeState(s: NudgeState): void {
  try {
    mkdirSync(hushHome(), { recursive: true, mode: 0o700 });
    writeFileSync(stateFile(), JSON.stringify(s, null, 2) + "\n");
  } catch {
    /* a nudge must never break a command */
  }
}

/**
 * Whether to show a nudge now. Higher risk means a shorter interval, but even
 * the worst case is once a day — this is a hint, not an alarm.
 */
export function shouldNudge(p: Posture): boolean {
  if (process.env.HUSH_NO_NUDGE || process.env.CI) return false;
  if (!p.next || p.rung === 5) return false;

  const state = readState();
  const now = Date.now();
  if (state.snoozedUntil && Date.parse(state.snoozedUntil) > now) return false;

  // Moving up a rung is worth acknowledging immediately.
  if (state.lastRung !== undefined && p.rung > state.lastRung) return true;

  const days = p.risk.weight >= 2 ? 1 : p.risk.weight === 1 ? 3 : 7;
  const last = state.lastNudge ? Date.parse(state.lastNudge) : 0;
  return now - last > days * 86_400_000;
}

export function recordNudge(p: Posture): void {
  writeState({ ...readState(), lastNudge: new Date().toISOString(), lastRung: p.rung });
}

export function snooze(days: number): void {
  writeState({
    ...readState(),
    snoozedUntil: new Date(Date.now() + days * 86_400_000).toISOString(),
  });
}
