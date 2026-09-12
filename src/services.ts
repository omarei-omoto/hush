/**
 * Services and accounts.
 *
 * A vault holds more than one key for the same service: your personal fal
 * account, your company's fal account, a client's fal account. So a secret is
 * addressed by (service, account), and you choose the account per service when
 * you run something:
 *
 *     hush run --with fal:acme --with gemini:team -- ./build.sh
 *
 * Under the hood an account is just a scope name with a slash in it —
 * "fal/acme" — stored in the same map as plain environments ("default",
 * "prod"). That keeps one storage shape and one crypto path.
 */

/** Which env vars a service needs, so `hush add fal` knows what to prompt for. */
export const CATALOG: Record<string, { vars: string[]; label: string }> = {
  fal: { vars: ["FAL_KEY"], label: "fal.ai" },
  openai: { vars: ["OPENAI_API_KEY"], label: "OpenAI" },
  anthropic: { vars: ["ANTHROPIC_API_KEY"], label: "Anthropic" },
  gemini: { vars: ["GEMINI_API_KEY"], label: "Google Gemini" },
  google: { vars: ["GOOGLE_API_KEY"], label: "Google" },
  openrouter: { vars: ["OPENROUTER_API_KEY"], label: "OpenRouter" },
  groq: { vars: ["GROQ_API_KEY"], label: "Groq" },
  mistral: { vars: ["MISTRAL_API_KEY"], label: "Mistral" },
  replicate: { vars: ["REPLICATE_API_TOKEN"], label: "Replicate" },
  huggingface: { vars: ["HF_TOKEN"], label: "Hugging Face" },
  elevenlabs: { vars: ["ELEVENLABS_API_KEY"], label: "ElevenLabs" },
  deepgram: { vars: ["DEEPGRAM_API_KEY"], label: "Deepgram" },
  stripe: { vars: ["STRIPE_SECRET_KEY"], label: "Stripe" },
  github: { vars: ["GITHUB_TOKEN"], label: "GitHub" },
  vercel: { vars: ["VERCEL_TOKEN"], label: "Vercel" },
  cloudflare: { vars: ["CLOUDFLARE_API_TOKEN"], label: "Cloudflare" },
  resend: { vars: ["RESEND_API_KEY"], label: "Resend" },
  sendgrid: { vars: ["SENDGRID_API_KEY"], label: "SendGrid" },
  twilio: { vars: ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"], label: "Twilio" },
  slack: { vars: ["SLACK_BOT_TOKEN"], label: "Slack" },
  notion: { vars: ["NOTION_API_KEY"], label: "Notion" },
  linear: { vars: ["LINEAR_API_KEY"], label: "Linear" },
  figma: { vars: ["FIGMA_ACCESS_TOKEN"], label: "Figma" },
  unsplash: { vars: ["UNSPLASH_ACCESS_KEY"], label: "Unsplash" },
  supabase: {
    vars: ["SUPABASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY"],
    label: "Supabase",
  },
  aws: {
    vars: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"],
    label: "AWS",
  },
  postgres: { vars: ["DATABASE_URL"], label: "Postgres" },
  mongodb: { vars: ["MONGODB_URI"], label: "MongoDB" },
  redis: { vars: ["REDIS_URL"], label: "Redis" },
  pinecone: { vars: ["PINECONE_API_KEY"], label: "Pinecone" },
};

export const SCOPE_SEP = "/";

/**
 * The name a set gets when someone creates one "for a service" — fal +
 * account "acme" is the set named "fal/acme". This is the one function that
 * needs to know the "/" convention, so the CLI and MCP surfaces that create
 * such a set never have to encode it themselves.
 */
export const setNameFor = (service: string, account: string): string =>
  `${service}${SCOPE_SEP}${account}`;


export const knownVars = (service: string): string[] =>
  CATALOG[service.toLowerCase()]?.vars ?? [];

export const serviceLabel = (service: string): string =>
  CATALOG[service.toLowerCase()]?.label ?? service;

/** Best-guess service for an env var name, used to suggest `hush add`. */
export function serviceForVar(varName: string): string | null {
  for (const [service, def] of Object.entries(CATALOG)) {
    if (def.vars.includes(varName)) return service;
  }
  return null;
}

/**
 * CLI name -> service, so "set up wrangler" can find the Cloudflare token
 * without the user having to know which variable it authenticates with.
 */
export const TOOL_HINTS: Record<string, string> = {
  genmedia: "fal",
  fal: "fal",
  openai: "openai",
  claude: "anthropic",
  anthropic: "anthropic",
  gemini: "gemini",
  replicate: "replicate",
  elevenlabs: "elevenlabs",
  gh: "github",
  git: "github",
  stripe: "stripe",
  vercel: "vercel",
  wrangler: "cloudflare",
  supabase: "supabase",
  aws: "aws",
  psql: "postgres",
  mongosh: "mongodb",
  "redis-cli": "redis",
  twilio: "twilio",
  resend: "resend",
  hf: "huggingface",
};

/** Which service a command most likely needs. */
export function serviceForTool(tool: string): string | null {
  const base = tool.split("/").pop()!.replace(/\.(js|mjs|py|sh)$/, "").toLowerCase();
  return TOOL_HINTS[base] ?? (CATALOG[base] ? base : null);
}
