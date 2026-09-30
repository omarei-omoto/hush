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
/**
 * `rotate` is where a person replaces the credential at the provider — the
 * page `hush exposed` and `hush team rm` point at. Checked to resolve on
 * 2026-09-30; a database URL has no such page (you change the password where
 * the database lives), so those have none.
 */
export const CATALOG: Record<string, { vars: string[]; label: string; rotate?: string }> = {
  fal: { vars: ["FAL_KEY"], label: "fal.ai", rotate: "https://fal.ai/dashboard/keys" },
  openai: { vars: ["OPENAI_API_KEY"], label: "OpenAI", rotate: "https://platform.openai.com/api-keys" },
  anthropic: { vars: ["ANTHROPIC_API_KEY"], label: "Anthropic", rotate: "https://platform.claude.com/settings/keys" },
  gemini: { vars: ["GEMINI_API_KEY"], label: "Google Gemini", rotate: "https://aistudio.google.com/app/apikey" },
  google: { vars: ["GOOGLE_API_KEY"], label: "Google", rotate: "https://console.cloud.google.com/apis/credentials" },
  openrouter: { vars: ["OPENROUTER_API_KEY"], label: "OpenRouter", rotate: "https://openrouter.ai/settings/keys" },
  groq: { vars: ["GROQ_API_KEY"], label: "Groq", rotate: "https://console.groq.com/keys" },
  mistral: { vars: ["MISTRAL_API_KEY"], label: "Mistral", rotate: "https://console.mistral.ai/api-keys" },
  replicate: { vars: ["REPLICATE_API_TOKEN"], label: "Replicate", rotate: "https://replicate.com/account/api-tokens" },
  huggingface: { vars: ["HF_TOKEN"], label: "Hugging Face", rotate: "https://huggingface.co/settings/tokens" },
  elevenlabs: { vars: ["ELEVENLABS_API_KEY"], label: "ElevenLabs", rotate: "https://elevenlabs.io/app/developers/api-keys" },
  deepgram: { vars: ["DEEPGRAM_API_KEY"], label: "Deepgram", rotate: "https://console.deepgram.com/" },
  stripe: { vars: ["STRIPE_SECRET_KEY"], label: "Stripe", rotate: "https://dashboard.stripe.com/apikeys" },
  github: { vars: ["GITHUB_TOKEN"], label: "GitHub", rotate: "https://github.com/settings/tokens" },
  vercel: { vars: ["VERCEL_TOKEN"], label: "Vercel", rotate: "https://vercel.com/account/settings/tokens" },
  cloudflare: { vars: ["CLOUDFLARE_API_TOKEN"], label: "Cloudflare", rotate: "https://dash.cloudflare.com/profile/api-tokens" },
  resend: { vars: ["RESEND_API_KEY"], label: "Resend", rotate: "https://resend.com/api-keys" },
  sendgrid: { vars: ["SENDGRID_API_KEY"], label: "SendGrid", rotate: "https://app.sendgrid.com/settings/api_keys" },
  twilio: { vars: ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"], label: "Twilio", rotate: "https://console.twilio.com/" },
  slack: { vars: ["SLACK_BOT_TOKEN"], label: "Slack", rotate: "https://api.slack.com/apps" },
  notion: { vars: ["NOTION_API_KEY"], label: "Notion", rotate: "https://www.notion.so/profile/integrations" },
  linear: { vars: ["LINEAR_API_KEY"], label: "Linear", rotate: "https://linear.app/settings/account/security" },
  figma: { vars: ["FIGMA_ACCESS_TOKEN"], label: "Figma", rotate: "https://www.figma.com/settings" },
  unsplash: { vars: ["UNSPLASH_ACCESS_KEY"], label: "Unsplash", rotate: "https://unsplash.com/oauth/applications" },
  supabase: {
    vars: ["SUPABASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY"],
    label: "Supabase",
    rotate: "https://supabase.com/dashboard/project/_/settings/api-keys",
  },
  aws: {
    vars: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"],
    label: "AWS",
    rotate: "https://console.aws.amazon.com/iam/home#/security_credentials",
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

/** Where to replace the credential a variable holds, when hush knows. */
export function rotationUrl(varName: string): string | null {
  const service = serviceForVar(varName);
  return service ? (CATALOG[service].rotate ?? null) : null;
}
