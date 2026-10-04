// tryhush.dev. The pages come from the repository's Markdown, written into
// src/content/docs by ../scripts/build-docs.mjs (`npm run build` runs it first).
import { readFileSync } from "node:fs";
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

const SITE = "https://tryhush.dev";
const sidebar = JSON.parse(readFileSync(new URL("./src/sidebar.json", import.meta.url), "utf8"));

export default defineConfig({
  site: SITE,
  integrations: [
    starlight({
      title: "hush",
      description: "Envelope-encrypted team secrets your AI agent can use but never read.",
      logo: { light: "./src/assets/logo-light.svg", dark: "./src/assets/logo-dark.svg", replacesTitle: true },
      favicon: "/favicon.svg",
      social: [{ icon: "github", label: "GitHub", href: "https://github.com/omarei-omoto/hush" }],
      sidebar,
      customCss: ["./src/styles/hush.css"],
      head: [
        { tag: "meta", attrs: { property: "og:image", content: `${SITE}/assets/social-preview.jpg` } },
        { tag: "meta", attrs: { name: "twitter:card", content: "summary_large_image" } },
      ],
      expressiveCode: { themes: ["github-dark", "github-light"] },
    }),
  ],
});
