/** Types for test/docs-site.test.ts. */
export declare const REPO: string;
export declare function pageSources(dir?: string): string[];
export declare function slugOf(src: string): string;
export declare const urlOf: (slug: string) => string;
export declare function convert(md: string, src: string, opts: { published: Set<string>; branch?: string; dir?: string }): { title: string; body: string };
export declare function buildContent(site: string, opts?: { dir?: string; branch?: string; siteUrl?: string; now?: number }): { src: string; slug: string; file: string }[];
