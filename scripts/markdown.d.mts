/** Types for test/docs-site.test.ts. */
export declare const slugify: (text: string) => string;
export declare function inline(text: string, opts?: { link?: (href: string) => string }): string;
export declare function render(md: string, opts?: { link?: (href: string) => string; ids?: Map<string, number> }): string;
