/** Types for test/docs-site.test.ts. */
export declare const DEMO_REFUSAL: string;
export declare function demoPage(page: string, answers: Record<string, unknown>, at: string): string;
export declare function buildDemo(out: string): Promise<{ out: string; answers: Record<string, unknown> }>;
