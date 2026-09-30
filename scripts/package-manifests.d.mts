/** Types for test/distribution.test.ts. */
export declare function parseSums(text: string): Record<string, string>;
export declare function homebrewFormula(version: string, sums: Record<string, string>): string;
export declare function scoopManifest(version: string, sums: Record<string, string>): string;
export declare function wingetManifests(version: string, sums: Record<string, string>): Record<string, string>;
export declare function writeManifests(version: string, sumsText: string, out: string): void;
