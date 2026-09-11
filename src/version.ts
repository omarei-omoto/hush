/**
 * The one place the version is written.
 *
 * It was stated in three: src/cli.ts, src/mcp.ts and package.json. Nothing kept
 * them together, so `hush --version` and the version the MCP server reports to
 * a client could quietly disagree with what was actually published.
 */
export const VERSION = "0.1.1";
