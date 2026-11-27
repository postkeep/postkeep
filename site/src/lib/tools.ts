// The home's tool metadata: risk hints from the server's pinned tools/list and code spans from README.md.
import pin from "../../../crates/server/tests/pins/tools-list.json";

type Hints = { readOnlyHint?: boolean; destructiveHint?: boolean; openWorldHint?: boolean };
const TOOLS = new Map((pin.result.tools as { name: string; annotations?: Hints }[]).map((x) => [x.name, x.annotations ?? {}]));

/** The hints a tool carries, in the order the home shows them. */
export function hints(name: string): string[] {
  const a = TOOLS.get(name);
  if (!a) throw new Error(`Not a server tool: ${name}`);
  return (["readOnlyHint", "openWorldHint", "destructiveHint"] as const).filter((h) => a[h]);
}

/** The Markdown table whose first header cell is `head`. */
export const tableOf = (md: string, head: string) => md.split("\n\n").find((p) => p.trim().startsWith(`| ${head} |`));

/** The rows of a table keyed by the code name in their first cell. */
export const rowsOf = (table = "") =>
  new Map([...table.matchAll(/^\| `(\w+)` \| (.*) \|$/gm)].map((m) => [m[1]!, m[2]!]));

/** The canonical tool table, not the providers table elsewhere in the README. */
export function mcpToolTable(readme: string): string {
  const section = readme.split("\n## MCP tools\n")[1]?.split("\n## ")[0] ?? "";
  const table = tableOf(section, "Tool");
  if (!table) throw new Error("README.md is missing its MCP tools table");
  return table.trim();
}

/** Read the README once, then look up the code runs for each tool's description. */
export function toolCodeRuns(readme: string): (name: string) => string[] {
  const rows = rowsOf(mcpToolTable(readme));
  return (name) => {
    const desc = rows.get(name);
    if (desc === undefined) throw new Error(`Tool missing from README.md's MCP tools table: ${name}`);
    const runs = [...desc.matchAll(/`([^`]+)`/g)].map((m) => m[1]!.trim().replace(/\s+/g, " ").replace(/'/g, "’"));
    return [...new Set(runs)].sort((a, b) => b.length - a.length);
  };
}
