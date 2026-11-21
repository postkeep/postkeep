// The server's MCP tools as the pinned tools/list answer gives them (crates/server/tests/pins), for the
// risk hints the home shows beside each tool.
import pin from "../../../crates/server/tests/pins/tools-list.json";

type Hints = { readOnlyHint?: boolean; destructiveHint?: boolean; openWorldHint?: boolean };
const TOOLS = new Map((pin.result.tools as { name: string; annotations?: Hints }[]).map((x) => [x.name, x.annotations ?? {}]));

/** The hints a tool carries, in the order the home shows them. */
export function hints(name: string): string[] {
  const a = TOOLS.get(name);
  if (!a) throw new Error(`Not a server tool: ${name}`);
  return (["readOnlyHint", "openWorldHint", "destructiveHint"] as const).filter((h) => a[h]);
}
