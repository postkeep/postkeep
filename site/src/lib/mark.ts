// The postkeep mark as a path, for places that draw it in the text's colour (the agent window's chip). It is
// read from the synced favicon (public/favicon.svg, src/design/manifest.json), so a redrawn mark arrives with
// the next sync. The viewBox frames the glyph with the clear space the chip draws it with (1/51 of its height).
import favicon from "../../public/favicon.svg?raw";

const d = /<path[^>]* d="([^"]+)"/.exec(favicon)?.[1];
if (!d) throw new Error("public/favicon.svg has no mark path");

// The path's points (M, L, Q, H and V, absolute, as the brand files draw it) give its box.
const xs: number[] = [];
const ys: number[] = [];
for (const [, cmd, args] of d.matchAll(/([A-Za-z])([^A-Za-z]*)/g)) {
  const n = (args!.match(/-?\d*\.?\d+/g) ?? []).map(Number);
  if (cmd === "H") xs.push(...n);
  else if (cmd === "V") ys.push(...n);
  else if ("MLQ".includes(cmd!)) n.forEach((v, i) => (i % 2 ? ys : xs).push(v));
  else if (cmd !== "Z") throw new Error(`public/favicon.svg: mark path command ${cmd} isn't read here`);
}
const [x0, x1, y0, y1] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)];
const pad = (y1 - y0) / 51;
const r = (v: number) => Math.round(v * 100) / 100;

export const MARK = { d, viewBox: [x0 - pad, y0 - pad, x1 - x0 + 2 * pad, y1 - y0 + 2 * pad].map(r).join(" ") };
