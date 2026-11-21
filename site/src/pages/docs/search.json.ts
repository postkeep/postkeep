// The docs search index: each page's address, title, section headings and plain text, which
// src/scripts/search.ts fetches the first time someone types in the search field.
import type { APIRoute } from "astro";
import { pages } from "../../lib/docs";

const plain = (md: string) =>
  md
    .replace(/^import .*$/gm, "")
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/^:::\w*$/gm, "")
    .replace(/[#*_`>|]/g, " ")
    .replace(/\s+/g, " ")
    .trim();

export const GET: APIRoute = async () => {
  const items = (await pages()).map((p) => ({
    url: `/${p.path}`,
    title: p.label,
    group: p.group,
    headings: [...(p.entry.body ?? "").matchAll(/^#{2,3} (.+)$/gm)].map((m) => m[1]!.replace(/[`*_]/g, "")),
    text: plain(p.entry.body ?? ""),
  }));
  return new Response(JSON.stringify(items), { headers: { "Content-Type": "application/json" } });
};
