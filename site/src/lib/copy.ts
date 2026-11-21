// Copy lookups. Every word on a page comes from a copy.json slot; a missing slot id throws, so a typo fails
// the build instead of shipping. Lists are counted from the slots, so a page never keeps its own count.
import { copy, SITE } from "./data";

export interface Slot {
  n: string;
  text: string;
  mobile?: string;
  kind?: "code" | "link";
  lang?: string;
  /** A link slot's docs page, as the deck names it (/docs/PAGE/#anchor). */
  to?: string;
}

const slots = copy.slots as Record<string, Slot>;

export function slot(id: string): Slot {
  const s = slots[id];
  if (!s) throw new Error(`Missing copy slot: ${id}`);
  return s;
}

const ids = Object.keys(slots);

/** How many items a list has in copy.json: `${list}[0]…`, `${list}[1]…`, up to the first missing index. */
export function count(list: string): number {
  let n = 0;
  while (ids.some((k) => k.startsWith(`${list}[${n}]`))) n++;
  return n;
}

/** A list's item indices, 0 to count(list) − 1. */
export const items = (list: string): number[] => Array.from({ length: count(list) }, (_, i) => i);

/** A list kept beside the copy (logos, icons, colours), item for item with a copy list; a length that differs
 *  from the copy's fails the build. */
export function pair<T>(list: string, extra: readonly T[]): readonly T[] {
  const n = count(list);
  if (extra.length !== n) throw new Error(`${list} has ${n} items in copy.json, but ${extra.length} are kept beside it`);
  return extra;
}

/** The desktop line, for headings, labels and attributes. */
export const t = (id: string): string => slot(id).text;

/** A code snippet: {repo} filled from Cargo.toml; {image} is filled where the snippet is drawn. */
export function snippet(id: string): { text: string; lang: string } {
  const s = slot(id);
  return { text: s.text.replaceAll("{repo}", SITE.source.clone), lang: s.lang ?? "text" };
}

/** A template with its {key}s filled by name; a key without a value fails the build. */
export const fill = (format: string, values: Record<string, string | number>) =>
  format.replace(/\{(\w+)\}/g, (_, key: string) => {
    if (!(key in values)) throw new Error(`No value for {${key}} in "${format}"`);
    return String(values[key]);
  });

/** A page's title in the site's format ("Cloud or self-host · postkeep"); docs pages use the docs format. */
export const pageTitle = (page: string, docs = false) => fill(docs ? SITE.docsTitle : SITE.title, { page, name: SITE.name });
