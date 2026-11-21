// The docs sidebar and pager: the groups follow the Getting started steps (docs.index.steps), each link is
// a copy slot, and the pager walks the sidebar in order. The pages come from src/content/docs/docs and
// src/content/repo (written from docs/ by scripts/docs.ts); pages the design doesn't list (EXTRA) go at the end
// of Reference under their own title. Every sidebar page must have its Markdown file, titled with its label, every
// Markdown file a place in the sidebar, and no two files one address.
import { getCollection, type CollectionEntry } from "astro:content";
import { count, items, slot, t } from "./copy";
import { docsPathOf } from "./links";

/** How many links each docs index step has, counted from the copy. */
export const STEP_LINKS = items("docs.index.steps").map((i) => count(`docs.index.steps[${i}].links`));
const steps = (i: number) => Array.from({ length: STEP_LINKS[i]! }, (_, k) => `docs.index.steps[${i}].links[${k}]`);
export const REFERENCE = items("docs.index.reference.links").map((k) => `docs.index.reference.links[${k}]`);

// Each step is a group with its links to whole pages: a link to a heading (a "#" in its `to`) is on a page the group
// already has.
const GROUPS: [string, string[]][] = [
  ...STEP_LINKS.map((_, i): [string, string[]] => [`docs.index.steps[${i}].title`, steps(i).filter((id) => !slot(id).to!.includes("#"))]),
  ["docs.index.reference.title", REFERENCE],
];

/** Docs pages the design has no slot for, by their path under /docs/. */
const EXTRA = ["embedding/", "providers/microsoft-admin-consent/"];

export type DocEntry = CollectionEntry<"docs"> | CollectionEntry<"repo">;

export interface SideItem {
  /** Path from the site root without the leading slash: "docs/webhooks/". */
  path: string;
  /** The copy slot whose text names the page, or null for an EXTRA page. */
  slot: string | null;
  label: string;
  /** The phone line of the label, when the slot has one. */
  mobile?: string | undefined;
  group: string;
  entry: DocEntry;
}

export interface SideGroup {
  title: string;
  items: SideItem[];
}

/** An entry's site path: deployment/index.md and deployment.md both give "docs/deployment/". */
const pathOf = (e: DocEntry) => `docs/${e.id.replace(/(^|\/)index$/, "")}/`.replace(/\/\/$/, "/");

let cache: SideGroup[] | null = null;

export async function sidebar(): Promise<SideGroup[]> {
  if (cache) return cache;
  const entries = new Map<string, DocEntry>();
  for (const e of [...(await getCollection("docs")), ...(await getCollection("repo"))]) {
    if (entries.has(pathOf(e))) throw new Error(`docs: two files give ${pathOf(e)}, in src/content/docs/docs and src/content/repo`);
    entries.set(pathOf(e), e);
  }
  const used = new Set<string>();
  const groups = GROUPS.map(([g, ids]) => ({
    title: t(g),
    items: ids.map((id): SideItem => {
      const path = docsPathOf(id);
      const entry = path ? entries.get(path) : undefined;
      if (!path || !entry) throw new Error(`docs: ${id} names ${path}, which has no file in src/content/docs/docs or docs/`);
      if (entry.data.title !== t(id)) throw new Error(`docs: ${path} is titled "${entry.data.title}", but ${id} says "${t(id)}"`);
      used.add(path);
      return { path, slot: id, label: t(id), mobile: slot(id).mobile, group: t(g), entry };
    }),
  }));
  const reference = groups[groups.length - 1]!;
  for (const p of EXTRA) {
    const path = `docs/${p}`;
    const entry = entries.get(path);
    if (!entry) throw new Error(`docs: ${path} is listed in EXTRA but has no file`);
    used.add(path);
    reference.items.push({ path, slot: null, label: entry.data.title, group: reference.title, entry });
  }
  const left = [...entries.keys()].filter((p) => !used.has(p));
  if (left.length) throw new Error(`docs: no sidebar place for ${left.join(", ")}`);
  cache = groups;
  return groups;
}

/** Every docs page in sidebar order, which the pager follows. */
export async function pages(): Promise<SideItem[]> {
  return (await sidebar()).flatMap((g) => g.items);
}
