// Where each link slot points. Pages of this site are root paths with a trailing slash ("/docs/webhooks/");
// a docs link's slot names its page in `to` (/docs/PAGE/#anchor). A link to a docs page or heading that
// doesn't exist fails check:dist.
import { SITE } from "./data";
import { slot } from "./copy";

export type Target = { href: string; ext?: boolean };

/** The in-site docs page a link slot points at ("docs/webhooks/"), or null. */
export function docsPathOf(id: string): string | null {
  const to = slot(id).to;
  return to ? to.split("#")[0]!.slice(1) : null;
}

// Pages of this site that link slots name without a docs path.
const PAGES: Record<string, string> = {
  "nav.links[0]": "/#agent",
  "nav.links[1]": "/#install",
  "nav.links[3]": "/compare/",
  "footer.columns[0].links[0]": "/#agent",
  "footer.columns[0].links[1]": "/#install",
  "footer.columns[0].links[3]": "/compare/",
  "404.primary": "/",
};
const SOURCE = ["nav.source", "home.hero.secondary", "home.mit.links[0]", "footer.columns[2].links[0]"];
const FILES: Record<string, string> = {
  "footer.columns[2].links[2]": "CHANGELOG.md",
  "footer.columns[2].links[5]": "SECURITY.md",
};
const CLOUD = ["nav.cloud", "home.cloud.button", "compare.cloud.button"];

/** A file in the source repository, on its web host. */
export const repoFile = (file: string) => `${SITE.source.web}/blob/${SITE.source.branch}/${file}`;

export function target(id: string): Target {
  slot(id);
  const src = SITE.source;
  if (SOURCE.includes(id)) return { href: src.web, ext: true };
  const file = FILES[id];
  if (file) return { href: repoFile(file), ext: true };
  if (id === "footer.columns[2].links[1]") return { href: src.releases, ext: true };
  if (id === "home.mit.links[1]") return { href: SITE.image.hub, ext: true };
  if (CLOUD.includes(id)) return { href: SITE.cloud.url, ext: true };
  const page = PAGES[id];
  if (page) return { href: page };
  const to = slot(id).to;
  if (!to) throw new Error(`No target for link slot ${id}`);
  return { href: to };
}
