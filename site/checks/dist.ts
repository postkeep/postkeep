// Static checks over the built site in dist/ (run `bun run build` first):
//
// - every page carries the CSP meta tag (src/lib/csp.ts), and dist/_headers carries the CSP header
// - the policy allows only 'self', 'none' and Cloudflare Web Analytics' script host (script-src only), and the
//   referrer policy is same-origin in the header and in every page's meta tag
// - nothing inline: no <script> without src, no <style> element, no style attribute, no on* handler,
//   no javascript: URL
// - nothing from another origin: scripts, stylesheets, icons, images and CSS url() are same-origin paths
//   that exist in dist/
// - links: every internal href and dist/_redirects target resolves to a built page or file, and each #fragment is on it
// - titles: the home page's is M1; every other page's is "<page> · postkeep", docs pages
//   "<page> · postkeep docs" (src/data/site.json); og:site_name is the site's name; every page but the 404
//   has a canonical URL on the site's origin that matches its own address and og:url
// - dist/sitemap.xml lists exactly the pages that are not noindex, and robots.txt points to it
// - every email address in a page's text stands alone between <!--email_off--> comments, and no link is mailto:
//
//   bun checks/dist.ts
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { CSP_HEADER, CSP_META, HEADERS } from "../src/lib/csp";
import { EMAIL } from "../src/lib/highlight";
import copy from "../src/data/copy.json";
import own from "../src/data/site.json";

const DIST = join(import.meta.dir, "..", "dist");
const problems: string[] = [];
const fail = (s: string) => problems.push(s);

if (!existsSync(DIST)) {
  console.error("dist/ is missing: run bun run build first");
  process.exit(2);
}

function walk(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

const files = walk(DIST);
const html = files.filter((f) => f.endsWith(".html"));

/** The site path a built file answers: dist/docs/webhooks/index.html is /docs/webhooks/. */
const pathOf = (f: string) => `/${relative(DIST, f).replace(/index\.html$/, "")}`;

/** The file the host serves for a site path, or null. */
function resolve(path: string): string | null {
  const p = join(DIST, decodeURIComponent(path));
  if (existsSync(p) && statSync(p).isFile()) return p;
  if (path.endsWith("/") && existsSync(join(p, "index.html"))) return join(p, "index.html");
  return null;
}

interface Page {
  file: string;
  path: string;
  csp: string[];
  referrer: string[];
  ids: Set<string>;
  loads: string[];
  links: string[];
  inline: string[];
  title: string;
  meta: Record<string, string>;
  canonical: string | null;
  noindex: boolean;
}

async function read(file: string): Promise<Page> {
  const page: Page = { file: relative(DIST, file), path: pathOf(file), csp: [], referrer: [], ids: new Set(), loads: [], links: [], inline: [], title: "", meta: {}, canonical: null, noindex: false };
  let inScript = false;
  let inTitle = false;
  await new HTMLRewriter()
    .on("*", {
      element(el) {
        const id = el.getAttribute("id");
        if (id) page.ids.add(id);
        if (el.getAttribute("style") !== null) page.inline.push(`style attribute on <${el.tagName}>`);
        for (const [name, value] of el.attributes) {
          if (/^on/i.test(name)) page.inline.push(`${name} handler on <${el.tagName}>`);
          if (/^\s*javascript:/i.test(value)) page.inline.push(`javascript: URL on <${el.tagName}>`);
        }
      },
    })
    .on("meta", {
      element(el) {
        if (el.getAttribute("http-equiv")?.toLowerCase() === "content-security-policy") page.csp.push(el.getAttribute("content") ?? "");
        if (el.getAttribute("name")?.toLowerCase() === "referrer") page.referrer.push(el.getAttribute("content") ?? "");
        const key = el.getAttribute("property") ?? el.getAttribute("name");
        if (key) page.meta[key] = el.getAttribute("content") ?? "";
        if (key === "robots" && /noindex/.test(el.getAttribute("content") ?? "")) page.noindex = true;
      },
    })
    .on("script", {
      element(el) {
        const src = el.getAttribute("src");
        if (src) page.loads.push(src);
        else {
          inScript = true;
          page.inline.push("<script> without src");
        }
      },
    })
    .on("style", { element() { page.inline.push("<style> element"); } })
    .on("link", {
      element(el) {
        const rel = el.getAttribute("rel") ?? "";
        const href = el.getAttribute("href") ?? "";
        if (rel === "canonical") page.canonical = href;
        else if (href) page.loads.push(href);
      },
    })
    .on("img, source", { element(el) { const s = el.getAttribute("src"); if (s) page.loads.push(s); } })
    .on("a", { element(el) { const h = el.getAttribute("href"); if (h !== null) page.links.push(h); } })
    .on("title", {
      element() { inTitle = true; },
      text(t) { if (inTitle) page.title += t.text; if (t.lastInTextNode) inTitle = false; },
    })
    .transform(new Response(readFileSync(file)))
    .text();
  void inScript;
  page.title = page.title.replace(/&amp;/g, "&").trim();
  return page;
}

const pages = await Promise.all(html.map(read));
const byPath = new Map(pages.map((p) => [p.path, p]));

// ------------------------------------------------------------------ CSP and inline content
const BEACON = "https://static.cloudflareinsights.com";
/** The policy's invariants, whatever its text: no empty or repeated directive (a browser keeps the first), no source but 'self', 'none' and the beacon's host in script-src (so no *, unsafe-*, data:, blob: or http:), and the directives default-src doesn't cover. */
function policyProblems(csp: string): string[] {
  const out: string[] = [];
  const dirs = new Map<string, string>();
  for (const d of csp.split(";")) {
    const [name = "", ...sources] = d.trim().split(/\s+/);
    const key = name.toLowerCase();
    if (!key) out.push("an empty directive");
    else if (dirs.has(key)) out.push(`${key} appears twice`);
    else dirs.set(key, sources.join(" "));
    for (const s of sources) if (!["'self'", "'none'"].includes(s) && !(key === "script-src" && s === BEACON)) out.push(`${key} allows ${s}`);
  }
  for (const [name, value] of Object.entries({ "default-src": "'none'", "connect-src": "'self'", "base-uri": "'none'", "form-action": "'none'" })) if (dirs.get(name) !== value) out.push(`${name} is not ${value}`);
  return out;
}
const headers = existsSync(join(DIST, "_headers")) ? readFileSync(join(DIST, "_headers"), "utf8") : "";
if (headers !== HEADERS) fail("_headers: differs from HEADERS in src/lib/csp.ts");
const all = headers.split("\n").filter((l) => /^\s*(content-security-policy|referrer-policy)\s*:/i.test(l));
const first = headers.split("\n\n")[0]!.split("\n");
if (all.length !== 2 || !first.includes(`  Content-Security-Policy: ${CSP_HEADER}`) || !first.includes("  Referrer-Policy: same-origin")) fail("_headers: the /* block needs exactly one CSP header and one Referrer-Policy: same-origin (Cloudflare Web Analytics needs the Referer header)");
if (/set-cookie/i.test(headers)) fail("_headers: sets a cookie");
for (const problem of policyProblems(CSP_HEADER)) fail(`src/lib/csp.ts: ${problem}`);
if (CSP_HEADER !== `${CSP_META}; frame-ancestors 'none'`) fail("src/lib/csp.ts: CSP_HEADER adds more than frame-ancestors 'none' to CSP_META");
for (const p of pages) {
  if (p.csp.length !== 1 || p.csp[0] !== CSP_META) fail(`${p.file}: CSP meta tag missing or different from src/lib/csp.ts`);
  if (p.referrer.length !== 1 || p.referrer[0] !== "same-origin") fail(`${p.file}: needs exactly one referrer meta tag, same-origin`);
  for (const i of new Set(p.inline)) fail(`${p.file}: ${i}`);
}

// ------------------------------------------------------------------ loads: same origin, and present
const sameOrigin = (u: string) => u.startsWith("/") && !u.startsWith("//");
for (const p of pages) {
  for (const u of p.loads) {
    if (!sameOrigin(u)) fail(`${p.file}: loads ${u} from another origin or by a relative path`);
    else if (!resolve(u.split(/[?#]/)[0]!)) fail(`${p.file}: loads ${u}, which is not in dist/`);
  }
}
for (const css of files.filter((f) => f.endsWith(".css"))) {
  const text = readFileSync(css, "utf8");
  for (const m of text.matchAll(/url\(\s*["']?([^"')]+)["']?\s*\)/g)) {
    const u = m[1]!;
    if (u.startsWith("data:") || u.startsWith("#")) continue;
    if (!sameOrigin(u)) fail(`${relative(DIST, css)}: url(${u}) is not a same-origin path`);
    else if (!resolve(u.split(/[?#]/)[0]!)) fail(`${relative(DIST, css)}: url(${u}) is not in dist/`);
  }
  if (/@import\s/.test(text)) fail(`${relative(DIST, css)}: @import`);
}

// ------------------------------------------------------------------ links and fragments
const external = new Set<string>();
for (const p of pages) {
  for (const href of p.links) {
    if (/^mailto:/i.test(href)) fail(`${p.file}: mailto link ${href}, whose address Cloudflare would hide: set the address as code`);
    if (/^(https?:|mailto:)/.test(href)) {
      external.add(href);
      continue;
    }
    const [path = "", frag] = href.split("#");
    const target = path === "" ? p : (() => {
      if (!path.startsWith("/")) {
        fail(`${p.file}: relative link ${href}`);
        return null;
      }
      const f = resolve(path);
      if (!f) {
        fail(`${p.file}: link to ${href}, which is not in dist/`);
        return null;
      }
      return byPath.get(pathOf(f)) ?? null;
    })();
    if (frag && target && !target.ids.has(decodeURIComponent(frag))) fail(`${p.file}: link to ${href}: no #${frag} on ${target.file}`);
  }
}
// Each redirect's target, as a link: "<from> <to> <status>" per line.
for (const line of readFileSync(join(DIST, "_redirects"), "utf8").split("\n").filter((l) => l.trim() && !l.startsWith("#"))) {
  const [from, to = ""] = line.trim().split(/\s+/);
  const [path = "", frag] = to.split("#");
  const f = resolve(path);
  const target = f ? byPath.get(pathOf(f)) : undefined;
  if (!target || (frag && !target.ids.has(decodeURIComponent(frag)))) fail(`_redirects: ${from} goes to ${to}, which is not in dist/`);
}

// ------------------------------------------------------------------ titles, canonical and Open Graph
const slots = copy.slots as Record<string, { text: string }>;
const homeTitle = slots["meta.home.title"]!.text;
const titleRx = (format: string) => new RegExp(`^.+ ${format.replace("{page}", "").replace("{name}", own.name).trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`);
for (const p of pages) {
  if (p.path === "/") {
    if (p.title !== homeTitle) fail(`${p.file}: title "${p.title}", expected M1 "${homeTitle}"`);
  } else {
    const docs = p.path.startsWith("/docs/");
    const format = docs ? own.docsTitle : own.title;
    if (!titleRx(format).test(p.title)) fail(`${p.file}: title "${p.title}" does not follow "${format}"`);
    if (!docs && p.path !== "/404.html" && p.meta["og:title"] !== p.title) fail(`${p.file}: og:title differs from the title`);
  }
  if (p.meta["og:site_name"] !== own.name) fail(`${p.file}: og:site_name is "${p.meta["og:site_name"] ?? ""}"`);
  if (!p.meta["description"]) fail(`${p.file}: no meta description`);
  if (!p.meta["og:image"]?.startsWith(own.origin)) fail(`${p.file}: og:image is not on ${own.origin}`);
  if (p.noindex) {
    if (p.canonical) fail(`${p.file}: noindex page has a canonical URL`);
  } else {
    const want = new URL(p.path, own.origin).href;
    if (p.canonical !== want) fail(`${p.file}: canonical ${p.canonical ?? "missing"}, expected ${want}`);
    if (p.meta["og:url"] !== want) fail(`${p.file}: og:url ${p.meta["og:url"] ?? "missing"}, expected ${want}`);
  }
}
if (!byPath.get("/404.html")?.noindex) fail("404.html: missing or not noindex");

// ------------------------------------------------------------------ sitemap and robots
const sitemap = existsSync(join(DIST, "sitemap.xml")) ? readFileSync(join(DIST, "sitemap.xml"), "utf8") : "";
const listed = new Set([...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]!));
const indexed = new Set(pages.filter((p) => !p.noindex).map((p) => new URL(p.path, own.origin).href));
for (const u of indexed) if (!listed.has(u)) fail(`sitemap.xml: ${u} is missing`);
for (const u of listed) if (!indexed.has(u)) fail(`sitemap.xml: lists ${u}, which is not an indexed page`);
const robots = existsSync(join(DIST, "robots.txt")) ? readFileSync(join(DIST, "robots.txt"), "utf8") : "";
if (!robots.includes(`Sitemap: ${new URL("/sitemap.xml", own.origin).href}`)) fail("robots.txt: no Sitemap line");

// ------------------------------------------------------------------ email addresses, which Cloudflare hides unless email_off
const alone = new RegExp(`^${EMAIL.source}$`);
let addresses = 0;
for (const f of html) {
  const parts = readFileSync(f, "utf8").split(/(<[^>]*>)/);
  for (let i = 0; i < parts.length; i += 2) {
    if (!EMAIL.test(parts[i]!)) continue;
    addresses++;
    if (!alone.test(parts[i]!) || parts[i - 1] !== "<!--email_off-->" || parts[i + 1] !== "<!--/email_off-->")
      fail(`${relative(DIST, f)}: "${parts[i]!.trim().slice(0, 80)}" holds an address outside <!--email_off--> comments: Markdown pages get them from lib/markdown.ts; a component, or an MDX page through a component, renders the address with emailOff() from lib/highlight.ts`);
  }
}
if (!addresses) fail("no page holds an email address: the address pattern in lib/highlight.ts no longer matches the demo addresses");

if (problems.length) {
  console.error(problems.map((p) => `FAIL ${p}`).join("\n"));
  console.error(`check:dist: ${problems.length} problems in ${pages.length} pages`);
  process.exit(1);
}
console.log(`check:dist: ${pages.length} pages, ${files.length} files, ${external.size} external links, ${addresses} addresses; ok`);
