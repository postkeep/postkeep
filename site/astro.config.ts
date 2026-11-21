import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import mdx from "@astrojs/mdx";
import { satteri } from "@astrojs/markdown-satteri";
import { defineConfig } from "astro/config";
import { HEADERS } from "./src/lib/csp";
import { addresses, asides, docsHast } from "./src/lib/markdown";
import own from "./src/data/site.json";

// Every built page, as its site path ("/", "/docs/webhooks/"), except those marked noindex (404.html).
function indexedPages(dist: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name === "index.html" && !/<meta name="robots" content="noindex"/.test(readFileSync(p, "utf8"))) {
        out.push(`/${relative(dist, p).replace(/index\.html$/, "")}`);
      }
    }
  };
  walk(dist);
  return out.sort();
}

export default defineConfig({
  site: own.origin,
  trailingSlash: "always",
  build: {
    // /docs/webhooks/ is docs/webhooks/index.html, the design's addresses.
    format: "directory",
    // The CSP allows no <style> element, so every stylesheet stays a file.
    inlineStylesheets: "never",
  },
  devToolbar: { enabled: false },
  markdown: {
    // Code is coloured by src/lib/markdown.ts with classes; Shiki would write style attributes.
    syntaxHighlight: false,
    processor: satteri({ features: { directive: true }, mdastPlugins: [asides], hastPlugins: [docsHast, addresses] }),
  },
  vite: {
    build: {
      // Nothing becomes a data: URL (img-src and font-src allow 'self' only), and the page's module stays a
      // file rather than an inline script.
      assetsInlineLimit: 0,
    },
  },
  integrations: [
    mdx(),
    {
      name: "postkeep-static-files",
      hooks: {
        "astro:build:done": ({ dir }) => {
          const dist = fileURLToPath(dir);
          writeFileSync(join(dist, "_headers"), HEADERS);
          const urls = indexedPages(dist).map((p) => `  <url><loc>${new URL(p, own.origin).href}</loc></url>`);
          writeFileSync(
            join(dist, "sitemap.xml"),
            `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join("\n")}\n</urlset>\n`,
          );
          writeFileSync(join(dist, "robots.txt"), `User-agent: *\nAllow: /\n\nSitemap: ${new URL("/sitemap.xml", own.origin).href}\n`);
        },
      },
    },
  ],
});
