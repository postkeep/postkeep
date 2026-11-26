# postkeep site

The open-source postkeep website, served at `https://postkeep.dev`: the home page, the docs under `/docs/`,
Cloud or self-host at `/compare/`, and a 404 page. Built with Astro, TypeScript and Bun into plain files in
`dist/`. Every page reads in full without JavaScript.

## Commands

From this directory, with the [Bun](https://bun.sh) version pinned by `packageManager` in `package.json`:

```sh
bun install --frozen-lockfile --ignore-scripts
bun run dev            # Astro dev server
bun run build          # static site in dist/
bun run preview        # serve dist/
bun run check          # types, build, facts test, content and dist (what a pull request should pass)
bun run check:types    # astro check and tsc
bun run check:content  # forbidden words in the build
bun run check:dist     # CSP, nothing inline or external, links and anchors, titles, sitemap, email addresses
bun run sync-design    # copy the brand's files again (see below)
bun run check:design   # fail if a copied brand file has drifted
```

## Deploying

`.github/workflows/main.yml` builds and deploys the site when a push to `main` changes a
`site-deploy` input in `.github/paths`, or on a hand dispatch from `main`. `build-site` uses
SHA-256-verified Bun and a frozen install with lifecycle scripts disabled. It checks that
`dist/` contains only regular files and directories, with no `_worker.js`, then uploads it
as an artifact. It does not receive deployment credentials.

`deploy-site` installs Wrangler from the separate `deploy/bun.lock`, also with lifecycle
scripts disabled, downloads the artifact, and repeats the static check. Only the final
Wrangler step receives Cloudflare credentials. It deploys the artifact to the Pages project
named by the `CLOUDFLARE_PAGES_PROJECT` variable.

The build writes `dist/_headers` (the CSP and the other security headers, and long caching for `/_astro/`
and `/fonts/`), `dist/sitemap.xml` (every page that is not `noindex`) and `dist/robots.txt`. Pages are
directories (`/docs/webhooks/` is `docs/webhooks/index.html`); the host serves `404.html` with status 404
for anything else.

## Design source

The look follows the postkeep brand book (v4). Its files come from the brand source, copied byte for byte by
`scripts/sync-design.ts`: the book's tokens (colors, type, space, radii, shadows; dark by `data-theme`), the favicon
set, the postkeep lockups, the postkeep.dev social card, and the web fonts (Instrument Sans and
JetBrains Mono, WOFF2, Latin) with their OFL texts. The script's list names each file and where it goes.

`DESIGN_SRC` points at a checkout of the brand source; it has no default. `bun run sync-design` copies the files
again and records the source commit and a SHA-256 per file in `src/design/manifest.json`; `bun run check:design`
fails if a file has drifted.

Everything else is the site's own: the pages and components, the stylesheets in `src/styles/` (on the
book's tokens), the words in `src/data/copy.json` and the settings in `src/data/site.json` (the origin,
the title formats, where links go). The icons are Feather's (`src/lib/icons.ts`, MIT, notice in
`public/licenses/`); the agent app, mail provider and host logos are in `public/assets/logos/`, with
their sources and terms in `src/lib/LOGO-SOURCES.md`. The home's tool hints come from the same pinned
tools list the facts test reads. The site is dark until the reader picks a theme.

## Content rules

- Every word on a page comes from a slot in `src/data/copy.json`, through `src/lib/copy.ts`. A missing
  slot fails the build.
- Every address comes from `src/data/site.json`, the repository in `Cargo.toml`, or a slot's docs path,
  through `src/lib/data.ts` and `src/lib/links.ts`. A sidebar slot naming a missing page fails the build;
  any link to a missing page or heading fails
  `check:dist`.
- Titles: the home page uses M1; every other page is `<page> · postkeep` and docs pages
  `<page> · postkeep docs`, from the formats in `src/data/site.json`.
- No names of people and no real email addresses: examples use `alice@example.com` and
  `mail.example.com`.
- The console on /compare/ is a picture of postkeep Cloud's console in its own words and design: it changes when
  they do, not only when the product's code does.

## Docs

- The docs pages are one page per file at `/docs/<path>/`. The repository's `docs/` is the one source of
  every plain-Markdown page, written to `src/content/repo/` by `scripts/docs.ts` before `dev`, `build` and
  `check:types` (its header comment says what it converts). Edit `docs/`, never the output; restart `dev`
  to see a change.
- `src/content/docs/docs/` keeps the site's own pages built from components (Quickstart, Mail providers
  and iCloud Mail), which link to `docs/` rather than copy it.
- `src/lib/docs.ts` builds the sidebar from the docs index steps in the copy deck. The sidebar label is
  the page's title; pages the design has no slot for (Embedding) go at the end of Reference. The build
  fails if a sidebar page has no file or another title, a file has no place in the sidebar, or two files
  give one address.
- `src/lib/markdown.ts` adds Sätteri plugins: `:::note` and `:::caution` become an aside, long inline
  code may break after `=` and `/`, fenced code becomes the dark code block with a copy button (colored
  by `src/lib/highlight.ts` with classes; Shiki is off because it writes style attributes), tables
  scroll in their own box, and every email address sits between `<!--email_off-->` comments, so Cloudflare
  leaves it as written. An MDX page renders an address through a component that uses `emailOff()`.
- MDX files import `Steps`, `LinkCard`, `CardGrid`, `ProviderTable` and `RecipeTabs` from `~/components/docs/`.
- `/docs/` is the Getting started page. `/docs/search.json` holds each page's title, headings
  and text; the search field at the top of the sidebar loads it on the first keystroke. Without
  JavaScript the field is hidden and the sidebar does the job.

## Checks

| Script | What it checks |
| --- | --- |
| `check:types` | `astro check` and `tsc --noEmit` |
| `check:content` | the built pages hold no forbidden word (stored as SHA-256 digests) and no glued separators |
| `check:dist` | the CSP meta tag on every page and the header in `dist/_headers`; no inline script, `<style>`, style attribute, event handler or `javascript:` URL; every script, stylesheet, image, icon and CSS `url()` is a same-origin file in `dist/`; every internal link, `#fragment` and `_redirects` target resolves; titles follow the formats in `src/data/site.json`, with `og:site_name`, a description, `og:image` on the origin, and a canonical URL and `og:url` matching each indexed page; the sitemap lists exactly the indexed pages and `robots.txt` points to it; every email address in a page's text stands alone between `<!--email_off-->` comments, and no link is `mailto:` |
| `facts.test.ts` | after the build: the home lists exactly the tools in `crates/server/tests/pins/tools-list.json` and its tools title counts them; every home and /compare/ slot that quotes `README.md` (the headline, the tool descriptions, the mailboxes and agent apps, the install and self-host lines, /compare/'s address line) is its words; `docs/clients.md` has a section per agent app, opening with the home's line for it and linked from the docs index; the install snippets are the commands in `docs/deployment.md`, and `README.md`'s is its Docker Compose one, with the Rust version and repository links from `Cargo.toml`; `docs/reference/tools.md`'s summary table is `README.md`'s, its parameter rows match the pin's descriptions, and the tools it names as destructive or not destructive match the pin's hints; the footer's independence line is `README.md`'s; it names the owner of every logo, as `src/lib/LOGO-SOURCES.md` records it; each app-password link in `crates/mail/src/presets.rs` is on its provider's page and in `docs/clients.md` |
| `check:design` | the copied brand files match their source; for maintainers with a checkout of the brand source in `DESIGN_SRC`, so not part of `bun run check` |

`bun run check` runs types, build, the facts test, content and dist.

## Security headers

`src/lib/csp.ts` holds the Content Security Policy: everything from this origin, nothing inline (no inline
scripts, no `<style>`, no style attributes). Each page carries it in a meta tag, and `dist/_headers` sends
it as a header with `frame-ancestors 'none'`. The theme is set before the first paint by
`public/js/theme-init.js`, a file rather than an inline script. Nothing sets a cookie: the theme choice
stays in local storage.
