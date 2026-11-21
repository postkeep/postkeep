// The home page's facts that follow the code and README.md, each tied to its source (bun run build
// first, then bun test checks/facts.test.ts):
//   1. the tools the home lists are exactly the server's, and the tools title counts them
//   2. every home slot that quotes README.md is README.md's words: the headline (the banner's alt text), the tool
//      descriptions, the mailboxes and agent apps, the install and self-host lines, and /compare/'s address line;
//      the tool reference's summary table is README.md's; docs/clients.md has a section per agent app, opening with
//      the home's line for it and linked from the docs index, and the one-mailbox note
//   3. the install snippets are docs/deployment.md's commands, and README.md's is its Docker Compose one; the
//      binary's Rust version and repository links are Cargo.toml's
//   4. the footer's independence line is README.md's, word for word
//   5. the crates panel names each crate in crates/, and its title counts them
//   6. the independence line names the owner of every logo the site shows, as src/lib/LOGO-SOURCES.md records it
//   7. the tool reference's parameter rows and destructive tools follow the tools pin
//   8. each app-password link in crates/mail/src/presets.rs is on its provider's page and in docs/clients.md
import { expect, test } from "bun:test";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { items, slot, snippet, t } from "../src/lib/copy";
import { SITE } from "../src/lib/data";
import { LOGOS } from "../src/lib/logos.js";

const ROOT = resolve(import.meta.dir, "../..");
const read = (path: string) => readFileSync(join(ROOT, path), "utf8");
const html = read("site/dist/index.html");
const readme = read("README.md");
/** Markdown as a visitor reads it: no backticks, no "([setup](…))" links, other links as their text, lines joined,
 *  and apostrophes curled as the site sets them. */
const plain = (md: string) =>
  md.replace(/`/g, "").replace(/'/g, "’").replace(/ ?\(\[[^\]]*\]\([^)]*\)\)/g, "").replace(/\[([^\]]*)\]\([^)]*\)/g, "$1").replace(/\s+/g, " ").trim();
/** The fenced sh blocks of a Markdown text, in order. */
const blocks = (md: string) => [...md.matchAll(/^```sh\n([\s\S]*?)\n```$/gm)].map((m) => m[1]!);
const section = (md: string, heading: string) => md.split(`\n## ${heading}\n`)[1]!.split("\n## ")[0]!;
/** The paragraph of a Markdown text that is the table whose first header cell is `head`. */
const tableOf = (md: string, head: string) => md.split("\n\n").find((p) => p.trim().startsWith(`| ${head} |`));
/** A table's rows whose first cell is a code name, as that name → the rest of the row, through `cell`. */
const rowsOf = (table = "", cell = (text: string) => text) =>
  new Map([...table.matchAll(/^\| `(\w+)` \| (.*) \|$/gm)].map((m) => [m[1]!, cell(m[2]!)]));

type Schema = { description: string; $ref?: string; oneOf?: { const: string; description: string }[] };
type Tool = { name: string; annotations?: { destructiveHint?: boolean }; inputSchema: { properties: Record<string, Schema>; $defs?: Record<string, Schema> } };
const tools = JSON.parse(read("crates/server/tests/pins/tools-list.json")).result.tools as Tool[];
const pinned = tools.map((x) => x.name);
const listed = [...html.matchAll(/<code class="[^"]*\bref__name">([^<]+)<\/code>/g)].map((m) => m[1]!);
const NUMBERS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve",
  "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen", "twenty"];

test("1. the tools the home lists are exactly the server's, and the tools title counts them", () => {
  expect([...listed].sort()).toEqual([...pinned].sort());
  const title = html.match(/<h2 class="h1 sec__h" id="tools-h">(\w+) tools/)![1]!.toLowerCase();
  const chip = `The tools title must count ${pinned.length}. README.md's banner shows "16 tools" too: when the count changes, redraw it from the brand files.`;
  expect(NUMBERS.indexOf(title), chip).toBe(pinned.length);
});

test("2. every home slot that quotes README.md is README.md's words", () => {
  // The tools table only: the providers table under it also has tool rows.
  const table = tableOf(section(readme, "MCP tools"), "Tool")!;
  const rows = rowsOf(table, plain);
  // The tool reference's summary table is this one, word for word.
  expect(tableOf(read("docs/reference/tools.md"), "Tool")).toBe(table.trim());
  for (let n = 0; n < pinned.length; n++) {
    const name = t(`home.tools[${n}].name`);
    expect({ name, desc: t(`home.tools[${n}].desc`) }).toEqual({ name, desc: rows.get(name)! });
  }
  // The Mailboxes table, row by row, and the paragraph under it.
  const boxes = [...section(readme, "Mailboxes").matchAll(/^\| (?!Mailbox |---)(.*?) \| (.*) \|$/gm)].map((m) => [m[1]!, plain(m[2]!)]);
  expect(boxes).toHaveLength(6);
  expect(boxes.map((_, i) => [t(`home.works.boxes[${i}].name`), t(`home.works.boxes[${i}].how`)])).toEqual(boxes);
  const mailboxes = section(readme, "Mailboxes").split("\n\n").filter((p) => p.trim() && !p.trim().startsWith("|"));
  expect(mailboxes.map(plain)).toEqual([t("home.works.boxes.footnote")]);
  // The agent apps, as Connect your agent app names them.
  const apps = plain(section(readme, "Connect your agent app")).match(/has the steps for (.*?)\./)![1]!.split(/, | and /);
  expect(apps).toHaveLength(5);
  expect(apps.map((_, i) => t(`home.works.apps[${i}].name`))).toEqual(apps);
  // docs/clients.md has their sections first, in that order, each opening with the home's line for the app (the
  // section goes on with ":" or ","; plain() keeps VS Code's *) and linked from the docs index; and the note.
  const guide = read("docs/clients.md");
  expect([...guide.matchAll(/^## (.*)$/gm)].slice(0, 5).map((m) => m[1])).toEqual(apps);
  apps.forEach((app, i) => {
    const opens = plain(section(guide, app)).replace(/\*/g, "").startsWith(t(`home.works.apps[${i}].how`).replace(/\.$/, ""));
    expect(opens, `docs/clients.md's ${app} section must open with home.works.apps[${i}].how`).toBe(true);
    const { text, to } = slot(`docs.index.steps[2].links[${i + 1}]`);
    expect({ text, to }).toEqual({ text: app, to: `/docs/clients/#${app.toLowerCase().replace(/ /g, "-")}` });
  });
  expect(plain(guide.replace(/^> /gm, ""))).toContain(t("home.works.boxes.footnote").match(/Each connection is one mailbox.*you want/)![0]);
  // Self-host's first five bullets: each title is the bold lead, each text the rest. The sixth is the README's own.
  const bullets = section(readme, "Self-host").split(/\n(?=- )/).filter((b) => b.startsWith("- **")).map((b) => plain(b).match(/^- \*\*(.*?)\.\*\* (.*)$/)!);
  expect(bullets).toHaveLength(6);
  const five = bullets.slice(0, 5);
  expect(five.map((_, i) => [t(`home.selfhost.points[${i}].title`), t(`home.selfhost.points[${i}].text`)])).toEqual(five.map((m) => [m[1]!, m[2]!]));
  // Lines quoted whole.
  const paragraphs = readme.split("\n\n").map(plain);
  expect(readme).toContain(`alt="${t("home.hero.headline")}"`);
  expect(paragraphs.some((p) => p.startsWith(t("home.install.needs")))).toBe(true);
  expect(paragraphs).toContain(`${t("compare.selfhost.connect")} ${t("home.install.connect.url")}.`);
  expect(paragraphs.some((p) => p.startsWith(t("home.tools.after")))).toBe(true);
});

test("3. install snippets follow the docs, and repository links and the Rust version follow Cargo.toml", () => {
  const fill = (id: string) => snippet(id).text.replaceAll("{image}", SITE.image.name);
  const deployment = read("docs/deployment.md");
  const first = (heading: string) => blocks(section(deployment, heading))[0]!;
  expect(fill("home.install.snippet")).toBe(first("Docker"));
  expect(fill("home.install.snippet.compose")).toBe(first("Docker Compose"));
  expect(fill("home.install.snippet.binary")).toBe(first("Plain binary"));
  expect(blocks(section(readme, "Install"))).toEqual([first("Docker Compose")]);
  const rust = read("Cargo.toml").match(/^rust-version = "([\d.]+)"$/m)![1]!;
  expect(slot("home.install.snippet.binary").text.split("\n")[0]).toBe(`# Rust ${rust} or newer`);
  const manifest = Bun.TOML.parse(read("Cargo.toml")) as { workspace: { package: { repository: string } } };
  const repository = manifest.workspace.package.repository;
  expect(SITE.source).toMatchObject({ web: repository, clone: `${repository}.git`, issues: `${repository}/issues`, releases: `${repository}/tags` });
  for (const path of ["", "/tags", `/blob/${SITE.source.branch}/CHANGELOG.md`, `/blob/${SITE.source.branch}/SECURITY.md`]) {
    expect(html).toContain(`href="${repository}${path}"`);
  }
  expect(read("site/dist/docs/index.html")).toContain(`href="${repository}/issues"`);
});

test("4. the footer's independence line is README.md's, word for word", () => {
  const line = plain(readme.split("\n---\n").at(-1)!);
  expect(line.startsWith("postkeep is an independent project.")).toBe(true);
  expect(t("footer.trademark")).toBe(line);
  expect(html.match(/<p class="ft__small ft__line">([^<]*)<\/p>/)?.[1]).toBe(line);
});

test("5. the crates panel names each crate in crates/, and its title counts them", () => {
  const crates = readdirSync(join(ROOT, "crates")).filter((d) => existsSync(join(ROOT, "crates", d, "Cargo.toml"))).sort();
  const names = items("home.mit.crates").map((i) => t(`home.mit.crates[${i}].name`));
  expect([...names].sort()).toEqual(crates);
  expect(NUMBERS.indexOf(t("home.mit.crates.title").match(/ (\w+) crates$/)![1]!)).toBe(crates.length);
});

test("6. the independence line names the owner of every logo the site shows", () => {
  const owners = /endorsed by (.+?)\./.exec(t("footer.trademark"))![1]!.split(/, | or /);
  const rows = read("site/src/lib/LOGO-SOURCES.md").split("\n").filter((l) => l.startsWith("| `"));
  for (const logo of Object.values(LOGOS).flatMap((l) => ("src" in l ? [l] : [l.light, l.dark]))) {
    const terms = rows.find((r) => r.includes(`\`${basename(logo.src)}\``))?.split(" | ")[3] ?? "";
    expect(owners.some((o) => terms.includes(o)), `${logo.src}: its LOGO-SOURCES.md Terms must name a company in footer.trademark`).toBe(true);
  }
});

test("7. the tool reference's parameter rows and destructive tools follow the tools pin", () => {
  const doc = read("docs/reference/tools.md");
  const marked = doc.match(/The tools marked `destructiveHint: true` are\s+([^.]+)\./)![1]!;
  expect([...marked.matchAll(/`(\w+)`/g)].map((m) => m[1]!).sort()).toEqual(tools.filter((x) => x.annotations?.destructiveHint === true).map((x) => x.name).sort());
  const unmarked = doc.match(/([^.]+) are not marked destructive:/)![1]!;
  for (const [, name] of unmarked.matchAll(/`(\w+)`/g)) expect(tools.find((x) => x.name === name)?.annotations?.destructiveHint, name).toBe(false);

  for (const { name, inputSchema: { properties, $defs } } of tools) {
    // A property reads as its description, then each value of an enum it refers to as "`value`: description".
    const values = (p: Schema) => ($defs?.[p.$ref?.split("/").at(-1) ?? ""]?.oneOf ?? []).map((v) => ` \`${v.const}\`: ${v.description}`);
    const pin = Object.entries(properties).map(([key, p]) => [key, (p.description + values(p).join("")).replace(/\s+/g, " ").trim()]);
    const heading = `\`${name}\``;
    const rows = doc.includes(`\n## ${heading}\n`) ? rowsOf(tableOf(section(doc, heading), "Parameter")) : new Map();
    expect(Object.fromEntries(rows), `docs/reference/tools.md's ${name} parameters`).toEqual(Object.fromEntries(pin));
  }
});

test("8. each app-password link in crates/mail/src/presets.rs is on its provider's page and in docs/clients.md", () => {
  const match = read("crates/mail/src/presets.rs").split("fn app_password_url")[1]!.split("\n    }\n")[0]!;
  const urls = [...match.matchAll(/"(https:[^"]+)"/g)].map((m) => m[1]!);
  // In the match's order: iCloud, Fastmail, Yahoo, Gmail.
  const pages = ["site/src/content/docs/docs/providers/icloud.mdx", "docs/providers/fastmail.md", "docs/providers/yahoo.md", "docs/providers/google.md"];
  expect(urls).toHaveLength(pages.length);
  const disconnect = tableOf(read("docs/clients.md"), "Mailbox");
  urls.forEach((url, i) => {
    expect(read(pages[i]!), `${pages[i]} must link ${url}`).toContain(`](${url})`);
    expect(disconnect, `docs/clients.md's Disconnect table must link ${url}`).toContain(`](${url})`);
  });
});
