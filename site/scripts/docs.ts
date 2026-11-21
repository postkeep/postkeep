#!/usr/bin/env bun
// Writes the site's plain-Markdown docs pages from the repository's docs/ folder, the one copy of their text:
// every ../docs/**/*.md except ../docs/assets/** becomes src/content/repo/<same path>.md (a folder's README.md
// becomes its index.md), and that folder is emptied first. Edit docs/, never the output. For each file:
// - title: the first line's "# " heading, removed from the body;
// - description: the first sentence of the first paragraph that starts with a letter, "*" or a backtick (up to a
//   "." followed by a space, or the paragraph's end), with links as their text, backticks and "*" removed, and a
//   final ":" as ".";
// - links outside fenced code, resolved against the file's folder ("/x" against the repository's root), each to a
//   file or folder that exists in the repository: a .md file inside docs/ ("x.md#a") becomes /docs/<path>/#a,
//   without "index" or "README"; any other target becomes its file on GitHub (/tree/ for a folder); a link on
//   the site's origin becomes its path; "#a" and other absolute URLs stay;
// - a "> [!NOTE]" or "> [!TIP]" blockquote becomes :::note or :::tip, and [!IMPORTANT], [!WARNING] and
//   [!CAUTION] become :::caution, the quote marks removed, closed by ":::".
// It stops, naming the file, on a missing title or description, a link to no file, or a "> [!" left over.
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";
import { SITE } from "../src/lib/data";
import { repoFile } from "../src/lib/links";

const ROOT = resolve(import.meta.dir, "../..");
const DOCS = join(ROOT, "docs");
const OUT = resolve(import.meta.dir, "../src/content/repo");
const ASIDE: Record<string, string> = { NOTE: "note", TIP: "tip", IMPORTANT: "caution", WARNING: "caution", CAUTION: "caution" };

function fail(file: string, why: string): never {
  console.error(`docs: ${relative(ROOT, file)}: ${why}`);
  process.exit(1);
}

const files = (dir: string): string[] =>
  readdirSync(dir, { withFileTypes: true }).flatMap((d) => {
    const path = join(dir, d.name);
    if (d.isDirectory()) return path === join(DOCS, "assets") ? [] : files(path);
    return d.name.endsWith(".md") ? [path] : [];
  });

/** Fenced code, also indented under a list item. */
const FENCE = /^ *```[^\n]*\n[\s\S]*?^ *```$/gm;
/** Calls `edit` on each run of lines outside fenced code, and keeps the fences as they are. */
const outsideFences = (md: string, edit: (text: string) => string) =>
  md.split(new RegExp(`(${FENCE.source})`, "m")).map((part, i) => (i % 2 ? part : edit(part))).join("");

function link(file: string, target: string): string {
  if (target.startsWith(`${SITE.origin}/`)) return target.slice(SITE.origin.length);
  if (/^([a-z]+:|#)/i.test(target)) return target;
  const [path, anchor] = target.split("#") as [string, string | undefined];
  const hash = anchor === undefined ? "" : `#${anchor}`;
  const abs = path.startsWith("/") ? join(ROOT, path) : resolve(dirname(file), path);
  if (!abs.startsWith(`${ROOT}/`) || !existsSync(abs)) fail(file, `${target} is no file or folder in the repository`);
  if (abs.endsWith(".md") && abs.startsWith(`${DOCS}/`)) {
    const page = relative(DOCS, abs).replace(/\.md$/, "").replace(/(^|\/)(index|README)$/, "");
    return `/docs/${page ? `${page}/` : ""}${hash}`;
  }
  const rel = relative(ROOT, abs);
  if (existsSync(abs) && statSync(abs).isDirectory()) return `${SITE.source.web}/tree/${SITE.source.branch}/${rel}${hash}`;
  return `${repoFile(rel)}${hash}`;
}

/** GitHub alerts ("> [!NOTE]" and the quoted lines under it) as the site's asides. */
const asides = (text: string) =>
  text.replace(/^> \[!(\w+)\]\n((?:>.*\n?)*)/gm, (all, kind: string, quoted: string) => {
    const name = ASIDE[kind];
    if (!name) return all;
    const end = quoted.endsWith("\n") ? "\n" : "";
    return `:::${name}\n${quoted.replace(/^> ?/gm, "").replace(/\n$/, "")}\n:::${end}`;
  });

function description(file: string, body: string): string {
  const first = body.replace(FENCE, "").split(/\n\s*\n/).map((p) => p.trim()).find((p) => /^[\p{L}*`]/u.test(p));
  if (!first) fail(file, "no paragraph to take a description from");
  const text = first.replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1").replace(/[`*]/g, "").replace(/\s+/g, " ");
  const sentence = (/^.*?\.(?= )/.exec(text)?.[0] ?? text).replace(/:$/, ".");
  if (!sentence.trim()) fail(file, "an empty description");
  return sentence;
}

function convert(file: string): string {
  const md = readFileSync(file, "utf8");
  const head = /^# (.+)\n/.exec(md);
  if (!head) fail(file, 'no "# " title on its first line');
  const body = outsideFences(md.slice(head[0].length).replace(/^\n+/, ""), (text) =>
    asides(text).replace(/(\]\()([^)\s]+)\)/g, (_, open: string, target: string) => `${open}${link(file, target)})`),
  );
  if (body.replace(FENCE, "").includes("> [!")) fail(file, 'a "> [!" alert left over');
  return `---\ntitle: ${JSON.stringify(head[1]!.trim())}\ndescription: ${JSON.stringify(description(file, body))}\n---\n\n${body}`;
}

rmSync(OUT, { recursive: true, force: true });
for (const file of files(DOCS)) {
  const rel = relative(DOCS, file);
  const out = join(OUT, dirname(rel), basename(rel) === "README.md" ? "index.md" : basename(rel));
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, convert(file));
}
