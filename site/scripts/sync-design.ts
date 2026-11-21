#!/usr/bin/env bun
// Copies the brand's files (the brand book and the web fonts in the brand source) into this site, byte for byte.
//
//   bun scripts/sync-design.ts          copy every file listed below and write src/design/manifest.json
//   bun scripts/sync-design.ts --check  fail if a copied file differs from its source
//
// DESIGN_SRC points at a checkout of the brand source; it has no default. The source is only read, never written.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";

const ROOT = resolve(import.meta.dir, "..");
const SRC = resolve(process.env.DESIGN_SRC || fail("DESIGN_SRC is not set: point it at a checkout of the brand source"));
const CHECK = process.argv.includes("--check");
const MANIFEST = "src/design/manifest.json";
const BOOK = "brand/book";

const ENTRIES: [from: string, to: string][] = [
  [`${BOOK}/tokens.css`, "src/design/tokens.css"],
  ...["favicon.svg", "favicon.ico", "apple-touch-icon.png"].map((f): [string, string] => [`${BOOK}/assets/favicon/postkeep/${f}`, `public/${f}`]),
  ...["kelp", "reversed"].map((v): [string, string] => [`${BOOK}/assets/logo/lockup-horizontal-postkeep-${v}.svg`, `public/assets/lockup-${v}.svg`]),
  [`${BOOK}/assets/social/og-postkeep-dev-1200x630.png`, "public/assets/og-postkeep-dev-1200x630.png"],
  ...["InstrumentSans-latin.woff2", "InstrumentSans-OFL.txt", "JetBrainsMono-latin.woff2", "JetBrainsMono-OFL.txt"].map(
    (f): [string, string] => [`site/public/fonts/${f}`, `public/fonts/${f}`],
  ),
];

function fail(why: string): never {
  console.error(why);
  process.exit(2);
}
if (!existsSync(join(SRC, BOOK, "tokens.css"))) fail(`DESIGN_SRC ${SRC} is not the brand source (no ${BOOK}/tokens.css)`);

const sha = (buf: Buffer) => new Bun.CryptoHasher("sha256").update(buf).digest("hex");
const problems: string[] = [];
const files: Record<string, string> = {};
for (const [from, to] of ENTRIES) {
  const want = readFileSync(join(SRC, from));
  const dest = join(ROOT, to);
  files[to] = sha(want);
  if (!CHECK) {
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, want);
  } else if (!existsSync(dest)) problems.push(`${to} is missing`);
  else if (!readFileSync(dest).equals(want)) problems.push(`${to} differs from ${from}`);
}

let commit: string | null = null;
try {
  commit = execFileSync("git", ["-C", SRC, "rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || null;
} catch {
  /* not a git checkout */
}

if (CHECK) {
  const old = existsSync(join(ROOT, MANIFEST)) ? JSON.parse(readFileSync(join(ROOT, MANIFEST), "utf8")) : null;
  if (!old) problems.push(`${MANIFEST} is missing`);
  else for (const k of Object.keys(old.files).filter((k) => !(k in files))) problems.push(`${MANIFEST} lists ${k}, which the sync no longer copies`);
} else {
  const about = "Files copied from the brand source at this commit by scripts/sync-design.ts. Do not edit them here.";
  writeFileSync(join(ROOT, MANIFEST), JSON.stringify({ about, commit, files }, null, 2) + "\n");
}

if (problems.length) {
  console.error(problems.map((p) => `FAIL ${p}`).join("\n"));
  process.exit(1);
}
console.log(`design: ${ENTRIES.length} files from ${relative(ROOT, SRC) || SRC}${CHECK ? " match the source" : " copied"}; commit ${commit ?? "unknown"}`);
