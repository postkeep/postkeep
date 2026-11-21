// Sätteri plugins for the docs Markdown and MDX. They keep the CSP intact (classes, never style
// attributes) and draw content in the design's components:
// - :::note and :::caution become an aside, with its kind's icon and its kind's word for screen readers;
// - fenced code becomes the dark code block, colored by lib/highlight.ts, with a copy button; a one-line value
//   (no language) is one row: the value, then Copy;
// - tables sit in a scroll box that a keyboard can reach, a column of numbers set right-aligned;
// - a text node is split at each email address (lib/highlight.ts's EMAIL), each between email_off comments, in its own pass.
import { defineHastPlugin, defineMdastPlugin } from "satteri";
import type { Element, ElementContent } from "hast";
import { t } from "./copy";
import { SITE } from "./data";
import { EMAIL, highlight } from "./highlight";
import { ICONS } from "./icons";

const ASIDE_ICON: Record<string, string> = { note: "file", tip: "check-circle", caution: "warning", danger: "error" };

export const asides = defineMdastPlugin({
  name: "postkeep-asides",
  containerDirective(node, ctx) {
    const kind = ASIDE_ICON[node.name] ? node.name : "note";
    ctx.setProperty(node, "data", { hName: "aside", hProperties: { className: ["aside", `aside--${kind}`], dataAside: kind } });
  },
  // Long inline code (env vars, URLs, paths, Rust paths) may break after "=", "/", "_", "(", "<", "::" and a "." before a
  // letter (<wbr>, which adds no text), so it never runs past the column, a table cell included, but never before its
  // first letter or digit ("/docs", ".env"); a part with a "?" is kept whole by markup (.nw), never by an inserted character.
  inlineCode(node, ctx) {
    const at = /(?<=[=_(<]|::)|(?<=\/)(?!\/)|(?<=\.)(?=[A-Za-z])/;
    if (!at.test(node.value)) return;
    const runs = node.value.split(at).reduce<string[]>((a, v) => (a.length && !/[\p{L}\p{N}]/u.test(a.at(-1)!) ? [...a.slice(0, -1), a.at(-1)! + v] : [...a, v]), []);
    const parts = runs.flatMap((v, i) => [...(i ? [{ type: "wbr", data: { hName: "wbr" }, children: [] }] : []), v.includes("?") ? { type: "nowrap", data: { hName: "span", hProperties: { className: ["nw"] } }, children: [{ type: "text", value: v }] } : { type: "text", value: v }]);
    ctx.replaceNode(node, { type: "breakableCode", data: { hName: "code" }, children: parts });
  },
});

const el = (tagName: string, properties: Element["properties"], children: ElementContent[] = []): Element => ({
  type: "element",
  tagName,
  properties,
  children,
});

const txt = (value: string): ElementContent => ({ type: "text", value });

function icon(name: string, cls = ""): Element {
  const parts = [...(ICONS[name] ?? "").matchAll(/<(\w+) ([^>]*)\/>/g)].map((m) =>
    el(m[1]!, Object.fromEntries([...m[2]!.matchAll(/([\w-]+)="([^"]*)"/g)].map((a) => [a[1]!, a[2]!]))),
  );
  return el("svg", { className: ["pk-icon", ...(cls ? [cls] : [])], viewBox: "0 0 24 24", ariaHidden: "true", focusable: "false" }, parts);
}

const textOf = (n: ElementContent): string =>
  n.type === "text" ? n.value : n.type === "element" ? n.children.map(textOf).join("") : "";

let codeId = 0;

function copyButton(of: string): Element {
  return el("button", { className: ["copy"], type: "button", dataCopy: of }, [
    icon("copy", "copy__ic"),
    icon("check", "copy__ok"),
    el("span", { className: ["copy__t"] }, [txt(t("home.install.copy"))]),
    el("span", { className: ["copy__done"] }, [txt(t("home.install.copied"))]),
  ]);
}

const ENT: Record<string, string> = { "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#39;": "'" };
const unesc = (s: string) => s.replace(/&(amp|lt|gt|quot|#39);/g, (m) => ENT[m]!);

/** lib/highlight.ts output (escaped text and flat <span class> runs) as hast. */
function spans(html: string): ElementContent[] {
  const out: ElementContent[] = [];
  let at = 0;
  for (const m of html.matchAll(/<span class="([\w-]+)"(?: title="([^"]*)")?>([^<]*)<\/span>/g)) {
    if (m.index > at) out.push(txt(unesc(html.slice(at, m.index))));
    out.push(el("span", { className: [m[1]!], ...(m[2] ? { title: unesc(m[2]) } : {}) }, [txt(unesc(m[3]!))]));
    at = m.index + m[0].length;
  }
  if (at < html.length) out.push(txt(unesc(html.slice(at))));
  return out;
}

const LANGS: Record<string, string> = { sh: "sh", bash: "sh", shell: "sh", console: "sh", json: "json" };

export const docsHast = defineHastPlugin({
  name: "postkeep-docs",
  element: [
    {
      filter: ["aside"],
      visit(node, ctx) {
        const kind = String((node.properties as Record<string, unknown>).dataAside ?? "");
        if (!kind) return;
        const label = (SITE.asides as Record<string, string>)[kind] ?? SITE.asides.note;
        ctx.prependChild(node, [icon(ASIDE_ICON[kind]!), el("strong", { className: ["vh"] }, [txt(`${label}: `)])]);
      },
    },
    {
      filter: ["pre"],
      visit(node, ctx) {
        const code = node.children.find((c): c is Element => c.type === "element" && c.tagName === "code");
        if (!code) return;
        const cls = ([] as unknown[]).concat((code.properties as Record<string, unknown>).className ?? []).map(String);
        const given = cls.find((c) => c.startsWith("language-"))?.slice("language-".length) ?? "";
        const text = code.children.map(textOf).join("").replace(/\n$/, "");
        const id = `doc-code-${++codeId}`;
        const lang = LANGS[given] ?? "text";
        const chip = given && given !== "text" ? el("span", { className: ["code__lang"] }, [txt(given)]) : null;
        const pre = el("pre", { className: ["code__pre"], id, tabindex: "0" }, [el("code", {}, spans(highlight(text, lang)))]);
        const row = !chip && !text.includes("\n");
        ctx.replaceNode(
          node,
          el("div", { className: ["code", "code--doc"] }, [
            el("div", { className: ["code__bar"] }, [row ? pre : (chip ?? el("span", {})), copyButton(id)]),
            ...(row ? [] : [pre]),
          ]),
        );
      },
    },
    {
      filter: ["table"],
      visit(node, ctx) {
        const rows = (tag: string) => node.children.filter((c): c is Element => c.type === "element" && c.tagName === tag).flatMap((s) => s.children.filter((r): r is Element => r.type === "element" && r.tagName === "tr"));
        const cells = (r: Element) => r.children.filter((c): c is Element => c.type === "element");
        const body = rows("tbody");
        const num = (i: number) => body.length > 0 && body.every((r) => /^[\d.,]+$/.test(textOf(cells(r)[i] ?? txt("")).trim()));
        const cols = new Set(cells([...rows("thead"), ...body][0] ?? el("tr", {})).map((_, i) => i).filter(num));
        for (const r of [...rows("thead"), ...body]) cells(r).forEach((c, i) => cols.has(i) && ctx.setProperty(c, "className", ["num"]));
        ctx.wrapNode(node, el("div", { className: ["tbl-scroll"], tabindex: "0" }));
      },
    },
  ],
});

// Splits a text node at every address it holds, each between two comments (satteri doesn't visit what it builds).
export const addresses = defineHastPlugin({
  name: "postkeep-addresses",
  text(node, ctx) {
    const parts = node.value.split(new RegExp(`(${EMAIL.source})`));
    if (parts.length === 1) return;
    const off = (value: string): ElementContent => ({ type: "comment", value });
    ctx.replaceNode(node, parts.flatMap((v, i) => (i % 2 ? [off("email_off"), txt(v), off("/email_off")] : v ? [txt(v)] : [])));
  },
});
