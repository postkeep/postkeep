// Code colouring: classes only (tk-*), never style attributes, so
// the CSP needs nothing inline. Shell gets commands, flags, variables, URLs and <placeholders>; JSON gets
// keys, strings and <placeholders>; {image} becomes the image name from site.json.
import { SITE } from "./data";

const ESC: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ESC[c]!);
// An email address, without the g flag, so no shared lastIndex skips a match: build a global copy or split on it.
export const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/;
// Each address between the comments that keep Cloudflare's email obfuscation off it, so it reads as written.
export const emailOff = (html: string) => html.replace(new RegExp(EMAIL, "g"), "<!--email_off-->$&<!--/email_off-->");

const SH_CMD = /^(\s*)(docker compose|docker run|docker|git clone|git|cd|cp|chmod|cargo build|cargo|export|\.\/target\/release\/postkeep)(?=\s|$)/;
const SH_TOK = /(\{image\})|(<[^>]+>)|(https?:\/\/[^\s\\]+)|((?:^|\s)--?[a-z][\w-]*)|(\b[A-Z][A-Z0-9_]{2,}(?==))|(\$PWD)|(\s\\$)|(&&|>)/g;

function shLine(line: string, cont: boolean): string {
  if (/^\s*#/.test(line)) return `<span class="tk-c">${esc(line)}</span>`;
  let out = "";
  let rest = line;
  const m = cont ? null : SH_CMD.exec(line);
  if (m) {
    out += esc(m[1]!) + `<span class="tk-k">${esc(m[2]!)}</span>`;
    rest = line.slice(m[0].length);
  }
  let last = 0;
  for (const t of rest.matchAll(SH_TOK)) {
    const [all, ph, angle, url, flag, env, pwd] = t;
    out += esc(rest.slice(last, t.index));
    if (ph) out += esc(SITE.image.name);
    else if (angle) out += `<span class="tk-a">${esc(angle)}</span>`;
    else if (url) out += `<span class="tk-s">${esc(url)}</span>`;
    else if (flag) out += `<span class="tk-f">${esc(flag)}</span>`;
    else if (env) out += `<span class="tk-v">${esc(env)}</span>`;
    else if (pwd) out += `<span class="tk-v">${esc(pwd)}</span>`;
    else out += `<span class="tk-o">${esc(all)}</span>`;
    last = t.index + all.length;
  }
  return out + esc(rest.slice(last));
}

export function highlight(text: string, lang: string): string {
  if (lang === "sh") {
    let cont = false;
    return text
      .split("\n")
      .map((line) => {
        const h = shLine(line, cont);
        cont = /\\$/.test(line);
        return h;
      })
      .join("\n");
  }
  if (lang === "json") {
    return esc(text).replace(/(&quot;(?:(?!&quot;).)*?&quot;)(\s*:)?/g, (_, s: string, colon?: string) =>
      colon ? `<span class="tk-v">${s}</span>${colon}` : `<span class="${s.includes("&lt;") ? "tk-a" : "tk-s"}">${s}</span>`,
    );
  }
  return esc(text).replace(/\{image\}/g, esc(SITE.image.name));
}

