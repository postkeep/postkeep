// Docs search. Loads /docs/search.json once, on the first keystroke, and lists the pages whose title,
// headings or text contain every word typed, best matches first. The count is announced politely.
interface Item {
  url: string;
  title: string;
  group: string;
  headings: string[];
  text: string;
}

let index: Promise<Item[]> | null = null;
const load = (): Promise<Item[]> =>
  (index ??= fetch("/docs/search.json")
    .then((r) => (r.ok ? (r.json() as Promise<Item[]>) : []))
    .catch(() => []));

function score(item: Item, words: string[]): number {
  const title = item.title.toLowerCase();
  const heads = item.headings.join(" ").toLowerCase();
  const text = item.text.toLowerCase();
  let s = 0;
  for (const w of words) {
    if (title.includes(w)) s += 10;
    else if (heads.includes(w)) s += 4;
    else if (text.includes(w)) s += 1;
    else return 0;
  }
  return s;
}

function snippet(item: Item, word: string): string {
  const at = item.text.toLowerCase().indexOf(word);
  if (at < 0) return item.group;
  const from = Math.max(0, at - 40);
  return `${from ? "…" : ""}${item.text.slice(from, at + 80).trim()}…`;
}

function wire(box: HTMLElement) {
  const input = box.querySelector<HTMLInputElement>("input");
  const list = box.querySelector<HTMLUListElement>(".dsearch__list");
  const count = box.querySelector<HTMLElement>(".dsearch__n");
  if (!input || !list || !count) return;
  const say = (n: number) =>
    (n === 0 ? box.dataset.none : n === 1 ? box.dataset.one : box.dataset.many)?.replace("{n}", String(n)) ?? "";

  let run = 0;
  input.addEventListener("input", async () => {
    const q = input.value.trim().toLowerCase();
    const mine = ++run;
    if (q.length < 2) {
      list.hidden = true;
      list.replaceChildren();
      count.textContent = "";
      return;
    }
    const items = await load();
    if (mine !== run) return;
    const words = q.split(/\s+/);
    const hits = items
      .map((it) => ({ it, s: score(it, words) }))
      .filter((h) => h.s > 0)
      .sort((a, b) => b.s - a.s)
      .slice(0, 8);
    list.replaceChildren(
      ...hits.map(({ it }) => {
        const li = document.createElement("li");
        const a = document.createElement("a");
        a.className = "dsearch__a";
        a.href = it.url;
        const name = document.createElement("span");
        name.className = "dsearch__t";
        name.textContent = it.title;
        const sub = document.createElement("span");
        sub.className = "dsearch__s";
        sub.textContent = snippet(it, words[0]!);
        a.append(name, sub);
        li.append(a);
        return li;
      }),
    );
    list.hidden = hits.length === 0;
    count.textContent = say(hits.length);
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && input.value) {
      e.stopPropagation();
      input.value = "";
      input.dispatchEvent(new Event("input"));
    }
    if (e.key === "ArrowDown" && !list.hidden) {
      e.preventDefault();
      list.querySelector<HTMLAnchorElement>("a")?.focus();
    }
  });
  list.addEventListener("keydown", (e) => {
    const links = [...list.querySelectorAll<HTMLAnchorElement>("a")];
    const i = links.indexOf(document.activeElement as HTMLAnchorElement);
    if (e.key === "ArrowDown" && i < links.length - 1) {
      e.preventDefault();
      links[i + 1]!.focus();
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      (i > 0 ? links[i - 1]! : input).focus();
    }
  });
}

document.querySelectorAll<HTMLElement>("[data-search]").forEach(wire);
