// The page's one script, on static pages: the theme pill, the menus, code tabs, copy buttons, the skip link,
// the header's stuck state and the docs rail's mark. Every page reads in full without it. The theme changes at once.
const root = document.documentElement;

// ------------------------------------------------------------------ theme
const CHOICES = ["light", "dark", "system"] as const;
type Choice = (typeof CHOICES)[number];
const KEY = "postkeep-theme";
const device = window.matchMedia("(prefers-color-scheme: dark)");
const isChoice = (v: unknown): v is Choice => CHOICES.includes(v as Choice);

/** The saved pick; dark until the reader picks one. */
function saved(): Choice {
  let v: string | null = null;
  try {
    v = localStorage.getItem(KEY);
  } catch {
    /* storage blocked */
  }
  return isChoice(v) ? v : "dark";
}

let choice: Choice = isChoice(root.dataset.themeChoice) ? root.dataset.themeChoice : saved();

function applyTheme() {
  const theme = choice === "system" ? (device.matches ? "dark" : "light") : choice;
  root.dataset.theme = theme;
  root.dataset.themeChoice = choice;
  document.querySelectorAll<HTMLMetaElement>('meta[name="theme-color"]').forEach((m) => {
    m.content = m.dataset[theme] ?? m.content;
  });
  document.querySelectorAll<HTMLInputElement>("[data-theme-set]").forEach((r) => {
    r.checked = r.value === choice;
  });
}

function setChoice(next: string) {
  if (!isChoice(next)) return;
  choice = next;
  try {
    localStorage.setItem(KEY, next);
  } catch {
    /* storage blocked: the choice lasts for this page */
  }
  applyTheme();
}

device.addEventListener("change", () => {
  if (choice === "system") applyTheme();
});
window.addEventListener("storage", (e) => {
  if (e.key !== KEY && e.key !== null) return;
  choice = saved();
  applyTheme();
});
applyTheme();

// ------------------------------------------------------------------ behaviours
const live = document.getElementById("live");

function focusQuietly(el: HTMLElement) {
  if (!el.hasAttribute("tabindex")) el.setAttribute("tabindex", "-1");
  el.focus({ preventScroll: true });
}

function closeMenus(except?: Element) {
  document.querySelectorAll<HTMLDetailsElement>("details.menu[open]").forEach((d) => {
    if (d !== except) d.open = false;
  });
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.className = "vh";
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  }
}

function selectTab(tab: HTMLElement, focus: boolean) {
  const list = tab.closest('[role="tablist"]');
  if (!list) return;
  list.querySelectorAll<HTMLElement>('[role="tab"]').forEach((x) => {
    const on = x === tab;
    x.setAttribute("aria-selected", String(on));
    x.tabIndex = on ? 0 : -1;
    const panel = document.getElementById(x.getAttribute("aria-controls") ?? "");
    if (panel) panel.hidden = !on;
  });
  if (focus) tab.focus();
  // On narrow screens the tabs scroll sideways: bring the picked one wholly into the strip, without moving the page.
  const [t, l] = [tab.getBoundingClientRect(), list.getBoundingClientRect()];
  list.scrollLeft += Math.max(0, t.right - l.right) + Math.min(0, t.left - l.left);
}

const timers = new WeakMap<Element, number>();

document.addEventListener("click", async (e) => {
  const el = e.target as Element;
  const a = el.closest("a");
  // The skip link keeps the address as it is and moves focus to the content.
  if (a?.classList.contains("skip")) {
    const main = document.getElementById("main");
    if (main) {
      e.preventDefault();
      main.scrollIntoView({ block: "start" });
      focusQuietly(main);
    }
    return;
  }
  if (a?.getAttribute("href")?.includes("#")) closeMenus();

  const copy = el.closest<HTMLElement>("[data-copy]");
  if (copy) {
    // What the block shows: a command set over two lines on a narrow screen copies as shown.
    const pre = document.getElementById(copy.dataset.copy ?? "");
    if (pre && (await copyText(pre.innerText))) {
      copy.classList.add("is-done");
      if (live) {
        live.textContent = "";
        live.textContent = copy.querySelector(".copy__done")?.textContent ?? "";
      }
      clearTimeout(timers.get(copy));
      timers.set(copy, window.setTimeout(() => copy.classList.remove("is-done"), 2000));
    }
    return;
  }
  const tab = el.closest<HTMLElement>('[role="tab"]');
  if (tab) {
    selectTab(tab, false);
    return;
  }
  const open = document.querySelector("details.menu[open]");
  if (open && !open.contains(el)) (open as HTMLDetailsElement).open = false;
});

document.addEventListener("keydown", (e) => {
  const tab = (e.target as Element).closest?.<HTMLElement>('[role="tab"]');
  if (tab) {
    const tabs = [...(tab.closest('[role="tablist"]')?.querySelectorAll<HTMLElement>('[role="tab"]') ?? [])];
    const i = tabs.indexOf(tab);
    const go = ({ ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 } as Record<string, number>)[e.key];
    if (go !== undefined) {
      e.preventDefault();
      selectTab(tabs[(go + tabs.length) % tabs.length]!, true);
    }
  }
  if (e.key === "Escape") {
    const open = document.querySelector<HTMLDetailsElement>("details.menu[open]");
    if (open) {
      open.open = false;
      open.querySelector("summary")?.focus();
    }
  }
});

document.addEventListener(
  "toggle",
  (e) => {
    const d = e.target as Element;
    if (d.matches?.("details.menu") && (d as HTMLDetailsElement).open) closeMenus(d);
  },
  true,
);

document.addEventListener("change", (e) => {
  const input = e.target as HTMLInputElement;
  if (input.matches("[data-theme-set]")) setChoice(input.value);
});

// The header takes its ground and blur once the page scrolls under it. The docs rail marks the section being
// read: the last heading at or above the line a jump puts headings on, else the first; at the page's end, the
// one the address names if it is on screen, else the last. Scrolls, clicks and anchors all come through here.
const header = document.querySelector(".hd");
const rail = [...document.querySelectorAll<HTMLAnchorElement>(".rail__a")];
const heads = rail.map((a) => document.getElementById(decodeURIComponent(a.hash.slice(1))));
const px = (el: Element, prop: "scrollPaddingTop" | "scrollMarginTop") => parseFloat(getComputedStyle(el)[prop]) || 0;
function onScroll() {
  header?.classList.toggle("is-stuck", window.scrollY > 0);
  if (!rail.length) return;
  const line = px(root, "scrollPaddingTop") + 1;
  let at = Math.max(0, heads.findLastIndex((h) => h !== null && h.getBoundingClientRect().top <= line + px(h, "scrollMarginTop")));
  if (window.scrollY > 0 && window.scrollY + window.innerHeight >= root.scrollHeight - 1) {
    const named = rail.findIndex((a) => a.hash === location.hash);
    const box = heads[named]?.getBoundingClientRect();
    at = box && box.top < window.innerHeight && box.bottom > 0 ? named : rail.length - 1;
  }
  rail.forEach((a, i) => (i === at ? a.setAttribute("aria-current", "location") : a.removeAttribute("aria-current")));
}
window.addEventListener("scroll", onScroll, { passive: true });
window.addEventListener("hashchange", onScroll);
onScroll();
