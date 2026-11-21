// The agent app, mail provider and host logos in public/assets/logos/ (sources and terms in LOGO-SOURCES.md),
// each an unaltered file shown with <img>. A brand with a file per surface gives `light` (for light surfaces)
// and `dark`; the page's theme picks one.
const f = (src, w, h) => ({ src: `assets/logos/${src}`, w, h });
export const LOGOS = {
  claude: f("claude-icon.svg", 128, 128),
  openai: { light: f("openai-blossom-black.svg", 716, 716), dark: f("openai-blossom-white.svg", 716, 716) },
  grok: { light: f("grok-dark.svg", 1024, 1024), dark: f("grok-light.svg", 1024, 1024) },
  cursor: { light: f("cursor-cube-2d-light.svg", 467, 532), dark: f("cursor-cube-2d-dark.svg", 467, 532) },
  vscode: f("vscode.svg", 100, 100),
  icloud: { light: f("icloud-light.png", 180, 180), dark: f("icloud-dark.png", 180, 180) },
  gmail: f("gmail.svg", 192, 192),
  outlook: f("outlook-icon-fy26.svg", 48, 48),
  fastmail: f("fastmail-icon.png", 192, 192),
  yahoo: f("yahoo.png", 512, 512),
  github: { light: f("github-mark-black.svg", 98, 96), dark: f("github-mark-white.svg", 98, 96) },
  docker: { light: f("docker-mark-ocean-blue.svg", 340, 268), dark: f("docker-mark-white.svg", 340, 268) },
};

// The agent apps (home.works.apps[i]) and the mailboxes (home.works.boxes[i]) by their logo, in the copy's
// order, each mailbox with its setup guide; null is the own IMAP server, which has no brand. The home's
// install step and How it works, and the docs' provider table, all read these.
export const APPS = ["claude", "openai", "grok", "cursor", "vscode"];
export const BOXES = [
  { logo: "icloud", guide: "/docs/providers/icloud/" },
  { logo: "gmail", guide: "/docs/providers/google/" },
  { logo: "outlook", guide: "/docs/providers/microsoft/" },
  { logo: "fastmail", guide: "/docs/providers/fastmail/" },
  { logo: "yahoo", guide: "/docs/providers/yahoo/" },
  { logo: null, guide: "/docs/providers/imap/" },
];
