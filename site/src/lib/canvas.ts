// The page canvas in each theme, read from the synced tokens (src/design/tokens.css: --bg-canvas in :root, and
// --dark-bg-canvas), for the browser's theme-color, so a new canvas in the brand book reaches the phone's bar.
import tokens from "../design/tokens.css?raw";

/** A token's value, following var() to the colour it names; its first declaration is the light one. */
function token(name: string): string {
  const v = new RegExp(`--${name}:\\s*([^;]+);`).exec(tokens)?.[1]?.trim();
  if (!v) throw new Error(`src/design/tokens.css has no --${name}`);
  const ref = /^var\(--([\w-]+)\)$/.exec(v);
  return ref ? token(ref[1]!) : v;
}

export const CANVAS = { light: token("bg-canvas"), dark: token("dark-bg-canvas") };
