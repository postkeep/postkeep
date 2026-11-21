// The Content Security Policy the design ships: everything from this origin, nothing inline (no inline
// scripts, no <style>, no style attributes), nothing from another origin. Pages carry it in a meta tag; the
// build also writes it to dist/_headers as an HTTP header, where frame-ancestors works too.
export const CSP_META = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join("; ");

export const CSP_HEADER = `${CSP_META}; frame-ancestors 'none'`;

/** Headers for every path, in the _headers format Cloudflare Pages reads. */
export const HEADERS = [
  "/*",
  `  Content-Security-Policy: ${CSP_HEADER}`,
  "  X-Content-Type-Options: nosniff",
  "  Referrer-Policy: no-referrer",
  "  X-Frame-Options: DENY",
  "  Permissions-Policy: camera=(), microphone=(), geolocation=()",
  "",
  "/_astro/*",
  "  Cache-Control: public, max-age=31536000, immutable",
  "",
  "/fonts/*",
  "  Cache-Control: public, max-age=604800",
  "",
].join("\n");
