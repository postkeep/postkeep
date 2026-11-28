// The Content Security Policy the design ships: everything from this origin, nothing inline (no inline
// scripts, no <style>, no style attributes), nothing from another origin except Cloudflare Web Analytics'
// beacon script (https://static.cloudflareinsights.com), which Cloudflare injects on postkeep.dev and the
// privacy note names; it reports to this origin's /cdn-cgi/rum. Pages carry the policy in a meta tag; the
// build also writes it to dist/_headers as an HTTP header, where frame-ancestors works too.
export const CSP_META = [
  "default-src 'none'",
  "script-src 'self' https://static.cloudflareinsights.com",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join("; ");

/** The referrer policy, in the header and every page's meta tag: Cloudflare Web Analytics needs the Referer header on this origin's /cdn-cgi/rum, and other sites still get none. */
export const REFERRER_POLICY = "same-origin";

export const CSP_HEADER = `${CSP_META}; frame-ancestors 'none'`;

/** Headers for every path, in the _headers format Cloudflare Pages reads. */
export const HEADERS = [
  "/*",
  `  Content-Security-Policy: ${CSP_HEADER}`,
  "  X-Content-Type-Options: nosniff",
  `  Referrer-Policy: ${REFERRER_POLICY}`,
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
