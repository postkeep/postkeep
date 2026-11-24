# Security

How postkeep protects what it stores, and how to report a problem.

## Security model

- App passwords, Microsoft and Google tokens, webhook secrets, webhook
  filter patterns, stored events and the keys of uploaded files are
  encrypted with AES-256-GCM under data keys wrapped by a master key you
  supply. Each value has a random nonce and is bound to the tenant, column and
  row it is stored in. Uploaded files wait in the operator's bucket, sealed
  piece by piece under a key of their own, with the piece's number as the
  nonce and fixed associated data.
- MCP access tokens, MCP refresh tokens, authorization codes and client
  secrets are stored only as SHA-256 hashes. Codes are single use, refresh
  tokens rotate on every use, and PKCE (`S256`) is mandatory. Presenting a
  used code or refresh token again revokes the whole grant
  ([RFC 9700 §4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2)),
  except a refresh token presented again within 30 seconds of its first use:
  it issues a separate pair, without extending that window. This tolerates
  public clients refreshing twice ([MCP TypeScript SDK #2915](https://github.com/modelcontextprotocol/typescript-sdk/issues/2915),
  [Claude Code #85236](https://github.com/anthropics/claude-code/issues/85236)).
  The grace can also give a token thief an undetected sign-in (see the
  [residual risks](threat-model.md#assumptions-and-residual-risks)).
- The sign-in page works without JavaScript and is served with a strict
  Content Security Policy (no inline script or style; only a small
  same-origin script for conveniences such as show/hide password). It can't
  be framed. Failed sign-ins back off
  exponentially per client IP (up to 15 minutes) and per address (up to one
  minute, so nobody can lock you out); the OAuth endpoints are rate-limited
  per client IP, and client registrations are capped and expire when unused.
- The account page uses a short-lived session cookie (`__Host-` prefixed over
  HTTPS, `HttpOnly`, `SameSite=Lax`; 1 hour idle, 12 hours at most) stored
  only as a hash. Every change needs a same-origin `Origin` and a CSRF token,
  and destructive actions need explicit confirmation.
- Webhooks go only to `https` URLs on public addresses: private, loopback,
  link-local and cloud metadata addresses are refused, also after DNS
  resolution, and redirects are not followed. Events can be signed with
  HMAC-SHA256; the header value and signing secret are encrypted at rest.
- An allow-list (`POSTKEEP_ALLOWED_EMAILS`) limits which accounts can
  connect and is re-checked on every request.
- Passwords, tokens and message contents are kept out of the logs (see the
  [threat model](threat-model.md)).
- TLS uses rustls; there is no OpenSSL. The container runs as a
  non-root user on a distroless base.

To report a vulnerability privately, see [SECURITY.md](../../SECURITY.md).

## Further reading

- [Threat model](threat-model.md)
- [Internal security review, October 2026](audit-2026-10.md)
- [Security review: Outlook and Gmail support, October 2026](providers-review-2026-10.md)
