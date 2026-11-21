# postkeep-auth

The OAuth 2.1 authorization server built into `postkeep`. MCP
clients use it to connect a user's mailbox without seeing the mailbox
password: iCloud Mail, Fastmail, Yahoo Mail, Gmail or a custom IMAP server
with an app password, or Outlook and Gmail through Microsoft or Google
sign-in.

## Endpoints

| Path | Purpose |
| ---- | ------- |
| `GET /.well-known/oauth-protected-resource/mcp` | Protected resource metadata (RFC 9728), also served without the `/mcp` suffix |
| `GET /.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| `POST /register` | Dynamic client registration (RFC 7591): public (`none`) or confidential clients |
| (client ID URL) | A `client_id` that is an `https` URL names a Client ID Metadata Document, fetched at `/authorize` through the webhook crate's SSRF-safe client and cached for its `max-age` (5 min to 24 h) |
| `GET /authorize` | Validates the request and shows the sign-in page, or hands it to an embedding's sign-in hook |
| `POST /authorize` | Checks the address and app password with an IMAP login, then redirects back with a code |
| `POST /token` | `authorization_code` (PKCE `S256` required) and `refresh_token` grants |
| `POST /revoke` | Token revocation (RFC 7009); revokes the whole grant |

`require_bearer` is axum middleware for the MCP endpoint. Without a valid
token it answers `401` with
`WWW-Authenticate: Bearer resource_metadata="…"`, which starts discovery in
MCP clients.

An embedding's own `PrincipalResolver` can also take this server's access
tokens. `AuthState::access_grant` looks a token up with the same expiry and
audience checks as the default `TokenResolver` and returns its grant, which
is for a mailbox account or for a principal. `TokenResolver` accepts only
mailbox accounts.

Checks that an embedding runs on the MCP endpoint, such as the one in
`postkeep`'s `ToolExtension`, see each tool call as a `ToolCall`: the tool,
whether it only reads, its arguments, the caller and the mailbox it names.
A check turns a call down with a `Refusal`, whose message the caller gets
as the call's error.

An embedding that signs people in for some resources itself installs a
`SignInHook` with `AuthState::set_sign_in_hook`. `GET /authorize` checks
those requests as usual and hands them to the hook, typically for a
consent page of the embedding's own. The embedding finishes each one with
`AuthState::approve_sign_in`, for a principal it chooses, or with
`deny_sign_in`. The mailbox sign-in page and Microsoft or Google sign-in
cannot finish them. Their tokens are for the principal, so only the
embedding's resolver, reading them with `access_grant`, accepts them.

An embedding with its own error pages installs an `InvalidRequestPage` with
`AuthState::set_invalid_request_page`. A request that `/authorize` refuses
(no or an unknown client, a redirect URI that is not registered or not
allowed, an incomplete sign-in form, or an invalid request that cannot go
back to a web app) then gets the embedding's page, with its status, in place
of the server's "This link can't be used" page. The page sees the request's
method, URI, version and headers and the reason the server would show. Both
can hold text taken from the request (the reason for a Client ID Metadata
Document names the `client_id`'s host and why its document was refused), so
the page escapes them as HTML. With `callback_page`, the embedding also
answers the server's own pages at `/oauth/{provider}/callback`: a Microsoft
or Google sign-in that the callback does not finish, its other pages and the
request limit's `429` there, from the server's status, title and text (which
can name the address the provider gave); a finished sign-in stays the
server's. The server adds `Cache-Control: no-store`, the `Set-Cookie` that
clears the browser-binding cookie, and the `429`'s `Retry-After`.

An embedding page can also add a Microsoft or Google mailbox to one of its
tenants. It calls `AuthState::start_upstream_sign_in` with the tenant and
a continuation of its own and returns the redirect it gets. The callback
checks the sign-in as it does for the sign-in page's buttons, creates or
updates the account in that tenant, and hands it with the continuation to
the `ContinuationHook` installed with `AuthState::set_continuation_hook`,
whose response the browser gets. The embedding decides who may add
mailboxes: it starts a sign-in only for a same-origin post from a person it
signed in, with the tenant taken from that person's session.

An embedding that limits how many mailboxes a tenant may have installs a
`UsageHook` with `AuthState::set_usage_hook`. Before a sign-in stores a
mailbox that its tenant doesn't have yet, whether with an app password at
`/authorize` or on the account page, or with Microsoft or Google, the
server passes the hook the tenant, the address and the provider as a
`NewMailbox`. A `Refusal` stops the sign-in before anything is stored, and
its message is shown to the person; postkeep revokes the grant it was just
given (Google; Microsoft has no revocation endpoint for apps). Signing in
again to a mailbox the tenant has is not checked. Without a hook there is
no limit.

The `postkeep` server installs the same hook with `Extensions::usage_hook`.
There it also sees every tool call as a `ToolCall`, after the tool
extension's check, and every message that `send_message` or
`reply_to_message` is about to send as a `Sending`, before the mailbox is
opened. A refusal becomes the tool's error: a refused call doesn't run,
and a refused message isn't sent.

The hook can also lower a mailbox's outbox ceilings, the longest retention
and the most new-mail events it may keep. `set_webhook_outbox_limits`
refuses values above them, and `get_webhook_status` and the account page
report them. The server's ceilings still apply, and pruning keeps using
the limits a mailbox already set, so an embedding that lowers a mailbox's
ceilings resets those limits. Its ceilings can also say how many of a
mailbox's webhook filter rules count, in place of the server's setting.

## The sign-in page

The page offers **Sign in with Microsoft** and **Sign in with Google** when
the server has them configured, and a form for an email address and app
password, with a picker for the IMAP providers the server offers. Below the
form (beside it on wide screens) an expandable guide explains step by step
how to create the provider's app password; for iCloud Mail that is an
app-specific password at [account.apple.com](https://account.apple.com).
Badly formed fields are marked inline with `aria-invalid` and a linked
error summary.

Every page is server-rendered and works with JavaScript off.
`/assets/js/app.js` (same-origin, no dependencies) only adds conveniences,
such as show/hide password, copy buttons and a busy state that blocks double
submits; the provider it picks for a typed address is the one the server uses
anyway. Pages are served with a strict Content Security Policy (everything
they load comes from the same origin, nothing runs inline and no other site
can frame them) and `Cache-Control: no-store`. The header shows the postkeep
mark; provider logos appear only next to the matching sign-in choice.

## The account page

`/account` lets a user sign in with the same credentials as the OAuth sign-in
(same backoff and allow-list) and then:

- see the connected address, when it was connected and how many apps hold
  tokens;
- revoke every app's tokens (`POST /account/revoke`, needs `confirm=yes`);
- disconnect one app (`POST /account/clients/revoke`);
- replace the stored app password of an IMAP account, checked with its mail
  server first (`POST /account/password`);
- delete the account and everything stored for it (`POST /account/delete`,
  needs the address typed again);
- sign out (`POST /account/sign-out`).

When the embedding server calls `AuthState::enable_webhooks`, the page also
shows the "Webhook" section (`POST /account/webhook`, `/account/webhook/test`
and `/account/webhook/rotate-secret`, all with the CSRF token). Its filter
rules are added, changed, turned on or off and removed at
`/account/webhook/filters/{add,edit,enabled,remove}`, with the same token.
URLs and custom headers are validated with `postkeep-webhook`; the saved
header value is never rendered back (only its last four characters when it is
long), the signing secret is shown to the signed-in user, and test events
are sent once, without retries, at most every 10 seconds. After repeated
delivery failures the section shows the webhook as paused (still enabled,
retrying slowly) rather than turned off. Only the user turning it off
stops it. The section also shows how long events are kept and how many,
and whether each limit is the server default or this account's override.
That line is read-only; the limits are changed with the MCP tool
`set_webhook_outbox_limits`. Settings no configured key can decrypt are
shown empty, with an alert that asks for the URL and auth header again.
The outbox line is still filled from the plaintext limit columns. Saving
replaces the endpoint row and leaves those columns alone.

Account listeners also run when an MCP client turns the webhook on or off,
the same way they run when the account page is saved, so a watcher starts
or stops with that change.

Signing in stores the app password used. When that password differs
from the stored one, it replaces it and ends other account-page sessions:
`/account` keeps only the new session, and `/authorize` ends them all. The
same password, a first-time sign-in, and Microsoft or Google sign-in leave
existing account-page sessions in place. The session cookie is
`__Host-postkeep_session` over HTTPS
(`postkeep_session` on plain-HTTP development servers), `HttpOnly`,
`SameSite=Lax`, with a 1 hour idle and 12 hour absolute lifetime; the
database holds only its SHA-256 hash. Every post must carry a same-origin
`Origin` (or `Referer`) and, once signed in, a CSRF token derived from the
session. Pages send `Referrer-Policy: same-origin`, since `no-referrer` makes
browsers send `Origin: null` on same-origin form posts. Embedding
applications can register an account listener on `AuthState` to drop cached
state (such as pooled IMAP sessions) when an account is revoked or deleted.

## Security notes

- Authorization codes last 5 minutes and work once. Access tokens last 1
  hour, refresh tokens 30 days, and refresh tokens rotate on every use.
  Used codes and refresh tokens are kept until they expire: presenting one
  again revokes the grant and all of its tokens (RFC 9700 section 4.14.2),
  except a refresh token presented again within 30 seconds of its first use:
  it issues a separate pair, without extending that window.
- Redirect URIs must match the registered ones exactly. `http` is accepted
  only for loopback addresses, where any port matches (RFC 8252).
  Private-use schemes such as `com.example.app:`, `cursor://`, `vscode://`
  and `claude://` are accepted. Browser and OS handlers are not, including
  `microsoft-edge*`, `ms-*`, `googlechrome*` (and `googlechromes`),
  `firefox*`, `opera*`, `brave*`, `x-safari-*`, and any other scheme whose
  name contains `http` (`x-safari-https`, `opera-http`). A private-use URI
  that embeds another URL is refused too.
- Invalid authorization requests for a web redirect URI (`https`,
  non-loopback `http`, or a handler scheme above) show an error page
  instead of redirecting, so an openly registered client cannot turn the
  server into an open redirector (RFC 9700 section 4.11.1). Loopback and
  private-use scheme redirect URIs get the standard error redirect.
  `/authorize` checks the URI again, so one registered before a scheme was
  rejected no longer receives a redirect.
- Failed sign-ins slow down instead of locking anyone out. After five
  failures, each further failure doubles the wait before the next attempt,
  starting at one second: up to 15 minutes per client IP, and up to one
  minute per address, so someone guessing at an address can make its owner
  wait at most a minute. A successful sign-in clears the address's backoff
  but not the IP's, so signing in to one's own account does not reset the
  backoff for guessing at others.
- An optional allow-list restricts which addresses may connect.
- Passwords and tokens are kept out of the logs.
