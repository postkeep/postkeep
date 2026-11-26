# Threat model

This describes what postkeep protects, from whom, and how. It covers the
server in `crates/server`, the OAuth authorization server in `crates/auth`,
storage in `crates/store`, the mail client in `crates/mail`, the OAuth client
for Microsoft and Google accounts in `crates/upstream` and webhook delivery in
`crates/webhook`, as deployed from the container image. The latest reviews are
[audit-2026-10.md](audit-2026-10.md) and
[providers-review-2026-10.md](providers-review-2026-10.md).

## System overview

```
MCP client ──HTTPS──▶ reverse proxy / Fly edge ──▶ postkeep ──IMAP/SMTP · Microsoft Graph · Gmail API──▶ mailbox
   ▲  (OAuth 2.1, bearer tokens)                     │   │
   │                                                 │   └──HTTPS──▶ webhook receiver (user-chosen)
 user's browser (sign-in page, account page) ◀───────┘
                                                     └──▶ SQLite / PostgreSQL
```

- MCP clients discover the authorization server (RFC 9728, RFC 8414),
  identify themselves with a Client ID Metadata Document at an `https` URL
  or register dynamically (RFC 7591), and send the user to `/authorize`.
- The user signs in with Microsoft or Google, or with an app-specific
  password for iCloud Mail, Fastmail, Yahoo Mail, Gmail, or an IMAP
  server the
  operator configured. App-password sign-in is checked with an IMAP login.
  The server stores the app password or the provider tokens encrypted, and
  issues an authorization code (PKCE `S256` required).
- Tool calls on `/mcp` carry an opaque bearer token. The server loads the
  account's credentials and uses IMAP/SMTP, Microsoft Graph, or the Gmail
  API on the user's behalf.
- Optionally, one watcher per account watches the Inbox: IMAP `IDLE` (or a
  60-second poll without `IDLE`), Graph notifications, or Gmail watch
  through Pub/Sub, and POSTs a small signed JSON event to the user's
  webhook URL when mail arrives.

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| App-specific passwords | `accounts` table, AES-256-GCM | Full IMAP/SMTP access to the mailbox (read, send, delete) until the app password is revoked at that provider (for iCloud Mail, account.apple.com; for Gmail, myaccount.google.com/apppasswords) |
| Master key | Environment / secret file, process memory | Wraps the data keys. Decrypts directly only app passwords, webhook secrets, provider tokens, events and sign-ins in progress that an earlier version stored and that have been neither saved again nor moved by the sweep (a sign-in is gone once used or expired). Everything this version writes, the sweep included, is under data keys, which it unwraps |
| MCP access and refresh tokens, codes | Client, SHA-256 hashes in the database | Act as the user through the MCP tools |
| Mail content | Bodies and attachments typed into a call pass through memory and postkeep does not store them; an uploaded file is kept until it is used or its hour ends, as the next row says. Held sends keep one fingerprint, which covers attachment names, types, sizes and digests, never the message or file bytes. If the user turns on sender and subject, those two fields are stored inside the encrypted webhook event | Private correspondence; returned to the MCP client, never logged |
| Uploaded files | The operator's bucket: sealed pieces under random names, each upload under a key of its own that only the database holds, sealed under the tenant's data key; no name or type is stored. Once used or ended, its removal is asked and retried by the cleanup, and the bucket's expiry rule removes what is left, with no guaranteed deadline (see Uploads in the configuration guide) | Private files waiting for their message; the bucket's company sees only how many, how large and when |
| Account page sessions | Cookie, hash in the database | Disconnect one app or all, replace the stored password (checked with the mail server first), delete data, configure webhooks |
| Webhook auth header and signing secret | Encrypted in the database | Authenticate deliveries to the user's own endpoint |
| Webhook filter rules | `webhook_filter_rules`: each pattern encrypted under the data key of the mailbox's tenant; action, field and kind in the clear | Patterns can hold addresses and names; the rules decide which new mail calls the webhook |
| Availability | — | A personal server that silently stops is a nuisance; one that leaks is worse. Large Gmail and IMAP forwards share one memory budget. |

## Actors

| Actor | Capabilities assumed |
|---|---|
| Anonymous internet user | Reaches every public endpoint, registers OAuth clients, sends crafted requests at volume, hosts web pages and webhook receivers |
| Malicious OAuth client | Registers any valid redirect URI and client name, crafts authorization links, keeps stolen codes or tokens |
| Malicious email sender | Controls the headers and bodies of mail delivered to a connected account |
| Other tenant | A different signed-in account on the same (shared) server |
| Network attacker | Observes or tampers with traffic between components (TLS is assumed on every hop) |
| Compromised dependency or CI action | Code running in the build or in the process |
| Operator | Trusted: holds the master key and the database. Not a threat the server can defend against |

## Trust boundaries and entry points

1. **Public HTTP** (`/register`, `/authorize`, `/token`, `/revoke`,
   `/.well-known/*`, `/account*`, static assets, `/`, `/healthz`,
   `/readyz`).
   Unauthenticated. The per-IP request rate limit covers `/register`,
   `/authorize`, `/token`, `/revoke`, `/account` and `/account/*`, and
   `/oauth/{provider}/start` and `/oauth/{provider}/callback`.
   These routes have no per-IP request rate limit: `/.well-known/*`,
   static assets (`/assets/*`, the favicons, `/oauth/icon.svg` and
   `/oauth/logo.svg`), `/`, `/mcp`, `/healthz`, `/readyz`, and the
   provider push endpoints (`/push/microsoft`, `/push/microsoft/lifecycle`,
   `/push/google`). `/healthz` and `/readyz` are also outside the global
   concurrency cap, the body limit and the request timeout. `/`, `/mcp`
   and the push endpoints stay inside those three.
2. **Protected MCP endpoint** (`/mcp`). Bearer token required, stateless
   (no MCP sessions), `Host` and `Origin` allow-lists against DNS
   rebinding. No per-IP request rate limit; a per-account concurrency cap
   applies.
3. **Mail providers**: IMAP/SMTP servers (iCloud, Fastmail, Yahoo, Gmail,
   or a
   configured server), Microsoft Graph, the Gmail API, and Microsoft's and
   Google's OAuth endpoints. TLS with webpki roots. Responses (mail data,
   tokens, error bodies) are untrusted input. Outlook returns an attachment
   upload URL with its own token. postkeep checks its HTTPS origin, sends it
   no bearer header and never records the URL in errors or logs.
4. **Provider push endpoints** (`/push/microsoft`,
   `/push/microsoft/lifecycle`, `/push/google`). Public and
   unauthenticated at the HTTP level, and outside the per-IP request
   rate limit. Each request is verified
   (`clientState`, Google-signed OIDC token). A verified Graph
   notification is handled only for the subscription id it names.
   Change notifications and a `missed` lifecycle event schedule a
   catch-up. `reauthorizationRequired` reauthorizes that id when the
   local row still stores it, and `subscriptionRemoved` deletes the
   local row only when it still stores that id. A verified Gmail push
   only schedules a catch-up. See the
   [provider review](providers-review-2026-10.md).
5. **Upstream sign-in callbacks** (`/oauth/microsoft/callback`,
   `/oauth/google/callback`). Bound to the starting browser by `state`,
   PKCE and a `__Host-` cookie.
6. **Webhook receivers**. User-supplied URLs reached from the server. Risk
   of SSRF.
7. **Client ID Metadata Documents**. An unauthenticated `/authorize`
   request names an `https` URL that the server fetches. Risk of SSRF and
   of a self-named client.
8. **Database**. Trusted storage, but its contents are assumed readable by
   whoever gets a backup. Secrets are encrypted or hashed. An embedding can
   destroy a tenant's data keys (`Store::destroy_data_keys`): that tenant's
   secrets are then unreadable through the database and in logical dumps taken
   afterwards. Backups from before, and physical copies (database files,
   snapshots, WAL archives) until the space is reused and they expire, can still
   hold the wrapped keys. A backup taken while an uploaded file waits holds its
   sealed key: after a restore, delete the restored copy's upload rows before it
   serves.
9. **Build and supply chain**. Crates, CI jobs and their images, base images.
10. **Metrics listener** (`POSTKEEP_METRICS_BIND`), off by default.
    `GET /metrics` only, without authentication, on its own address with a
    cap of 16 connections and the header read timeout. Its labels are
    routes as written, statuses, tool names, outcomes, mail server ids and
    providers, so they carry no address, tenant, principal, account id,
    token or request path. The operator keeps the address private.
11. **Uploads** (`PUT /upload`). No sign-in: a one-time token in the
    `Authorization` header, never in the URL, counted against the auth routes'
    per-IP limit. Whoever holds a token can put one file in, once, within the
    hour, and only the mailbox, caller and app that asked can attach it.

## Threats and mitigations

### Authentication and authorization (OAuth 2.1, MCP authorization)

| Threat | Mitigation |
|---|---|
| Stolen authorization code redeemed | PKCE `S256` mandatory; codes last 5 min and work once; a replayed code revokes the grant made from it |
| Stolen refresh token | Rotation on every use. A replay of a used refresh token revokes the whole grant (RFC 9700 §4.14.2), except when presented again within 30 seconds of its first use: it issues a separate pair without extending that window |
| Token for another resource (confused deputy) | RFC 8707 `resource` checked at `/authorize`, `/token` and on every bearer request; no token passthrough (the server uses the stored app password or the stored provider tokens, never the client's token). An embedding that serves several hosts turns on per-request resources: each allowed host is its own resource, and so is each name under a resource prefix (such as `/w/<name>/mcp`) when the embedding sets one. `resource` is required at `/authorize` and `/token`, and a token is accepted only at the exact resource it names (not the issuer, not another host or name, never without one). Requests for hosts the server does not serve are refused before authentication |
| Redirect URI manipulation | Exact match (any port only for loopback, RFC 8252); `https` or loopback `http` or private-use schemes; fragments, whitespace, control characters and dangerous schemes refused at registration and again at `/authorize` |
| Open redirector via error redirects | Invalid requests for web redirect URIs show an error page instead of redirecting (RFC 9700 §4.11.1) |
| Mix-up attacks | `iss` returned with every authorization response (RFC 9207) |
| Sign-in for an embedding's own resources | An embedding's sign-in hook gets only the `/authorize` requests for the resources it claims; a request without a resource always gets the mailbox sign-in. The mailbox sign-in page and Microsoft or Google sign-in can neither finish nor cancel those requests, and the embedding cannot approve or deny any other request. Codes and tokens for its principals follow the same PKCE, single-use, rotation, replay and audience rules, and never act for a mailbox account: the default principal resolver refuses them, so only a resolver the embedding installs can accept them. The hook's response is sent with `Cache-Control: no-store`, and the pending request's ID, which is all it takes to approve or deny it, is kept secret |
| Mailboxes added to an embedding's tenants | Only an embedding's own page can start a Microsoft or Google sign-in for a tenant (`AuthState::start_upstream_sign_in`); `POST /oauth/{provider}/start` cannot name one. The callback makes the same checks as for any provider sign-in (single-use `state`, the browser-binding cookie, PKCE, every scope, the allow-list) before it stores the account in that tenant and calls the embedding's continuation hook, and without that hook it stops before the code exchange. The continuation is stored encrypted. The embedding starts these sign-ins only for same-origin posts from a person it signed in, with the tenant taken from that session, so nobody can add a mailbox to someone else's tenant |
| Phishing with a lookalike client name | The sign-in page shows the redirect host next to the client-supplied name. App-password sign-in requires typing that password; Microsoft and Google sign-in do not. Registration strips bidi overrides, other format controls and Unicode line separators from the client name, and the pages strip them again before display and isolate the name and the redirect host (`<bdi>`) so they cannot reorder the surrounding text. Residual risk: users may still trust a convincing name |
| Brute-forcing app passwords through the sign-in page | Exponential backoff per client IP (to 15 min) and per address (to 1 min, so the owner can't be locked out for long); malformed addresses and empty passwords are rejected before any connection; other input goes only to the selected preset or the operator's IMAP server |
| Login CSRF / account page CSRF | Every account page POST needs a session-bound CSRF token and a same-origin `Origin`/`Referer`; cookie `__Host-`, `HttpOnly`, `SameSite=Lax`, `Secure` |
| Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options: DENY` |
| Web pages calling `/mcp` from a browser (DNS rebinding, cross-site requests) | The `Host` must be one the server serves, and an `Origin`, when sent, the public URL's origin or one in `POSTKEEP_ALLOWED_ORIGINS`; anything else gets `403` before the token is checked. `/mcp` sends no CORS headers, so pages on other origins cannot read its replies |
| Unwanted accounts on a personal server | `POSTKEEP_ALLOWED_EMAILS` checked at sign-in, on every MCP request and refresh, on the account page, before an IMAP watcher logs in, before a Graph subscription or a Gmail watch is created or renewed, before Graph or Gmail catch-up reads mail, and before a queued webhook event is sent. Principals that an embedding's sign-in hook approves have no address; the embedding decides who they are |

### Multi-tenant isolation

- The bearer token determines which tenancies and mailboxes a tool call
  may use. With mailbox selection enabled, the call acts in one tenancy:
  the one named by the resolver's optional tenant argument, the one holding
  the named `mailbox`, or the default when neither is named. A mailbox must
  be allowed in that tenancy. An address matching several of the caller's
  mailboxes requires an ID. A refused selection stops the call before checks,
  usage hooks or tools run. An embedding's extension gets the same checked
  caller and mailbox, and cannot take the name of one of the server's tools.
  The per-account concurrency limit counts the mailbox actually used.
  IMAP sessions are pooled per account **and** per credential fingerprint,
  so they can't cross accounts or outlive a password change.
- Account page and webhook queries are scoped by the session's account ID.
  Deleting an account removes its tokens, sessions, codes, webhooks and
  delivery history. Filter rule queries are scoped by the account too, so
  another mailbox's rule id removes nothing.
- Encryption contexts bind each ciphertext to its account (password AAD is
  the address; webhook secrets use the account ID) and, under a data key, to
  its tenant and column, so swapping rows between accounts fails to decrypt.
  Webhook filter patterns are bound to their tenant, column and rule ID, not
  to the account. A pattern moved to another account of the same tenant
  therefore still decrypts, and only the account scoping of every rule
  query keeps it apart.

### Injection

- IMAP: search values reject control characters and are quoted or sent as
  literals; folder names are modified-UTF-7 encoded and quoted by
  async-imap, which rejects CR/LF. Fuzzed (`imap_search`, `utf7`).
- SMTP: subjects and display names with line breaks are refused; headers
  are built by lettre, which encodes attachment names as MIME parameters.
  Replies to hostile messages carry only the headers the crate sets, except
  that Outlook builds large replies from the original and postkeep replaces
  the subject, body and recipients and removes the files Outlook copied. Fuzzed
  (`reply_headers`). A reply to a message whose
  sender does not read as one address, or whose Reply-To (or, for the
  mailbox's own message, To) does not read as addresses, each alone or
  after a name, is refused unless `to` names the recipients, and a reply
  to all is refused when the message's To or Cc does not.
- HTML: pages are askama templates with auto-escaping and a strict CSP
  (no inline script or style). Mail HTML is converted to Markdown text
  for tool results, never rendered; its text is escaped so that it cannot
  form Markdown links, images or HTML. Links keep only http, https and
  mailto URLs, and images only http and https URLs or the message's own
  inline images (attachment:N); javascript:, data: and every other scheme
  keep only their text. Images of 1 pixel, or hidden by their style, are
  left out. Text, links and images inside an element with the `hidden` or
  `popover` attribute, or inside template, datalist, rp, a closed dialog,
  video, audio, object, progress, meter or marquee, whose content browsers
  don't draw or draw only in some clients, are left out too, and so is the
  whole message when its `<body>` or `<html>` tag hides it. The converter
  doesn't rebuild the page as browsers do: where it can't be sure where
  hidden content ends, it leaves out more, and a hidden element stays in
  force until its own end tag closes it in order, which can be the end of
  the message. When nothing is left, or the HTML part can't be decoded,
  the body is empty and `body_note` says why: get_message never returns
  the plain-text part in place of an HTML part, because the person's mail
  client may not show it.
  Without an HTML part, the body is the plain-text parts the mail client
  shows, from the last member of an alternative that it can show; when
  that member has no plain text, such as an image, or the first of those
  parts is base64 or quoted-printable that can't be decoded, the body is
  empty, or the text of another part the mail client also shows, and an
  empty body usually comes with a `body_note` saying why. A last member
  in text/enriched, text/richtext or text/markdown, which some mail
  clients show and others pass over, counts as one without plain text,
  and with an HTML member before it the body is empty too.
  Of a multipart/related part, the mail client shows only the root, its
  first part; when its `start` parameter names another part or is
  repeated, or its Content-Type also holds a `*`, as RFC 2231 pieces do,
  or an encoded word, mail clients differ, and none of its parts is used
  as the body.
  A body that a mail client may read differently from the parser, because
  the message's parts and its boundary lines do not line up, a part has
  Content-Type headers that differ or a type and subtype that are not two
  plain words around a `/` (one in quotes, say, or with a comment), or a
  multipart's `boundary` parameter is not written once as a plain value
  (it is repeated, say, or comes in RFC 2231 pieces or as an encoded
  word), comes back empty too, HTML or plain text, and download_attachment
  refuses every attachment that does not end before the place where the
  two readings start to differ.
  A part in a transfer encoding the parser doesn't decode, anything but
  7bit, 8bit, binary, base64 and quoted-printable, counts as one that
  can't be decoded, as some mail clients decode it. So does a part whose
  Content-Transfer-Encoding is more than that one word, such as an
  encoded word, or whose copies of that header differ, as mail clients
  may read it otherwise. So does a part read as text whose `charset`
  parameter is not written once as a plain value, as the parser and a
  mail client may then read its text in different charsets. So does text
  that mail clients may convert otherwise: under a charset label the
  Encoding Standard (encoding.spec.whatwg.org) doesn't list, such as
  UTF-7, or under one of its UTF-16 or replacement labels; in an East
  Asian charset, or another the parser converts with the standard's own
  decoders, when they find bytes the charset has no character for, such
  as a broken byte pair, or leave one of the ISO-2022 control bytes ESC,
  SO and SI in the text; without a charset, unless it is UTF-8 without
  ISO-2022 escapes; and text that starts with the byte order mark of
  another charset, which browsers follow over the one named.
  Other plain-text and HTML parts that mail clients show as part of the
  body, not as attachments, such as a second HTML part after the first,
  join it in the order they come, each converted or filtered on its own
  like the body. A part that can't be decoded is left out; nothing joins
  a body that is empty on purpose; nothing joins after an HTML part that
  may not end where it seems to, such as one that leaves an element open
  at its end; and nothing joins when any HTML part's html or body style
  dims, shrinks or clips text, since such a style reaches every part.
  Style sheets, which the converter doesn't read, can reach every part as
  they reach a single part. `body_format: html` returns the HTML part
  alone.
  Content hidden by an inline style is left out too: `display:none`,
  `visibility:hidden` or `collapse`, `content-visibility:hidden`, or zooms
  that multiply down the tree to 0.1 or less. An element 1 px or less wide
  or high is left out under overflow that isn't visible, on the element or
  a parent; a table cell grows past its width and height to fit its text,
  so for a cell only a maximum size that small counts. An element with
  overflow that isn't visible is left out when its own or inherited
  line-height is 1 px, or a tenth of the font size, or less. Under a font
  size of 1 px or less, sizes and line-heights in em and the other font
  units count as 0. A style with a CSS comment, with an entity the
  converter can't decode, or with a hiding property whose value it can't
  read, such as var() or calc(), counts as hiding. Nothing inside `<svg>`,
  `<math>` or `<select>` is written, and when their markup isn't plainly
  nested, the rest of the message is left out. Content with an opacity,
  an opacity() filter, or a text color whose alpha is below 0.1 is left
  out too; opacities multiply down the tree, and the faintest color of an
  element and its parents counts. `all` other than a reset counts as
  opacity 0. Text in a font smaller than 2 px is left out too, but the
  images and links around it are kept; font sizes in em, % and the other
  relative units multiply down the tree, and so does zoom; font-size-adjust
  and text-size-adjust count at their lowest value in force, and a `font`
  shorthand can only make the size smaller.
  A larger size set inside a smaller one counts only on elements that
  browsers still hold open, as far as the converter can follow them.
  Past the depth at which a browser stops nesting plainly nested elements
  and attaches deeper ones higher up, only the lowest size so far counts,
  as far as the converter can follow them.
  Browsers also copy a
  closed formatting element, such as `<b>`, into later text, and the
  converter counts the size of that copy. Text that browsers move out of
  a table, and table parts they ignore, count the size where browsers put
  them. A formatting element that browsers copy into a block at a
  misnested end tag counts there too, as far as the converter can follow
  it. Text hidden by
  a style sheet, by its color against the background, by a parent's overflow over a tiny
  line-height, or by position, clip, transform, mask, a filter other than
  opacity() or CSS containment is kept, and so is the content of a closed
  `<details>`, which the person can open.
  The server never fetches a URL from a message. A message without an HTML
  part gives its plain-text body as sent, without Markdown escapes, apart
  from the invisible characters and controls below.
  With `body_format: html`, get_message returns the HTML part as sent
  instead, unescaped and unfiltered: it can hold tracking URLs, scripts,
  hidden text and instructions aimed at the agent. It is off by default,
  and Markdown is the format to use with an LLM; the server still fetches
  nothing.
- Invisible characters: characters that mail apps draw as nothing are
  left out of get_message's body (Markdown or plain text), subject,
  addresses, Message-ID and attachment details, of the text that
  download_attachment returns, of the subjects and senders
  search_messages returns, and of the sender, subject and
  Message-ID of webhook events: tag characters, except in the England,
  Scotland and Wales flags; variation selectors, except one U+FE0F
  after a character; joiners, except one after a character or that
  U+FE0F; and the other default-ignorable code points, such as
  zero-width spaces and the invisible math operators. Bidi controls,
  which make text read differently from how it is drawn, and the other
  control characters but whitespace are written as `\u{…}` escapes
  instead. In an address itself every such character is written as an
  escape, and so are `<`, `>` and their look-alikes, so no address reads
  as another. The look-alikes are the characters that Unicode's
  confusables data (UTS 39, version 18.0.0) maps to text with `<` or `>`
  in it, after the canonical decomposition that UTS 39 applies first,
  the characters whose Unicode 18.0.0 name holds ANGLE BRACKET or ANGLE
  QUOTATION MARK, but the vertical forms U+FE3D to U+FE40, and the
  modifier letter arrowheads U+02C2, U+02C3, U+02F1 and U+02F2. In the
  name before it, `<`, `>`, their look-alikes, line breaks and the other
  control characters are written as escapes too, so the address is the
  only text in angle brackets and each address reads as one line. A
  sender that does not read as one address, alone or after a name, is
  written whole, as an address is, with `<`, `>` and their look-alikes
  as escapes, and marked `from_unclear`, so that no part of it passes
  for the sender's address: in get_message, search_messages and webhook
  events, except for Outlook's search results and events, which take
  the address from Microsoft Graph. A kept U+FE0F or joiner can still
  carry a little data after each character.
  `body_format: html` is as sent. What download_attachment returns as
  base64 is not filtered either: a file that is neither an image nor
  UTF-8 text, or any attachment with `base64: true`, where a text
  attachment comes as its text in UTF-8.
- SQL: static, parameterised queries only.
- Logs: secrets, tokens and message content are never logged. Crates that
  would log IMAP traffic, SMTP commands, MCP tool results or the hosts the
  HTTPS client connects to, the upload bucket's included, stay capped even
  when `POSTKEEP_LOG` asks for trace. The request log line holds
  only ids, routes as written, the status, the time, and a tool's name and
  outcome, and no line logs a client's IP address or a request's path.

### SSRF (webhooks and client metadata documents)

`https` only; no userinfo; local names refused; every resolved address must
be public (no private, loopback, link-local, CGNAT, multicast,
documentation or metadata ranges; IPv4-mapped/NAT64 addresses use the IPv4
rules); the connection is pinned to the vetted address (no DNS rebinding);
redirects aren't followed; short timeouts and a 16 KiB response cap. Test
sends are limited to one per 10 s per account. Fuzzed (`webhook_target`).

Client ID Metadata Documents use the same client and rules, with a 5 s limit
and a 64 KiB body cap. The URL must already be in normal form and the
document must name it as its `client_id`. Only public clients are accepted:
no `client_secret`; a `token_endpoint_auth_methods_supported` list must
include `none`, name no shared-secret method and hold any
`token_endpoint_auth_method` given (null included); without the list, that
method must be `none`, null or absent. At `/token` and `/revoke`, such a
client's secret, Basic credentials or `client_assertion` gets
`invalid_client`. Redirect URIs pass the registration rules and must then
match exactly, with no loopback port leeway. A valid document is reused for
its `Cache-Control: max-age`, clamped to 5 minutes to 24 hours, which limits
how often `/authorize` can make the server fetch. Errors are never cached.
Fetches count against the per-IP request limit; a new client counts against
the per-IP registration limit and the client limit, like a registration. The
sign-in page shows the host that published the document next to the
self-asserted name. Because `/authorize` needs no sign-in, anyone can make
the server fetch a public HTTPS URL once per cache lifetime; the error page
then shows only the HTTP status, never the body.

### Denial of service

Request body limits (16 KiB for auth endpoints, 1 MiB for MCP), header
read timeout, request timeout, a global concurrency cap (every route
except `/healthz` and `/readyz`; `/readyz` runs one round of database
checks at a time and reuses the answer for a second), a per-account
concurrency cap on `/mcp`, per-IP
request rate limits on the auth routes in item 1, a per-IP registration
limit on `/register`, a cap on registered clients with purging of
abandoned ones, a cap on watchers, and watcher reconnect backoff (longer
after an authentication failure).
Limits are per process and in memory. Outgoing mail tools also check the
attachment count against their schema before decoding any of the files.
Uploads have their own bounds (per tenant and per server) and the per-IP
limit; a bucket that is down makes uploads answer `503` and sends that name
an upload refuse it, and nothing else waits on the bucket.

At most 2,000 webhook filter rules count per mailbox. Patterns are at most
512 bytes and are compiled by the `regex` crate, which matches in linear
time. Compiled, they take at most about 10 MiB per mailbox, plus the
reverse automaton and a lazy-DFA cache of up to 2 MiB per set and
searching thread (eight sets at most), dropped at the next lookup of any
mailbox's rules once they have judged nothing for 10 minutes. The sender's text is cut before matching.

download_attachment returns one attachment of at most 3 MiB; like
get_message it reads the whole message first (Microsoft and Google
messages at most 48 MiB).

### Cryptography

AES-256-GCM with a random 96-bit nonce per value and context-bound AAD;
the server moves secrets to data keys and re-wraps data keys at start and then
every hour, and `POSTKEEP_PREVIOUS_MASTER_KEYS` (or `_FILE`) keeps a rotated-out
master key readable until both are done; SHA-256 hashes
for high-entropy secrets (MCP tokens, codes, session IDs, client secrets);
constant-time comparisons; 256-bit random tokens from the OS RNG. Webhooks
are signed with HMAC-SHA256 over `timestamp.body`.

### Supply chain and container

`cargo-deny` (advisories, licences, sources, bans) in CI; `Cargo.lock`
committed and builds `--locked`; the runtime base image pinned by digest
and bumped by hand. CI runs on GitHub-hosted runners. The image is
distroless, runs as a non-root user, and holds only the binary.

## Assumptions and residual risks

- **The operator is trusted.** Anyone with the master key and the database
  can read every stored app password, Microsoft and Google token, webhook
  secret, stored webhook event and webhook filter pattern, and, with the
  bucket's pieces, an uploaded file still waiting. Use a secret store for the
  key.
- **An agent steered by mail can upload a local file and send it.** Uploads
  raise what such an agent can attach from about 0.75 MB to 25 MiB. The guard
  is the app's own prompt before a send.
- **One tenant could fill uploads for all.** Each tenant's bounds are exact,
  and the server's are the backstop. They bound what is reserved at once, not
  the bucket's bill.
- **A backup can open a file.** With the master key and the file's pieces still
  in the bucket, a backup taken while it waited opens it.
- **A proxy could save or log an upload.** The token is not in the request
  line; the deployment guide says how a proxy streams `/upload`.
- **The bucket's key is a secret.** Whoever holds it reads only sealed pieces,
  which nothing in the bucket opens; can delete pieces, so the sends that name
  them refuse, by name, and send nothing; or can add objects, which postkeep
  never reads and the expiry rule removes.
- **Destroyed data keys live on for a while.** Backups taken before a
  destruction still hold the wrapped keys, and so can physical copies taken
  after it, until the space is reused and they expire. A store with a cache of
  its own keeps the keys it has unwrapped until it next asks for one of that
  tenant's keys or restarts.
- **App-specific passwords are powerful.** They grant full mailbox access
  until the app password is revoked at that provider (for iCloud Mail,
  account.apple.com; for Gmail, myaccount.google.com/apppasswords). The
  account page says so. Changing the Google Account password revokes every
  Google app password, and Google describes one as permission to access
  the Google Account
  ([Google](https://support.google.com/accounts/answer/185833)).
- **TLS terminates in front of the app** (Fly edge or a reverse proxy).
  The app doesn't send HSTS itself; set it at the proxy.
- **Client display names aren't verified** (open registration). The
  redirect host shown on the sign-in page is the reliable signal. The
  name and that host are isolated so a name cannot reorder the sentence.
- **Replay detection can be used to sign someone out:** whoever presents a
  stolen used refresh token after the grace revokes the grant. That's the
  intended trade-off of RFC 9700.
- **The refresh grace can hide token theft.** A refresh token presented
  again within 30 seconds of its first use gives its holder a separate
  sign-in that replay detection never catches if both token chains keep
  rotating independently. Malware watching the app's token file can exploit
  this window on every refresh.
- **Rate limits are per process.** Several replicas multiply them; the
  limit maps prune old entries but can grow under a large distributed
  attack.
- **An agent can stop webhook calls.** A client that may call changing tools
  can add a block rule, or an allow rule that matches little. An agent
  reading untrusted mail could be steered to do so. The mail stays in the
  mailbox, the status shows the counts, and the rules can be listed and
  removed, by the agent or by the person on the account page, who can also
  turn them off.
- **A held send is not proof of the user's yes.** Where an embedding holds
  sends, it tells the agent to show the exact message and each attachment by
  name and size, and ask. A forward sends the original's files without the
  agent reading them; show the original and its files as well. An agent
  steered by mail can make both calls itself. Keep the app's confirmation
  prompt on for `send_message`: the agent cannot answer it.
- **One call can move many messages to the trash.** An app's permission to
  call `delete_message` covers this too, as does permission to `move_message`
  with the trash as its destination, which is not marked destructive.
  Trash can be undone; permanent deletion stays one message a call. Keep the
  app's confirmation prompt on before `delete_message`: the agent cannot
  answer that prompt.
- **A selection is a checksum, not a seal.** It catches a garbled search or
  one passed with another mailbox, but does only what a new search by the
  same caller would. A selection planted in mail can carry a working tag.
  The tool tells agents to pass only selections from `search_messages`.
  A selection can trash a whole folder over repeated calls: `delete_message`
  has the app's confirmation prompt; `move_message` to the trash is not
  marked destructive and has no such prompt. Held sends do not hold either
  tool's changes. Permanent deletion still takes one id, not a selection.
- **A draft keeps the recipients an agent gave it.** create_draft saves a
  draft's Bcc recipients, as mail apps do, and an agent reading untrusted
  mail could be steered to add one. Check a draft's recipients, Bcc
  included, before you send it.
- **Remote images and links reach the agent.** get_message shows a
  message's remote image and link URLs. A client that renders the
  Markdown, or an agent that fetches an image, can tell the sender that
  the message was read; the server leaves out only obvious tracking
  pixels. With `body_format: html` the agent gets every URL in the HTML,
  tracking pixels included.
- **Attachments reach the agent.** download_attachment hands an
  attachment's text, image or bytes to the agent, which may act on
  instructions written in it, as in a message body. Nothing is scanned
  for malware.
  download_attachment refuses an attachment that did not decode cleanly,
  such as base64 that is broken or cut off, as its bytes may differ from
  what the person's mail client opens.
- **Filters are not a privacy control.** A code or a reset link lets
  whoever reads it take over an account; rules only decide what wakes the
  agent.
- **Webhook payloads leave the server.** Sender and subject leave the
  server only when the user turns on "Include sender and subject" (off
  by default).
- **Provider grants are powerful.** A Microsoft or Google refresh token
  grants mail read, modify and send access until it expires or the user
  revokes it at the provider. Microsoft doesn't let apps remove their own
  access: remove postkeep at account.live.com/consent/Manage (personal
  accounts) or myapps.microsoft.com (work or school). Deleting a Gmail
  account on the account page tries to revoke postkeep's access at Google;
  users can also remove it at myaccount.google.com/permissions. postkeep
  stores the refresh token and the cached access token encrypted, as it does an
  app password: under a data key that the master key wraps (a token that an
  earlier version stored stays under the master key until it is saved again or
  the sweep moves it).
  Residual risks of
  provider support are listed in the
  [provider review](providers-review-2026-10.md#residual-risks).
- **A stopped machine doesn't watch.** Webhooks need an always-on
  instance (see [deployment](../deployment.md#new-mail-webhooks)).
