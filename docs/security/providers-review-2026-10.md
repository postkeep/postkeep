# Security review: Outlook and Gmail support, October 2026

This review covers what Phase 2 added: sign-in with Microsoft and Google,
the Microsoft Graph and Gmail mailboxes, Graph change notifications, Gmail
push through Cloud Pub/Sub, and the durable webhook outbox. It follows the
[October 2026 audit](audit-2026-10.md) and extends the
[threat model](threat-model.md).

## Scope

| Area | Code |
| ---- | ---- |
| Upstream OAuth client, token refresh and revocation | `crates/upstream/src/{oauth,tokens,http,pkce}.rs` |
| Sign-in pages and callbacks | `crates/auth/src/upstream.rs` |
| Graph and Gmail API access | `crates/upstream/src/api.rs`, `crates/server/src/mailbox/{graph,gmail,id}.rs` |
| Push endpoints | `crates/server/src/push.rs`, `crates/upstream/src/pubsub.rs` |
| Subscriptions, watches and catch-up | `crates/server/src/watch/{graph,gmail,outbox}.rs` |

Questions asked: SSRF, token leakage (logs, errors, URLs), verification of
push requests (JWT, `clientState`), replay, CSRF and login CSRF on the
upstream leg, scope minimization, and isolation between accounts.

## Method

Manual review of every new entry point and every outbound request, with
tests for each finding: wiremock tests for the provider APIs, the token
endpoints, the Gmail API and the Pub/Sub JWT (signed with a throwaway RSA
key), property tests for id parsing, and cargo-fuzz targets
`graph_notification`, `pubsub_push` and `provider_id`.

## Affected versions

v0.2.0 was released before these fixes. Findings 1, 2, 4 and 8 are fixed
by the change that adds this review, and findings 3 and 5 by the fuzzing
change (#48); all of them ship in the release after 0.2.0. Findings 1, 4
and 8 only apply when a Microsoft or Google client is configured, and
finding 2 only when push is in use. A server that offers only IMAP
sign-in, like a 0.1.0 installation upgraded with its existing settings, is
not affected.

## Findings

| # | Severity | Finding | Status |
| - | -------- | ------- | ------ |
| 1 | Medium | A Microsoft directory user without a mailbox can carry any `mail` value its tenant admin sets, and that address was checked against `POSTKEEP_ALLOWED_EMAILS` and for conflicts (the "nOAuth" pattern) | Fixed |
| 2 | Low | Every accepted push notification scheduled its own catch-up, so a burst (or a replayed Pub/Sub token within its validity) caused one provider API call per notification | Fixed |
| 3 | Low | Extreme `exp`/`iat` claims overflowed `i64` arithmetic in the ID token and push token checks (a panic in debug builds; rejected in release) | Fixed |
| 4 | Low | The `error` parameter of an upstream callback was logged verbatim, allowing log-line injection by the signed-in user | Fixed |
| 5 | Info | Provider error codes were copied into errors without a length bound | Fixed |
| 6 | Info | Deleting an account didn't cancel its Graph subscription or Gmail watch at the provider | Fixed |
| 7 | Info | `gmail.send` is redundant with `gmail.modify` | Open question |
| 8 | Low | A sign-in refused for missing scopes or a missing mailbox left the fresh grant in place at the provider | Fixed |

### 1. Microsoft addresses without a mailbox (fixed)

Accounts are keyed by the provider's immutable subject (Graph user `id`,
Google `sub`), never by address, so no one could take over an existing
account. But the address from `GET /me` (`mail`, else
`userPrincipalName`) decided whether the allow-list admitted the user and
whether the sign-in conflicted with an existing Outlook account. For a
directory user without an Exchange Online mailbox, `mail` is whatever the
tenant administrator typed in, so an attacker controlling any tenant could
present an allowed address, get an account on a server restricted to
other people, and block the real owner's Outlook sign-in with a conflict.

Fix: Microsoft sign-in now also requires `GET /me/mailFolders/inbox` to
succeed. For mailbox users Exchange Online keeps `mail` equal to the
mailbox's primary SMTP address, which must be in an accepted (verified)
domain of the tenant. Accounts without a mailbox are refused with a clear
message (`OAuthError::NoMailbox`). Test:
`microsoft_accounts_without_a_mailbox_are_refused`.

Gmail addresses come from the Gmail profile of the authorized mailbox and
are Google-verified.

### 2. Catch-up amplification (fixed)

Graph notifications with a valid `clientState` and Pub/Sub pushes with a
valid token each spawned a catch-up. They were serialized per account, so
no duplicate events resulted, but each still called the provider. A
captured Pub/Sub token stays valid for up to an hour, so a replay loop
could burn the account's Gmail API quota. Now a catch-up that is scheduled
but not yet started absorbs further requests for the same account;
requests arriving once it has started schedule exactly one more, so no
change is missed. Test: the burst step of
`graph_notifications_become_ordered_webhook_events`.

### 3. Timestamp overflow in claim checks (fixed)

`exp + leeway` and `iat - leeway` now saturate. Found while writing the
`pubsub_push` fuzz target; unit test `extreme_timestamps_do_not_overflow`.

### 4. Log injection through the callback `error` (fixed)

Only reachable after the `state` and browser-binding checks, so only by the
user who started the sign-in. The value is now logged only if it looks like
an OAuth error code (`[a-z_]{1,64}`), else as `unrecognized`.

### 5. Unbounded provider error codes (fixed)

Error messages were already capped at 300 characters; codes are now capped
at 100.

### 8. Grants left behind by refused sign-ins (fixed)

The allow-list refusal already revoked the grant postkeep had just
received; refusals for missing scopes or a missing mailbox didn't. Both now
revoke it (Google; Microsoft has no revocation endpoint). Test: the
revocation expectation in
`sign_in_fails_without_required_scopes_or_refresh_token`.

### 6. Subscriptions outlive deleted accounts (fixed)

Deleting an account deletes its tokens, after which postkeep can no longer
call the provider. The account page therefore first stops the account's
watcher and deletes the Graph subscription or stops the Gmail watch, and
only then revokes the Google grant and deletes the account. This is best
effort: a subscription the provider fails to delete lapses within 7 days,
and its notifications are ignored because the subscription records are
deleted with the account. Tests:
`deleting_an_outlook_account_deletes_its_graph_subscription_first` and
`deleting_the_account_stops_the_gmail_watch_being_created`.

### 7. `gmail.send` (open question)

`gmail.modify` already allows sending, so `gmail.send` adds no capability.
It is requested because the brief asked for it and because it makes the
consent screen say "send email on your behalf" explicitly. Dropping it
would shorten the consent screen by one line; it doesn't change the
verification category (`gmail.modify` is restricted either way).

## Checked and found sound

**SSRF.** All provider endpoints are fixed constants (overridable only in
tests). The Graph `@odata.nextLink` is followed only when scheme, host,
port and path prefix match the Graph endpoint, so the bearer token never
leaves Graph. Message and folder ids go into URL paths through
`join_segments`, which percent-encodes each segment, after
`parse_provider_id` limits them to `[A-Za-z0-9-_=+/]` and 1024 bytes.
Outlook and Gmail search values are split into words of letters, digits and
`@.-_+'`, lowercased, with leading `-` or `+` removed, so no word is an
operator (KQL and Gmail operators are uppercase). Outlook joins the words with
`AND`; Gmail quotes each filter as one phrase. The push endpoints fetch nothing based on request content;
the only outbound request they can trigger is the JWKS fetch from the
fixed Google URL, at most once a minute for unknown key ids. HTTP clients
don't follow redirects and verify TLS against webpki roots.

**Token handling.** Refresh and access tokens are encrypted at rest with
the existing envelope (same KDF and contexts as IMAP passwords) and
wrapped in `SecretString`; `Debug` output redacts them. Logs carry the
provider, account id and error codes, never tokens, codes, `state`,
`clientState` or push JWTs. Tokens are sent only in `Authorization`
headers, never in URLs. A refresh rejected with `invalid_grant` marks the
account as needing a new sign-in and stops retries; transient failures
don't. A 401 from Graph or Gmail triggers exactly one refresh and retry.

**Push verification.** Graph: each notification must name a stored
subscription whose provider is Graph, and its `clientState` (a 256-bit
random secret, stored only as a SHA-256 hash) is compared in constant
time; at most 100 notifications per request are considered; validation
tokens are echoed only if short and free of control characters, as
`text/plain` with `nosniff`. Gmail: the push must carry a Google-signed
RS256 OIDC token (no other algorithm, key id required) whose issuer is
`accounts.google.com`, whose audience equals the configured audience,
which hasn't expired (60 s leeway) and whose `email` is the configured
service account with `email_verified` true. Keys come from Google's JWKS
and are cached per `Cache-Control`. Tests cover wrong audience, issuer,
email, unverified email, expiry, future `iat`, a tampered payload and an
unsigned token.

**Replay.** Notifications are hints, never data: each triggers a catch-up
that reads the provider from the stored position (Graph:
`receivedDateTime` plus the ids already reported at that instant; Gmail:
history id plus recently reported ids). Replayed, duplicated or
reordered notifications therefore can't create duplicate events, and
missed ones are caught up on the next notification, renewal or Graph
`missed` lifecycle event. The outbox numbers events per account, keeps
them until the receiver accepts them, and delivers them in order with the
same `X-Webhook-Id` on retries.

**CSRF on the upstream leg.** Starting a sign-in is a same-origin POST.
It creates a single-use `state` (256-bit, stored server-side with a short
TTL), a PKCE S256 verifier, and a browser binding: a random value in a
`__Host-` cookie (`Secure`, `HttpOnly`, `SameSite=Lax`, path `/`) whose
hash is stored with the `state`. The callback consumes the `state`
atomically and requires the binding cookie to match in constant time and
the provider to match the callback path, so a callback URL lured into
another browser connects nothing (login CSRF). The upstream authorization
code is redeemed with the PKCE verifier and the client secret.

**Scope minimization.** Microsoft: `Mail.ReadWrite`, `Mail.Send`,
`offline_access`, `User.Read`, delegated only. Google: `openid`,
`gmail.modify`, `gmail.send`; not `https://mail.google.com/`, so postkeep
can't permanently delete Gmail (the delete tool refuses `permanent` for
Gmail instead), and not `email` or `profile`. Google's granular consent
is checked after sign-in: without `gmail.modify` the sign-in is refused
and the grant revoked.

**Cross-account isolation.** MCP tools build their API client from the
account bound to the access token; ids carry no account information and
are resolved only within that mailbox. Graph notifications map to an
account only through the stored subscription id; the body is never
trusted for the account. Gmail pushes map the notified address to the
Gmail account with that address and only act if that account has an
active watch. Token refresh is serialized per account. Accounts are
unique per provider and subject; the same address can exist once per
provider.

## Residual risks

- Finding 1's fix relies on Exchange Online keeping `mail` equal to a
  mailbox's primary address in a verified domain. A hybrid tenant whose
  on-premises administrator controls proxy addresses could still present
  an address in one of its own verified domains, which is the expected
  trust in that tenant.
- Pub/Sub tokens are bearer tokens valid for up to an hour. Someone who
  captures one (for example from a misconfigured proxy log) can trigger
  catch-ups for watched Gmail accounts during that hour, coalesced as in
  finding 2, but can't read or inject mail.
- Graph and Gmail calls are subject to provider quotas; heavy MCP use of
  one account can exhaust them for that account.
- Microsoft offers apps no endpoint to revoke a grant; deleting an Outlook
  account removes postkeep's tokens but the grant stays listed at
  Microsoft until the user removes it.
