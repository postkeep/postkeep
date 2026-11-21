# Configuration reference

Every setting is an environment variable. Each `serve` setting also has a
flag with the same name in kebab case (`POSTKEEP_PUBLIC_URL` is
`--public-url`); run `postkeep serve --help` for the full list.
`POSTKEEP_DATABASE_MIGRATE_URL` belongs to
[`postkeep migrate` and `postkeep storage-level`](reference/cli.md) only.

[Changing a setting](deployment.md#changing-a-setting)
shows how to change one.

## Core

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `POSTKEEP_PUBLIC_URL` | (required) | Public origin, for example `https://mail.example.com` (no path) |
| `POSTKEEP_MASTER_KEY` | | 32-byte key, hex or base64 (`postkeep generate-key`) |
| `POSTKEEP_MASTER_KEY_FILE` | | File holding the key, instead of `MASTER_KEY` |
| `POSTKEEP_PREVIOUS_MASTER_KEYS` | | Comma-separated previous keys, only while rotating (see below) |
| `POSTKEEP_PREVIOUS_MASTER_KEYS_FILE` | | File with previous keys, one per line |
| `POSTKEEP_BIND` | `0.0.0.0:8080` | Listen address |
| `POSTKEEP_SHUTDOWN_DRAIN` | `0` | Seconds to keep serving after SIGINT or SIGTERM while `/readyz` answers `503`, so load balancers stop sending requests first; a second signal ends the wait (see [deployment](deployment.md#health-and-operations)) |
| `POSTKEEP_DATABASE_URL` | `sqlite://postkeep.db` | `sqlite://...` or `postgres://...`. For a remote PostgreSQL server, add `?sslmode=verify-full`, and `sslrootcert=/path/ca.pem` when the provider uses a private CA |
| `POSTKEEP_DATABASE_MIGRATE_ON_START` | `true` | Apply pending migrations at start. With `false` the server refuses to start while any is pending; run `postkeep migrate` first |
| `POSTKEEP_DATABASE_MIGRATE_URL` | (`POSTKEEP_DATABASE_URL`) | Database URL `postkeep migrate` and `postkeep storage-level` use, for example a direct connection that bypasses a pooler |
| `POSTKEEP_DATABASE_MAX_CONNECTIONS` | `10` | Most database connections this server opens at once |
| `POSTKEEP_DATABASE_ACQUIRE_TIMEOUT` | `30` | Seconds a request waits for a free database connection before it fails |
| `POSTKEEP_DATABASE_IDLE_TIMEOUT` | `600` | Seconds an unused database connection stays open; `0` keeps it open |
| `POSTKEEP_DATABASE_MAX_LIFETIME` | `1800` | Seconds before a database connection is replaced; `0` never replaces it |
| `POSTKEEP_ALLOWED_HOSTS` | | Extra `Host` values accepted on `/mcp` besides the public host, comma-separated. `*.example.com` matches exactly one more label (`a.example.com`, not `example.com` or `a.b.example.com`). Other hosts get `403` before any token is checked |
| `POSTKEEP_ALLOWED_ORIGINS` | | Extra `Origin` values accepted on `/mcp` besides the public URL's origin, comma-separated, such as `https://app.example.com` for an MCP client that runs in a web page there. A request with any other `Origin` gets `403` before any token is checked; requests without one pass. postkeep sends no CORS headers, so a page on another origin also needs a proxy that adds them |
| `POSTKEEP_LOG` | `info` | Log filter (`tracing` syntax) |
| `POSTKEEP_LOG_FORMAT` | `text` | `text` or `json` |
| `POSTKEEP_METRICS_BIND` | | Address for Prometheus metrics at `/metrics`, such as `127.0.0.1:9091`; unset serves none. Anyone who reaches it can read it: keep it private (see below) |

`POSTKEEP_LOG` uses `tracing` filter syntax. Directives for postkeep's own
crates are kept as written, including span directives such as
`[serve_inner]=trace`. These crates stay capped no matter what the filter
says, because their trace or debug logs can include credentials, message
bodies or the upload bucket's address: `async_imap` and `imap_proto` at
`warn`, `rmcp` at `info`, `lettre` at `warn`, and `hyper_util` and `rustls`
at `info`. The cap is a separate filter on the event's own target,
so a directive with no target (`trace`, `[serve_inner]=trace`) cannot raise
those crates. A directive that names one of them, such as
`async_imap::imap_stream=trace` or `rmcp::service=debug`, is also dropped.
`lettre` only logs SMTP commands when its `tracing` feature is compiled;
this server does not enable that feature, and the cap still applies if it
is.

Each answered request, except `/healthz` and `/readyz`, gets one `info` line
from `postkeep::request_log`, "answered a request", with `request_id` (32
random hex digits), `method` (`other` for a method that is not one of the
nine standard ones), `route` (the route as the server writes it, such as
`/oauth/{provider}/callback`, left out when no route serves the address),
`status` and `ms` (milliseconds until the answer's head). A request to
`/mcp` that passed the token check adds `principal` and `tenant`. A tool
call adds `outcome` (`ok`, `tool_error` or `rpc_error`), and `tool` when the
name is one of the server's tools or of an embedding's. Every line logged
while a request runs, a tool call's included, has the same `request_id`
among its spans (`spans` in JSON): in `span` itself for postkeep's own
lines, in an outer span for a library's, such as rmcp's. That span,
`request`, has the target `postkeep::request` and the level `error`, so a
`warn` or `error` filter keeps the ids. The line never holds the query, a
value from the path, a header, a body, a tool's arguments or result, a
token, the client's IP address or an email address.
`POSTKEEP_LOG=info,postkeep::request_log=off` turns the line off and keeps
the ids.

With `POSTKEEP_METRICS_BIND` set, the server also listens on that address
and answers only `GET /metrics` there, in Prometheus text format 0.0.4;
every other path is `404`. Anyone who reaches that address can read it, so
bind it to `127.0.0.1` for a Prometheus on the same host, or on Fly.io to
`[::]:9091` with a `[metrics]` section and no service on that port. It
serves:

- `postkeep_http_requests_total` (counter), by `route` (the route as
  written, or `unmatched` when no route serves the address) and `status`;
- `postkeep_http_request_duration_seconds` (histogram), the seconds until
  the answer's head by `route`, with bounds (`le`) of 0.005, 0.01, 0.025,
  0.05, 0.1, 0.25, 0.5, 1, 1.5, 2.5, 5 and 10 seconds;
- `postkeep_tool_calls_total` (counter), by `tool` (a tool's name, or
  `unknown`) and `outcome` (`ok`, `tool_error` or `rpc_error`);
- `postkeep_imap_logins_total` (counter), by `server` (`icloud`,
  `fastmail`, `yahoo`, `gmail` or `custom`) and `outcome`: `ok`, `rejected`
  (the password), `unavailable` (the server said to try later) or `failed`
  (the network, TLS, a timeout or the protocol). A login is one per new IMAP
  connection with a stored password, a tool call's (when no idle connection
  is pooled) or a watcher's; sign-in checks are not counted;
- `postkeep_smtp_sends_total` (counter), by `server` and `outcome` as
  above, one per message an IMAP account sends or replies with. A send
  refused before it reaches the server is not counted, and neither is one
  the server refuses with a permanent reply other than 535, such as 550 for
  an unknown recipient: the recipient or the message caused it. A temporary
  reply, or none at all, is `failed`;
- `postkeep_watcher_errors_total` (counter), by `provider` (`imap`, `graph`
  or `gmail`): new-mail watcher runs that ended in an error, which the
  watcher retries. A rejected password is not one;
  `postkeep_imap_logins_total{outcome="rejected"}` counts it;
- `postkeep_watchers_refused_total` (counter): new-mail watchers not started
  because `POSTKEEP_WEBHOOK_MAX_WATCHERS` run;
- `postkeep_watchers` (gauge): the new-mail watchers running in this
  process, `0` with `POSTKEEP_WEBHOOKS=false`;
- `postkeep_db_connections` (gauge), by `state` (`idle` or `in_use`): this
  process's open database connections.

`/healthz`, `/readyz` and the scrapes themselves are not counted. No label
holds an address, a tenant, a principal, an account id, a token, or a
request's path or query.

### Rotating the master key

The sweep, and the re-wrap of data keys (step 3), run before a process serves
when previous keys are set, and, with or without them, shortly after every start
and then every hour. With more than one replica, a
replica that has not been rolled yet and runs this version writes no value
under the old master key: it encrypts a new value with its tenant's data key.
What it can do is add a data key version: when it writes for a tenant whose
data key a new replica has made or wrapped again (that includes the first key
that a new replica's sweep makes for a tenant that had none), it makes a new
one, wrapped under the old master key, and logs
`no data key of this tenant can be unwrapped`. The next pass of a new replica
wraps that version again, and the old replica adds another at its next write for
that tenant, so while it keeps writing a tenant gains at most one version for
each pass of a rolled replica, every hour on each; the rows are small, but
finish the roll within the hour. Remove the previous key only after every
replica has run a pass that moved and wrapped nothing (step 4). The re-wrap
follows the same rules as the sweep: a replica not rolled yet cannot unwrap a
data key that a new
replica has made or wrapped again, so a read of a value under that key can fail
on it until it is rolled; the user can connect again if a request hits it in the
meantime. A pending event that such a replica cannot open is held for an hour
(`POSTKEEP_WEBHOOK_OUTBOX_HOLD`), with the events after it, and then skipped. The
account's delivery position in the shared database then moves past it, so no
replica sends it: finish the roll within the hour, or stop the old ones first where
webhooks matter. Everything this version stores
(passwords, webhook secrets, filter patterns, events, provider tokens and
sign-ins in progress)
is encrypted with a data key that the master key wraps: the sweep leaves it
alone, and the re-wrap is what lets the previous key go for it. A value that an
earlier version stored directly under the master key is moved to the data key
of its tenant by the sweep, with previous keys or without: a start with them
moves it before serving, and any start moves it shortly after. An instance on
0.3.2 or earlier writes
values under the master key and cannot read a value once it is moved, so
replace such instances together (see
[deployment](deployment.md#upgrading)).

1. Generate a new key (`postkeep generate-key`).
2. Set it as `POSTKEEP_MASTER_KEY` and keep the old key in
   `POSTKEEP_PREVIOUS_MASTER_KEYS` (or `_FILE`). Roll every replica onto that
   configuration and start each one again
   ([changing a setting](deployment.md#changing-a-setting)). Leave the old
   key in place. A new value
   is encrypted with its tenant's data key, and a data key that a rolled
   replica makes is wrapped under the new master key. Replicas that are not
   rolled yet cannot unwrap a data key that a new replica has made or wrapped
   again, so expect reads to fail on them until the rollout finishes. On a
   database whose values are all still under the master key, such as one from
   0.3.x, the reads that fail include every value the first rolled replica's
   sweep moves, because the sweep makes the tenants' first data keys.
3. At startup each replica decrypts stored secrets with the new key or,
   failing that, a previous key, and moves each value that is still under the
   master key to the data key of its tenant. The log line
   `moved stored secrets to data keys` reports `converted` (values moved),
   `already_v2` (values already under a data key), `unreadable` (values no key
   could read, and values still under the master key in a row without an
   account, which are left as they are) and `lost_races` (values a writer
   changed meanwhile, which the next start looks at again). It then wraps each
   tenant's data key again under the new key if a previous key wrapped it. The
   log line `re-wrapped data keys` reports how many it wrapped again, and how
   many no configured key could unwrap, which are left as they are. A tenant's
   data key is made when a password, a webhook secret, a filter pattern, an
   event, a provider token or a sign-in in progress is first stored for it, or
   the sweep first moves a value for it (sign-ins that no tenant started use
   the `default` tenant's), so on a database that earlier versions filled both
   re-wrap counts can be 0.
4. After every replica is running that configuration, wait an hour from the
   start of the last one, or restart each one once more. A pass, or a start,
   moves anything a replica on 0.3.2 or earlier wrote under the master key after
   the previous sweep, and wraps again a data key version that a replica still
   on the old master key added meanwhile. While previous keys are set, every
   pass logs one line at `info`, `migrated stored values`, with the counts of
   step 3 (`unreadable_keys` is the second line's `unreadable`). Go on only
   when each replica that runs the job (an embedding's `runs` may leave it to
   some processes) has logged that line in that hour with `converted`,
   `lost_races` and `rewrapped` all 0. A replica that has logged no such line
   has shown nothing, so wait for it, also after a warning
   (`could not move stored secrets to data keys`, `could not re-wrap data keys`):
   it says that a pass failed, not what is left.
5. Only then remove the previous keys and start the server again. A value that
   no configured key can read is left alone. The account owner signs in again
   to replace a password. Webhook settings that cannot be read stay on the
   account page: it explains that the encryption key changed and asks for the
   URL and auth header again. Saving replaces the unreadable row, and rotating
   the signing secret asks for that re-entry instead of failing the page. A
   data key that no configured key can unwrap is counted as unreadable by every
   pass, so that count can stay above 0 for good; it does not hold up this
   step.

The sweep is idempotent and safe while serving, so a restart halfway
through simply continues. Do not drop `POSTKEEP_PREVIOUS_MASTER_KEYS` as soon
as every replica has started once: after that sweep, a replica that was still
on the old master key can have added a data key version wrapped under it, and
one on 0.3.2 or earlier can have written a value under it.

## Who can connect

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `POSTKEEP_ALLOWED_EMAILS` | (anyone) | Comma-separated addresses allowed to use the server |

`POSTKEEP_ALLOWED_EMAILS` is the main access control for a personal
server. Set it to your own address. It is checked case-insensitively:

- on the sign-in page, before anything is sent to the mail provider, so addresses
  outside the list never cause a login attempt;
- on every MCP request and every token refresh, so removing an address
  from the list cuts off its existing tokens at once;
- on the account page, before an IMAP watcher logs in, before a Graph
  subscription or a Gmail watch is created or renewed, before Graph or
  Gmail catch-up reads mail, and before a queued webhook event is sent, so
  removing an address stops its webhooks once the server runs with the new
  list ([changing a setting](deployment.md#changing-a-setting)), including
  events already waiting.

With Microsoft or Google sign-in the address is only known once the
provider sends the user back, so the check runs then: a refused address
gets no account, and postkeep revokes the grant it was just given (Google;
Microsoft has no revocation endpoint for apps).

Leave it empty only for a server that is meant to be open to anyone.

## Microsoft and Google sign-in

Step-by-step setup, including the provider consoles, publisher and app
verification, and webhooks: [Outlook](providers/microsoft.md),
[Gmail](providers/google.md).

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `POSTKEEP_MICROSOFT_CLIENT_ID` | | Application (client) ID of your Microsoft Entra app registration |
| `POSTKEEP_MICROSOFT_CLIENT_SECRET` | | A client secret of that app registration |
| `POSTKEEP_GOOGLE_CLIENT_ID` | | OAuth client ID of your Google Cloud project (web application) |
| `POSTKEEP_GOOGLE_CLIENT_SECRET` | | Its client secret |

Each provider is optional. Its button appears on the sign-in pages only
when both its ID and its secret are set; setting just one of the pair is
a startup error. Register these redirect URIs with the provider, built
from `POSTKEEP_PUBLIC_URL`:

- Microsoft: `{POSTKEEP_PUBLIC_URL}/oauth/microsoft/callback`
- Google: `{POSTKEEP_PUBLIC_URL}/oauth/google/callback`

The server logs both at startup. Refresh tokens from the provider are
stored encrypted under a data key that the master key wraps. If the
provider rejects a refresh token (for example after a password change or
a revoked consent), the account page asks the user to sign in again.

## Gmail push

New-mail webhooks for Gmail accounts connected with Sign in with Google
need Google Cloud Pub/Sub: Gmail
publishes a notification to a topic in your Google Cloud project, and an
authenticated push subscription delivers it to `POST /push/google` on your
server. Outlook accounts need nothing extra: Microsoft Graph calls
`POST /push/microsoft` directly.

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `POSTKEEP_GOOGLE_PUBSUB_TOPIC` | | Full topic name, `projects/<project>/topics/<topic>`; enables Gmail push |
| `POSTKEEP_GOOGLE_PUBSUB_SERVICE_ACCOUNT` | | Email of the service account the push subscription authenticates as (required with the topic) |
| `POSTKEEP_GOOGLE_PUBSUB_AUDIENCE` | `{POSTKEEP_PUBLIC_URL}/push/google` | Audience set on the push subscription |

Gmail push also needs Google sign-in (`POSTKEEP_GOOGLE_CLIENT_ID` and
`POSTKEEP_GOOGLE_CLIENT_SECRET`); a topic without it is a startup error.
postkeep accepts a push only with a Google-signed OIDC token whose
audience and service account match these settings, and renews each
account's Gmail watch daily (a watch lapses after seven days).

## Uploads

[`upload_attachment`](reference/tools.md#uploads) lets an agent attach a file
of up to 25 MiB that it sends with a command. Its bytes wait in an
S3-compatible bucket, sealed by postkeep; uploads are off until it is set.

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `POSTKEEP_UPLOAD_BUCKET_URL` | | The bucket's `https://` address, which turns uploads on; files go under `uploads/` in it. For example `https://<bucket>.t3.storage.dev` (Tigris), `https://<account>.r2.cloudflarestorage.com/<bucket>` (Cloudflare R2), `https://<bucket>.s3.<region>.amazonaws.com` (AWS) |
| `POSTKEEP_UPLOAD_BUCKET_REGION` | `auto` | The region its requests are signed for: `auto` for Tigris and R2, the bucket's region for AWS |
| `POSTKEEP_UPLOAD_BUCKET_KEY_ID` | | The ID of an access key for that bucket |
| `POSTKEEP_UPLOAD_BUCKET_SECRET` | | Its secret |

The address, the key's ID and its secret are set together or not at all,
else `serve` doesn't start. The address must be `https://`, with no user,
password, query or fragment, and a path of letters, digits, `-`, `.`, `_`
and `/` only. All three are hidden from `--help` and never logged. A store
on plain HTTP needs TLS in front of it.

The bucket:

- is postkeep's own and private, with no versioning, snapshots or soft
  delete, so a deleted object is gone;
- has one expiry rule on the whole bucket, making each object due for
  deletion a day after it was written, with any provider's S3 API:

  ```sh
  aws s3api put-bucket-lifecycle-configuration --endpoint-url <endpoint> --bucket <bucket> \
    --lifecycle-configuration '{"Rules":[{"ID":"postkeep-uploads","Status":"Enabled","Filter":{},"Expiration":{"Days":1}}]}'
  ```

  or, on Tigris, `tigris buckets lifecycle create <bucket> --expire-days 1`;

- takes a key that can only read, write and delete objects in that bucket.

An upload stops working at once, when it is used or its hour ends.
postkeep then clears its key and asks the bucket to remove its pieces, and
retries outstanding removals in batches, at most 100 uploads and 2 minutes a
cleanup; the expiry rule removes what they leave. Removal has no guaranteed
deadline.

postkeep bounds what it reserves at once (per tenant 2 files arriving and
250 MiB kept, per server 8 and 1 GiB), not the bucket's bill: the provider's
console shows its use. Unsetting the three settings turns uploads off; sends
that name an upload then refuse it, and the expiry rule removes its pieces.

## OAuth tokens and clients

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `POSTKEEP_ACCESS_TOKEN_TTL` | `3600` | Access token lifetime (seconds) |
| `POSTKEEP_REFRESH_TOKEN_TTL` | `2592000` | Refresh token lifetime (seconds); each refresh issues a new one |
| `POSTKEEP_MAX_CLIENTS` | `10000` | Maximum registered OAuth clients; registration answers `503` beyond it |
| `POSTKEEP_REGISTRATION_LIMIT` | `20` | Client registrations allowed per client IP in each window |
| `POSTKEEP_REGISTRATION_WINDOW` | `3600` | Length of that window (seconds) |
| `POSTKEEP_UNUSED_CLIENT_TTL` | `86400` | A client that never obtained a token is deleted this long after registering |
| `POSTKEEP_IDLE_CLIENT_TTL` | `2592000` | A client without live grants is deleted this long after it last obtained a token |

Expired codes, tokens, pending sign-ins and abandoned client registrations
are removed every 10 minutes.

## Abuse limits

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `POSTKEEP_CLIENT_IP_HEADER` | (peer address) | Header with the real client IP, set by your reverse proxy |
| `POSTKEEP_RATE_LIMIT` | `120` | Requests per minute per client IP on `/register`, `/authorize`, `/token`, `/revoke`, `/account` and `/account/*`, `/oauth/{provider}/start` and `/oauth/{provider}/callback`, and `/upload` |
| `POSTKEEP_ACCOUNT_BACKOFF_MAX` | `60` | Longest sign-in backoff for one address (seconds) |
| `POSTKEEP_IP_BACKOFF_MAX` | `900` | Longest sign-in backoff for one client IP (seconds) |

`POSTKEEP_RATE_LIMIT` does not cover `/`, `/mcp`, `/healthz`, `/readyz`,
`/.well-known/*`, static assets, or the provider push endpoints
(`/push/microsoft`, `/push/microsoft/lifecycle`, `/push/google`).
`/healthz` and `/readyz` are also outside the global concurrency cap, the
body limit and the request timeout.

Behind a reverse proxy, every request arrives from the proxy's address, so
per-client limits would lump all users together. Set
`POSTKEEP_CLIENT_IP_HEADER` to the header your proxy sets:

| Proxy | Header |
| ----- | ------ |
| Fly.io | `Fly-Client-IP` |
| Cloudflare | `CF-Connecting-IP` |
| Caddy, nginx, Traefik, most load balancers | `X-Forwarded-For` (the last entry is used) |

Only set it when the proxy always overwrites or appends to that header;
otherwise clients can forge their address. IPv6 clients are grouped by /64.

### Sign-in backoff

Failed sign-ins slow down instead of locking anyone out. After five failures,
each further failure doubles the wait before the next attempt, starting at
one second:

- **per client IP**, up to 15 minutes, so someone guessing passwords is
  slowed down hard;
- **per address**, up to only one minute, so someone guessing at
  *your* address can make you wait at most a minute, from anywhere.

A successful sign-in clears the address's backoff but not the IP's, so
signing in to one's own account does not reset the backoff for guessing at
others. The limits are kept in memory per process.

## Request limits

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `POSTKEEP_MAX_BODY_BYTES` | `1048576` | Largest accepted request body, including any attachments (OAuth endpoints: 16 KiB) |
| `POSTKEEP_REQUEST_TIMEOUT` | `120` | Seconds a request may take, including reading its body, before `503` |
| `POSTKEEP_MAX_CONCURRENT_REQUESTS` | `256` | Requests handled at once; more get `503` with `Retry-After` |
| `POSTKEEP_ACCOUNT_CONCURRENCY` | `4` | MCP requests handled at once per account; more wait up to 10 s, then `503` |
| `POSTKEEP_MAX_CONNECTIONS` | `1024` | Open HTTP connections; further connections are closed at once |

Request headers must arrive within 15 seconds of a connection becoming
active, which stops slow-header ("slowloris") attacks. `/healthz` and
`/readyz` are exempt from the concurrency and timeout limits so a busy
server is not restarted by its health check or taken out of rotation by its
readiness check. Mail operations use `POSTKEEP_MAIL_TIMEOUT` (30 seconds).
An IMAP search has a separate timeout for listing candidates and for each
batch it fetches. A search with header filters starts no more fetches after
one mail timeout, but a fetch already in progress can finish.

`/upload` keeps its own limits instead of the body limit and timeout: a file
of up to 25 MiB, 10 minutes in all and 30 seconds without a byte.

## IMAP connection reuse

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `POSTKEEP_IMAP_POOL_IDLE` | `60` | Seconds an idle IMAP session is kept for the next tool call of the same account; `0` turns reuse off |

Tool calls reuse an idle IMAP session of the same account instead of
connecting and logging in again. Sessions are keyed by account and by a
fingerprint of the stored credentials, so they are never shared between
accounts and a changed password never reuses an old session. A session goes
back to the pool only after a clean result, must answer `NOOP` before reuse,
and every operation selects its folder again. At most two idle sessions are
kept per account (256 in total); they are closed after the idle time and at
shutdown. Sending mail always uses a fresh SMTP connection.

## New-mail webhooks

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `POSTKEEP_WEBHOOKS` | `true` | Offer opt-in new-mail webhooks on the account page; `false` hides them and starts no watchers |
| `POSTKEEP_WEBHOOK_MAX_WATCHERS` | `100` | Accounts watched at once. An IMAP webhook keeps one IMAP connection open; Outlook, and Gmail with Sign in with Google, do not. A paused webhook still uses a slot: IMAP keeps that connection, and Gmail and Graph keep renewing their watches. Turning the webhook off frees the slot. |
| `POSTKEEP_WEBHOOK_RETRY_INTERVAL` | `3600` | Seconds between delivery attempts while a webhook is paused after repeated failures, and the longest wait before it is paused. From 1 to 86400. |
| `POSTKEEP_WEBHOOK_OUTBOX_RETENTION` | `604800` | Seconds events are kept when the account has no override (7 days). The cap counts delivered and undelivered events. From 3600 to 31622400, and at most `POSTKEEP_WEBHOOK_OUTBOX_MAX_RETENTION`. |
| `POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS` | `1000` | Events kept per account, delivered or not, when the account has no override. From 1 to 100000, and at most `POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS_LIMIT`. |
| `POSTKEEP_WEBHOOK_OUTBOX_MAX_RETENTION` | `2592000` | Longest retention an account may set (30 days). From 3600 to 31622400. |
| `POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS_LIMIT` | `10000` | Most events one account may keep. From 1 to 100000. An event is about 1 KB of encrypted JSON, so 10000 events is about 10 MB per account, and 100 accounts at that ceiling is about 1 GB. The event cap is the disk bound: a busy inbox reaches it before the retention clock does. |
| `POSTKEEP_WEBHOOK_OUTBOX_HOLD` | `3600` | Seconds an event that this server cannot open is held, with the events after it, before it is skipped with a warning, counted from when the event was stored. A replica that has not been rolled onto the keys that wrote it cannot open it; holding writes nothing, so a replica that can open it is not held up. From 0 to 31622400; 0 skips at once. An event in a newer format than this version reads is held until a version that reads it sends it or the outbox removes it. |
| `POSTKEEP_WEBHOOK_FILTER_MAX_RULES` | `1000` | How many of a mailbox's [filter rules](webhooks.md#filter-rules) count, oldest first; newer ones judge nothing and none can be added past it. From 0 to 2000; a higher value stops the server at start. An embedding's usage hook replaces it per mailbox. Not used while `POSTKEEP_WEBHOOKS=false`. |

Users turn webhooks on for their own account at `/account`. A watcher per
enabled webhook waits for new Inbox mail: IMAP `IDLE` (renewed every 25
minutes, or a poll every minute if the server has no `IDLE`), a Graph
subscription, or a Gmail watch. A paused webhook stays enabled, so it
still uses one slot: IMAP keeps its connection, and Gmail (`users.watch`)
and Graph (the subscription) keep renewing on their usual schedule. A
pause does not add provider calls. Turning the webhook off stops that
watcher, frees the slot, and stops the provider watch (Gmail `users.stop`,
Graph subscription delete). It waits 3 seconds
to batch a burst. A large backlog can be several events. Watchers need a
process that keeps running: on platforms that stop idle instances, events
are only sent while an instance is up (see
[deployment](deployment.md#new-mail-webhooks)). The payload, signature and
retry rules are in [webhooks](webhooks.md).

## Mail providers

Users sign in with an app password at one of the providers this server offers.
The sign-in page shows a provider picker when more than one is offered, with
the default provider picked. An address at a provider's own domain
(`@icloud.com`, `@fastmail.com`, `@yahoo.com`, ...) always uses that provider:
the picker switches to it as the address is typed, and the server uses it even
when the picker names another one. For any other domain, the provider picked
is used.

| Variable | Default | Meaning |
|---|---|---|
| `POSTKEEP_IMAP_PROVIDERS` | `icloud,fastmail,yahoo,gmail` (none when `POSTKEEP_IMAP_HOST` is set) | Comma-separated presets to offer: `icloud`, `fastmail`, `yahoo`, `gmail` |
| `POSTKEEP_IMAP_HOST` | (unset) | IMAP host of a custom mail server, offered instead of the presets unless `POSTKEEP_IMAP_PROVIDERS` lists them |
| `POSTKEEP_IMAP_NAME` | `Custom mail server` | Name of the custom server on the sign-in page |
| `POSTKEEP_IMAP_PORT` | `993` | IMAP port of the custom server |
| `POSTKEEP_IMAP_SECURITY` | `tls` | `tls` or `plaintext` (local test servers only) |
| `POSTKEEP_SMTP_HOST` | the IMAP host | SMTP host of the custom server |
| `POSTKEEP_SMTP_PORT` | `587` | SMTP port of the custom server |
| `POSTKEEP_SMTP_SECURITY` | `starttls` | `tls`, `starttls` or `plaintext` (local test servers only) |
| `POSTKEEP_MAIL_TIMEOUT` | `30` | Mail timeout in seconds; IMAP searches use separate timeouts for the initial listing and each fetch batch |

| Preset | IMAP | SMTP | App passwords |
|---|---|---|---|
| `icloud` | `imap.mail.me.com:993` (TLS) | `smtp.mail.me.com:587` (STARTTLS) | [Apple](https://support.apple.com/en-us/102654) |
| `fastmail` | `imap.fastmail.com:993` (TLS) | `smtp.fastmail.com:465` (TLS) | [Fastmail](https://www.fastmail.help/hc/en-us/articles/360058752854-App-passwords) |
| `yahoo` | `imap.mail.yahoo.com:993` (TLS) | `smtp.mail.yahoo.com:465` (TLS) | [Yahoo](https://login.yahoo.com/account/security) |
| `gmail` | `imap.gmail.com:993` (TLS) | `smtp.gmail.com:465` (TLS) | [Google](https://myaccount.google.com/apppasswords) |

Users can't type in a server address: only the operator can add a custom
server, so the sign-in form can't be used to make this server connect to
arbitrary hosts.

Each account records the provider it signed in with. Accounts created by
versions before 0.2 recorded none; at startup they are assigned the default
provider (the custom server if `POSTKEEP_IMAP_HOST` is set, otherwise iCloud
Mail, otherwise the first provider offered). The first two are the
servers those accounts already used. Removing a provider from
`POSTKEEP_IMAP_PROVIDERS` stops its accounts from working until it is offered
again; their data is kept.

A version from before the Gmail preset does not know `gmail`: it reports a
Gmail account's provider as not offered, and it refuses to start when
`POSTKEEP_IMAP_PROVIDERS` names it. In a rolling upgrade, add `gmail` to a list
you set yourself only once every replica runs the new version.

Upgrading from 0.1 with the default settings changes nothing for existing
iCloud accounts. To keep offering only iCloud Mail, set
`POSTKEEP_IMAP_PROVIDERS=icloud`. Before 0.2, setting `POSTKEEP_IMAP_HOST`
replaced iCloud; it still does unless `POSTKEEP_IMAP_PROVIDERS` is also set.
The tests use it to point the server at GreenMail.
