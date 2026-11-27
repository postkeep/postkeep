# Embedding postkeep

postkeep is also a Rust library: your own binary can run the server with
additions, such as pages, its own way of deciding who an MCP caller is,
tenants, tools, usage limits, or several processes on one database. With
nothing added it serves exactly what `postkeep serve` serves:
`crates/server/tests/pins.rs` checks that, and `extension_contract.rs`
beside it checks that every extension point is called.

## Before you start

The crates are not on crates.io, and their API can change in any 0.x
release. Depend on them by git revision, all on the same one:

```toml
[dependencies]
postkeep = { git = "https://github.com/postkeep/postkeep.git", rev = "<commit>" }
postkeep-auth = { git = "https://github.com/postkeep/postkeep.git", rev = "<commit>" }
postkeep-store = { git = "https://github.com/postkeep/postkeep.git", rev = "<commit>" }
axum = "0.8"
clap = { version = "4.6", features = ["derive"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

The extension points take `axum` 0.8 routers and `rmcp` 3.9 tool types,
and the crates need Rust 1.94. `cargo doc --open -p postkeep` documents
every method; `crates/server/tests` and `crates/auth/tests` hold worked
examples.

## A minimal embedding

```rust
use std::sync::Arc;

use axum::{Router, routing::get};
use clap::Parser;
use postkeep::cli::ServeArgs;
use postkeep_auth::{CheckFuture, NewMailbox, Refusal, UsageHook};
use postkeep_store::Store;

#[derive(Parser)]
struct Args {
    #[command(flatten)]
    serve: ServeArgs,
}

/// Lets each tenant connect at most three mailboxes.
struct ThreeMailboxes(Store);

impl UsageHook for ThreeMailboxes {
    fn before_connect<'a>(&'a self, mailbox: NewMailbox<'a>) -> CheckFuture<'a> {
        Box::pin(async move {
            match self.0.for_tenant(mailbox.tenant).accounts_in_tenant().await {
                Ok(accounts) if accounts.len() < 3 => Ok(()),
                Ok(_) => Err(Refusal::new("This plan connects up to three mailboxes.")),
                Err(_) => Err(Refusal::new("Try again in a minute.")),
            }
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), postkeep::Error> {
    let args = Args::parse();
    let store = postkeep::open_store(&args.serve).await?;
    postkeep::ServerBuilder::new(args.serve)
        .store(store.clone())
        .usage_hook(Arc::new(ThreeMailboxes(store)))
        .route(Router::new().route("/status", get(|| async { "ok" })))
        .serve()
        .await
}
```

`ServeArgs` reads the same `POSTKEEP_*` variables and flags as `postkeep
serve` ([configuration](configuration.md)). `open_store` opens the
database as the server would, and `store` hands it to the server, so your
code shares its pool (`Store::pool`). Your tables can live in the same
database; postkeep's are not a stable interface, so use `Store`'s methods
for them.

`listener` hands the server a `std::net::TcpListener` you bound, such as
one on port 0 whose address you read first: `serve` then leaves
`POSTKEEP_BIND` unused and logs the listener's address.
`POSTKEEP_METRICS_BIND` is unaffected.

`serve` runs until SIGINT or SIGTERM, then drains and stops like the
binary ([health and operations](deployment.md#health-and-operations)). It
sets up logging from `POSTKEEP_LOG` and fails if a global `tracing`
subscriber is already set: add your crates to `POSTKEEP_LOG`
(`info,my_app=debug`) instead, and run one server per process. The
request log covers your routes too, by their route as written.
So do the metrics on `POSTKEEP_METRICS_BIND`, where the route is a label.
Register a route with a value in its path, such as `/w/{id}`, never one
route per tenant or id.

## Extension points

`ServerBuilder` has these methods, and `app::Extensions` the same ones for
tests that build the router with `app::router_with` (`store` and `listener`
are the builder's alone):

| Method | Without it | Use it for |
| ------ | ---------- | ---------- |
| `route` | Nothing extra | Your own pages and endpoints, behind the same request limits. Handlers can extract `axum::Extension<AuthState>`. A path the server already serves panics at start |
| `default_pages(false)` | `/` and `/account` are served | Leaves out `/`, `/account`, `POST /oauth/{provider}/start` and the upstream OAuth buttons on `/authorize`. Keeps `/authorize`, the MCP OAuth endpoints, `/oauth/{provider}/callback`, `/mcp`, `/healthz` and `/readyz`. |
| `principal_resolver` | This server's access tokens, each for one mailbox | Your own keys or tenants, and several mailboxes per caller (`selects_mailboxes`) |
| `sign_in_hook` | The mailbox sign-in page | `/authorize` for the resources the hook claims: your own sign-in or consent page, finished with `AuthState::approve_sign_in` or `deny_sign_in` |
| `continuation_hook` | `AuthState::start_upstream_sign_in` fails | Microsoft or Google sign-ins that your page starts to add a mailbox to a tenant |
| `invalid_request_page` | The server's own "This link can't be used" page, and its own pages at `/oauth/{provider}/callback` | Your own error page for a request `/authorize` refuses (no or unknown client, a redirect address that is not registered or allowed, an invalid request it cannot send back to a web app); a request that goes back to the app, and the server's `500`, `429` and `403` pages, stay the server's. With `callback_page`, your own pages for a Microsoft or Google sign-in that the callback does not finish, for its other pages and for the request limit's `429` there, from the server's status, title and text; a finished sign-in stays the server's |
| `tool_extension` | No extra tools, skills or checks | Tools and skills for the callers you pick (`tools`, `skills`), a pure caller-specific check that removes a server tool from the list and refuses its calls (`hides_tool`; hidden names cannot be reused by extensions), static mailbox capabilities from the live deployment (`ExtensionCall::mailbox_capabilities`), instructions, the website and icons `initialize` reports (`server_info`), a `check` before dispatching a visible tool, after resolving the caller’s selection (hidden or unknown tool names bypass checks and usage hooks), and the `message` of the webhook tools when the mail server rejected a mailbox's password (`password_rejected`; the default sends the person to the account page, which an embedding that turns it off should replace, and `Store::password_rejected_at` tells its own pages), and what the webhook tools say about a webhook that is missing, can't be read or has no usable URL, and about filter rules that can't be read or compiled (`webhook_problem`; the defaults name the account page and, for rules that can't be decrypted, the operator's previous master key) |
| `usage_hook` | No limits | Holding sends for the user's yes, limits on new mailboxes per tenant, tool calls, sends, outbox ceilings and how many filter rules count for a mailbox, and how each tool call it allowed ended (`after_call`) |
| `watch_ownership` | This process watches every mailbox and runs every job | Several processes on one database. `owns`, `forward` and `runs` must answer at once, from memory, and `forward` drops what it gets unless you implement it |
| `per_request_resources(true)` | One resource, at the public URL | Each host in `POSTKEEP_ALLOWED_HOSTS` (which takes `*.example.com`) its own protected resource, with strict audience checks |
| `resource_prefix` | No prefix | Each name under a prefix, such as `/w/<name>/mcp`, its own resource; turns on per-request resources |
| `readiness_check` | `/readyz` checks the database and migrations | `/readyz` also waits for your check, such as a warm-up |

`runs` is asked before each run of a shared job: `SharedJob::Purge` (deletes
expired sign-ins, codes and tokens, abandoned client registrations and events
past their outbox limits; at start and then every 10 minutes) and
`SharedJob::Reencrypt` (moves values still under the master key to data keys and
wraps data keys again, see
[Data keys and key wrappers](#data-keys-and-key-wrappers); at start and then
every hour). `Reencrypt` is safe in several processes at once but repeats the
work. `SharedJob` is `#[non_exhaustive]`: a wildcard arm that answers `false`
leaves a job you did not name undone in every process.

## Tenants and migrations

A principal resolver answers with an `Authenticated`: the `principal`
(who is calling, an opaque string), its `tenant`, the mailbox tools use by
default (`account_id`) and all it may use (`mailboxes`). Build one with
`Authenticated::for_account` and its `with_*` methods. With
`selects_mailboxes`, tools take a `mailbox` argument naming one of those.

For a connection that can act in several tenants, enable `selects_mailboxes`,
build one `Authenticated` per tenant and give them to `with_tenancies`, default
first. A resolver can name a `tenant_argument`, an optional tenant ID on tool
calls; the embedding advertises it in its own tool schemas, not the server's.
With a tenant ID, `mailbox` is looked up only there. Otherwise an address
matching in several of the caller's tenants needs a mailbox ID instead.
With neither argument the call uses the first tenancy's default mailbox.
Tools and hooks see the selected tenancy's caller; `tenancies()` still
lists the full connection, default first.

The request log writes `principal` and `tenant` on authenticated MCP requests
([configuration](configuration.md)), using the pair from the selected tenancy
when a call narrows it. Keep addresses and secrets out of both: IDs are enough.

An address can be connected once per tenant. `Store::for_tenant` scopes
address lookups and new accounts (lookups by ID are not scoped). The
server alone only uses the tenant `default`, and SQLite keeps addresses
unique across the database, so tenants sharing one need PostgreSQL.

With `POSTKEEP_DATABASE_MIGRATE_ON_START=false` the server refuses to
start while a migration is pending: run `postkeep migrate`, or
`postkeep::migrate` from your binary, first. Keep your own migrations out
of postkeep's `_sqlx_migrations` table, whose migrator refuses versions it
doesn't know; with sqlx, give yours its own table
(`Migrator::dangerous_set_table_name`).

Raise the storage level ([deployment](deployment.md#storage-level-and-rollbacks)) the same way, once every
instance runs a version that reads it: `postkeep storage-level raise`, or
`Store::raise_storage_level` from your binary.

## Data keys and key wrappers

A store keeps a data key for each tenant: 32 random bytes, numbered from
1, stored in the `data_keys` table only after a key wrapper has wrapped
them. `Store::data_key` returns the newest key it can unwrap for the store's
tenant (`Store::for_tenant`) and its version, and makes version 1 on first use;
`Store::data_key_version` returns one version, or `StoreError::Decrypt`
if there is none. The store remembers the keys it unwrapped, so a wrapper
normally unwraps each key once per process.

A `KeyWrapper` (from `postkeep_store`) does the wrapping. A key
encryption key (KEK) is a `Kek`: a provider, an ID and a version. `wrap`
and `unwrap` return futures and take the tenant, which `wrap` must bind to
its result so that only `unwrap` for the same tenant returns the key.
`wrap` returns a `Wrapped`: the bytes and the `Kek` it wrapped with, which
a key service can only tell in its answer. The table keeps the KEK's three
parts beside the bytes, and `unwrap` is given them back. `current` is the
KEK that new wraps would use as far as the wrapper knows: answer it from
memory, because it can lag behind a rotation, and the table never records
it. A new key is unwrapped to check it before it is stored, and when
several processes make the first key at once, the one stored first wins
and all of them use it.

Choose the errors of `unwrap` with care. `StoreError::Decrypt` says that
the value can never be unwrapped with the keys the wrapper holds (it is
another tenant's, corrupt, or wrapped by a KEK the wrapper doesn't have),
and postkeep reads it as unreadable for good. If that is the answer for
every key of a tenant, as after the master key was replaced, `data_key`
adds the next version and logs a warning, and the values under the older
versions stay unreadable until they are entered again. So a `Decrypt` that
was wrong costs an extra key version: the older keys stay, and unwrap again
when the wrapper does. Anything that may succeed later, such as a key
service that doesn't answer or is sealed, is `StoreError::KeyWrap`, which
skips no key and makes none: a sealed vault must answer `KeyWrap`. A
`Decrypt` for a key just wrapped is `KeyWrap` to the caller, and stores nothing.
`unwrap` is given a stored key whatever its provider, also one that an
earlier wrapper made if you replaced it: answer `Decrypt` for a provider
you don't know, or hand the key to the wrapper that made it.
`DataKey::from_bytes` returns `KeyWrap` for a wrong length; after an
authenticated unwrap that never goes away, so return `Decrypt` then, as
`LocalKeyWrapper` does.

When a KEK changes, a new master key or a key service you moved on, call
`Store::rewrap_data_keys`. For each data key of every tenant whose stored KEK
differs from `current`, it calls `unwrap` with the KEK in the row and `wrap`.
If `wrap` returns the KEK the row has, as it can while `current` lags, that key
is left alone and not counted. Otherwise it calls `unwrap` on the result to
check that the wrapper reads back the key, and stores the new bytes and the KEK
that `wrap` returned in one statement that changes the row only if it still
holds what was read. A read-back that fails stops the pass with an error and
leaves the row untouched. So passes in several processes, or a crash, lose no
key; the key itself does not change. The result counts the keys wrapped again
(`rewrapped`) and those that can never be unwrapped (`Decrypt`; `unreadable`),
which stay as they are and are counted at every pass. The rows of a destroyed
tenant are neither visited nor counted. Any other error ends the pass and is
returned. The server calls it, through the store's wrapper, after
the sweep: before it serves when previous master keys are set, and, with or
without them, shortly after it starts and then every hour. So a change of your
wrapper's KEK is picked up within the hour. After a pass wraps a key again,
every other process asks the wrapper once for that tenant at its next write, and
a write fails with `KeyWrap` if the key service does not answer then; reads keep
the key they hold. A key stored under the KEK that `current` names is not looked
at, so a pass says nothing about a KEK that `current` still names: make
`current` name the KEK that `wrap` uses before the pass you rely on. Retire
the old KEK only after such a pass on every process, with the old KEK still
available, reports nothing re-wrapped: a process still on the old KEK may make
a tenant's first key or a new version.

`Store::destroy_data_keys`, on a store scoped to a tenant, destroys that
tenant's data keys, so that nothing sealed under them opens again: not through
the database, and not from a logical dump (such as `pg_dump`) taken afterwards.
That covers the passwords, webhook secrets, filter patterns, events and tokens
of the tenant's accounts, and the sign-ins in progress started for it (those
that no tenant started are `default`'s). In one transaction, which on PostgreSQL
holds other writes to `data_keys` back for its few statements, it deletes the
keys. It leaves rows that hold none (provider `destroyed`, among them one at
version 9223372036854775807 that marks the tenant destroyed), and returns how
many keys it deleted. From then on `data_key`, `data_key_version`, every read of
such a value, and every write that stores or reads a secret of the tenant answer
`StoreError::KeysDestroyed`, and no key is made for the tenant again. A build
from before this one makes none either: it cannot unwrap those rows, and every
version it could add is taken, so its writes fail with `KeyWrap`. Writes that
touch no secret still work, among them `Store::delete_account`, which needs no
key. `KeysDestroyed` is not `Decrypt`, so no caller skips, overwrites or removes
anything because of it: stop serving the tenant, and delete its accounts. Do
first whatever needs the tenant's secrets. Call it on a clone of the store that
serves the tenant, such as `for_tenant` on your server's store: clones share one
cache of keys, which forgets the tenant's at once. It is safe to call again, and
it returns 0 when there is nothing left to delete; after restoring a backup from
before, call it again. It asks the key wrapper nothing. It refuses the `default`
tenant, which holds every sign-in that no tenant started, and a tenant that
still has a value under the master key (`StoreError::InvalidInput`).
`Store::reencrypt` moves each such value that a configured master key opens. For
one that no key opens, delete the account that holds it; a sign-in in progress
goes when it expires. Then call it again. The server has no command for it,
because it serves only `default`.

What it doesn't cover: a store with a cache of its own (in another process, or
from another `Store::connect` or `with_key_wrapper`) keeps the keys it has
already unwrapped. It reads with them until it next asks for one of the tenant's
keys (a write that stores a secret, or `data_key`) or restarts. A backup from
before the destruction still holds the wrapped keys, which the master key
unwraps. So can physical copies taken after it, until the space is reused and
the log and the copies expire: the SQLite file and its write-ahead log, volume
snapshots, and PostgreSQL base backups and WAL archives. The plain columns
(addresses, webhook URLs, the action, field and kind of filter rules, delivery
summaries, times) stay until their rows are deleted. A value under the master
key that is put back into a row opens again.

Without a wrapper of your own, a store uses `LocalKeyWrapper`: AES-256-GCM
under the master key, with the tenant as associated data. It names the
provider `local` and the KEK by an ID derived from the master key, and it
also unwraps keys wrapped under `POSTKEEP_PREVIOUS_MASTER_KEYS`. To use
your own, pass an `Arc<dyn KeyWrapper>` to `Store::with_key_wrapper` on the
store that `open_store` returns, before `for_tenant` or any clone, which
keep the wrapper they had; `ServerBuilder` has no method for it.

postkeep writes everything it encrypts with data keys: IMAP passwords, webhook
secrets (the signing secret and the custom header value), the patterns of filter rules,
the payloads of stored events, the tokens of Microsoft and Google accounts, the keys and digests
of uploaded files, and the secrets of sign-ins in progress (the PKCE verifier, the pending request ID and your continuation). A
password, and the tokens that a sign-in creates, are written in the tenant of the
store that saves them. Webhook secrets, filter patterns, events and token refreshes are written
in the tenant of their account, and a sign-in in progress in the tenant it was
started for, else `default`, whichever store saves them. A write uses the key
that `data_key` finds or makes for that tenant. The master key now decrypts
directly only a value that an earlier version wrote and that has not been saved
again or moved by the sweep; an event is never saved again, so one stored before
stays until the sweep moves it or the outbox removes it, and a sign-in in
progress is removed when it is used or expires.
postkeep reads the data-key format in all twelve encrypted columns:
`v2.<version>.<base64url of nonce and ciphertext>`,
AES-256-GCM under that version of the key of the value's tenant, with
`postkeep/v2/<tenant>/<table>.<column>/<row key>` as associated data. In
the tenant, `%` is written `%25` and `/` is written `%2F`; the row key is
as it is. The tenant is that of the row's account (for a sign-in, the
tenant it was started for, else `default`), not that of the store that
reads, and a copy in another tenant, column or row doesn't decrypt. The
row key is the email address for an IMAP password, the account ID for
webhook and token
columns, the hash of the OAuth `state` for a sign-in, the event ID for an event,
the rule ID for a filter pattern, and the upload's `id_hash` for an upload's key
and file digest. Don't change the `tenant` of an account: its values stop
opening. Only `StoreError::Decrypt`, which also covers a key version that
doesn't exist, makes a value unreadable. Any other error, such as your
wrapper not answering, goes to the caller, so it never makes an event be
skipped, a webhook be reported unreadable, a password be overwritten or a
sign-in in progress be taken away: taking one opens it before it removes it, so
on such an error it stays and the person can finish it once the service
answers. A write that can't get its key for such a reason fails with that error
and stores nothing; the new-mail watcher then keeps its position and tries again,
and a token refresh leaves the stored tokens as they are and does not mark the
account as needing a new sign-in.

A value whose text starts `v<number>.` with a number above the newest format
the build reads (`v3.` and up) is in a format that a newer build may have
written. It is `StoreError::NewerFormat`, not `Decrypt`: the build cannot tell
whether it is sound, and a build that reads the format may open it. It goes to
the caller like any other error above (a pending event is reported in `held`), so for it an event is not skipped, a
webhook is not reported unreadable, a password is not overwritten and a sign-in
in progress is not taken away. The sweep leaves it as it is and counts it in
none of its counts. Text that only looks like it, such as `v03.`, is `Decrypt`.

`Store::reencrypt` is the sweep. It opens each value that is still under the
master key, one that an earlier version wrote, with the master key or a previous
one, and moves it to the data key of its row's tenant, making that key if the
tenant has none. The server runs it before it serves when previous master keys
are set, before the re-wrap, and does not start if it fails; with or without
them it runs it again shortly after it starts and then every hour. A pass is
logged as `migrated stored values`, at `info` while previous master keys are set
and otherwise when it moved a value, lost a race or wrapped a key again, else at
`debug`. An embedding may run it at any time, also in several processes at once,
and calls `Store::rewrap_data_keys` after it. Retire a previous master key only
after a pass of both on every process moves nothing, loses no race and wraps
nothing again.

It returns a `Reencrypted` with four counts: `updated` (`converted` in the
server's log), the values it moved; `already_v2`, those that start with `v2.`,
which it counts without opening them, so one that is not a valid value counts
here too; `unreadable`, those that no configured key opens, values whose
tenant's data keys were destroyed, and those still under the master key in a webhook, token or event row whose account does not
exist, which stay as they are; and `lost_races`, those that changed between
being read and being replaced, which the next pass looks at again. The struct is
`#[non_exhaustive]`, so an embedding reads its fields and cannot build it or
destructure it without `..`. A key wrapper that does not answer ends the pass
with `StoreError::KeyWrap`, with what it moved still moved. A build from before
data keys cannot read what the sweep moved, as the next paragraph says.

A build from before postkeep read the data-key format, such as 0.3.2 or
earlier, loses the stored events it cannot open, for every process
([Upgrading](deployment.md#upgrading)). So move a pin to a commit that
writes data keys in two steps: first to one that reads them and writes no
data-key values, deployed to every process, and only then to the one that
writes. The last commit that reads them and writes no data-key values is
`eb43b31e03b183093e18286b7eeef5832b1cf5cd`, the parent of
`feat(store): write passwords and webhook secrets under data keys`; no tag
points at it. Once a process has written, do not go back to a pin that cannot
read them. The `Reencrypt` job moves every older value to data keys shortly
after a process starts, so such a build then reads none of them.

## Holding sends for the user's yes

An embedding's `UsageHook::holds` answers whether a call waits for the
user's yes. The default answers no. Only tools that can hold a call ask:
`send_message` and `reply_to_message`, after their address checks and only
without `hold_id`. The question carries the whole `ToolCall`, so the hook
can decide by caller or tenant without keeping its own list of tool names.
The tool schema caps the number of files (`maxItems` on `attachments`);
postkeep checks the count before decoding files or asking `holds`.
For `holds`, outgoing attachments are names, MIME types, sizes and SHA-256
digests, not the bytes. A forward adds a `forwarded` digest of the original.
The extension check, `before_call` and `after_call`
get attachment arguments as sent, including their bytes as base64 or text.
An uploaded file is there as its `upload_id`, name and type, and for `holds`
as the stored upload's size and digest, like a typed file of the same bytes.
No hook sees its bytes, and the token that writes it is only in the answer of
`upload_attachment`, which an agent then puts in a command.
Uploads are on when `ServeArgs` gets the bucket settings of
[Uploads](configuration.md#uploads); a router built with `app::router_with`
takes the bucket as `AppConfig::bucket`, and its cleanup is
`app::purge_on_schedule` with the same bucket.

A holding call sends nothing. It answers `status: "held"`, with `hold_id`,
`expires_at` and `next`: show the user exactly the message, its recipients
and whole body, and every attachment by name and size. For a forward, also
show the original message and its files by name and size. Ask whether to send,
unless they have already seen exactly this message and said yes to it; a request to send it is not a yes. Only after that yes,
call the same tool with the same arguments and `hold_id`. The store keeps
only a fingerprint, not the message. Holds expire and there is a soft cap
per caller and mailbox. A changed message needs a new hold and its own yes.

Scripts must check `status`: a held answer is not a sent message. The
holding call never asks `before_send`, and `after_call` hears `Done` with
`CallEnd::held`. Only a matching, single-use confirming call asks
`before_send`; a later refusal or failure uses the hold up too.

Keep the app's own confirmation prompt on. An agent can make both calls,
so a hold is not proof that the user said yes. An app may ask at both calls;
its prompt is the one an agent steered by untrusted mail cannot answer.

## Rules for hooks

- Call `AuthState::start_upstream_sign_in` only for a same-origin `POST`
  from a person you signed in who may change that tenant, with the tenant
  taken from their session, never from the request.
- Accept `approve_sign_in` and `deny_sign_in` only as same-origin form
  posts. A pending request's ID is a secret: it is all it takes to approve
  or deny the request.
- Tokens from a sign-in hook act for a principal, never for a mailbox; the
  default resolver refuses them, and yours reads them with `access_grant`.
- Callers see a `Refusal`'s message, a `Resolution::Refused` text (the
  `401`'s `error_description`, so never the token) and a readiness reason
  (the body of a public `503`).
- `UsageHook::before_connect` and the insert after it are not atomic: two
  sign-ins at the same moment can both pass.
- `UsageHook::outbox_ceilings` also sets how many of a mailbox's filter
  rules count (`OutboxCeilings::with_max_filter_rules`). The watchers ask
  once per batch of new mail and judge it with the answer. So a hook that
  can't work out the number answers `None` or leaves it out, never a
  fallback number: a lower number drops mail that only a newer allow rule
  matches.
- `UsageHook::after_call` runs once for each tool call the checks allowed,
  on the call's task before its answer goes, so it must not block: spawn
  any write. A call that stopped before it answered ends `Failed`, and its
  tool may have done its work. A call whose client went away, or whose
  request timed out, runs on to its end, which the hook then hears.
- Delete an account the way the account page does. First await
  `AuthState::before_account_deleted` for it, while its tokens can still
  be read: before `Store::delete_account`, and before
  `Store::destroy_data_keys` for its tenant. The deletion listeners undo
  what was set up at the provider, such as the webhook watchers' Graph
  subscription or Gmail watch. Then call `AuthState::notify_account_changed`
  whatever happened, also when the deletion failed or stopped early: a
  listener may have stopped the account's watcher, and the notification
  starts it again.

The [threat model](security/threat-model.md) lists what the server
enforces around each hook.
