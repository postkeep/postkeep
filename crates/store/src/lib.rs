//! Storage for postkeep: accounts (IMAP accounts with encrypted app
//! passwords, and Microsoft or Google accounts with encrypted OAuth
//! tokens), the OAuth 2.1 state (clients, authorization codes and tokens),
//! account page sessions, webhooks with their event outbox, and push
//! subscriptions.
//!
//! The backend is chosen at runtime from the database URL through `sqlx`'s
//! `Any` driver: SQLite (`sqlite://...`, the default) or PostgreSQL
//! (`postgres://...`, with the `postgres` feature). The schema is migrated
//! automatically on [`Store::connect`].
//!
//! Security properties:
//!
//! * App passwords, Microsoft and Google tokens, webhook secrets, the patterns of
//!   webhook filter rules, stored events, and the secrets of a provider sign-in
//!   in progress are encrypted
//!   with AES-256-GCM under a [`MasterKey`] or a tenant's data key (below),
//!   with a fresh random nonce per value and associated data naming the value
//!   and its row (the email address for passwords; the hash of the OAuth
//!   `state` for a sign-in).
//!   Those sign-in secrets are the PKCE verifier (`verifier_ciphertext`) and,
//!   when the sign-in continues a pending authorization request, that request
//!   ID (`request_id_ciphertext`), or, when an embedding started it for one of
//!   its tenants, the embedding's continuation (`continuation_ciphertext`).
//!   The key can be rotated: values written under a previous key stay
//!   readable (see [`Store::connect_rotating`]) until [`Store::reencrypt`]
//!   moves them to data keys, and data keys wrapped under a previous
//!   key stay readable until [`Store::rewrap_data_keys`] wraps them again.
//! * Every one of those values is read in two formats: directly under the
//!   master key, and as `v2.`, under a tenant's data key ([`Store::data_key`])
//!   that the master key wraps. The associated data of a `v2.` value names the
//!   tenant stored in the value's row, which is not always the tenant of the
//!   [`Store`] that reads it, the table and column, and the row's key, so a
//!   copy in another tenant, column or row does not decrypt. Every value a
//!   store writes is in the second format, under the newest key of the row's
//!   tenant that the store can unwrap: IMAP passwords, webhook secrets (the
//!   signing secret and the custom header value), the patterns of webhook filter
//!   rules, stored events, the refresh
//!   and access tokens of Microsoft and Google accounts, and the secrets of
//!   sign-ins in progress (bound to the tenant an embedding started the
//!   sign-in for, else `default`). Only a value that an earlier version wrote
//!   is still under the master key, until it is saved again or
//!   [`Store::reencrypt`] moves it, as the server's pass does shortly after it
//!   starts and then every hour. An event is never saved again, so an
//!   earlier one stays until the sweep moves it or the outbox removes it, and a
//!   sign-in is removed when it is used or expires. The sweep leaves `v2.`
//!   values alone: only [`Store::rewrap_data_keys`] lets a previous master key
//!   go for them.
//! * A value whose text starts `v<number>.` with a number above 2 is in a
//!   format that only a newer version may read. Reading it is
//!   [`StoreError::NewerFormat`], which no caller treats as unreadable: it is
//!   not skipped, overwritten or removed.
//! * [`Store::destroy_data_keys`] destroys a tenant's data keys, so that its
//!   values never open again, through the database or from a logical dump
//!   taken afterwards ([`StoreError::KeysDestroyed`]).
//! * A database recorded above [`STORAGE_LEVEL_READS`] is a newer version's,
//!   and a store does not open it ([`StoreError::StorageLevelAhead`]).
//! * Access tokens, refresh tokens, authorization codes and client secrets
//!   issued by postkeep are stored only as SHA-256 hashes; the store accepts
//!   and compares the raw values itself. A pending authorization request ID
//!   is stored as the SHA-256 hash that keys its `authorization_requests` row.
//!   A Microsoft or Google sign-in is keyed by the SHA-256 hash of its OAuth
//!   `state` (`upstream_requests.state_hash`) and does not store that request
//!   ID, the continuation or the PKCE verifier as a hash; those values are the
//!   encrypted copies named above.

mod accounts;
mod clients;
mod crypto;
mod db;
mod envelope;
mod error;
mod events;
mod filters;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;
mod held;
mod oauth;
mod push;
mod rotation;
mod sessions;
mod upstream;
mod webhooks;

pub use accounts::{
    Account, AccountId, OAuthAccount, Provider, RemovedRefreshToken, StoredCredentials,
    UpsertedImapAccount,
};
pub use clients::{Client, NewClient};
pub use crypto::{KEY_LEN, MasterKey, constant_time_eq, hash_secret};
pub use db::{
    DEFAULT_TENANT, Migrations, PoolSettings, PurgePolicy, STORAGE_LEVEL_READS,
    STORAGE_LEVEL_WRITES, Store, now,
};
pub use envelope::{DataKey, Kek, KeyWrapper, LocalKeyWrapper, Rewrapped, WrapFuture, Wrapped};
pub use error::{Result, StoreError};
pub use events::{
    ABSOLUTE_MAX_OUTBOX_EVENTS, ABSOLUTE_MAX_OUTBOX_RETENTION_SECS, AppendOutcome,
    DEFAULT_OUTBOX_MAX_EVENTS, DEFAULT_OUTBOX_MAX_EVENTS_LIMIT, DEFAULT_OUTBOX_MAX_RETENTION_SECS,
    DEFAULT_OUTBOX_RETENTION_SECS, EVENT_RETENTION, EffectiveOutboxLimits, KEPT_EVENTS,
    MIN_OUTBOX_EVENTS, MIN_OUTBOX_RETENTION_SECS, MailEvent, OutboxLimitChange,
    OutboxLimitsApplied, OutboxPolicy, PendingMailEvents, format_outbox_retention,
};
pub use filters::{AddedFilterRule, ChangedFilterRule, FilterRule, NewFilterRule};
pub use held::{HeldSend, HeldSendMatch};
pub use oauth::{
    AuthorizationRequest, CodeGrant, GrantSubject, Redemption, RefreshRotation, TokenGrant,
};
pub use push::PushSubscription;
pub use rotation::Reencrypted;
pub use sessions::{AccountClient, AccountOverview, SessionTtl};
pub use upstream::{StoredUpstreamTokens, UpstreamPurpose, UpstreamRequest, UpstreamTokens};
pub use webhooks::{
    DeliveryEffect, DeliveryRecord, KEPT_DELIVERIES, LoadedWebhook, MAX_CONSECUTIVE_FAILURES,
    WatchAdvance, WatchCursor, Webhook, WebhookSettings,
};
