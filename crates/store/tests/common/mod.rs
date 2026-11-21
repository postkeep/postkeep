//! Values in the first stored format (`v1.`), sealed by the tests themselves.
//!
//! A test that needs a value for the sweep to move, or one that no key opens,
//! builds it here from the layout instead of asking a writer for one: what a
//! writer stores depends on its version, while a store reads both formats. The
//! layout is `v1.` and the base64url, without padding, of a nonce and the
//! AES-256-GCM ciphertext under the master key, with the associated data of
//! the column written out below.

#![allow(
    dead_code,
    reason = "each test file that includes this module uses part of it"
)]

use aes_gcm::aead::{Aead, Generate, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use postkeep_store::{MasterKey, Store};
use sha2::{Digest, Sha256};
use sqlx::{AssertSqlSafe, Row};

/// A master key whose bytes the test knows, so that it can seal under it.
#[derive(Clone, Copy)]
pub struct KnownKey([u8; 32]);

impl KnownKey {
    /// The key whose 32 bytes are all `byte`.
    pub const fn new(byte: u8) -> Self {
        Self([byte; 32])
    }

    /// The key of 64 hexadecimal digits, as a store takes it from configuration.
    pub fn from_hex(hex: &str) -> Self {
        let byte = |i: usize| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        Self(std::array::from_fn(byte))
    }

    /// The key as a store takes it.
    pub fn master(&self) -> MasterKey {
        MasterKey::parse(&STANDARD.encode(self.0)).unwrap()
    }

    /// `plaintext` as a v1 value bound to `context`.
    pub fn seal(&self, context: &str, plaintext: &str) -> String {
        let nonce = Nonce::try_generate().unwrap();
        let payload = Payload {
            msg: plaintext.as_bytes(),
            aad: context.as_bytes(),
        };
        let sealed = Aes256Gcm::new((&self.0).into())
            .encrypt(&nonce, payload)
            .unwrap();
        let blob = [nonce.as_slice(), &sealed].concat();
        format!("v1.{}", URL_SAFE_NO_PAD.encode(blob))
    }
}

/// A well-formed v1 value that no key opens, like one sealed under a key that
/// is lost: it fails on its tag.
pub fn unreadable() -> String {
    format!("v1.{}", URL_SAFE_NO_PAD.encode([0x5a_u8; 40]))
}

/// The key of a sign-in in progress: the SHA-256 of its state, as text.
pub fn state_hash(state: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(state.as_bytes()))
}

/// An encrypted column: its name and table, which column keys the table's
/// rows, and the start of the associated data of its v1 values, which goes on
/// with what the value belongs to (`owner`).
#[derive(Clone, Copy)]
pub struct Column {
    table: &'static str,
    name: &'static str,
    key: &'static str,
    context: &'static str,
}

impl Column {
    const fn new(
        table: &'static str,
        name: &'static str,
        key: &'static str,
        context: &'static str,
    ) -> Self {
        Self {
            table,
            name,
            key,
            context,
        }
    }

    /// The text stored in the row `row`.
    pub async fn get(self, store: &Store, row: &str) -> String {
        let sql = format!(
            "SELECT {} AS stored FROM {} WHERE {} = $1",
            self.name, self.table, self.key
        );
        let found = sqlx::query(AssertSqlSafe(sql.as_str()))
            .bind(row)
            .fetch_one(store.pool())
            .await
            .unwrap();
        found.try_get("stored").unwrap()
    }

    /// Stores `text` in the row `row`, which must exist.
    pub async fn set(self, store: &Store, row: &str, text: &str) {
        let sql = format!(
            "UPDATE {} SET {} = $1 WHERE {} = $2",
            self.table, self.name, self.key
        );
        let done = sqlx::query(AssertSqlSafe(sql.as_str()))
            .bind(text)
            .bind(row)
            .execute(store.pool())
            .await
            .unwrap();
        assert_eq!(done.rows_affected(), 1, "no row {row} in {}", self.table);
    }

    /// Stores `plaintext` in the row `row` as a v1 value under `key`.
    pub async fn put(self, store: &Store, key: &KnownKey, row: &str, owner: &str, plaintext: &str) {
        let context = format!("{}{owner}", self.context);
        self.set(store, row, &key.seal(&context, plaintext)).await;
    }
}

/// An account's password, bound to the account's email.
pub const PASSWORD: Column = Column::new(
    "accounts",
    "password_ciphertext",
    "id",
    "icloud-mail-mcp/account-password/v1/",
);
/// A webhook's custom header value, bound to the account's ID.
pub const AUTH: Column = Column::new(
    "webhooks",
    "auth_header_value_ciphertext",
    "account_id",
    "webhook/auth/",
);
/// A webhook's signing secret, bound to the account's ID.
pub const SECRET: Column = Column::new(
    "webhooks",
    "signing_secret_ciphertext",
    "account_id",
    "webhook/secret/",
);
/// A refresh token, bound to the account's ID.
pub const REFRESH: Column = Column::new(
    "upstream_tokens",
    "refresh_token_ciphertext",
    "account_id",
    "upstream/refresh/",
);
/// A cached access token, bound to the account's ID.
pub const ACCESS: Column = Column::new(
    "upstream_tokens",
    "access_token_ciphertext",
    "account_id",
    "upstream/access/",
);
/// A PKCE verifier, bound to the hash of the sign-in's state.
pub const VERIFIER: Column = Column::new(
    "upstream_requests",
    "verifier_ciphertext",
    "state_hash",
    "upstream-request/verifier/",
);
/// A pending authorization request ID, bound to the hash of the state.
pub const REQUEST_ID: Column = Column::new(
    "upstream_requests",
    "request_id_ciphertext",
    "state_hash",
    "upstream-request/request-id/",
);
/// An embedding's continuation, bound to the hash of the state.
pub const CONTINUATION: Column = Column::new(
    "upstream_requests",
    "continuation_ciphertext",
    "state_hash",
    "upstream-request/continuation/",
);
/// An event payload, bound to `<account ID>/<event ID>`.
pub const PAYLOAD: Column = Column::new("mail_events", "payload_ciphertext", "id", "event/");
