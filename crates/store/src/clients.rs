//! OAuth clients registered through dynamic client registration.

use secrecy::{ExposeSecret, SecretString};
use sqlx::Row;
use sqlx::any::AnyRow;

use crate::crypto::{constant_time_eq, hash_secret};
use crate::db::now;
use crate::{Result, Store, StoreError};

/// A client to register.
#[derive(Debug, Clone, Default)]
pub struct NewClient {
    /// Human-readable name shown on the sign-in page.
    pub name: Option<String>,
    /// Allowed redirect URIs (exact match).
    pub redirect_uris: Vec<String>,
    /// Client secret for confidential clients; `None` for public clients.
    pub secret: Option<SecretString>,
}

/// A registered client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    /// Client identifier.
    pub id: String,
    /// Human-readable name.
    pub name: Option<String>,
    /// Allowed redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Whether the client authenticates with a secret.
    pub confidential: bool,
    /// Registration time (Unix seconds).
    pub created_at: i64,
}

impl Store {
    /// Registers a client and returns it with a newly generated ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidInput`] if there are no redirect URIs or
    /// one contains a line break, or a database error.
    pub async fn create_client(&self, client: &NewClient) -> Result<Client> {
        if client.redirect_uris.is_empty() {
            return Err(StoreError::InvalidInput(
                "at least one redirect URI is required",
            ));
        }
        if client
            .redirect_uris
            .iter()
            .any(|uri| uri.contains(['\n', '\r']))
        {
            return Err(StoreError::InvalidInput(
                "redirect URIs must not contain line breaks",
            ));
        }
        let id = uuid::Uuid::new_v4().simple().to_string();
        let created_at = now();
        let secret_hash = client
            .secret
            .as_ref()
            .map(|secret| hash_secret(secret.expose_secret()));
        sqlx::query(
            "INSERT INTO oauth_clients (id, secret_hash, name, redirect_uris, created_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&id)
        .bind(&secret_hash)
        .bind(&client.name)
        .bind(client.redirect_uris.join("\n"))
        .bind(created_at)
        .execute(&self.pool)
        .await?;
        Ok(Client {
            id,
            name: client.name.clone(),
            redirect_uris: client.redirect_uris.clone(),
            confidential: secret_hash.is_some(),
            created_at,
        })
    }

    /// Stores a public client described by a Client ID Metadata Document,
    /// whose ID is the document's `https` URL, and returns it. A stored
    /// client with that ID gets the new name and redirect URIs.
    ///
    /// Generated client IDs never start with `https://`, so this cannot
    /// replace a dynamically registered client.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidInput`] if `id` is not an `https` URL,
    /// there are no redirect URIs or one contains a line break, or a
    /// database error.
    pub async fn upsert_metadata_client(
        &self,
        id: &str,
        name: Option<&str>,
        redirect_uris: &[String],
    ) -> Result<Client> {
        if !id.starts_with("https://") {
            return Err(StoreError::InvalidInput(
                "a metadata document client ID is an https URL",
            ));
        }
        if redirect_uris.is_empty() {
            return Err(StoreError::InvalidInput(
                "at least one redirect URI is required",
            ));
        }
        if redirect_uris.iter().any(|uri| uri.contains(['\n', '\r'])) {
            return Err(StoreError::InvalidInput(
                "redirect URIs must not contain line breaks",
            ));
        }
        sqlx::query(
            "INSERT INTO oauth_clients (id, secret_hash, name, redirect_uris, created_at) \
             VALUES ($1, NULL, $2, $3, $4) \
             ON CONFLICT (id) DO UPDATE SET name = excluded.name, \
             redirect_uris = excluded.redirect_uris",
        )
        .bind(id)
        .bind(name)
        .bind(redirect_uris.join("\n"))
        .bind(now())
        .execute(&self.pool)
        .await?;
        self.client(id).await?.ok_or(StoreError::InvalidInput(
            "the client disappeared while it was stored",
        ))
    }

    /// Looks up a client.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn client(&self, id: &str) -> Result<Option<Client>> {
        let row = sqlx::query(
            "SELECT id, secret_hash, name, redirect_uris, created_at FROM oauth_clients WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(client_from_row).transpose()
    }

    /// Number of registered clients.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn client_count(&self) -> Result<u64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients")
            .fetch_one(&self.pool)
            .await?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Records that a client just obtained tokens, which keeps its
    /// registration from expiring.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn touch_client(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE oauth_clients SET last_used_at = $1 WHERE id = $2")
            .bind(now())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Checks a confidential client's secret. Returns `false` for unknown or
    /// public clients.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn verify_client_secret(&self, id: &str, secret: &str) -> Result<bool> {
        let stored: Option<Option<String>> =
            sqlx::query_scalar("SELECT secret_hash FROM oauth_clients WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(stored
            .flatten()
            .is_some_and(|hash| constant_time_eq(hash, hash_secret(secret))))
    }
}

fn client_from_row(row: &AnyRow) -> Result<Client> {
    let secret_hash: Option<String> = row.try_get("secret_hash")?;
    let redirect_uris: String = row.try_get("redirect_uris")?;
    Ok(Client {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        redirect_uris: redirect_uris.lines().map(str::to_owned).collect(),
        confidential: secret_hash.is_some(),
        created_at: row.try_get("created_at")?,
    })
}
