//! `PUT /upload`: an agent sends one file's bytes for an upload that the
//! `upload_attachment` tool made, with the upload's token in the
//! `Authorization` header, never in the URL.
//!
//! Before a byte of the body is read, the client's IP has counted against the
//! auth routes' per-IP limit (a route layer), a missing or malformed token is
//! refused, so is a declared length over [`MAX_UPLOAD_BYTES`], and the claim
//! checks the token and the bounds in one write transaction. A refusal there
//! changes nothing, and the token still works.
//!
//! The bytes go to the bucket as they arrive, joined into pieces of
//! [`UPLOAD_PIECE`], each sealed under the upload's own key and put as an
//! object of its own once it fills, with a running SHA-256; what is left at the
//! body's end goes as the last piece, and an empty file is one empty piece. The
//! next frame is read once the bucket has the piece. A stop, for size, time or
//! a piece the bucket doesn't take, uses the upload up before the answer, and
//! a request that goes away does the same from a spawned task; either way its
//! pieces are deleted in the background. Only the key and digest of a file
//! that is all in reach the database, sealed.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::put;
use axum::{Json, Router};
use futures::StreamExt as _;
use http_body_util::BodyExt as _;
use postkeep_auth::AuthState;
use postkeep_store::{
    ClaimRefused, Claimed, PIECE_TAG, Store, UploadBounds, Used, now, seal_piece,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tokio::time::Instant;

use crate::bucket::Bucket;

/// Path of the upload route.
pub const UPLOAD_PATH: &str = "/upload";
/// Largest file an upload takes, and the most the uploaded files of one
/// message may total.
pub const MAX_UPLOAD_BYTES: usize = 25 * 1024 * 1024;
/// [`MAX_UPLOAD_BYTES`] in MiB, for the texts that state it.
pub const MAX_UPLOAD_MIB: usize = MAX_UPLOAD_BYTES / (1024 * 1024);
/// A piece of a file in the bucket, before its tag. Part of the pieces' stored
/// layout, with the nonce and associated data of [`seal_piece`].
pub const UPLOAD_PIECE: usize = 4 * 1024 * 1024;
/// Life of an upload never used, from the tool call.
pub const UPLOAD_TTL: Duration = Duration::from_hours(1);
/// Time for one upload's bytes; a claim this old whose file never came is
/// no longer arriving.
pub(crate) const UPLOAD_TIME: Duration = Duration::from_mins(10);
/// Time without a byte that ends an upload, counted while it waits on the client.
const UPLOAD_IDLE: Duration = Duration::from_secs(30);
/// Uploads of one tenant not yet given a file: a soft cap.
pub(crate) const MOST_UPLOADS: i64 = 10;
/// Deletes of one batch at once, and the time they all take at most.
const DELETES_AT_ONCE: usize = 4;
const DELETE_TIME: Duration = Duration::from_mins(2);
/// Used uploads whose pieces one cleanup deletes.
pub(crate) const CLEAN_BATCH: i64 = 100;
const MIB: i64 = 1024 * 1024;
/// The arriving and stored bounds, per tenant and for the whole server.
const BOUNDS: UploadBounds = UploadBounds {
    tenant_arriving: 2,
    tenant_stored: 250 * MIB,
    server_arriving: 8,
    server_stored: 1024 * MIB,
    least: 64 * 1024,
    window: UPLOAD_TIME,
};

/// What a tool and an attachment answer while no bucket is set.
pub(crate) const UPLOADS_OFF: &str = "Uploads are turned off on this server \
    (POSTKEEP_UPLOAD_BUCKET_URL is not set). Put a small file's bytes in attachments with \
    content or text; for a larger file, tell the user it can't be attached here.";
const NO_TOKEN: &str = "This upload can't take a file: its token was used, has ended or never \
    existed. Ask for a new one with upload_attachment.";
const TENANT_FULL: &str = "Too many files are arriving or kept here right now. Try again in a \
    few minutes; this token still works.";
const SERVER_FULL: &str = "postkeep is holding too many uploads right now. Try again in a few \
    minutes; this token still works.";
const NOT_CLAIMED: &str =
    "postkeep couldn't take the file just now. Try again in a minute; this token still works.";
const NOT_STORED: &str = "postkeep couldn't store the file just now, and this upload has ended. \
    In a minute, get a new upload with upload_attachment and send the file again.";
const STOPPED: &str = "The upload stopped arriving and was ended. Get a new upload with \
    upload_attachment and send the file again.";

fn too_large() -> String {
    format!("The file is larger than {MAX_UPLOAD_MIB} MiB, the most an upload takes.")
}

/// How many pieces a file of `size` bytes is: one for an empty file.
pub(crate) fn pieces(size: i64) -> u64 {
    let piece = UPLOAD_PIECE as u64;
    u64::try_from(size).unwrap_or(0).div_ceil(piece).max(1)
}

/// The object of piece `number` of the upload stored under `object`.
pub(crate) fn piece_name(object: &str, number: u64) -> String {
    format!("uploads/{object}/{number}")
}

#[derive(Clone)]
struct Uploads {
    store: Store,
    bucket: Option<Arc<dyn Bucket>>,
}

/// The upload route; with no bucket every `PUT` is refused as an unknown token.
/// The auth routes' per-IP limit, in `auth`, counts each upload before it is
/// looked at.
pub(crate) fn router(store: Store, bucket: Option<Arc<dyn Bucket>>, auth: AuthState) -> Router {
    let limit = axum::middleware::from_fn_with_state(auth, postkeep_auth::limit_requests);
    Router::new()
        .route(UPLOAD_PATH, put(receive))
        .route_layer(limit)
        .with_state(Uploads { store, bucket })
}

/// A claimed upload until its file is in: dropped any other way, it is used up
/// and its pieces deleted, from a spawned task.
struct Attempt {
    uploads: Uploads,
    claimed: Option<Claimed>,
}

impl Attempt {
    /// Uses the upload up, then answers `status` with `words`.
    async fn stop(mut self, status: StatusCode, words: &str) -> Response {
        if let Some(claimed) = self.claimed.take() {
            self.uploads.use_up(claimed).await;
        }
        answer(status, words)
    }

    /// Seals piece `number` in place and puts it in the bucket; `false`, with
    /// the bucket's fixed reason logged, when the bucket does not take it.
    async fn put(&self, bucket: &dyn Bucket, number: u64, mut piece: Vec<u8>) -> bool {
        let Some(claimed) = &self.claimed else {
            return false;
        };
        if seal_piece(claimed.key(), number, &mut piece).is_err() {
            return false;
        }
        let name = piece_name(claimed.object(), number);
        match bucket.put(&name, Bytes::from(piece)).await {
            Ok(()) => true,
            Err(reason) => {
                tracing::warn!(%reason, "upload piece not stored");
                false
            }
        }
    }

    /// Stores the file's key and digest; once they are in, the attempt is done.
    async fn finish(&mut self, size: i64, digest: &[u8; 32]) -> postkeep_store::Result<bool> {
        let Some(claimed) = &self.claimed else {
            return Ok(false);
        };
        let stored = self
            .uploads
            .store
            .finish_upload(claimed, size, digest)
            .await?;
        if stored {
            self.claimed = None;
        }
        Ok(stored)
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if let Some(claimed) = self.claimed.take() {
            let uploads = self.uploads.clone();
            tokio::spawn(async move { uploads.use_up(claimed).await });
        }
    }
}

impl Uploads {
    async fn use_up(&self, claimed: Claimed) {
        match self.store.use_attempt(&claimed).await {
            Ok(used) => {
                let (store, bucket) = (self.store.clone(), self.bucket.clone());
                tokio::spawn(
                    async move { delete_pieces(&store, bucket.as_deref(), &[used]).await },
                );
            }
            // The next cleanup uses it up once its window is over.
            Err(err) => tracing::warn!(error = %err, "could not end an upload"),
        }
    }
}

/// The token of `Authorization: Bearer <token>`, when it has a token's shape:
/// 43 base64url characters.
fn token(request: &Request) -> Option<&str> {
    let value = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let shaped = token.len() == 43
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    (scheme.eq_ignore_ascii_case("bearer") && shaped).then_some(token)
}

async fn receive(State(uploads): State<Uploads>, request: Request) -> Response {
    let (Some(bucket), Some(token)) = (uploads.bucket.clone(), token(&request)) else {
        return answer(StatusCode::UNAUTHORIZED, NO_TOKEN);
    };
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok()?.parse::<u64>().ok());
    if declared.is_some_and(|length| length > MAX_UPLOAD_BYTES as u64) {
        return answer(StatusCode::PAYLOAD_TOO_LARGE, &too_large());
    }
    let Ok(object) = postkeep_upstream::pkce::random_token() else {
        return answer(StatusCode::SERVICE_UNAVAILABLE, NOT_CLAIMED);
    };
    let most = i64::try_from(MAX_UPLOAD_BYTES).unwrap_or(i64::MAX);
    let reserve = declared.map_or(most, |length| i64::try_from(length).unwrap_or(i64::MAX));
    let claimed = match uploads
        .store
        .claim_upload(token, &object, reserve, BOUNDS)
        .await
    {
        Ok(Ok(claimed)) => claimed,
        Ok(Err(ClaimRefused::Unknown)) => return answer(StatusCode::UNAUTHORIZED, NO_TOKEN),
        Ok(Err(ClaimRefused::Tenant)) => {
            return answer(StatusCode::TOO_MANY_REQUESTS, TENANT_FULL);
        }
        Ok(Err(ClaimRefused::Server)) => {
            return answer(StatusCode::SERVICE_UNAVAILABLE, SERVER_FULL);
        }
        Err(err) => {
            tracing::warn!(error = %err, "could not claim an upload");
            return answer(StatusCode::SERVICE_UNAVAILABLE, NOT_CLAIMED);
        }
    };
    let left = u64::try_from(claimed.expires_at() - now()).unwrap_or(0);
    let deadline = Instant::now() + UPLOAD_TIME.min(Duration::from_secs(left));
    let attempt = Attempt {
        uploads,
        claimed: Some(claimed),
    };
    take(attempt, bucket.as_ref(), request.into_body(), deadline).await
}

/// The piece loop, then the file's key and digest stored.
async fn take(
    mut attempt: Attempt,
    bucket: &dyn Bucket,
    mut body: Body,
    deadline: Instant,
) -> Response {
    let mut piece = Vec::with_capacity(UPLOAD_PIECE + PIECE_TAG);
    let (mut digest, mut size, mut number) = (Sha256::new(), 0_usize, 0_u64);
    loop {
        let wait = deadline.min(Instant::now() + UPLOAD_IDLE);
        let mut data = match tokio::time::timeout_at(wait, body.frame()).await {
            Ok(None) => break,
            Ok(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => data,
                Err(_) => continue,
            },
            Ok(Some(Err(_))) | Err(_) => {
                return attempt.stop(StatusCode::REQUEST_TIMEOUT, STOPPED).await;
            }
        };
        size += data.len();
        if size > MAX_UPLOAD_BYTES {
            let words = too_large();
            return attempt.stop(StatusCode::PAYLOAD_TOO_LARGE, &words).await;
        }
        digest.update(&data);
        while !data.is_empty() {
            let room = UPLOAD_PIECE - piece.len();
            piece.extend_from_slice(&data.split_to(room.min(data.len())));
            if piece.len() == UPLOAD_PIECE {
                let full = std::mem::take(&mut piece);
                if !attempt.put(bucket, number, full).await {
                    return attempt
                        .stop(StatusCode::SERVICE_UNAVAILABLE, NOT_STORED)
                        .await;
                }
                piece.reserve_exact(UPLOAD_PIECE + PIECE_TAG);
                number += 1;
            }
        }
        if Instant::now() >= deadline {
            return attempt.stop(StatusCode::REQUEST_TIMEOUT, STOPPED).await;
        }
    }
    if (!piece.is_empty() || number == 0) && !attempt.put(bucket, number, piece).await {
        return attempt
            .stop(StatusCode::SERVICE_UNAVAILABLE, NOT_STORED)
            .await;
    }
    let size = i64::try_from(size).unwrap_or(i64::MAX);
    match attempt.finish(size, &digest.finalize().into()).await {
        Ok(true) => {}
        Ok(false) => return attempt.stop(StatusCode::REQUEST_TIMEOUT, STOPPED).await,
        Err(err) => {
            tracing::warn!(error = %err, "could not store an upload's key");
            return attempt
                .stop(StatusCode::SERVICE_UNAVAILABLE, NOT_STORED)
                .await;
        }
    }
    tracing::info!("upload stored");
    let mut response = Json(json!({ "size": size })).into_response();
    *response.status_mut() = StatusCode::CREATED;
    with_headers(response)
}

/// `{"error": words}` with `status` and its headers: `WWW-Authenticate` on a
/// `401`, `Retry-After` on a `429` or `503`.
fn answer(status: StatusCode, words: &str) -> Response {
    let mut response = with_headers((status, Json(json!({ "error": words }))).into_response());
    let headers = response.headers_mut();
    match status {
        StatusCode::UNAUTHORIZED => {
            headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
            headers.insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        }
        _ => {}
    }
    response
}

fn with_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Deletes the pieces of `used` uploads, four at a time and all within two
/// minutes, and forgets each upload whose deletes the bucket all answered;
/// the rest stay for a later cleanup. With no bucket the rows go alone, and
/// the bucket's expiry rule removes any pieces.
pub(crate) async fn delete_pieces(store: &Store, bucket: Option<&dyn Bucket>, used: &[Used]) {
    let mut left: Vec<u64> = used
        .iter()
        .map(|upload| bucket.map_or(0, |_| pieces(upload.size)))
        .collect();
    let mut reason = None;
    if let Some(bucket) = bucket {
        let mut deletes = Vec::new();
        for (place, upload) in used.iter().enumerate() {
            let names = (0..pieces(upload.size)).map(|number| piece_name(&upload.object, number));
            deletes.extend(names.map(|name| (place, name)));
        }
        let mut answers = futures::stream::iter(deletes)
            .map(|(place, name)| async move { (place, bucket.delete(&name).await) })
            .buffer_unordered(DELETES_AT_ONCE);
        let all = async {
            while let Some((place, answered)) = answers.next().await {
                match answered {
                    Ok(()) => left[place] -= 1,
                    Err(error) => reason = Some(error.to_string()),
                }
            }
        };
        if tokio::time::timeout(DELETE_TIME, all).await.is_err() {
            reason = Some("no answer in time".to_owned());
        }
    }
    for (upload, left) in used.iter().zip(left) {
        if left == 0
            && let Err(err) = store.forget_upload(upload).await
        {
            tracing::warn!(error = %err, "could not forget a used upload");
        }
    }
    if let Some(reason) = reason {
        tracing::warn!(%reason, "upload pieces not deleted");
    }
}
