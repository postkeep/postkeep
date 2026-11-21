//! Where uploaded files wait: the one bucket the operator sets, behind
//! [`Bucket`].
//!
//! The upload route, the send and the cleanup use only [`Bucket`]'s three
//! operations on a named object; [`S3Bucket`] speaks them to any S3-compatible
//! bucket. Every object is a piece postkeep sealed before it went, under a
//! random name.
//!
//! A request the bucket never answered may still have taken effect, as a
//! provider may have acted on one: a piece that may have been stored belongs to
//! an upload that is then used up, so it is deleted with the rest, and a delete
//! that may have failed is tried again by a later cleanup. So no caller tells
//! failures apart, and [`BucketError`] holds only a fixed reason for the log.

use std::fmt;

use axum::body::Bytes;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use hmac::{Hmac, KeyInit, Mac};
use postkeep_upstream::http::{JSON_LIMIT, request};
use postkeep_upstream::{Http, HttpError};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use url::Url;

/// A store of named objects, such as an S3-compatible bucket.
pub trait Bucket: Send + Sync + fmt::Debug {
    /// Stores `bytes` as the object `name`.
    fn put<'a>(&'a self, name: &'a str, bytes: Bytes) -> BoxFuture<'a, Result<(), BucketError>>;

    /// The object `name`, refused when it is longer than `most` bytes.
    fn get<'a>(&'a self, name: &'a str, most: usize) -> BoxFuture<'a, Result<Bytes, BucketError>>;

    /// Deletes the object `name`; one that is already gone counts as deleted.
    fn delete<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<(), BucketError>>;
}

/// Why a bucket's operation failed, as a fixed reason for the log.
///
/// A status, or the kind of transport failure. It never holds the bucket's
/// address, an object's name, a key, a signature or the bucket's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketError(Reason);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    Status(u16),
    Kind(&'static str),
}

impl BucketError {
    const fn status(status: StatusCode) -> Self {
        Self(Reason::Status(status.as_u16()))
    }
}

impl From<HttpError> for BucketError {
    fn from(error: HttpError) -> Self {
        Self(Reason::Kind(match error {
            HttpError::Deadline | HttpError::Timeout(_) => "no answer in time",
            HttpError::Request(_) => "the request could not be made",
            HttpError::Connect(_) => "no connection",
            HttpError::Transport { .. } => "no answer",
            HttpError::TooLarge(_) => "the answer was too large",
        }))
    }
}

impl fmt::Display for BucketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Reason::Status(status) => write!(f, "the bucket answered {status}"),
            Reason::Kind(kind) => f.write_str(kind),
        }
    }
}

impl std::error::Error for BucketError {}

/// An S3-compatible bucket, reached through the open crates' HTTPS client with
/// requests signed by AWS Signature Version 4 over the bytes sent.
#[derive(Clone)]
pub struct S3Bucket {
    url: Url,
    region: String,
    key_id: SecretString,
    secret: SecretString,
    http: Http,
}

impl fmt::Debug for S3Bucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Bucket").finish_non_exhaustive()
    }
}

impl S3Bucket {
    /// The bucket at `url`, in either of its forms (`https://<bucket>.<host>`
    /// or `https://<host>/<bucket>`), with requests signed for `region` with
    /// the access key `key_id` and its `secret` and sent through `http`. The
    /// caller checks `url`; its path is signed as it is sent, so it holds only
    /// characters that need no encoding.
    #[must_use]
    pub const fn new(
        url: Url,
        region: String,
        key_id: SecretString,
        secret: SecretString,
        http: Http,
    ) -> Self {
        Self {
            url,
            region,
            key_id,
            secret,
            http,
        }
    }

    /// The URL of the object `name`, under the bucket's own path.
    fn object_url(&self, name: &str) -> Url {
        let mut url = self.url.clone();
        let path = format!("{}/{name}", url.path().trim_end_matches('/'));
        url.set_path(&path);
        url
    }

    /// Sends one signed request for the object `name` and reads at most
    /// `limit` bytes of a successful answer. A `404` is a success when
    /// `missing_ok`.
    async fn call(
        &self,
        method: Method,
        name: &str,
        body: Bytes,
        limit: usize,
        missing_ok: bool,
    ) -> Result<Bytes, BucketError> {
        let url = self.object_url(name);
        let payload = hex::encode(Sha256::digest(&body));
        let now = Utc::now();
        let stamp = now.format("%Y%m%dT%H%M%SZ").to_string();
        let headers = [
            ("host", host(&url)),
            ("x-amz-content-sha256", payload.clone()),
            ("x-amz-date", stamp),
        ];
        let signing = Signing {
            key_id: self.key_id.expose_secret(),
            secret: self.secret.expose_secret(),
            region: &self.region,
            time: now,
        };
        let authorization = signing.authorization(method.as_str(), url.path(), &headers, &payload);
        let named = headers.map(|(name, value)| (HeaderName::from_static(name), value));
        let mut request = request(method, &url, &named, body)?;
        let mut value = HeaderValue::from_str(&authorization)
            .map_err(|_| BucketError(Reason::Kind("the request could not be made")))?;
        value.set_sensitive(true);
        request.headers_mut().insert(header::AUTHORIZATION, value);
        let response = self.http.send(request, limit).await?;
        if response.is_success() || (missing_ok && response.status == StatusCode::NOT_FOUND) {
            Ok(response.body)
        } else {
            Err(BucketError::status(response.status))
        }
    }
}

impl Bucket for S3Bucket {
    fn put<'a>(&'a self, name: &'a str, bytes: Bytes) -> BoxFuture<'a, Result<(), BucketError>> {
        Box::pin(async move {
            self.call(Method::PUT, name, bytes, JSON_LIMIT, false)
                .await
                .map(drop)
        })
    }

    fn get<'a>(&'a self, name: &'a str, most: usize) -> BoxFuture<'a, Result<Bytes, BucketError>> {
        Box::pin(self.call(Method::GET, name, Bytes::new(), most, false))
    }

    fn delete<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<(), BucketError>> {
        Box::pin(async move {
            self.call(Method::DELETE, name, Bytes::new(), JSON_LIMIT, true)
                .await
                .map(drop)
        })
    }
}

/// The `Host` header of `url`: its host, and its port when not the default.
fn host(url: &Url) -> String {
    let name = url.host_str().unwrap_or_default();
    url.port()
        .map_or_else(|| name.to_owned(), |port| format!("{name}:{port}"))
}

/// Who signs a request, for which region, and when.
struct Signing<'a> {
    key_id: &'a str,
    secret: &'a str,
    region: &'a str,
    time: DateTime<Utc>,
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC takes keys of any length"));
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// The canonical request of Signature Version 4: `headers` are lowercase and in
/// order, and `path` is as it is sent; there is never a query.
fn canonical_request(
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    payload: &str,
) -> String {
    let mut lines = String::new();
    for (name, value) in headers {
        lines.push_str(&[name, ":", value.trim(), "\n"].concat());
    }
    let signed = signed_headers(headers);
    format!("{method}\n{path}\n\n{lines}\n{signed}\n{payload}")
}

fn signed_headers(headers: &[(&str, String)]) -> String {
    let names: Vec<&str> = headers.iter().map(|(name, _)| *name).collect();
    names.join(";")
}

impl Signing<'_> {
    /// The `Authorization` header of a request with `headers` and the payload
    /// whose SHA-256, in hex, is `payload`.
    fn authorization(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        payload: &str,
    ) -> String {
        let date = self.time.format("%Y%m%d").to_string();
        let stamp = self.time.format("%Y%m%dT%H%M%SZ");
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let canonical = canonical_request(method, path, headers, payload);
        let digest = hex::encode(Sha256::digest(canonical.as_bytes()));
        let to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{digest}");
        let key = hmac(format!("AWS4{}", self.secret).as_bytes(), &date);
        let key = [self.region, "s3", "aws4_request"]
            .iter()
            .fold(key, |key, part| hmac(&key, part));
        let signature = hex::encode(hmac(&key, &to_sign));
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope},SignedHeaders={},Signature={signature}",
            self.key_id,
            signed_headers(headers)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS's example credentials and time, from its Signature Version 4 page.
    fn example() -> Signing<'static> {
        Signing {
            key_id: "AKIAIOSFODNN7EXAMPLE",
            secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            time: DateTime::parse_from_rfc3339("2013-05-24T00:00:00Z")
                .unwrap()
                .to_utc(),
        }
    }

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn signs_aws_get_object_example() {
        let headers = [
            ("host", "examplebucket.s3.amazonaws.com".to_owned()),
            ("range", "bytes=0-9".to_owned()),
            ("x-amz-content-sha256", EMPTY.to_owned()),
            ("x-amz-date", "20130524T000000Z".to_owned()),
        ];
        assert_eq!(
            canonical_request("GET", "/test.txt", &headers, EMPTY),
            "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\n\
             x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
             x-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            example().authorization("GET", "/test.txt", &headers, EMPTY),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,\
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,\
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn signs_aws_put_object_example() {
        let payload = hex::encode(Sha256::digest(b"Welcome to Amazon S3."));
        assert_eq!(
            payload,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        let headers = [
            ("date", "Fri, 24 May 2013 00:00:00 GMT".to_owned()),
            ("host", "examplebucket.s3.amazonaws.com".to_owned()),
            ("x-amz-content-sha256", payload.clone()),
            ("x-amz-date", "20130524T000000Z".to_owned()),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY".to_owned()),
        ];
        // The object `test$file.text` is sent, and signed, as `test%24file.text`.
        assert_eq!(
            example().authorization("PUT", "/test%24file.text", &headers, &payload),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,\
             SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,\
             Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    #[test]
    fn objects_are_under_the_bucket_in_both_forms() {
        let bucket = |url: &str| {
            S3Bucket::new(
                Url::parse(url).unwrap(),
                "auto".to_owned(),
                SecretString::from("id".to_owned()),
                SecretString::from("secret".to_owned()),
                Http::for_tests(),
            )
        };
        let virtual_host = bucket("https://examplebucket.s3.example").object_url("uploads/a/0");
        assert_eq!(
            (virtual_host.as_str(), host(&virtual_host).as_str()),
            (
                "https://examplebucket.s3.example/uploads/a/0",
                "examplebucket.s3.example"
            )
        );
        let path_style =
            bucket("https://store.example.com:9000/my.bucket/").object_url("uploads/a/0");
        assert_eq!(
            (path_style.as_str(), host(&path_style).as_str()),
            (
                "https://store.example.com:9000/my.bucket/uploads/a/0",
                "store.example.com:9000"
            )
        );
    }
}
