//! HMAC-SHA256 signatures over webhook deliveries.
//!
//! The signature covers `"{timestamp}.{body}"`, where `timestamp` is the
//! value of the [`TIMESTAMP_HEADER`] (Unix seconds) and `body` is the raw
//! request body. It is sent as `X-Signature-256: sha256=<lowercase hex>`.
//! The key is the whole signing secret, `whsec_` prefix included.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// Header carrying the signature.
pub const SIGNATURE_HEADER: &str = "x-signature-256";
/// Header carrying the Unix time (seconds) the delivery was signed at.
pub const TIMESTAMP_HEADER: &str = "x-webhook-timestamp";
/// Header carrying a unique id per event, the same across retries.
pub const ID_HEADER: &str = "x-webhook-id";
/// Header carrying an outbox event's position in the account's stream.
pub const SEQUENCE_HEADER: &str = "x-webhook-sequence";
/// Header naming the event, such as `new_mail`.
pub const EVENT_HEADER: &str = "x-webhook-event";

/// Prefix of every signing secret.
pub const SECRET_PREFIX: &str = "whsec_";

/// Generates a new signing secret: `whsec_` and 32 random bytes,
/// base64url-encoded.
///
/// # Errors
///
/// Returns an error if the operating system's random source fails.
pub fn generate_secret() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(format!("{SECRET_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

fn mac(secret: &str, timestamp: i64, body: &[u8]) -> Hmac<Sha256> {
    // HMAC accepts keys of any length, so this can't fail.
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes())
        .unwrap_or_else(|_| unreachable!("HMAC takes keys of any length"));
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    mac
}

/// The [`SIGNATURE_HEADER`] value for a body signed at `timestamp`.
#[must_use]
pub fn sign(secret: &str, timestamp: i64, body: &[u8]) -> String {
    format!(
        "sha256={}",
        hex::encode(mac(secret, timestamp, body).finalize().into_bytes())
    )
}

/// Checks a received signature in constant time, and that `timestamp` is
/// within `tolerance_secs` of `now` to limit replays.
#[must_use]
pub fn verify(
    secret: &str,
    timestamp: i64,
    body: &[u8],
    signature: &str,
    now: i64,
    tolerance_secs: i64,
) -> bool {
    // `abs_diff` cannot overflow, whatever timestamp a sender claims.
    if now.abs_diff(timestamp) > tolerance_secs.unsigned_abs() {
        return false;
    }
    let Some(hex_digest) = signature.trim().strip_prefix("sha256=") else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_digest) else {
        return false;
    };
    mac(secret, timestamp, body).verify_slice(&expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer() {
        // printf '1700000000.{"a":1}' | openssl dgst -sha256 -hmac whsec_test
        assert_eq!(
            sign("whsec_test", 1_700_000_000, br#"{"a":1}"#),
            "sha256=38877139021993b830af32feea6e18a8da83eb2f6e49ee50bd9e4cf4ca4d3789"
        );
    }

    #[test]
    fn round_trip_and_tampering() {
        let secret = generate_secret().unwrap_or_else(|e| unreachable!("{e}"));
        assert!(secret.starts_with(SECRET_PREFIX));
        assert_eq!(secret.len(), SECRET_PREFIX.len() + 43);
        let body = br#"{"event":"new_mail"}"#;
        let signature = sign(&secret, 1000, body);
        assert!(verify(&secret, 1000, body, &signature, 1100, 300));
        assert!(
            !verify(&secret, 1000, body, &signature, 1400, 300),
            "too old"
        );
        assert!(
            !verify(&secret, 1001, body, &signature, 1100, 300),
            "other timestamp"
        );
        assert!(
            !verify(&secret, 1000, b"{}", &signature, 1100, 300),
            "other body"
        );
        assert!(
            !verify("whsec_other", 1000, body, &signature, 1100, 300),
            "other secret"
        );
        assert!(!verify(
            &secret,
            1000,
            body,
            signature.trim_start_matches("sha256="),
            1100,
            300
        ));
        assert!(!verify(&secret, 1000, body, "sha256=zz", 1100, 300));
        assert_ne!(generate_secret().ok(), Some(secret));
    }

    #[test]
    fn extreme_timestamps_are_refused_without_overflow() {
        let signature = sign("whsec_test", i64::MIN, b"{}");
        assert!(!verify(
            "whsec_test",
            i64::MIN,
            b"{}",
            &signature,
            i64::MAX,
            300
        ));
        assert!(!verify(
            "whsec_test",
            i64::MAX,
            b"{}",
            &signature,
            i64::MIN,
            i64::MIN
        ));
        let signature = sign("whsec_test", i64::MAX, b"{}");
        assert!(verify(
            "whsec_test",
            i64::MAX,
            b"{}",
            &signature,
            i64::MAX,
            0
        ));
    }
}
