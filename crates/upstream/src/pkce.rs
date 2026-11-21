//! PKCE (RFC 7636, S256) and `state` values for the upstream sign-in.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// A random URL-safe value with 256 bits of entropy.
///
/// # Errors
///
/// Returns an error if the operating system's random source fails.
pub fn random_token() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// The S256 code challenge of `verifier`.
#[must_use]
pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_rfc_example() {
        // RFC 7636, appendix B.
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn random_tokens_are_long_and_distinct() {
        let a = random_token().unwrap_or_default();
        let b = random_token().unwrap_or_default();
        assert_eq!(a.len(), 43);
        assert_ne!(a, b);
        // A valid PKCE verifier: 43 to 128 unreserved characters.
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
    }
}
