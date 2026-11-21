//! Random tokens and PKCE.

use postkeep_store::constant_time_eq;
use postkeep_upstream::pkce;

use crate::error::OAuthError;

/// Returns 32 random bytes encoded as unpadded base64url (43 characters).
pub fn token() -> Result<String, OAuthError> {
    pkce::random_token().map_err(|err| {
        tracing::error!(error = %err, "random number generator failed");
        OAuthError::server_error()
    })
}

/// Whether `value` is a valid PKCE code verifier (RFC 7636 section 4.1).
fn valid_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// Whether `value` looks like an `S256` code challenge.
pub fn valid_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Checks a code verifier against an `S256` challenge.
pub fn verify_pkce(verifier: &str, challenge: &str) -> bool {
    if !valid_verifier(verifier) {
        return false;
    }
    let computed = pkce::challenge(verifier);
    constant_time_eq(computed.as_bytes(), challenge.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_base64url() {
        let (a, b) = (token().unwrap(), token().unwrap());
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert!(valid_challenge(&a));
    }

    #[test]
    fn checks_rfc7636_example() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(valid_challenge(challenge));
        assert!(verify_pkce(verifier, challenge));
        assert!(!verify_pkce(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXK",
            challenge
        ));
        assert!(!verify_pkce("short", challenge));
    }
}
