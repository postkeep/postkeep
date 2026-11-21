//! Checking IMAP credentials.

use std::future::Future;
use std::pin::Pin;

use postkeep_mail::{ImapServer, MailClient};
use secrecy::SecretString;

/// Why a sign-in attempt failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// The mail server rejected the address or password.
    #[error("the address or app password was rejected")]
    Rejected,
    /// The input was malformed, for example an address without `@`.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The mail server could not be reached or failed.
    #[error("mail server unavailable: {0}")]
    Unavailable(String),
}

/// Future returned by [`CredentialVerifier::verify`].
pub type VerifyFuture<'a> = Pin<Box<dyn Future<Output = Result<(), VerifyError>> + Send + 'a>>;

/// Checks an address and app password before an IMAP account is
/// connected. [`MailVerifier`] logs in over IMAP; tests can substitute
/// their own implementation.
pub trait CredentialVerifier: Send + Sync + 'static {
    /// Checks the credentials against `server`. `email` is trimmed and
    /// lowercase; `password` is normalized for the server.
    fn verify<'a>(
        &'a self,
        server: &'a ImapServer,
        email: &'a str,
        password: &'a SecretString,
    ) -> VerifyFuture<'a>;
}

/// Verifies credentials by logging in to IMAP and logging out again.
#[derive(Debug, Clone, Copy, Default)]
pub struct MailVerifier;

impl CredentialVerifier for MailVerifier {
    fn verify<'a>(
        &'a self,
        server: &'a ImapServer,
        email: &'a str,
        password: &'a SecretString,
    ) -> VerifyFuture<'a> {
        Box::pin(async move {
            let credentials = server.credentials(email, password).map_err(map_error)?;
            let client = MailClient::new(server.config.clone(), credentials).map_err(map_error)?;
            client.verify_credentials().await.map_err(map_error)
        })
    }
}

fn map_error(err: postkeep_mail::Error) -> VerifyError {
    match err {
        postkeep_mail::Error::Authentication => VerifyError::Rejected,
        postkeep_mail::Error::InvalidInput(message) => VerifyError::InvalidInput(message),
        other => VerifyError::Unavailable(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_temporary_refusal_is_not_a_rejected_password() {
        use postkeep_mail::Error;
        assert!(matches!(
            map_error(Error::Authentication),
            VerifyError::Rejected
        ));
        // The sign-in page blames the password and counts a failed attempt
        // for `Rejected`; a busy server is neither.
        let busy = Error::Unavailable { code: "LIMIT" };
        assert!(matches!(map_error(busy), VerifyError::Unavailable(_)));
    }
}
