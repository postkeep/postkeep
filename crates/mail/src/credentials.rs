//! Account credentials and app-specific password handling.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};

use crate::{Error, Result};

/// An iCloud email address paired with an app-specific password.
///
/// The password is held in a [`SecretString`] and is never printed by the
/// [`Debug`] implementation.
#[derive(Clone)]
pub struct Credentials {
    email: String,
    password: SecretString,
}

impl Credentials {
    /// Creates credentials after validating the address and normalizing the
    /// password with [`normalize_app_password`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] if the email address is not valid or
    /// the password is empty after normalization.
    pub fn new(email: &str, password: &SecretString) -> Result<Self> {
        let email = email.trim();
        email
            .parse::<lettre::Address>()
            .map_err(|_| Error::invalid("the email address is not valid"))?;
        let password = normalize_app_password(password.expose_secret());
        if password.expose_secret().is_empty() {
            return Err(Error::invalid("the app-specific password is empty"));
        }
        Ok(Self {
            email: email.to_owned(),
            password,
        })
    }

    /// Creates credentials with the password exactly as given (only an
    /// empty password is refused). For servers whose passwords may contain
    /// dashes or spaces, unlike app-specific passwords.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] if the email address is not valid or
    /// the password is empty.
    pub fn exact(email: &str, password: &SecretString) -> Result<Self> {
        let email = email.trim();
        email
            .parse::<lettre::Address>()
            .map_err(|_| Error::invalid("the email address is not valid"))?;
        if password.expose_secret().is_empty() {
            return Err(Error::invalid("the password is empty"));
        }
        Ok(Self {
            email: email.to_owned(),
            password: password.clone(),
        })
    }

    /// The account's email address, used as the login name.
    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }

    pub(crate) const fn password(&self) -> &SecretString {
        &self.password
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("email", &self.email)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Normalizes an app-specific password.
///
/// Apple shows app-specific passwords as four groups of four letters
/// separated by dashes (`abcd-efgh-ijkl-mnop`). Users paste them with or
/// without the dashes and sometimes with surrounding or embedded spaces, so
/// dashes and whitespace are removed. App-specific passwords never contain
/// either character, so this is lossless for valid input.
#[must_use]
pub fn normalize_app_password(raw: &str) -> SecretString {
    let compact: String = raw
        .chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .collect();
    SecretString::from(compact)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(value: &str) -> SecretString {
        SecretString::from(value.to_owned())
    }

    #[test]
    fn strips_dashes_and_whitespace() {
        for raw in [
            "abcd-efgh-ijkl-mnop",
            "abcdefghijklmnop",
            " abcd efgh ijkl mnop ",
            "abcd - efgh - ijkl - mnop\n",
        ] {
            assert_eq!(
                normalize_app_password(raw).expose_secret(),
                "abcdefghijklmnop"
            );
        }
    }

    #[test]
    fn credentials_validate_email() {
        assert!(Credentials::new("not an address", &secret("abcd-efgh-ijkl-mnop")).is_err());
        let creds = Credentials::new(" user@icloud.com ", &secret("abcd-efgh-ijkl-mnop")).unwrap();
        assert_eq!(creds.email(), "user@icloud.com");
        assert_eq!(creds.password().expose_secret(), "abcdefghijklmnop");
    }

    #[test]
    fn exact_credentials_keep_the_password() {
        let creds = Credentials::exact("user@example.com", &secret("a-b c")).unwrap();
        assert_eq!(creds.password().expose_secret(), "a-b c");
        assert!(Credentials::exact("user@example.com", &secret("")).is_err());
    }

    #[test]
    fn credentials_reject_empty_password() {
        assert!(Credentials::new("user@icloud.com", &secret(" - - ")).is_err());
    }

    #[test]
    fn debug_redacts_password() {
        let creds = Credentials::new("user@icloud.com", &secret("abcd-efgh-ijkl-mnop")).unwrap();
        let debug = format!("{creds:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("abcdefghijklmnop"));
    }
}
