//! Message submission over SMTP.

use std::io;
use std::time::Duration;

use lettre::transport::smtp::authentication::{Credentials as SmtpCredentials, DEFAULT_MECHANISMS};
use lettre::transport::smtp::client::{AsyncSmtpConnection, TlsParameters};
use lettre::transport::smtp::commands::{Data, Mail, Rcpt};
use lettre::transport::smtp::extension::{ClientId, Extension, MailBodyParameter, MailParameter};
use lettre::transport::smtp::response::Severity;
use secrecy::ExposeSecret;

use crate::imap::with_timeout;
use crate::{Credentials, Error, Result, SmtpConfig, SmtpSecurity};

/// SMTP reply code for rejected credentials: the client should ask for new
/// ones (RFC 4954, section 6).
const AUTH_FAILED: &str = "535";

/// SMTP reply code for a temporary server failure. RFC 4954 (section 6) gives
/// it to `AUTH`, where the client should not ask for another password, and
/// RFC 3207 to `STARTTLS`; a server may send it to `RCPT TO` too. lettre does
/// not say which command got the reply, so a 454 to any of them is caught here.
/// Other 4xx replies stay plain SMTP errors, which keep the server's text.
const AUTH_TEMPORARY: &str = "454";

/// Submits `message` and returns the exact bytes that were sent.
pub async fn submit(
    config: &SmtpConfig,
    credentials: &Credentials,
    timeout: Duration,
    message: &lettre::Message,
) -> Result<Vec<u8>> {
    let raw = message.formatted();
    let mut data_started = false;
    let mut accepted = false;
    tracing::debug!(host = %config.host, port = config.port, "submitting message over SMTP");
    let result = Box::pin(with_timeout(timeout, async {
        let mut conn = connect(config, credentials, timeout).await?;
        let envelope = message.envelope();
        let mut parameters = Vec::new();
        for (needed, extension, parameter, name) in [
            (
                envelope
                    .from()
                    .into_iter()
                    .chain(envelope.to())
                    .any(|address| !AsRef::<str>::as_ref(address).is_ascii()),
                Extension::SmtpUtfEight,
                MailParameter::SmtpUtfEight,
                "SMTPUTF8",
            ),
            (
                !raw.is_ascii(),
                Extension::EightBitMime,
                MailParameter::Body(MailBodyParameter::EightBitMime),
                "8BITMIME",
            ),
        ] {
            if needed {
                if !conn.server_info().supports_feature(extension) {
                    return Err(Error::Unsupported(name));
                }
                parameters.push(parameter);
            }
        }
        conn.command(Mail::new(envelope.from().cloned(), parameters))
            .await
            .map_err(smtp_error)?;
        // Any recipient refusal stops the transaction before any message bytes are sent.
        for to in envelope.to() {
            conn.command(Rcpt::new(to.clone(), vec![]))
                .await
                .map_err(smtp_error)?;
        }
        if !conn.command(Data).await.map_err(smtp_error)?.has_code(354) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected SMTP reply to DATA",
            )
            .into());
        }
        data_started = true;
        // lettre writes and dot-stuffs DATA, then reads the acknowledgement in one call.
        // With no final reply, we cannot tell whether the relay received the terminator.
        let reply = conn.message(&raw).await.map_err(smtp_error)?;
        if reply.code().severity != Severity::PositiveCompletion {
            return Err(Error::SubmissionUnconfirmed);
        }
        accepted = true;
        conn.abort().await;
        Ok(())
    }))
    .await;
    match result {
        // A QUIT timeout cannot undo the acknowledgement already received.
        Err(Error::Timeout) if accepted => Ok(raw),
        Err(Error::Timeout) if data_started => Err(Error::SubmissionUnconfirmed),
        Err(Error::Smtp(error)) if data_started && error.status().is_none() => {
            Err(Error::SubmissionUnconfirmed)
        }
        other => other.map(|()| raw),
    }
}

async fn connect(
    config: &SmtpConfig,
    credentials: &Credentials,
    timeout: Duration,
) -> Result<AsyncSmtpConnection> {
    let hello = ClientId::default();
    let (implicit_tls, starttls) = tls_modes(config)?;
    let mut conn = AsyncSmtpConnection::connect_tokio1(
        (config.host.as_str(), config.port),
        Some(timeout),
        &hello,
        implicit_tls,
        None,
    )
    .await
    .map_err(smtp_error)?;
    if let Some(tls) = starttls {
        conn.starttls(tls, &hello).await.map_err(smtp_error)?;
    }
    let smtp_credentials = SmtpCredentials::new(
        credentials.email().to_owned(),
        credentials.password().expose_secret().to_owned(),
    );
    conn.auth(DEFAULT_MECHANISMS, &smtp_credentials)
        .await
        .map_err(smtp_error)?;
    Ok(conn)
}

fn tls_modes(config: &SmtpConfig) -> Result<(Option<TlsParameters>, Option<TlsParameters>)> {
    match config.security {
        SmtpSecurity::Tls => Ok((Some(TlsParameters::new(config.host.clone())?), None)),
        SmtpSecurity::StartTls => Ok((None, Some(TlsParameters::new(config.host.clone())?))),
        SmtpSecurity::Plaintext => Ok((None, None)),
    }
}

fn smtp_error(err: lettre::transport::smtp::Error) -> Error {
    match err.status().map(|code| code.to_string()).as_deref() {
        Some(AUTH_FAILED) => Error::Authentication,
        Some(AUTH_TEMPORARY) => Error::Unavailable {
            code: AUTH_TEMPORARY,
        },
        _ => Error::Smtp(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_tls_modes() -> Result<()> {
        for (security, expected) in [
            (SmtpSecurity::Tls, (true, false)),
            (SmtpSecurity::StartTls, (false, true)),
            (SmtpSecurity::Plaintext, (false, false)),
        ] {
            let config = SmtpConfig {
                host: "mail.example.org".to_owned(),
                port: 0,
                security,
            };
            let (implicit_tls, starttls) = tls_modes(&config)?;
            assert_eq!(
                (implicit_tls.is_some(), starttls.is_some()),
                expected,
                "{security:?}"
            );
        }
        Ok(())
    }
}
