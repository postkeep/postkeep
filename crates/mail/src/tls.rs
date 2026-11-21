//! TLS setup (rustls with the Mozilla root store) and a stream that may or
//! may not be encrypted.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::{Error, Result};

/// Builds a TLS connector that verifies certificates against the bundled
/// Mozilla root store, so the result is the same on every host and container.
pub fn connector() -> Result<TlsConnector> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Performs a TLS handshake over `tcp`, verifying the certificate for `host`.
pub async fn handshake(
    connector: &TlsConnector,
    host: &str,
    tcp: TcpStream,
) -> Result<MaybeTlsStream> {
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| Error::invalid(format!("invalid server host name: {host}")))?;
    let stream = connector.connect(name, tcp).await?;
    Ok(MaybeTlsStream::Tls(Box::new(stream)))
}

/// A TCP stream that is either wrapped in TLS or left in plaintext.
#[derive(Debug)]
pub enum MaybeTlsStream {
    /// TLS-encrypted stream.
    Tls(Box<TlsStream<TcpStream>>),
    /// Unencrypted stream, only used against local test servers.
    Plain(TcpStream),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_builds() {
        assert!(connector().is_ok());
    }
}
