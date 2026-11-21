//! The JSON body of a webhook delivery.

use bytes::Bytes;
use http::{HeaderMap, HeaderValue};
use serde::Serialize;

use crate::{AuthHeader, Outgoing, WebhookUrl, sign};

/// The `event` value of a new-mail delivery.
pub const NEW_MAIL: &str = "new_mail";

/// A new-mail event.
///
/// The fields describe the newest message of one batch and `count` is how
/// many messages that batch covers. An IMAP backlog is several events of at
/// most 50 messages, oldest first. Messages that arrive within the debounce
/// window share one event when they fit in that batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NewMailEvent {
    /// Always [`NEW_MAIL`].
    pub event: &'static str,
    /// `true` for test deliveries sent from the account page, which carry
    /// sample data. Omitted otherwise.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub test: bool,
    /// The email address of the account.
    pub account: String,
    /// The folder, currently always `INBOX`.
    pub folder: String,
    /// Opaque id of the newest message, as used by the MCP tools.
    pub id: String,
    /// IMAP UID of the newest message. Only for IMAP accounts; prefer `id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Its `Message-ID` header, if it has one.
    pub message_id: Option<String>,
    /// Its `From` header. Omitted unless sender and subject are enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// `true` when the sender does not read as one address, alone or after a name, and `from`
    /// is its first `From` header written whole, so a mail app may show another sender.
    /// Omitted otherwise, and whenever `from` is omitted.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub from_unclear: bool,
    /// Its `Subject`. Omitted unless sender and subject are enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Its `Date` header as RFC 3339, if present and valid.
    pub date: Option<String>,
    /// How many new messages this delivery covers (at least 1).
    pub count: u32,
}

impl NewMailEvent {
    /// The serialized body.
    #[must_use]
    pub fn to_body(&self) -> Vec<u8> {
        // Serializing plain strings and integers can't fail.
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Removes the sender and subject.
    #[must_use]
    pub fn without_sender_and_subject(mut self) -> Self {
        self.from = None;
        self.from_unclear = false;
        self.subject = None;
        self
    }

    /// The request delivering this event: body, `X-Webhook-*` headers, the
    /// signature when `signing_secret` is given and the custom auth header.
    /// `id` must stay the same across retries; `timestamp` is Unix seconds.
    #[must_use]
    pub fn request(
        &self,
        url: WebhookUrl,
        id: &str,
        timestamp: i64,
        auth: Option<&AuthHeader>,
        signing_secret: Option<&str>,
    ) -> Outgoing {
        event_request(
            Bytes::from(self.to_body()),
            url,
            &EventMeta {
                id,
                sequence: None,
                timestamp,
            },
            auth,
            signing_secret,
        )
    }

    /// A sample event for test deliveries.
    #[must_use]
    pub fn sample(account: &str) -> Self {
        Self {
            event: NEW_MAIL,
            test: true,
            account: account.to_owned(),
            folder: "INBOX".to_owned(),
            id: "imap.1.SU5CT1g".to_owned(),
            uid: Some(1),
            message_id: Some("<test@postkeep.invalid>".to_owned()),
            from: Some("postkeep <test@postkeep.invalid>".to_owned()),
            from_unclear: false,
            subject: Some("Test event".to_owned()),
            date: None,
            count: 1,
        }
    }
}

/// Identifies one delivery of a stored event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventMeta<'a> {
    /// Event id, the same across retries and replays (`X-Webhook-Id`).
    pub id: &'a str,
    /// Position in the account's event stream (`X-Webhook-Sequence`), for
    /// events from the outbox.
    pub sequence: Option<i64>,
    /// Unix seconds the delivery is signed at (`X-Webhook-Timestamp`).
    pub timestamp: i64,
}

/// The request delivering an already serialized `new_mail` `body`.
#[must_use]
pub fn event_request(
    body: Bytes,
    url: WebhookUrl,
    meta: &EventMeta<'_>,
    auth: Option<&AuthHeader>,
    signing_secret: Option<&str>,
) -> Outgoing {
    let mut headers = HeaderMap::new();
    if let Some(auth) = auth {
        headers.insert(auth.name.clone(), auth.value.clone());
    }
    if let Ok(id) = HeaderValue::from_str(meta.id) {
        headers.insert(sign::ID_HEADER, id);
    }
    if let Some(sequence) = meta.sequence {
        headers.insert(sign::SEQUENCE_HEADER, HeaderValue::from(sequence));
    }
    headers.insert(sign::EVENT_HEADER, HeaderValue::from_static(NEW_MAIL));
    headers.insert(sign::TIMESTAMP_HEADER, HeaderValue::from(meta.timestamp));
    if let Some(secret) = signing_secret
        && let Ok(signature) = HeaderValue::from_str(&sign::sign(secret, meta.timestamp, &body))
    {
        headers.insert(sign::SIGNATURE_HEADER, signature);
    }
    Outgoing { url, headers, body }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_signed_requests() {
        let url = WebhookUrl::parse("https://hooks.example.com/x")
            .unwrap_or_else(|e| unreachable!("{e}"));
        let auth =
            AuthHeader::new("Authorization", "Bearer t").unwrap_or_else(|e| unreachable!("{e}"));
        let event = NewMailEvent::sample("me@icloud.com");
        let request = event.request(url.clone(), "id-1", 1000, Some(&auth), Some("whsec_k"));
        assert_eq!(request.body, Bytes::from(event.to_body()));
        assert_eq!(request.headers["authorization"], "Bearer t");
        assert_eq!(request.headers[sign::ID_HEADER], "id-1");
        assert_eq!(request.headers[sign::EVENT_HEADER], "new_mail");
        assert_eq!(request.headers[sign::TIMESTAMP_HEADER], "1000");
        let signature = request.headers[sign::SIGNATURE_HEADER]
            .to_str()
            .unwrap_or_default();
        assert!(sign::verify(
            "whsec_k",
            1000,
            &request.body,
            signature,
            1000,
            300
        ));

        let request = event.request(url, "id-1", 1000, None, None);
        assert!(!request.headers.contains_key(sign::SIGNATURE_HEADER));
        assert!(!request.headers.contains_key("authorization"));
    }

    #[test]
    fn serializes_the_documented_shape() {
        let event = NewMailEvent {
            date: Some("2026-10-08T02:12:04+00:00".to_owned()),
            test: false,
            count: 2,
            ..NewMailEvent::sample("me@icloud.com")
        };
        let json: serde_json::Value = serde_json::from_slice(&event.to_body()).unwrap_or_default();
        assert_eq!(
            json,
            serde_json::json!({
                "event": "new_mail",
                "account": "me@icloud.com",
                "folder": "INBOX",
                "id": "imap.1.SU5CT1g",
                "uid": 1,
                "message_id": "<test@postkeep.invalid>",
                "from": "postkeep <test@postkeep.invalid>",
                "subject": "Test event",
                "date": "2026-10-08T02:12:04+00:00",
                "count": 2
            })
        );
        let json: serde_json::Value = serde_json::from_slice(
            &NewMailEvent::sample("me@icloud.com")
                .without_sender_and_subject()
                .to_body(),
        )
        .unwrap_or_default();
        assert_eq!(json["test"], true);
        assert!(json.get("from").is_none() && json.get("subject").is_none());
        assert!(json["date"].is_null());
        let unclear = NewMailEvent {
            from_unclear: true,
            ..NewMailEvent::sample("me@icloud.com")
        };
        let json: serde_json::Value =
            serde_json::from_slice(&unclear.to_body()).unwrap_or_default();
        assert_eq!(json["from_unclear"], true);
        let json: serde_json::Value =
            serde_json::from_slice(&unclear.without_sender_and_subject().to_body())
                .unwrap_or_default();
        assert!(json.get("from_unclear").is_none());
        let json: serde_json::Value = serde_json::from_slice(
            &NewMailEvent {
                uid: None,
                id: "AAMkAD-graph-id".to_owned(),
                ..NewMailEvent::sample("me@example.com")
            }
            .to_body(),
        )
        .unwrap_or_default();
        assert!(json.get("uid").is_none());
        assert_eq!(json["id"], "AAMkAD-graph-id");
    }
}
