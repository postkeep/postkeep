//! Webhook delivery for postkeep: URL and header validation,
//! an HTTPS client that refuses non-public addresses (SSRF protection),
//! HMAC-SHA256 signing, the event payload, retries with backoff and the filter
//! rules that decide which new mail is reported at all.
//!
//! See `docs/webhooks.md` in the repository for the receiver's view.

mod client;
pub mod filter;
pub mod ip;
mod payload;
mod retry;
pub mod sign;
mod target;
#[cfg(feature = "testing")]
#[doc(hidden)]
pub mod testing;

pub use client::{
    ATTEMPT_TIMEOUT, Deliverer, DeliveryError, FetchError, Fetched, Outgoing, Response,
};
pub use payload::{EventMeta, NEW_MAIL, NewMailEvent, event_request};
pub use retry::{Delivery, RETRY_DELAYS, deliver, is_retryable, is_success};
pub use target::{
    AuthHeader, MAX_HEADER_VALUE_LEN, MAX_URL_LEN, TargetError, WebhookUrl, parse_header_name,
};
