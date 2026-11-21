//! Opaque message ids.
//!
//! Tools identify messages by an opaque `id` string. For IMAP accounts the
//! id encodes the folder, the UID and the folder's `UIDVALIDITY`
//! (`imap.<uid>.<base64url(folder)>.<uidvalidity>`), so it stays valid as
//! long as the message stays in its folder and the folder's `UIDVALIDITY`
//! does not change; the tools refuse it once that changes. Reads still accept
//! older ids without the `UIDVALIDITY` suffix; changing tools refuse them when
//! the folder reports UIDVALIDITY. Legacy folder-plus-UID selectors remain
//! unchecked, except for permanent deletion. Graph and Gmail use the
//! provider's own stable ids. Clients must treat ids as opaque.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use postkeep_mail::Uid;

/// Prefix of IMAP message ids.
pub(crate) const IMAP_PREFIX: &str = "imap.";
/// Prefix of Microsoft Graph message ids.
pub const GRAPH_PREFIX: &str = "graph.";
/// Prefix of Gmail message ids.
pub const GMAIL_PREFIX: &str = "gmail.";

/// Longest accepted id, in bytes. Provider ids are far shorter.
pub const MAX_ID_LEN: usize = 1024;

/// The id of the message `uid` in the IMAP folder `folder`, whose
/// `UIDVALIDITY` is `uid_validity`. `None` and 0 (which RFC 3501 does not
/// allow) leave the suffix out.
#[must_use]
pub fn imap_id(folder: &str, uid: Uid, uid_validity: Option<u32>) -> String {
    let id = format!("{IMAP_PREFIX}{uid}.{}", URL_SAFE_NO_PAD.encode(folder));
    match uid_validity.filter(|&value| value != 0) {
        Some(value) => format!("{id}.{value}"),
        None => id,
    }
}

/// Splits an IMAP message id into folder, UID and `UIDVALIDITY` (`None` for
/// an id without it). Returns `None` for anything that [`imap_id`] did not
/// produce.
#[must_use]
pub fn parse_imap_id(id: &str) -> Option<(String, Uid, Option<u32>)> {
    if id.len() > MAX_ID_LEN {
        return None;
    }
    let rest = id.strip_prefix(IMAP_PREFIX)?;
    let (uid, rest) = rest.split_once('.')?;
    // Unpadded base64url never contains a `.`, so a second one starts the suffix.
    let (folder, uid_validity) = match rest.split_once('.') {
        Some((folder, suffix)) => (folder, Some(positive(suffix)?)),
        None => (rest, None),
    };
    let uid = positive(uid)?;
    let folder = String::from_utf8(URL_SAFE_NO_PAD.decode(folder).ok()?).ok()?;
    if folder.is_empty() || folder.chars().any(char::is_control) {
        return None;
    }
    Some((folder, uid, uid_validity))
}

/// A nonzero `u32` written in ASCII digits without a sign or leading zero.
fn positive(digits: &str) -> Option<u32> {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) || digits.starts_with('0') {
        return None;
    }
    digits.parse().ok()
}

/// The id of a provider message: `prefix` plus the provider's own id.
#[must_use]
pub fn provider_id(prefix: &str, raw: &str) -> String {
    format!("{prefix}{raw}")
}

/// The provider's own id inside an id made by [`provider_id`]. Provider
/// ids are URL-safe base64-like strings; anything else is refused so it
/// can never change the shape of an API URL.
#[must_use]
pub fn parse_provider_id<'a>(prefix: &str, id: &'a str) -> Option<&'a str> {
    if id.len() > MAX_ID_LEN {
        return None;
    }
    let raw = id.strip_prefix(prefix)?;
    let valid = !raw.is_empty()
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'=' | b'+' | b'/'));
    valid.then_some(raw)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn round_trips() {
        let id = imap_id("INBOX", 42, Some(7));
        assert_eq!(id, "imap.42.SU5CT1g.7");
        assert_eq!(parse_imap_id(&id), Some(("INBOX".to_owned(), 42, Some(7))));
        let old = imap_id("INBOX", 42, None);
        assert_eq!(old, "imap.42.SU5CT1g");
        assert_eq!(parse_imap_id(&old), Some(("INBOX".to_owned(), 42, None)));
        assert_eq!(imap_id("INBOX", 42, Some(0)), old);
        let nested = imap_id("Archive/2026 Ä", 7, Some(u32::MAX));
        assert_eq!(
            parse_imap_id(&nested),
            Some(("Archive/2026 Ä".to_owned(), 7, Some(u32::MAX)))
        );
    }

    #[test]
    fn rejects_foreign_or_malformed_ids() {
        for id in [
            "",
            "imap.",
            "imap.42",
            "imap..SU5CT1g",
            "imap.042.SU5CT1g",
            "imap.0.SU5CT1g",
            "imap.-1.SU5CT1g",
            "imap.99999999999.SU5CT1g",
            "imap.42.!!!",
            "imap.42.",
            "imap.42.SU5CT1g.",
            "imap.42.SU5CT1g.0",
            "imap.42.SU5CT1g.07",
            "imap.42.SU5CT1g.+7",
            "imap.42.SU5CT1g.-7",
            "imap.42.SU5CT1g.x",
            "imap.42.SU5CT1g.4294967296",
            "imap.42.SU5CT1g.7.8",
            "AAMkAGI2THVSAAA=",
            "18c2f1a2b3c4d5e6",
        ] {
            assert_eq!(parse_imap_id(id), None, "{id}");
        }
    }

    #[test]
    fn provider_ids_round_trip_and_stay_url_safe() {
        let id = provider_id(GRAPH_PREFIX, "AAMkAGI2-THVS_AAA=");
        assert_eq!(
            parse_provider_id(GRAPH_PREFIX, &id),
            Some("AAMkAGI2-THVS_AAA=")
        );
        assert_eq!(parse_provider_id(GMAIL_PREFIX, &id), None);
        for bad in [
            "graph.",
            "graph.a b",
            "graph.../me",
            "graph.a?b",
            "graph.%2F",
            "imap.1.SU5CT1g",
        ] {
            assert_eq!(parse_provider_id(GRAPH_PREFIX, bad), None, "{bad}");
        }
    }

    proptest! {
        #[test]
        fn provider_ids_never_contain_url_syntax(id in "\\PC{0,80}") {
            if let Some(raw) = parse_provider_id(GRAPH_PREFIX, &id) {
                prop_assert!(!raw.contains(['?', '#', '%', '.', ' ']));
            }
        }

        #[test]
        fn any_folder_and_uid_round_trip(
            folder in "[^\\p{Cc}]{1,64}",
            uid in 1u32..,
            uid_validity in proptest::option::of(0u32..),
        ) {
            prop_assert_eq!(
                parse_imap_id(&imap_id(&folder, uid, uid_validity)),
                Some((folder, uid, uid_validity.filter(|&value| value != 0)))
            );
        }

        #[test]
        fn parsing_never_panics(id in "\\PC{0,80}") {
            let _ = parse_imap_id(&id);
        }
    }
}
