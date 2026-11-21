//! Portable search checksums, scoped to the mailbox of the call, not credentials.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use postkeep_store::{AccountId, constant_time_eq, hash_secret};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::Criteria;

const LABEL: &str = "postkeep selection v3";
macro_rules! selection_refusal {
    ($hint:literal) => {
        concat!(
            "this selection is from another mailbox, or was changed; ",
            $hint,
            "search again"
        )
    };
}
/// Refusal of an unreadable, changed or foreign search selection.
pub const REFUSAL: &str = selection_refusal!("");
/// The same refusal with guidance for callers using the mailbox selector.
pub(crate) const MAILBOX_REFUSAL: &str = selection_refusal!("pass the mailbox you searched, or ");

/// A search handed back to the caller, with a checksum, not a seal.
///
/// Any change to this type, [`Criteria`], [`super::Cutoff`] or what a selection covers must change the version label:
/// old readers must refuse, never silently drop a restriction.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchSelection {
    /// Folder searched.
    pub folder: String,
    /// Criteria, including the arrival boundary.
    pub criteria: Criteria,
}

impl SearchSelection {
    fn tag(account: &AccountId, json: &str) -> String {
        hash_secret(&json!([LABEL, account.0, json]).to_string())[..16].to_owned()
    }

    /// Encodes the search with a checksum for the call's mailbox.
    ///
    /// # Errors
    ///
    /// Returns the fixed selection refusal if serialization fails.
    pub fn encode(&self, account: &AccountId) -> Result<String, String> {
        let json = serde_json::to_string(self).map_err(|_| REFUSAL.to_owned())?;
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&json),
            Self::tag(account, &json)
        ))
    }

    /// Decodes a search, refusing every malformed or changed value alike.
    ///
    /// # Errors
    ///
    /// Returns the fixed selection refusal for a bad format, cutoff or tag.
    pub fn decode(value: &str, account: &AccountId) -> Result<Self, String> {
        let parse = || {
            let (encoded, tag) = value.split_once('.')?;
            let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
            let json = std::str::from_utf8(&bytes).ok()?;
            if !constant_time_eq(tag, Self::tag(account, json)) {
                return None;
            }
            let selection: Self = serde_json::from_str(json).ok()?;
            match selection.criteria.until? {
                super::Cutoff::Imap { uid, uid_validity } if uid > 0 && uid_validity > 0 => {}
                super::Cutoff::Time(seconds)
                    if seconds >= 0 && chrono::DateTime::from_timestamp(seconds, 0).is_some() => {}
                _ => return None,
            }
            Some(selection)
        };
        parse().ok_or_else(|| REFUSAL.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::Cutoff;

    fn example(until: Cutoff) -> SearchSelection {
        SearchSelection {
            folder: "INBOX".to_owned(),
            criteria: Criteria {
                from: Some("sender@example.com".to_owned()),
                to: Some("recipient@example.com".to_owned()),
                subject: Some("Digest".to_owned()),
                text: Some("placeholder".to_owned()),
                since: Some(chrono::NaiveDate::from_ymd_opt(2026, 1, 1).unwrap()),
                before: Some(chrono::NaiveDate::from_ymd_opt(2026, 11, 17).unwrap()),
                read: Some(false),
                flagged: Some(true),
                until: Some(until),
            },
        }
    }

    #[test]
    fn every_field_and_both_cutoffs_pin_the_versioned_format() {
        let account = AccountId("mailbox".to_owned());
        for (until, pinned) in [
            (
                Cutoff::Imap {
                    uid: 42,
                    uid_validity: 7,
                },
                "eyJmb2xkZXIiOiJJTkJPWCIsImNyaXRlcmlhIjp7ImZyb20iOiJzZW5kZXJAZXhhbXBsZS5jb20iLCJ0byI6InJlY2lwaWVudEBleGFtcGxlLmNvbSIsInN1YmplY3QiOiJEaWdlc3QiLCJ0ZXh0IjoicGxhY2Vob2xkZXIiLCJzaW5jZSI6IjIwMjYtMDEtMDEiLCJiZWZvcmUiOiIyMDI2LTExLTE3IiwicmVhZCI6ZmFsc2UsImZsYWdnZWQiOnRydWUsInVudGlsIjp7ImltYXAiOnsidWlkIjo0MiwidWlkX3ZhbGlkaXR5Ijo3fX19fQ.JNR79iI7bCIjET6_",
            ),
            (
                Cutoff::Time(1_794_912_000),
                "eyJmb2xkZXIiOiJJTkJPWCIsImNyaXRlcmlhIjp7ImZyb20iOiJzZW5kZXJAZXhhbXBsZS5jb20iLCJ0byI6InJlY2lwaWVudEBleGFtcGxlLmNvbSIsInN1YmplY3QiOiJEaWdlc3QiLCJ0ZXh0IjoicGxhY2Vob2xkZXIiLCJzaW5jZSI6IjIwMjYtMDEtMDEiLCJiZWZvcmUiOiIyMDI2LTExLTE3IiwicmVhZCI6ZmFsc2UsImZsYWdnZWQiOnRydWUsInVudGlsIjp7InRpbWUiOjE3OTQ5MTIwMDB9fX0.4Ey725kEAkeTLfFZ",
            ),
        ] {
            let encoded = example(until).encode(&account).unwrap();
            assert_eq!(encoded, pinned);
            let SearchSelection { folder, criteria } =
                SearchSelection::decode(pinned, &account).ok().unwrap();
            let Criteria {
                from,
                to,
                subject,
                text,
                since,
                before,
                read,
                flagged,
                until: decoded,
            } = criteria;
            assert_eq!(
                (
                    folder.as_str(),
                    from.as_deref(),
                    to.as_deref(),
                    subject.as_deref(),
                    text.as_deref()
                ),
                (
                    "INBOX",
                    Some("sender@example.com"),
                    Some("recipient@example.com"),
                    Some("Digest"),
                    Some("placeholder")
                )
            );
            assert_eq!(since.unwrap().to_string(), "2026-01-01");
            assert_eq!(before.unwrap().to_string(), "2026-11-17");
            assert_eq!(
                (read, flagged, decoded),
                (Some(false), Some(true), Some(until))
            );
            match until {
                Cutoff::Imap { uid, uid_validity } => assert_eq!((uid, uid_validity), (42, 7)),
                Cutoff::Time(seconds) => assert_eq!(seconds, 1_794_912_000),
            }
        }
        let v2 = "eyJmb2xkZXIiOiJJTkJPWCIsImNyaXRlcmlhIjp7ImZyb20iOiJzZW5kZXJAZXhhbXBsZS5jb20iLCJ0byI6InJlY2lwaWVudEBleGFtcGxlLmNvbSIsInN1YmplY3QiOiJEaWdlc3QiLCJ0ZXh0IjoicGxhY2Vob2xkZXIiLCJzaW5jZSI6IjIwMjYtMDEtMDEiLCJiZWZvcmUiOiIyMDI2LTExLTE3IiwicmVhZCI6ZmFsc2UsImZsYWdnZWQiOnRydWUsInVudGlsIjp7ImltYXAiOnsidWlkIjo0MiwidWlkX3ZhbGlkaXR5Ijo3fX19fQ.MrSpNT_hwuGTVtYA";
        assert_eq!(
            SearchSelection::decode(v2, &account).err().unwrap(),
            REFUSAL
        );
    }

    #[test]
    fn malformed_changed_foreign_and_newer_selections_share_one_refusal() {
        let account = AccountId("mailbox".to_owned());
        let selection = example(Cutoff::Time(1_794_912_000));
        let encoded = selection.encode(&account).unwrap();
        let raw = serde_json::to_string(&selection).unwrap();
        let v1 = hash_secret(&json!(["postkeep selection v1", account.0, raw]).to_string());
        let v1 = format!("{}.{}", URL_SAFE_NO_PAD.encode(&raw), &v1[..16]);
        assert_eq!(
            SearchSelection::decode(&v1, &account).err().unwrap(),
            REFUSAL
        );
        assert_eq!(
            SearchSelection::decode(&encoded, &AccountId("other".to_owned()))
                .err()
                .unwrap(),
            REFUSAL
        );
        let mut edited = serde_json::to_value(&selection).unwrap();
        edited["criteria"]["read"] = json!(true);
        let mut values = vec![
            String::new(),
            "garbled".to_owned(),
            format!("{encoded}x"),
            format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(edited.to_string()),
                encoded.split_once('.').unwrap().1
            ),
        ];
        for pointer in ["/extra", "/criteria/extra", "/criteria/until/imap/extra"] {
            let mut extra = serde_json::to_value(example(Cutoff::Imap {
                uid: 42,
                uid_validity: 7,
            }))
            .unwrap();
            // Put an unknown field in each object, with a valid checksum.
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            extra
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(key.to_owned(), json!(true));
            let raw = extra.to_string();
            values.push(format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(&raw),
                SearchSelection::tag(&account, &raw)
            ));
        }
        let raw = serde_json::to_string(&selection).unwrap();
        let old = hash_secret(&json!(["postkeep selection v0", account.0, raw]).to_string());
        values.push(format!("{}.{}", URL_SAFE_NO_PAD.encode(&raw), &old[..16]));
        for value in values {
            assert_eq!(
                SearchSelection::decode(&value, &account).err().unwrap(),
                REFUSAL
            );
        }
    }
}
