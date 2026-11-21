//! AES-256-GCM encryption of stored passwords and hashing of secrets.

use std::fmt::Write as _;

use aes_gcm::aead::{Aead, Generate, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
#[cfg(any(test, feature = "fuzzing"))]
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::envelope::DataKey;
use crate::{Result, StoreError};

/// Prefix of ciphertexts produced by this version of the format.
pub const FORMAT_V1: &str = "v1.";
/// Prefix of ciphertexts that a tenant's data key encrypts.
pub const FORMAT_V2: &str = "v2.";
/// The number of the newest format this build reads, the `2` of [`FORMAT_V2`].
/// A prefix `v<number>.` above it is a newer version's.
const NEWEST_FORMAT: u64 = 2;
/// AES-GCM nonce length in bytes.
const NONCE_LEN: usize = 12;
/// Length of a master key in bytes.
pub const KEY_LEN: usize = 32;

/// The 256-bit key that encrypts stored iCloud passwords.
///
/// Losing the key makes stored credentials unreadable (users simply sign in
/// again); leaking it together with the database exposes them.
pub struct MasterKey(Zeroizing<[u8; KEY_LEN]>);

impl MasterKey {
    /// Parses a key given as 64 hexadecimal characters or as base64
    /// (standard or URL-safe alphabet) of exactly 32 bytes. Surrounding
    /// whitespace is ignored, so the content of a secret file can be passed
    /// directly.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidKey`] if the text is not a 32-byte key.
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let bytes = Zeroizing::new(if text.len() == KEY_LEN * 2 && is_hex(text) {
            decode_hex(text)
        } else {
            [STANDARD, URL_SAFE, URL_SAFE_NO_PAD]
                .iter()
                .find_map(|engine| engine.decode(text).ok())
                .ok_or(StoreError::InvalidKey(
                    "expected 64 hex characters or base64 of 32 bytes",
                ))?
        });
        let key: [u8; KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::InvalidKey("the key must be exactly 32 bytes"))?;
        Ok(Self(Zeroizing::new(key)))
    }

    /// Generates a new random key, encoded as base64 for configuration.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Random`] if the system RNG fails.
    pub fn generate_encoded() -> Result<String> {
        let mut key = Zeroizing::new([0_u8; KEY_LEN]);
        getrandom::fill(key.as_mut_slice()).map_err(|_| StoreError::Random)?;
        Ok(STANDARD.encode(key.as_slice()))
    }

    pub(crate) fn aead(&self) -> Aes256Gcm {
        let key: &[u8; KEY_LEN] = &self.0;
        Aes256Gcm::new(key.into())
    }

    /// A name for this key that reveals nothing of it: the first 16 hex
    /// digits of a SHA-256 over a fixed label and the key.
    pub(crate) fn id(&self) -> String {
        let digest = Sha256::new()
            .chain_update(b"postkeep/kek-id/v1/")
            .chain_update(self.0.as_slice())
            .finalize();
        digest[..8].iter().fold(String::new(), |mut id, byte| {
            let _ = write!(id, "{byte:02x}");
            id
        })
    }

    /// Whether two keys are the same.
    fn same_as(&self, other: &Self) -> bool {
        constant_time_eq(self.0.as_slice(), other.0.as_slice())
    }

    /// A cipher that encrypts with `self` and can still decrypt values
    /// written under any of `previous` (for key rotation). Keys equal to
    /// `self` are ignored.
    pub(crate) fn cipher(&self, previous: &[Self]) -> Cipher {
        Cipher {
            current: self.aead(),
            previous: previous
                .iter()
                .filter(|key| !key.same_as(self))
                .map(Self::aead)
                .collect(),
        }
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey([REDACTED])")
    }
}

/// Which key decrypted a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsed {
    /// The current master key.
    Current,
    /// A previous master key.
    Previous,
}

/// Encrypts stored secrets with the current master key and decrypts them
/// with the current or a previous one.
pub struct Cipher {
    current: Aes256Gcm,
    previous: Vec<Aes256Gcm>,
}

impl Cipher {
    /// Encrypts `password`, binding the ciphertext to `email` as associated
    /// data so it cannot be moved to another account row. Only tests and the
    /// fuzz targets seal a password like this: a store writes it under a data key.
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn encrypt(&self, email: &str, password: &SecretString) -> Result<String> {
        self.seal(
            &password_context(email),
            password.expose_secret().as_bytes(),
        )
    }

    /// Decrypts a value produced by [`Cipher::encrypt`] for the same `email`.
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn decrypt(&self, email: &str, stored: &str) -> Result<SecretString> {
        self.decrypt_reporting(email, stored)
            .map(|(password, _)| password)
    }

    /// Like [`Cipher::decrypt`], also telling which key was used.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn decrypt_reporting(
        &self,
        email: &str,
        stored: &str,
    ) -> Result<(SecretString, KeyUsed)> {
        let (plaintext, used) = self.open(&password_context(email), stored)?;
        let text = std::str::from_utf8(&plaintext).map_err(|_| StoreError::Decrypt)?;
        Ok((SecretString::from(text.to_owned()), used))
    }

    /// Encrypts `plaintext` under the current key. `context` is bound as
    /// associated data: it names what the value is and which row it
    /// belongs to, so a ciphertext cannot be moved elsewhere. Nothing in a
    /// store writes this format any more: only tests and the fuzz targets
    /// make it, to have a value like those an earlier version stored.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn seal(&self, context: &str, plaintext: &[u8]) -> Result<String> {
        let nonce = Nonce::try_generate().map_err(|_| StoreError::Random)?;
        let ciphertext = self
            .current
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| StoreError::Decrypt)?;
        let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        Ok(format!("{FORMAT_V1}{}", URL_SAFE_NO_PAD.encode(blob)))
    }

    /// Decrypts a value produced by [`Cipher::seal`] with the same
    /// `context`, trying the current key first and then previous keys.
    pub(crate) fn open(
        &self,
        context: &str,
        stored: &str,
    ) -> Result<(Zeroizing<Vec<u8>>, KeyUsed)> {
        let encoded = stored.strip_prefix(FORMAT_V1).ok_or(StoreError::Decrypt)?;
        let blob = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| StoreError::Decrypt)?;
        if blob.len() <= NONCE_LEN {
            return Err(StoreError::Decrypt);
        }
        let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce = Nonce::try_from(nonce).map_err(|_| StoreError::Decrypt)?;
        let payload = || Payload {
            msg: ciphertext,
            aad: context.as_bytes(),
        };
        if let Ok(plaintext) = self.current.decrypt(&nonce, payload()) {
            return Ok((Zeroizing::new(plaintext), KeyUsed::Current));
        }
        self.previous
            .iter()
            .find_map(|key| key.decrypt(&nonce, payload()).ok())
            .map(|plaintext| (Zeroizing::new(plaintext), KeyUsed::Previous))
            .ok_or(StoreError::Decrypt)
    }

    /// Whether previous keys are configured.
    pub(crate) const fn rotating(&self) -> bool {
        !self.previous.is_empty()
    }
}

/// An encrypted column. A v2 value binds its table and column, so it opens
/// only in the column it was sealed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    pub table: &'static str,
    pub column: &'static str,
}

impl Slot {
    pub const fn new(table: &'static str, column: &'static str) -> Self {
        Self { table, column }
    }
}

/// Associated data of a v2 value: `postkeep/v2/<tenant>/<table>.<column>/<row
/// key>`, with `%` written `%25` and `/` written `%2F` in the tenant, and
/// nothing else escaped. The tenant comes first because the data key is the
/// tenant's. The escaped tenant and a slot have no `/`, and the row key is
/// last and as it is, so the parts cannot run into each other: no two
/// combinations of tenant, slot and row key give the same text. This exact
/// value is part of every stored v2 ciphertext; changing it would make them
/// unreadable.
pub fn v2_context(tenant: &str, slot: Slot, row_key: &str) -> String {
    let tenant = tenant.replace('%', "%25").replace('/', "%2F");
    format!(
        "postkeep/v2/{tenant}/{}.{}/{row_key}",
        slot.table, slot.column
    )
}

/// Whether `stored` starts `v<number>.` with a number above the newest format
/// this build reads. The number is one that a writer makes: digits, no sign, no
/// leading zero. Text that only looks like it, such as `v03.` or `vx.`, is not
/// a format any writer makes, so it is not a newer one. A number too long for a
/// `u64` is above any that this build knows.
fn is_newer_format(stored: &str) -> bool {
    let Some((number, _)) = stored
        .strip_prefix('v')
        .and_then(|rest| rest.split_once('.'))
    else {
        return false;
    };
    let digits = !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit());
    digits && !number.starts_with('0') && number.parse::<u64>().unwrap_or(u64::MAX) > NEWEST_FORMAT
}

/// How a stored value is encrypted, by its prefix.
#[derive(Debug, PartialEq, Eq)]
pub enum Stored<'a> {
    /// The master key, with the legacy context. Text in no known format lands
    /// here too, and `Cipher::open` rejects it. A newer version's format is not
    /// "no known format": [`Stored::parse`] sets it apart.
    V1,
    /// `v2.<version>.<blob>`: version `version` of a tenant's data key.
    V2 {
        /// The data key's version.
        version: i64,
        /// Base64url, without padding, of the nonce and the ciphertext.
        blob: &'a str,
    },
}

impl<'a> Stored<'a> {
    /// Reads the format of `stored`, without decrypting it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NewerFormat`] for text that starts `v<number>.`
    /// with a number above the newest format this build reads (`v3.` and up).
    /// A newer version may have written it, so it is not reported as damage.
    ///
    /// Returns [`StoreError::Decrypt`] for text that starts with `v2.` but is
    /// not `v2.<version>.<blob>` with the version in canonical decimal: digits
    /// only, no sign, no leading zero, from 1 to `i64::MAX`. Every value has
    /// one text, so a compare-and-set update on it stays exact.
    pub fn parse(stored: &'a str) -> Result<Self> {
        let Some(rest) = stored.strip_prefix(FORMAT_V2) else {
            return if is_newer_format(stored) {
                Err(StoreError::NewerFormat)
            } else {
                Ok(Self::V1)
            };
        };
        let (version, blob) = rest.split_once('.').ok_or(StoreError::Decrypt)?;
        if version.starts_with('0') || !version.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(StoreError::Decrypt);
        }
        // An empty version, or one above `i64::MAX`, does not parse.
        let version = version.parse().map_err(|_| StoreError::Decrypt)?;
        Ok(Self::V2 { version, blob })
    }
}

/// Decrypts the blob of a v2 value with the data key it names. `context` is
/// the associated data, see [`v2_context`].
pub fn open_v2(key: &DataKey, context: &str, blob: &str) -> Result<Zeroizing<Vec<u8>>> {
    let blob = URL_SAFE_NO_PAD
        .decode(blob)
        .map_err(|_| StoreError::Decrypt)?;
    if blob.len() <= NONCE_LEN {
        return Err(StoreError::Decrypt);
    }
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::try_from(nonce).map_err(|_| StoreError::Decrypt)?;
    Aes256Gcm::new(key.expose().into())
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: context.as_bytes(),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| StoreError::Decrypt)
}

/// Encrypts `plaintext` under version `version` of `key` as a v2 value, with a
/// fresh nonce. `context` is the associated data, see [`v2_context`].
pub fn seal_v2(key: &DataKey, version: i64, context: &str, plaintext: &[u8]) -> Result<String> {
    let nonce = Nonce::try_generate().map_err(|_| StoreError::Random)?;
    let ciphertext = Aes256Gcm::new(key.expose().into())
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: context.as_bytes(),
            },
        )
        .map_err(|_| StoreError::Decrypt)?;
    let blob = [nonce.as_slice(), &ciphertext].concat();
    Ok(format!(
        "{FORMAT_V2}{version}.{}",
        URL_SAFE_NO_PAD.encode(blob)
    ))
}

/// Associated data of an encrypted account password.
///
/// This exact value is part of every stored ciphertext; changing it would
/// make stored passwords unreadable.
pub fn password_context(email: &str) -> String {
    format!("icloud-mail-mcp/account-password/v1/{email}")
}

/// The column of an encrypted account password.
pub const PASSWORD_SLOT: Slot = Slot::new("accounts", "password_ciphertext");

/// Hashes a high-entropy secret (token, code, client secret) for storage.
#[must_use]
pub fn hash_secret(secret: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}

/// Compares bytes or strings without short-circuiting on the first difference.
#[must_use]
pub fn constant_time_eq(a: impl AsRef<[u8]>, b: impl AsRef<[u8]>) -> bool {
    let (a, b) = (a.as_ref(), b.as_ref());
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn is_hex(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn decode_hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .filter_map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> MasterKey {
        MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap()
    }

    fn secret(value: &str) -> SecretString {
        SecretString::from(value.to_owned())
    }

    /// The rule for a new format: it takes a new level, and a released
    /// level's formats never change.
    #[test]
    fn every_stored_format_has_a_storage_level() {
        let levels: &[(i64, &[&str])] = &[(1, &[FORMAT_V1, FORMAT_V2])];
        assert_eq!(levels[0], (1, &["v1.", "v2."][..]), "level 1 is released");
        assert_eq!(
            levels.iter().map(|(level, _)| *level).collect::<Vec<_>>(),
            (1..=crate::STORAGE_LEVEL_READS).collect::<Vec<_>>()
        );
        let listed: Vec<String> = levels
            .iter()
            .flat_map(|(_, formats)| formats.iter().map(|&format| format.to_owned()))
            .collect();
        let read: Vec<String> = (1..=NEWEST_FORMAT).map(|n| format!("v{n}.")).collect();
        assert_eq!(listed, read);
    }

    #[test]
    fn parses_hex_and_base64_keys() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        assert!(MasterKey::parse(hex).is_ok());
        assert!(MasterKey::parse(&format!("  {hex}\n")).is_ok());
        let b64 = STANDARD.encode([7_u8; 32]);
        assert!(MasterKey::parse(&b64).is_ok());
        assert!(MasterKey::parse(&URL_SAFE_NO_PAD.encode([7_u8; 32])).is_ok());
    }

    /// A password stored by version 0.1.0. The associated data must stay
    /// the same so this ciphertext still decrypts.
    #[test]
    fn decrypts_a_password_stored_by_version_0_1_0() {
        let key = MasterKey::parse("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=").unwrap();
        let stored = "v1.AAECAwQFBgcICQoLeeOKFHxrui0W0Ib4gzoPnpoIGEwd-_0hdUaq2rZR4IQ";
        let password = key.cipher(&[]).decrypt("a@icloud.com", stored).unwrap();
        assert_eq!(password.expose_secret(), "abcdabcdabcdabcd");
    }

    #[test]
    fn rejects_short_or_garbage_keys() {
        assert!(MasterKey::parse("").is_err());
        assert!(MasterKey::parse(&STANDARD.encode([1_u8; 16])).is_err());
        assert!(MasterKey::parse("not a key at all!").is_err());
    }

    #[test]
    fn encrypt_roundtrip_uses_fresh_nonces() {
        let cipher = key().cipher(&[]);
        let a = cipher
            .encrypt("a@icloud.com", &secret("abcdabcdabcdabcd"))
            .unwrap();
        let b = cipher
            .encrypt("a@icloud.com", &secret("abcdabcdabcdabcd"))
            .unwrap();
        assert_ne!(a, b);
        assert!(a.starts_with("v1."));
        assert!(!a.contains("abcdabcd"));
        let plain = cipher.decrypt("a@icloud.com", &a).unwrap();
        assert_eq!(plain.expose_secret(), "abcdabcdabcdabcd");
    }

    #[test]
    fn decryption_fails_for_other_account_or_key() {
        let cipher = key().cipher(&[]);
        let stored = cipher.encrypt("a@icloud.com", &secret("pw")).unwrap();
        assert!(cipher.decrypt("b@icloud.com", &stored).is_err());
        assert!(key().cipher(&[]).decrypt("a@icloud.com", &stored).is_err());
        assert!(cipher.decrypt("a@icloud.com", "v1.AAAA").is_err());
        assert!(cipher.decrypt("a@icloud.com", "garbage").is_err());
    }

    #[test]
    fn previous_keys_still_decrypt() {
        let old = key();
        let new = key();
        let stored = old
            .cipher(&[])
            .encrypt("a@icloud.com", &secret("pw"))
            .unwrap();

        let rotating = new.cipher(&[old]);
        assert!(rotating.rotating());
        let (plain, used) = rotating.decrypt_reporting("a@icloud.com", &stored).unwrap();
        assert_eq!(plain.expose_secret(), "pw");
        assert_eq!(used, KeyUsed::Previous);

        // New values use the new key only.
        let fresh = rotating.encrypt("a@icloud.com", &secret("pw")).unwrap();
        let (_, used) = rotating.decrypt_reporting("a@icloud.com", &fresh).unwrap();
        assert_eq!(used, KeyUsed::Current);
        assert!(new.cipher(&[]).decrypt("a@icloud.com", &fresh).is_ok());
        // The associated data still applies with previous keys.
        assert!(rotating.decrypt("b@icloud.com", &stored).is_err());
    }

    #[test]
    fn the_current_key_is_not_a_previous_key() {
        let current = key();
        let same = MasterKey(current.0.clone());
        assert!(!current.cipher(&[same]).rotating());
    }

    #[test]
    fn contexts_are_bound() {
        let cipher = key().cipher(&[]);
        let stored = cipher.seal("webhook/one", b"value").unwrap();
        assert_eq!(&*cipher.open("webhook/one", &stored).unwrap().0, b"value");
        assert!(cipher.open("webhook/two", &stored).is_err());
    }

    const SLOT: Slot = Slot::new("webhooks", "signing_secret_ciphertext");

    fn is_decrypt<T>(result: Result<T>) -> bool {
        result.is_err_and(|err| matches!(err, StoreError::Decrypt))
    }

    #[test]
    fn a_v2_value_opens_only_for_its_key_tenant_column_and_row() {
        let data = DataKey::generate().unwrap();
        let context = v2_context("tenant-a", SLOT, "row-1");
        let stored = seal_v2(&data, 3, &context, b"value").unwrap();
        let Ok(Stored::V2 { version: 3, blob }) = Stored::parse(&stored) else {
            panic!("not a v2 value: {stored}");
        };
        assert_eq!(&*open_v2(&data, &context, blob).unwrap(), b"value");
        let again = seal_v2(&data, 3, &context, b"value").unwrap();
        assert_ne!(stored, again, "a fresh nonce each time");

        let column = Slot::new("webhooks", "auth_header_value_ciphertext");
        let table = Slot::new("accounts", "signing_secret_ciphertext");
        for other in [
            v2_context("tenant-b", SLOT, "row-1"),
            v2_context("tenant-a", column, "row-1"),
            v2_context("tenant-a", table, "row-1"),
            v2_context("tenant-a", SLOT, "row-2"),
        ] {
            assert!(is_decrypt(open_v2(&data, &other, blob)), "{other}");
        }
        let stranger = DataKey::generate().unwrap();
        assert!(is_decrypt(open_v2(&stranger, &context, blob)));
        let mut bytes = URL_SAFE_NO_PAD.decode(blob).unwrap();
        bytes[NONCE_LEN] ^= 1;
        let tampered = URL_SAFE_NO_PAD.encode(bytes);
        assert!(is_decrypt(open_v2(&data, &context, &tampered)));
    }

    #[test]
    fn a_tenant_cannot_run_into_the_rest_of_the_associated_data() {
        let slot = Slot::new("accounts", "password_ciphertext");
        // The same text, split between the tenant and the row key in two ways.
        let a = v2_context("t", slot, "accounts.password_ciphertext/x@y.com");
        let b = v2_context("t/accounts.password_ciphertext", slot, "x@y.com");
        assert_ne!(a, b);
        assert_ne!(v2_context("a/b", SLOT, "r"), v2_context("a%2Fb", SLOT, "r"));
        // Only `%` and `/` of the tenant are escaped, and the row key is not.
        let plain = v2_context("tenant-a", SLOT, "row-1");
        assert_eq!(
            plain,
            "postkeep/v2/tenant-a/webhooks.signing_secret_ciphertext/row-1"
        );
        let escaped = v2_context("a/b%c", SLOT, "r/%");
        assert_eq!(
            escaped,
            "postkeep/v2/a%2Fb%25c/webhooks.signing_secret_ciphertext/r/%"
        );
    }

    #[test]
    fn only_canonical_versions_and_whole_values_parse() {
        for (text, version) in [("1", 1), ("10", 10), ("9223372036854775807", i64::MAX)] {
            let stored = format!("v2.{text}.AAAA");
            let parsed = Stored::parse(&stored).unwrap();
            assert_eq!(
                parsed,
                Stored::V2 {
                    version,
                    blob: "AAAA"
                }
            );
        }
        let versions = [
            "",
            "0",
            "01",
            "+1",
            "-1",
            " 1",
            "1e3",
            "\u{ff11}",
            "9223372036854775808",
        ];
        let bad = versions.map(|version| format!("v2.{version}.AAAA"));
        for text in ["v2.", "v2.1", "v2..x"]
            .map(String::from)
            .into_iter()
            .chain(bad)
        {
            assert!(is_decrypt(Stored::parse(&text)), "{text:?}");
        }
        // Not v2 at all: the master key's cipher decides.
        for text in ["v1.AAAA", "garbage", "v2"] {
            assert_eq!(Stored::parse(text).unwrap(), Stored::V1);
        }
    }

    #[test]
    fn a_higher_format_number_is_a_newer_version_not_damage() {
        assert_eq!(FORMAT_V2, format!("v{NEWEST_FORMAT}."));
        let overflow = format!("v{}0.x", u64::MAX);
        for text in ["v3.", "v3.x", "v3.1.x", "v10.x", &overflow] {
            let parsed = Stored::parse(text);
            assert!(matches!(parsed, Err(StoreError::NewerFormat)), "{text:?}");
        }
        // Not a number that a writer makes, or not above the newest format: as
        // before, the master key's cipher decides and rejects it.
        let arabic = "v\u{663}.x";
        let other = [
            "v0.x", "v03.x", "v+3.x", "v3x.x", "vx.x", "v.x", "V3.x", " v3.x", "v3", "v3,x",
            "v1.x", "", arabic,
        ];
        for text in other {
            assert_eq!(Stored::parse(text).unwrap(), Stored::V1, "{text:?}");
        }
    }

    #[test]
    fn a_malformed_blob_does_not_open() {
        let data = DataKey::generate().unwrap();
        let context = v2_context("t", SLOT, "r");
        let nonce_only = URL_SAFE_NO_PAD.encode([0_u8; NONCE_LEN]);
        let not_sealed = URL_SAFE_NO_PAD.encode([0_u8; 40]);
        for blob in ["!!!!", "", "AAAA", &nonce_only, &not_sealed] {
            assert!(is_decrypt(open_v2(&data, &context, blob)), "{blob:?}");
        }
        // The master key's cipher does not read a v2 value either.
        let v2 = seal_v2(&data, 1, "context", b"value").unwrap();
        assert!(key().cipher(&[]).open("context", &v2).is_err());
    }

    #[test]
    fn debug_hides_key() {
        assert_eq!(format!("{:?}", key()), "MasterKey([REDACTED])");
    }

    #[test]
    fn hashes_and_compares() {
        assert_eq!(hash_secret("x"), hash_secret("x"));
        assert_ne!(hash_secret("x"), hash_secret("y"));
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
    }
}
