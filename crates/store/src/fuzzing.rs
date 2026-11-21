//! Entry points for the `cargo-fuzz` targets in `fuzz/`.
//!
//! Only compiled with the `fuzzing` feature.

#![allow(clippy::missing_panics_doc, clippy::panic, clippy::expect_used)]

use secrecy::{ExposeSecret, SecretString};

use crate::MasterKey;

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/// Stored ciphertexts (a corrupted or tampered database) and master key
/// text from the environment: neither panics, and only values sealed with
/// the key and the same context open.
pub fn stored_secret(stored: &str, email: &str) {
    let _ = MasterKey::parse(stored);
    let key = MasterKey::parse(KEY).expect("test key");
    let cipher = key.cipher(&[]);
    if let Ok(password) = cipher.decrypt(email, stored) {
        // Forging a value without the key is not feasible; reaching here
        // means the input was produced by `encrypt`, which the fuzzer cannot.
        panic!("opened a forged value: {:?}", password.expose_secret());
    }
    let sealed = cipher
        .encrypt(email, &SecretString::from(stored.to_owned()))
        .expect("encrypt");
    let opened = cipher.decrypt(email, &sealed).expect("round trip");
    assert_eq!(opened.expose_secret(), stored);
    assert!(cipher.decrypt(&format!("{email}x"), &sealed).is_err());
}
