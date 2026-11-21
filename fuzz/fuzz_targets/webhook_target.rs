#![no_main]

use postkeep_webhook::ip::is_public;
use postkeep_webhook::{AuthHeader, WebhookUrl, sign};

// Webhook URLs and headers typed on the account page, and signatures
// presented to a receiver.
libfuzzer_sys::fuzz_target!(|input: (String, String, String, i64, i64)| {
    let (url, header_value, signature, timestamp, now) = input;
    if let Ok(parsed) = WebhookUrl::parse(&url) {
        let reparsed = url::Url::parse(parsed.as_str()).expect("accepted URLs parse");
        assert_eq!(reparsed.scheme(), "https");
        assert!(reparsed.username().is_empty() && reparsed.password().is_none());
        if let Some(ip) = parsed.ip() {
            assert!(is_public(ip), "accepted a non-public literal: {url}");
        }
        assert!(!parsed.host().is_empty());
    }
    if let Ok(header) = AuthHeader::new("Authorization", &header_value) {
        assert!(!header.value.as_bytes().iter().any(|b| matches!(b, b'\r' | b'\n' | 0)));
    }
    let body = url.as_bytes();
    let _ = sign::verify("whsec_test", timestamp, body, &signature, now, 300);
    let good = sign::sign("whsec_test", timestamp, body);
    assert!(sign::verify("whsec_test", timestamp, body, &good, timestamp, 300));
    assert!(!sign::verify("whsec_other", timestamp, body, &good, timestamp, 300));
});
