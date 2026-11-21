#![no_main]

use postkeep_upstream::pubsub::{fuzzing, parse_push_body};

// Requests to /push/google: the bearer token and the Pub/Sub body.
libfuzzer_sys::fuzz_target!(|input: (&str, &[u8], &[u8], i64)| {
    let (token, claims, body, now) = input;
    fuzzing::check_token(token, now);
    fuzzing::check_claims_bytes(claims, now);
    if let Ok(notification) = parse_push_body(body) {
        let _ = notification.email_address.len();
    }
});
