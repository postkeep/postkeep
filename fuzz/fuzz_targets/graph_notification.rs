#![no_main]

use postkeep::push::parse_graph_batch;

// Bodies posted to /push/microsoft and /push/microsoft/lifecycle by anyone
// on the internet, and Graph error bodies.
libfuzzer_sys::fuzz_target!(|body: &[u8]| {
    if let Ok(batch) = parse_graph_batch(body) {
        for notification in &batch.value {
            let _ = notification.subscription_id.as_deref().map(str::len);
            let _ = notification.client_state.as_deref().map(str::len);
        }
    }
    let (code, message) = postkeep_upstream::api::error_details(body);
    assert!(
        message.chars().count() <= 300,
        "error messages stay bounded"
    );
    assert!(
        code.is_none_or(|code| code.chars().count() <= 100),
        "error codes stay bounded"
    );
});
