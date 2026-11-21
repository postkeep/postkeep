#![no_main]

use postkeep::mailbox::id::{
    GMAIL_PREFIX, GRAPH_PREFIX, parse_imap_id, parse_provider_id, provider_id,
};

// Message ids passed to the MCP tools.
libfuzzer_sys::fuzz_target!(|input: (&str, &str)| {
    let (id, raw) = input;
    let _ = parse_imap_id(id);
    for prefix in [GRAPH_PREFIX, GMAIL_PREFIX] {
        if let Some(parsed) = parse_provider_id(prefix, id) {
            assert!(!parsed.is_empty());
            assert!(
                parsed
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_=+/".contains(&b)),
                "accepted {parsed:?}"
            );
            assert_eq!(provider_id(prefix, parsed), id);
        }
        if let Some(parsed) = parse_provider_id(prefix, &provider_id(prefix, raw)) {
            assert_eq!(parsed, raw);
        }
    }
});
