//! Entry points for the `cargo-fuzz` targets in `fuzz/`.
//!
//! Only compiled with the `fuzzing` feature.

#![allow(clippy::missing_panics_doc, clippy::panic, clippy::expect_used)]

use crate::text;

/// HTML bodies of incoming mail, converted to Markdown for tool results.
/// Output cut at `max_chars` is the uncut output's first `max_chars`
/// characters, trailing whitespace trimmed.
pub fn html_to_markdown(html: &str, max_chars: u16) {
    let max = usize::from(max_chars);
    let images = std::collections::HashMap::from([("a", 1)]);
    let (full, _) = text::html_to_markdown(html, &images, usize::MAX);
    let (out, cut) = text::html_to_markdown(html, &images, max);
    assert_eq!(cut, full.chars().count() > max, "cut follows the limit");
    if cut {
        let prefix: String = full.chars().take(max).collect();
        assert_eq!(out, prefix.trim_end(), "cut output is a prefix");
    } else {
        assert_eq!(out, full, "uncut output is the whole");
    }
}
