#![no_main]

libfuzzer_sys::fuzz_target!(|input: (String, u16)| {
    let (html, max_chars) = input;
    postkeep::fuzzing::html_to_markdown(&html, max_chars);
});
