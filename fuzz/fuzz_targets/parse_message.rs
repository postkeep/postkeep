#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| postkeep_mail::fuzzing::parse_message(data));
