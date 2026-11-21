#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| postkeep_mail::fuzzing::utf7(data));
