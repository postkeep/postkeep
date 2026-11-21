#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| postkeep_auth::fuzzing::client_ip(data));
