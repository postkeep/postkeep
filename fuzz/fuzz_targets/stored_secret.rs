#![no_main]

libfuzzer_sys::fuzz_target!(|input: (String, String)| {
    let (stored, email) = input;
    postkeep_store::fuzzing::stored_secret(&stored, &email);
});
