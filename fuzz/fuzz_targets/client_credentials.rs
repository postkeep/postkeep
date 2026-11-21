#![no_main]

libfuzzer_sys::fuzz_target!(|input: (Vec<u8>, String, String)| {
    let (header, verifier, challenge) = input;
    postkeep_auth::fuzzing::client_credentials(&header, &verifier, &challenge);
});
