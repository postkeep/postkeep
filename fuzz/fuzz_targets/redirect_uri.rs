#![no_main]

libfuzzer_sys::fuzz_target!(|input: (String, String, String)| {
    let (registered, requested, state) = input;
    postkeep_auth::fuzzing::redirect_uri(&registered, &requested, &state);
});
