#![no_main]

libfuzzer_sys::fuzz_target!(|input: (Vec<u8>, String, String)| {
    let (raw, subject, name) = input;
    postkeep_mail::fuzzing::reply(&raw, &subject, &name);
});
