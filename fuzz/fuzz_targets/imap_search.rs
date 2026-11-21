#![no_main]

libfuzzer_sys::fuzz_target!(|values: [String; 5]| postkeep_mail::fuzzing::search(&values));
