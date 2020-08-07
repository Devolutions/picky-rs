#![no_main]
use libfuzzer_sys::fuzz_target;
use picky::jose::{jwe::Jwe, jwk::Jwk, jws::Jws};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Jws::decode_without_validation(s);
        let _ = Jwe::decode_direct(s, s.as_bytes());
        let _ = Jwk::from_json(s);
    }
});
