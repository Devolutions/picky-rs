#![no_main]
use libfuzzer_sys::fuzz_target;
use picky::jose::{
    jwk::Jwk,
    jwt::{Jwt, JwtDate, JwtValidator},
};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Jwk::from_json(s);

        if data.len() >= 4 {
            let numeric_date = (data[0] as i64)
                + (data[1] as i64) * 2_i64.pow(8)
                + (data[2] as i64) * 2_i64.pow(16)
                + (data[3] as i64) * 2_i64.pow(24);
            let date = JwtDate::new(numeric_date);
            let validator = JwtValidator::dangerous().current_date(&date);
            let _ = Jwt::<()>::decode(s, &validator);
        }
    }
});
