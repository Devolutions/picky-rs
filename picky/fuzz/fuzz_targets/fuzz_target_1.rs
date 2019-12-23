#![no_main]
use libfuzzer_sys::fuzz_target;
use picky::{
    jose::{
        jwk::Jwk,
        jwt::{Jwt, JwtDate, JwtValidator},
    },
    key::{PrivateKey, PublicKey},
    pem::{parse_pem, Pem},
    x509::{certificate::Cert, csr::Csr},
};

fuzz_target!(|data: &[u8]| {
    // pem
    let _ = parse_pem(data);
    let pem = Pem::new("HEADER", data);
    let _ = parse_pem(&pem.to_string());

    // keys
    let _ = PrivateKey::from_pkcs8(data);
    let _ = PublicKey::from_der(data);

    // x509
    let _ = Csr::from_der(data);
    let _ = Cert::from_der(data);

    // jose
    if let Ok(s) = std::str::from_utf8(data) {
        if data.len() >= 4 {
            let numeric_date =
                (data[0] as i64) + (data[1] as i64) * 2_i64.pow(8) + (data[2] as i64) * 2_i64.pow(16) + (data[3] as i64) * 2_i64.pow(24);
            let date = JwtDate::new(numeric_date);
            let validator = JwtValidator::dangerous().current_date(&date);
            let _ = Jwt::<()>::decode(s, &validator);
        }

        let _ = Jwk::from_json(s);
    }
});
