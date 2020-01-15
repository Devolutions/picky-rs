#![no_main]
use libfuzzer_sys::fuzz_target;
use picky::{
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
});
