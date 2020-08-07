#![cfg(feature = "x509")]
#![cfg(feature = "jose")]
//! This test run problematic artifacts found by fuzzing

use picky::{
    jose::{jwe::Jwe, jwk::Jwk, jws::Jws},
    key::{PrivateKey, PublicKey},
    pem::{parse_pem, Pem},
    x509::{certificate::Cert, csr::Csr},
};
use std::{fs, io::Read, path::PathBuf, time::Instant};

fn read_vector() -> Vec<Vec<u8>> {
    let dir = PathBuf::from("tests/artifacts_vector");
    let mut vector = Vec::new();
    for entry in fs::read_dir(dir).expect("couldn't read dir") {
        let entry = entry.expect("couldn't read entry");
        let path = entry.path();
        if !path.is_dir() {
            let mut file = fs::File::open(path).expect("couldn't open file");
            let mut test = Vec::new();
            file.read_to_end(&mut test).expect("couldn't read file");
            vector.push(test);
        }
    }
    vector
}

fn fuzz_target(data: &[u8]) {
    println!("PEM...");
    let _ = parse_pem(data);
    let pem = Pem::new("HEADER", data);
    let _ = parse_pem(&pem.to_string());

    println!("Keys...");
    let _ = PrivateKey::from_pkcs8(data);
    let _ = PublicKey::from_der(data);

    println!("X509...");
    let _ = Csr::from_der(data);
    let _ = Cert::from_der(data);

    println!("JOSE...");
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Jws::decode_without_validation(s);
        let _ = Jwe::decode_direct(s, s.as_bytes());
        let _ = Jwk::from_json(s);
    }

    println!("Done!");
}

#[test]
fn fuzz_artifacts() {
    let mut success = true;

    for test in read_vector() {
        println!("==> Test: {:?}", test);

        let now = Instant::now();

        fuzz_target(&test);

        let duration = Instant::now().duration_since(now);
        println!("Duration: {:?}", duration);
        if duration.as_secs() > 1 {
            println!("/!!!!\\ WAY TOO SLOW");
            success = false;
        }
    }

    assert!(success);
}
