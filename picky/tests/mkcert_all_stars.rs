#![cfg(feature = "x509")]
//! This test attempts to parse all root certificate provided by https://mkcert.org/
//! Data fetched on the 2019/10 are in a file named `mkcert_all_root_ca_2019_10.txt`.

use picky::pem::parse_pem;
use picky::x509::Cert;
use std::cmp::min;
use std::fs;

const ALL_STARS_FILE_PATH: &str = "../test_assets/mkcert_all_root_ca_2019_10.txt";

fn print_context(contents: &str, cursor: usize) {
    eprintln!(
        "==== Context ====\n{}\n>>>>>>>>>> CURSOR HERE <<<<<<<<<<\n{}",
        &contents[cursor.saturating_sub(1000)..cursor],
        &contents[cursor..min(cursor + 1500, contents.len())],
    );
}

fn next_cursor(contents: &str, last_cursor: usize) -> Option<usize> {
    if last_cursor < contents.len() {
        contents[last_cursor..]
            .find("-----BEGIN")
            .map(|cursor| cursor + last_cursor)
    } else {
        None
    }
}

#[test]
fn all_stars_parsing() {
    let contents = fs::read_to_string(ALL_STARS_FILE_PATH).expect("couldn't read the mkcert file");
    let mut last_cursor: usize = 0;
    let mut number_decoded: usize = 0;
    let mut total_certificates: usize = 0;

    while let Some(cursor) = next_cursor(&contents, last_cursor) {
        let pem = match parse_pem(&contents[cursor..]) {
            Ok(pem) => pem,
            Err(e) => {
                eprintln!("Couldn't parse pem at cursor = {}: {}", cursor, e);
                print_context(&contents, cursor);
                panic!("couldn't parse pem");
            }
        };
        assert_eq!(pem.label(), "CERTIFICATE");

        match Cert::from_der(pem.data()) {
            Ok(cert) => {
                println!("Decoded CA: {}", cert.issuer_name().to_string());
                number_decoded += 1;
            }
            Err(e) => {
                let formatted_str = e.to_string();
                if formatted_str.contains("TeletexString not supported")
                    || formatted_str.contains("V1 certificates unsupported")
                {
                    // these won't be supported
                    eprintln!(
                        "Couldn't parse certificate (cursor = {}) [won't support]: {}",
                        cursor, formatted_str
                    );
                } else {
                    eprintln!("Couldn't parse certificate (cursor = {}): {}", cursor, formatted_str);
                    print_context(&contents, cursor);
                    panic!("couldn't parse certificate")
                }
            }
        };

        total_certificates += 1;
        last_cursor = cursor + 1;
    }

    println!(
        "successfully decoded {}/{} certificates",
        number_decoded, total_certificates
    );

    // we currently support 132 certificates out of the 136.
    assert!(number_decoded >= 134);
}
