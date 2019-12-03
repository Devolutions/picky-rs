use base64::encode as base64_encode;
use multihash::{decode, encode, to_hex, Hash};

const PICKY_HASH: Hash = Hash::SHA2256;
const CERT_PREFIX: &str = "-----BEGIN CERTIFICATE-----";
const CERT_SUFFIX: &str = "-----END CERTIFICATE-----";
const SHA256_MULTIHASH_PREFIX: &str = "1220";

pub fn der_to_pem(der: &[u8]) -> String {
    base64_encode(der)
}

pub fn multihash_encode(value: &[u8]) -> Result<String, String> {
    match encode(PICKY_HASH, value) {
        Ok(result) => Ok(to_hex(&result)),
        Err(e) => Err(e.to_string()),
    }
}

#[allow(dead_code)]
pub fn multihash_decode(value: &[u8]) -> Result<Vec<u8>, String> {
    match decode(value) {
        Ok(result) => Ok(result.digest.to_vec()),
        Err(e) => Err(e.to_string()),
    }
}

pub fn sha256_to_multihash(hash: &str) -> Result<String, String> {
    let hash = format!("{}{}", SHA256_MULTIHASH_PREFIX, hash);
    Ok(hash)
}

pub fn fix_pem(pem: &str) -> String {
    let mut pem = pem
        .replace("\n", "")
        .replace(CERT_PREFIX, "")
        .replace(CERT_SUFFIX, "")
        .replace(" ", "");

    let mut fixed_pem = String::default();

    while pem.len() / 64 > 0 {
        let s = pem.split_at(64);
        fixed_pem.push_str(&format!("{}{}", s.0, "\n"));
        pem = s.1.to_string();
    }

    if !pem.is_empty() {
        fixed_pem.push_str(&format!("{}{}", pem, "\n"));
    }

    let fixed_pem = format!(
        "{}{}{}",
        format!("{}{}", CERT_PREFIX, "\n"),
        fixed_pem,
        format!("{}{}", CERT_SUFFIX, "\n")
    );
    fixed_pem
}
