use picky_crypto::{CipherAlgorithm, KeyType};
use serde_json::Value;

use crate::areas::cipher::CipherVector;
use crate::{der, keys, published, vectors as v};

fn required<T>(file: &str, property: &str, selected: Option<T>) -> T {
    selected.unwrap_or_else(|| panic!("{file}: no published {property}"))
}

pub fn nonempty<T>(file: &str, property: &str, inputs: &[T]) {
    assert!(!inputs.is_empty(), "{file}: no published {property}");
}

fn test<'a>(
    file: &str,
    vectors: &'a v::Wycheproof,
    property: &str,
    qualifies: impl Fn(&Value, &Value) -> bool,
) -> (&'a Value, &'a Value) {
    required(
        file,
        property,
        vectors
            .test_groups
            .iter()
            .find_map(|group| v::tests(group).iter().find(|t| qualifies(group, t)).map(|t| (group, t))),
    )
}

pub fn signature_control<'a>(file: &str, vectors: &'a v::Wycheproof) -> (&'a Value, &'a Value) {
    test(file, vectors, "valid signature with its own public key", |g, t| {
        v::string(t, "result") == "valid"
            && (!g["publicKeyAsn"].is_string() || keys::rsa_public_must(&v::field(g, "publicKeyAsn")))
    })
}

pub fn ed25519_small_order_r(vectors: &v::Wycheproof) -> &Value {
    test(
        "ed25519_test.json",
        vectors,
        "R==0 signature with a 32-byte R",
        |_, t| v::string(t, "comment") == "R==0" && v::field(t, "sig").len() == 64,
    )
    .1
}

pub fn rsa_private_group<'a>(file: &str, vectors: &'a v::Wycheproof) -> &'a Value {
    required(
        file,
        "must-support RSA private key",
        vectors
            .test_groups
            .iter()
            .find(|g| der::rsa_must(&v::field(g, "privateKeyPkcs8"))),
    )
}

pub fn group_message<'a>(file: &str, group: &'a Value) -> &'a Value {
    required(file, "first test in the private key's group", v::tests(group).first())
}

/// Returns the first test of the group with a nonempty message, or its first test when every message is empty.
pub fn group_nonempty_message<'a>(file: &str, group: &'a Value) -> &'a Value {
    let tests = v::tests(group);
    required(
        file,
        "test in the private key's group",
        tests
            .iter()
            .find(|t| !v::field(t, "msg").is_empty())
            .or_else(|| tests.first()),
    )
}

pub fn ecdh_control<'a>(file: &str, vectors: &'a v::Wycheproof) -> &'a Value {
    test(file, vectors, "valid ECDH scalar and peer", |_, t| {
        v::string(t, "result") == "valid"
    })
    .1
}

pub fn gcm_control(vectors: &v::Wycheproof, key_bits: usize) -> &Value {
    test(
        "aes_gcm_test.json",
        vectors,
        &format!("valid {key_bits}-bit key, 96-bit nonce and 128-bit tag"),
        |g, t| {
            v::number(g, "keySize") == key_bits
                && v::number(g, "tagSize") == 128
                && v::field(t, "iv").len() == 12
                && v::string(t, "result") == "valid"
        },
    )
    .1
}

pub fn wrap_control(vectors: &v::Wycheproof, key_bits: usize) -> &Value {
    test(
        "aes_wrap_test.json",
        vectors,
        &format!("valid {key_bits}-bit KEK and AES key data"),
        |g, t| {
            v::number(g, "keySize") == key_bits
                && v::string(t, "result") == "valid"
                && [16, 24, 32].contains(&v::field(t, "msg").len())
        },
    )
    .1
}

pub fn cbc_control(algorithm: CipherAlgorithm, records: &[CipherVector]) -> &CipherVector {
    let file = match algorithm {
        CipherAlgorithm::Aes128Cbc => "nist/aes/CBC*128.rsp",
        CipherAlgorithm::Aes192Cbc => "nist/aes/CBC*192.rsp",
        CipherAlgorithm::Aes256Cbc => "nist/aes/CBC*256.rsp",
        CipherAlgorithm::TdesEde3Cbc => "nist/tdes/TCBCMMT3.rsp",
        CipherAlgorithm::Rc2Cbc => "rfc/rfc2268.txt",
        _ => unreachable!(),
    };
    required(file, "must-support CBC key", records.iter().find(|r| !r.5))
}

pub fn weak_des_component() -> Vec<u8> {
    required(
        "rfc/rfc2268.txt",
        "eight-byte all-one key",
        v::rc2()
            .into_iter()
            .map(|r| r.bytes("Key"))
            .find(|key| key.len() == 8 && key.iter().all(|b| *b == 255)),
    )
}

pub fn ed25519_empty() -> &'static v::EdVector {
    required(
        "rfc/rfc8032.txt",
        "Ed25519 vector with an empty message",
        v::ed25519().iter().find(|t| t.message.is_empty()),
    )
}

pub fn ed25519_nonempty() -> &'static v::EdVector {
    required(
        "rfc/rfc8032.txt",
        "Ed25519 vector with a nonempty message",
        v::ed25519().iter().find(|t| !t.message.is_empty()),
    )
}

/// Returns the public key of the RFC 8032 vector after the one with `public`, wrapping around.
pub fn ed25519_other_public(public: &[u8]) -> &'static [u8] {
    let vectors = v::ed25519();
    let index = required(
        "rfc/rfc8032.txt",
        "Ed25519 vector with the given public key",
        vectors.iter().position(|t| t.public == public),
    );
    let other = &vectors[(index + 1) % vectors.len()].public;
    assert_ne!(
        other, public,
        "rfc/rfc8032.txt: need two Ed25519 vectors with different public keys"
    );
    other
}

pub fn ed25519_attributes() -> Vec<u8> {
    required(
        "rfc/rfc8410.txt",
        "Ed25519 private key with attributes and an outer public key",
        v::ed8410().into_iter().find(|key| {
            let fields = der::children(key);
            fields.iter().any(|f| f.tag == 0xa0) && fields.iter().any(|f| f.tag == 0x81)
        }),
    )
}

pub fn mac_message(index: usize, inputs: &[published::Triple], empty: bool) -> &published::Triple {
    required(
        &format!("hmac_{}_test.json", crate::algorithms::SHAS[index]),
        if empty {
            "valid empty HMAC message"
        } else {
            "valid nonempty HMAC message"
        },
        inputs.iter().find(|(_, _, msg, _)| msg.is_empty() == empty),
    )
}

pub fn mac_probe(index: usize, inputs: &[published::Triple]) -> &published::Triple {
    required(
        &format!("hmac_{}_test.json", crate::algorithms::SHAS[index]),
        "valid full HMAC tag",
        inputs.first(),
    )
}

pub fn rsa_plaintext(limit: usize) -> (String, Vec<u8>) {
    required(
        "rfc/rfc1320.txt; rfc/rfc8032.txt",
        &format!("nonempty RSA plaintext of at most {limit} bytes"),
        published::messages()
            .into_iter()
            .find(|(_, message)| !message.is_empty() && message.len() <= limit),
    )
}

pub fn rsa_messages(limit: usize) -> Vec<(String, Vec<u8>)> {
    let inputs = published::messages()
        .into_iter()
        .filter(|(_, message)| message.len() <= limit)
        .collect::<Vec<_>>();
    nonempty(
        "rfc/rfc1320.txt; rfc/rfc8032.txt",
        &format!("RSA messages of at most {limit} bytes"),
        &inputs,
    );
    inputs
}

pub fn ffdh_order(group: &v::DhGroup) -> &[u8] {
    required(&group.id, "FFDH subgroup order", group.q.as_deref())
}

pub fn ffdh_group(groups: &[v::DhGroup], bits: usize) -> &v::DhGroup {
    required(
        "rfc/rfc5114.txt; rfc/rfc3526.txt; rfc/rfc7919.txt",
        &format!("{bits}-bit FFDH group"),
        groups.iter().find(|group| der::bit_length(&group.p) == bits),
    )
}

pub fn ffdh_smallest_generator(groups: &[v::DhGroup]) -> &[u8] {
    required(
        "rfc/rfc5114.txt; rfc/rfc3526.txt; rfc/rfc7919.txt",
        "FFDH generator",
        groups
            .iter()
            .map(|group| group.g.as_slice())
            .min_by_key(|g| der::bit_length(g)),
    )
}

pub fn ecc_private_control(kind: KeyType) -> (KeyType, picky_crypto::KeyAgreementAlgorithm, usize, v::Record) {
    required(
        keys::ECC_FILE,
        &format!("passing {kind:?} private key"),
        keys::ecc_cases()
            .into_iter()
            .find(|(k, _, _, r)| *k == kind && r.text("Result").starts_with('P')),
    )
}
