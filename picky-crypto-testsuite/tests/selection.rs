use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use picky_crypto::*;
use rstest::rstest;

use picky_crypto_testsuite::{Options, algorithms::*, asymmetric, der, published, select, symmetric, vectors as v};

#[rstest]
#[case("rsa_signature_2048_sha224_test.json")]
#[case("rsa_signature_2048_sha256_test.json")]
#[case("rsa_signature_2048_sha384_test.json")]
#[case("rsa_signature_2048_sha512_test.json")]
#[case("rsa_signature_2048_sha3_384_test.json")]
#[case("rsa_signature_2048_sha3_512_test.json")]
#[case("rsa_signature_3072_sha256_test.json")]
#[case("rsa_signature_4096_sha512_test.json")]
#[case("ecdsa_secp256r1_sha256_p1363_test.json")]
#[case("ecdsa_secp384r1_sha384_p1363_test.json")]
#[case("ecdsa_secp521r1_sha512_p1363_test.json")]
#[case("ed25519_test.json")]
fn signature_controls(#[case] file: &str) {
    let vectors = v::wycheproof(file);
    let (group, test) = select::signature_control(file, &vectors);
    assert_eq!(v::string(test, "result"), "valid");
    assert!(v::tests(group).contains(test));
    assert!(!v::field(test, "sig").is_empty());
}

#[test]
fn ed25519_small_order_positive_control_uses_its_own_group() {
    let mut vectors = v::wycheproof("ed25519_test.json");
    let small_order = select::ed25519_small_order_r(&vectors);
    assert_eq!(v::number(small_order, "tcId"), 60);
    let (group, positive) = select::signature_control("ed25519_test.json", &vectors);
    assert!(!v::tests(group).contains(small_order));
    assert_eq!(v::string(positive, "result"), "valid");
    let public = v::field(&group["publicKey"], "pk");
    let spki = v::field(group, "publicKeyDer");
    assert_eq!(der::spki_public(&spki), public);
    assert_eq!(
        der::sequence(&[
            der::children(&spki)[0].encoded.to_vec(),
            der::tlv(3, &[&[0][..], &public].concat()),
        ]),
        spki
    );
    let invalid_only = vectors
        .test_groups
        .iter()
        .position(|g| v::tests(g).contains(small_order))
        .unwrap();
    vectors.test_groups.rotate_left(invalid_only);
    assert!(
        v::tests(&vectors.test_groups[0])
            .iter()
            .all(|t| v::string(t, "result") == "invalid")
    );
    let (_, positive) = select::signature_control("ed25519_test.json", &vectors);
    assert_eq!(v::string(positive, "result"), "valid");
}

#[rstest]
#[case("rsa_pkcs1_2048_sig_gen_test.json")]
#[case("rsa_pkcs1_3072_sig_gen_test.json")]
#[case("rsa_pkcs1_4096_sig_gen_test.json")]
fn rsa_private_controls(#[case] file: &str) {
    let vectors = v::wycheproof(file);
    let group = select::rsa_private_group(file, &vectors);
    assert!(der::rsa_must(&v::field(group, "privateKeyPkcs8")));
    for group in &vectors.test_groups {
        assert!(std::ptr::eq(select::group_message(file, group), &v::tests(group)[0]));
        let test = select::group_nonempty_message(file, group);
        let first_nonempty = v::tests(group).iter().find(|t| !v::field(t, "msg").is_empty());
        assert!(std::ptr::eq(test, first_nonempty.unwrap_or(&v::tests(group)[0])));
    }
}

#[rstest]
#[case("ecdh_secp256r1_ecpoint_test.json")]
#[case("ecdh_secp384r1_ecpoint_test.json")]
#[case("ecdh_secp521r1_ecpoint_test.json")]
fn ecdh_controls(#[case] file: &str) {
    let vectors = v::wycheproof(file);
    let test = select::ecdh_control(file, &vectors);
    assert_eq!(v::string(test, "result"), "valid");
    assert!(!v::field(test, "private").is_empty());
    assert_eq!(v::field(test, "public").first(), Some(&4));
}

#[rstest]
#[case(128)]
#[case(192)]
#[case(256)]
fn symmetric_controls(#[case] key_bits: usize) {
    let mut gcm = v::wycheproof("aes_gcm_test.json");
    let mut wrap = v::wycheproof("aes_wrap_test.json");
    gcm.test_groups.reverse();
    wrap.test_groups.reverse();
    let test = select::gcm_control(&gcm, key_bits);
    assert_eq!(v::string(test, "result"), "valid");
    assert_eq!(v::field(test, "key").len() * 8, key_bits);
    assert_eq!(v::field(test, "iv").len(), 12);
    assert_eq!(v::field(test, "tag").len(), 16);
    let test = select::wrap_control(&wrap, key_bits);
    assert_eq!(v::string(test, "result"), "valid");
    assert_eq!(v::field(test, "key").len() * 8, key_bits);
    assert!([16, 24, 32].contains(&v::field(test, "msg").len()));
}

#[rstest]
#[case(CipherAlgorithm::Aes128Cbc)]
#[case(CipherAlgorithm::Aes192Cbc)]
#[case(CipherAlgorithm::Aes256Cbc)]
#[case(CipherAlgorithm::TdesEde3Cbc)]
#[case(CipherAlgorithm::Rc2Cbc)]
fn cbc_controls(#[case] algorithm: CipherAlgorithm) {
    let records = symmetric::cipher_records(algorithm);
    let control = select::cbc_control(algorithm, &records);
    assert!(!control.5);
    if algorithm == CipherAlgorithm::TdesEde3Cbc {
        assert!(control.0.contains("TCBCMMT3.rsp"));
    }
}

#[rstest]
#[case("nist/shs/SHA1Monte.rsp")]
#[case("nist/shs/SHA224Monte.rsp")]
#[case("nist/shs/SHA256Monte.rsp")]
#[case("nist/shs/SHA384Monte.rsp")]
#[case("nist/shs/SHA512Monte.rsp")]
#[case("nist/sha3/SHA3_384Monte.rsp")]
#[case("nist/sha3/SHA3_512Monte.rsp")]
fn monte_seeds(#[case] file: &str) {
    let records = v::response(file);
    let seed = select::monte_seed(file, &records);
    assert_eq!(seed, records[0].bytes("Seed"));
    assert!(!seed.is_empty());
}

#[rstest]
#[case(0)]
#[case(1)]
#[case(2)]
#[case(3)]
#[case(4)]
fn mac_controls(#[case] index: usize) {
    let inputs = published::mac(index);
    assert!(select::mac_message(index, &inputs, true).2.is_empty());
    assert!(!select::mac_message(index, &inputs, false).2.is_empty());
    assert_eq!(
        select::mac_probe(index, &inputs).3.len(),
        HASHES[index + 2].output_len()
    );
    published::empty_mac(index);
}

#[test]
fn rfc_and_nist_controls() {
    assert!(select::ed25519_empty().message.is_empty());
    assert!(!select::ed25519_nonempty().message.is_empty());
    let vectors = v::ed25519();
    for (index, test) in vectors.iter().enumerate() {
        let next = &vectors[(index + 1) % vectors.len()].public;
        assert_eq!(select::ed25519_other_public(&test.public), next.as_slice());
        assert_ne!(next, &test.public);
    }
    let attributes = select::ed25519_attributes();
    assert!(der::children(&attributes).iter().any(|f| f.tag == 0xa0));
    assert!(der::encoded_public(KeyType::Ed25519, &attributes).is_some());
    let weak = select::weak_des_component();
    assert_eq!(weak.len(), 8);
    assert!(weak.iter().all(|b| *b == 255));
    for (kind, _, _, _, _) in CURVES {
        let (_, _, _, record) = select::ecc_private_control(kind);
        assert!(record.text("Result").starts_with('P'));
    }
    for group in v::dh_groups().iter().filter(|g| g.q.is_some()) {
        assert!(!select::ffdh_order(group).is_empty());
    }
    for bits in [2048, 3072, 4096] {
        for algorithm in ENCRYPTIONS {
            let limit = asymmetric::rsa_plaintext_limit(algorithm, bits / 8);
            let (_, message) = select::rsa_plaintext(limit);
            assert!(!message.is_empty() && message.len() <= limit);
            assert!(select::rsa_messages(limit).iter().all(|(_, m)| m.len() <= limit));
        }
    }
}

#[test]
fn missing_controls_name_the_file_and_property() {
    let vectors = v::Wycheproof {
        number_of_tests: 0,
        test_groups: Vec::new(),
    };
    macro_rules! missing {
        ($file:literal, $property:literal, $selection:expr) => {
            let panic = catch_unwind(AssertUnwindSafe(|| {
                $selection;
            }))
            .expect_err("missing control must fail");
            let message = panic.downcast_ref::<String>().expect("selection diagnostic");
            assert!(
                message.contains($file) && message.contains($property),
                "{message}"
            );
        };
    }
    missing!(
        "signature.json",
        "valid signature",
        select::signature_control("signature.json", &vectors)
    );
    missing!("ed25519_test.json", "R==0", select::ed25519_small_order_r(&vectors));
    missing!(
        "rsa.json",
        "must-support RSA",
        select::rsa_private_group("rsa.json", &vectors)
    );
    missing!("ecdh.json", "valid ECDH", select::ecdh_control("ecdh.json", &vectors));
    missing!("aes_gcm_test.json", "96-bit nonce", select::gcm_control(&vectors, 128));
    missing!("aes_wrap_test.json", "128-bit KEK", select::wrap_control(&vectors, 128));
    missing!(
        "SHA256Monte.rsp",
        "Monte Carlo seed",
        select::monte_seed("SHA256Monte.rsp", &[])
    );
    missing!(
        "rfc/rfc2268.txt",
        "must-support CBC",
        select::cbc_control(CipherAlgorithm::Rc2Cbc, &[])
    );
    missing!(
        "hmac_sha1_test.json",
        "empty HMAC message",
        select::mac_message(0, &[], true)
    );
    missing!(
        "hmac_sha1_test.json",
        "nonempty HMAC message",
        select::mac_message(0, &[], false)
    );
    missing!("hmac_sha1_test.json", "full HMAC tag", select::mac_probe(0, &[]));
    missing!("rfc/rfc1320.txt", "nonempty RSA plaintext", select::rsa_plaintext(0));
    missing!(
        "rsa.json",
        "first test in the private key's group",
        select::group_message("rsa.json", &serde_json::json!({"tests": []}))
    );
    missing!(
        "empty.rsp",
        "records",
        select::nonempty::<()>("empty.rsp", "records", &[])
    );
    let group = v::DhGroup {
        id: "dh.txt".to_owned(),
        p: Vec::new(),
        g: Vec::new(),
        q: None,
    };
    missing!("dh.txt", "FFDH subgroup order", select::ffdh_order(&group));
}

struct Reject<A>(A);

macro_rules! failure_methods {
    ($(fn $name:ident(&self $(, $arg:ident: $ty:ty)*) -> $result:ty;)*) => {
        $(fn $name(&self $(, $arg: $ty)*) -> $result {
            Err(Error::ProviderFailure)
        })*
    };
}

macro_rules! reject {
    ($capability:ident, $algorithm:ty, $identity:ident, {$($methods:tt)*}) => {
        impl $capability for Reject<$algorithm> {
            fn $identity(&self) -> $algorithm { self.0 }
            fn fips(&self) -> bool { false }
            $($methods)*
        }
    };
}

macro_rules! protections {
    () => {
        fn supports(&self, _: Protection) -> bool {
            true
        }
    };
}

reject!(Hash, HashAlgorithm, algorithm, {
    failure_methods! { fn start(&self) -> Result<Box<dyn HashContext>, Error>; }
});
reject!(Mac, MacAlgorithm, algorithm, {
    protections!();
    failure_methods! { fn start(&self, _key: &[u8], _protection: Protection) -> Result<Box<dyn MacContext>, Error>; }
});
reject!(PasswordKdf, PasswordKdfAlgorithm, algorithm, {
    failure_methods! { fn derive(&self, _password: &[u8], _salt: &[u8], _iterations: u32, _len: usize) -> Result<OutputBytes, Error>; }
});
reject!(Kdf, KdfAlgorithm, algorithm, {
    failure_methods! { fn derive(&self, _secret: &[u8], _info: &[u8], _len: usize) -> Result<OutputBytes, Error>; }
});
reject!(Cipher, CipherAlgorithm, algorithm, {
    protections!();
    failure_methods! {
        fn encrypt(&self, _key: &[u8], _iv: &[u8], _data: &[u8]) -> Result<OutputBytes, Error>;
        fn decrypt(&self, _key: &[u8], _iv: &[u8], _data: &[u8]) -> Result<OutputBytes, Error>;
    }
});
reject!(StreamCipher, StreamCipherAlgorithm, algorithm, {
    failure_methods! { fn start(&self, _key: &[u8]) -> Result<Box<dyn StreamCipherContext>, Error>; }
});
reject!(Aead, AeadAlgorithm, algorithm, {
    protections!();
    failure_methods! {
        fn seal(&self, _key: &[u8], _aad: &[u8], _data: &[u8]) -> Result<Sealed, Error>;
        fn open(&self, _key: &[u8], _nonce: &[u8], _aad: &[u8], _data: &[u8]) -> Result<OutputBytes, Error>;
    }
});
reject!(KeyWrap, KeyWrapAlgorithm, algorithm, {
    protections!();
    failure_methods! {
        fn wrap(&self, _key: &[u8], _data: &[u8]) -> Result<OutputBytes, Error>;
        fn unwrap(&self, _key: &[u8], _data: &[u8]) -> Result<OutputBytes, Error>;
    }
});
reject!(SignatureVerifier, SignatureAlgorithm, algorithm, {
    failure_methods! { fn verify(&self, _key: PublicKey<'_>, _message: &[u8], _signature: &[u8]) -> Result<(), Error>; }
});
reject!(AsymmetricEncryptor, AsymmetricEncryptionAlgorithm, algorithm, {
    failure_methods! { fn encrypt(&self, _key: PublicKey<'_>, _message: &[u8]) -> Result<OutputBytes, Error>; }
});
reject!(KeyAgreement, KeyAgreementAlgorithm, algorithm, {
    failure_methods! { fn generate_ephemeral(&self) -> Result<Box<dyn EphemeralSecret>, Error>; }
});
reject!(PrivateKeyLoader, KeyType, key_type, {
    failure_methods! { fn load(&self, _material: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error>; }
});
reject!(KeyGenerator, KeyGenerationAlgorithm, algorithm, {
    failure_methods! { fn generate(&self) -> Result<OutputBytes, Error>; }
});
reject!(SecureRandom, RandomAlgorithm, algorithm, {
    failure_methods! { fn fill(&self, _dest: &mut [u8]) -> Result<(), Error>; }
});
impl FfdhKeyAgreement for Reject<()> {
    fn fips(&self) -> bool {
        false
    }
    failure_methods! { fn generate_ephemeral(&self, _parameters: FfdhParameters<'_>) -> Result<Box<dyn EphemeralSecret>, Error>; }
}

fn rejecting_provider() -> CryptoProvider {
    let mut builder = CryptoProvider::builder();
    macro_rules! add {
        ($algorithms:expr, $entry:ident) => {
            for algorithm in $algorithms {
                builder = builder.with(Entry::$entry(Arc::new(Reject(algorithm))));
            }
        };
    }
    add!(HASHES, Hash);
    add!(MACS, Mac);
    add!(PASSWORD_KDFS, PasswordKdf);
    add!(KDFS, Kdf);
    add!(CIPHERS, Cipher);
    add!([StreamCipherAlgorithm::Rc4], StreamCipher);
    add!(AEADS, Aead);
    add!(WRAPS, KeyWrap);
    add!(SIGNATURES, SignatureVerifier);
    add!(ENCRYPTIONS, AsymmetricEncryptor);
    add!(
        AGREEMENTS.into_iter().filter(|a| *a != KeyAgreementAlgorithm::Ffdh),
        KeyAgreement
    );
    add!(KEY_TYPES, PrivateKeyLoader);
    add!(GENERATIONS, KeyGenerator);
    add!([RandomAlgorithm::SecureRandom], SecureRandom);
    builder
        .with(Entry::FfdhKeyAgreement(Arc::new(Reject(()))))
        .build()
        .unwrap()
}

#[test]
fn error_only_entries_never_bypass_the_conformance_report() {
    type Area = fn(&CryptoProvider, Options);
    let provider = rejecting_provider();
    assert!(all().iter().all(|a| provider.get(*a).is_some()));
    let areas: &[(&str, Area)] = &[
        ("hash", picky_crypto_testsuite::hash),
        ("mac", picky_crypto_testsuite::mac),
        ("password_kdf", picky_crypto_testsuite::password_kdf),
        ("kdf", picky_crypto_testsuite::kdf),
        ("cipher", picky_crypto_testsuite::cipher),
        ("stream_cipher", picky_crypto_testsuite::stream_cipher),
        ("aead", picky_crypto_testsuite::aead),
        ("key_wrap", picky_crypto_testsuite::key_wrap),
        ("signature", picky_crypto_testsuite::signature),
        ("asymmetric_encryption", picky_crypto_testsuite::asymmetric_encryption),
        ("key_agreement", picky_crypto_testsuite::key_agreement),
        ("ffdh", picky_crypto_testsuite::ffdh),
        ("private_key", picky_crypto_testsuite::private_key),
        ("key_generation", picky_crypto_testsuite::key_generation),
        ("random", picky_crypto_testsuite::random),
        ("provider", picky_crypto_testsuite::provider),
        ("properties", picky_crypto_testsuite::properties),
    ];
    for (name, area) in areas {
        let outcome = picky_crypto_testsuite::properties::without_failure_persistence(|| {
            catch_unwind(AssertUnwindSafe(|| area(&provider, Options::default())))
        });
        match outcome {
            Ok(()) => assert_eq!(*name, "provider", "{name}: failing operations must fail conformance"),
            Err(panic) => {
                let message = panic.downcast_ref::<String>().expect("conformance report");
                assert!(message.contains(" conformance failure(s):\n"), "{name}: {message}");
            }
        }
    }
}
