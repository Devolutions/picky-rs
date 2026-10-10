use picky_crypto_testsuite::vectors::*;
use rstest::rstest;

const CRT_FIELDS: [&str; 8] = [
    "coefficient",
    "exponent1",
    "exponent2",
    "modulus",
    "prime1",
    "prime2",
    "privateExponent",
    "publicExponent",
];

#[rstest]
#[case("rsa_oaep_misc_test.json", 0, true)]
#[case("rsa_oaep_misc_test.json", 127, true)]
#[case("rsa_oaep_2048_sha1_mgf1sha1_test.json", 0, true)]
#[case("rsa_oaep_2048_sha224_mgf1sha1_test.json", 0, true)]
#[case("rsa_oaep_3072_sha256_mgf1sha1_test.json", 0, true)]
#[case("rsa_oaep_4096_sha256_mgf1sha1_test.json", 0, true)]
#[case("rsa_pkcs1_2048_sig_gen_test.json", 0, false)]
fn wycheproof_private_key_fields(#[case] file: &str, #[case] group: usize, #[case] crt: bool) {
    let key = wycheproof_private_key(file, group);
    let expected: Vec<_> = if crt {
        CRT_FIELDS.to_vec()
    } else {
        vec!["modulus", "privateExponent", "publicExponent"]
    };
    assert_eq!(key.keys().map(String::as_str).collect::<Vec<_>>(), expected);
    let published = &wycheproof(file).test_groups[group];
    for (name, bytes) in &key {
        let text = string(&published["privateKey"], name);
        assert_eq!(bytes.len() * 2, text.len(), "{file}/{group}/{name}");
        assert_eq!(hex::encode(bytes), text.to_ascii_lowercase(), "{file}/{group}/{name}");
    }
    let modulus = &key["modulus"];
    let significant = modulus.iter().skip_while(|b| **b == 0).count();
    assert!(
        modulus.len() > significant,
        "{file}/{group}: published leading zero byte kept"
    );
    assert_eq!(
        picky_crypto_testsuite::der::bit_length(modulus),
        number(published, "keySize"),
        "{file}/{group}: modulus size"
    );
}

#[test]
#[should_panic(expected = "no test group")]
fn wycheproof_private_key_rejects_missing_group() {
    wycheproof_private_key("rsa_pkcs1_2048_sig_gen_test.json", 8);
}

#[test]
#[should_panic(expected = "not listed")]
fn wycheproof_private_key_rejects_unlisted_file() {
    wycheproof_private_key("rsa_oaep_2048_sha512_mgf1sha1_test.json", 0);
}

#[test]
#[should_panic(expected = "has no privateKey")]
fn wycheproof_private_key_rejects_groups_without_private_key() {
    wycheproof_private_key("rsa_signature_2048_sha256_test.json", 0);
}

#[rstest]
#[case("nist/shs/SHA1ShortMsg.rsp", 65)]
#[case("nist/shs/SHA224ShortMsg.rsp", 65)]
#[case("nist/shs/SHA256ShortMsg.rsp", 65)]
#[case("nist/shs/SHA384ShortMsg.rsp", 129)]
#[case("nist/shs/SHA512ShortMsg.rsp", 129)]
#[case("nist/sha3/SHA3_384ShortMsg.rsp", 105)]
#[case("nist/sha3/SHA3_512ShortMsg.rsp", 73)]
#[case("nist/shs/SHA1Monte.rsp", 100)]
#[case("nist/shs/SHA224Monte.rsp", 100)]
#[case("nist/shs/SHA256Monte.rsp", 100)]
#[case("nist/shs/SHA384Monte.rsp", 100)]
#[case("nist/shs/SHA512Monte.rsp", 100)]
#[case("nist/sha3/SHA3_384Monte.rsp", 100)]
#[case("nist/sha3/SHA3_512Monte.rsp", 100)]
#[case("nist/aes/CBCGFSbox128.rsp", 14)]
#[case("nist/aes/CBCGFSbox192.rsp", 12)]
#[case("nist/aes/CBCGFSbox256.rsp", 10)]
#[case("nist/aes/CBCKeySbox128.rsp", 42)]
#[case("nist/aes/CBCKeySbox192.rsp", 48)]
#[case("nist/aes/CBCKeySbox256.rsp", 32)]
#[case("nist/aes/CBCMMT128.rsp", 20)]
#[case("nist/aes/CBCMMT192.rsp", 20)]
#[case("nist/aes/CBCMMT256.rsp", 20)]
#[case("nist/tdes/TCBCMMT2.rsp", 10)]
#[case("nist/tdes/TCBCMMT3.rsp", 20)]
#[case("nist/kbkdf/KDFCTR_gen.rsp", 160)]
#[case("nist/kas/KASValidityTest_ECCEphemeralUnified_KDFConcat_NOKC_init.fax", 180)]
#[case("nist/kas/KASValidityTest_FFCStatic_NOKC_ZZOnly_init.fax", 48)]
fn response_count(#[case] file: &str, #[case] count: usize) {
    assert_eq!(response(file).len(), count, "{file}");
}

#[test]
fn rfc_parsers() {
    md(1320);
    md(1321);
    assert_eq!(rc2().len(), 3);
    rc4();
    ed25519();
    x25519_rfc();
    x25519_iterations();
    let (a, ap, b, bp, s) = x25519_dh();
    for value in [a, ap, b, bp, s] {
        assert_eq!(value.len(), 32);
    }
    pbkdf2_rfc();
    hmac_rfc();
    dh_groups();
    rsa_labs();
    ec9500();
    for section in [1, 2, 3, 6, 7, 8] {
        assert!(!rfc5114(section).is_empty());
    }
}

#[rstest]
#[case("hmac_sha1_test.json")]
#[case("hmac_sha224_test.json")]
#[case("hmac_sha256_test.json")]
#[case("hmac_sha384_test.json")]
#[case("hmac_sha512_test.json")]
#[case("pbkdf2_hmacsha1_test.json")]
#[case("pbkdf2_hmacsha224_test.json")]
#[case("pbkdf2_hmacsha256_test.json")]
#[case("pbkdf2_hmacsha384_test.json")]
#[case("pbkdf2_hmacsha512_test.json")]
#[case("aes_gcm_test.json")]
#[case("aes_wrap_test.json")]
#[case("x25519_test.json")]
#[case("ed25519_test.json")]
#[case("ecdsa_secp256r1_sha256_p1363_test.json")]
#[case("ecdsa_secp384r1_sha384_p1363_test.json")]
#[case("ecdsa_secp521r1_sha512_p1363_test.json")]
#[case("ecdh_secp256r1_ecpoint_test.json")]
#[case("ecdh_secp384r1_ecpoint_test.json")]
#[case("ecdh_secp521r1_ecpoint_test.json")]
#[case("rsa_signature_2048_sha224_test.json")]
#[case("rsa_signature_2048_sha256_test.json")]
#[case("rsa_signature_2048_sha384_test.json")]
#[case("rsa_signature_2048_sha512_test.json")]
#[case("rsa_signature_2048_sha3_384_test.json")]
#[case("rsa_signature_2048_sha3_512_test.json")]
#[case("rsa_signature_3072_sha256_test.json")]
#[case("rsa_signature_4096_sha512_test.json")]
#[case("rsa_pkcs1_2048_sig_gen_test.json")]
#[case("rsa_pkcs1_3072_sig_gen_test.json")]
#[case("rsa_pkcs1_4096_sig_gen_test.json")]
#[case("rsa_pkcs1_2048_test.json")]
#[case("rsa_oaep_2048_sha1_mgf1sha1_test.json")]
#[case("rsa_oaep_2048_sha256_mgf1sha256_test.json")]
#[case("rsa_oaep_3072_sha256_mgf1sha256_test.json")]
#[case("rsa_oaep_4096_sha256_mgf1sha256_test.json")]
fn wycheproof_schema(#[case] file: &str) {
    let parsed = wycheproof(file);
    for group in parsed.test_groups {
        for test in tests(&group) {
            for name in [
                "msg", "tag", "ct", "key", "iv", "aad", "password", "salt", "dk", "public", "private", "shared", "sig",
            ] {
                if test[name].is_string() {
                    field(test, name);
                }
            }
            for name in ["privateKeyPkcs8", "publicKeyDer", "publicKeyAsn", "keyDer", "keyAsn"] {
                if group[name].is_string() {
                    let bytes = field(&group, name);
                    let parts = picky_crypto_testsuite::der::children(&bytes);
                    assert_eq!(
                        picky_crypto_testsuite::der::sequence(
                            &parts.iter().map(|p| p.encoded.to_vec()).collect::<Vec<_>>()
                        ),
                        bytes
                    );
                }
            }
        }
    }
}

#[test]
fn assembled_inputs() {
    for a in picky_crypto_testsuite::algorithms::CIPHERS {
        let records = picky_crypto_testsuite::symmetric::cipher_records(a);
        assert!(!records.is_empty());
        for (_, key, iv, plaintext, ciphertext, _) in records {
            assert!(!key.is_empty());
            assert!(matches!(iv.len(), 8 | 16));
            assert_eq!(plaintext.len(), ciphertext.len());
            assert_eq!(plaintext.len() % iv.len(), 0);
        }
    }
    for (_, _, _, r) in picky_crypto_testsuite::asymmetric::ecc_cases() {
        for name in ["QeCAVSx", "QeCAVSy", "OI", "DKM", "Z"] {
            r.bytes(name);
        }
    }
    for index in 0..picky_crypto_testsuite::algorithms::KDFS.len() {
        for (id, secret, info) in picky_crypto_testsuite::published::kdf(index) {
            assert!(!secret.is_empty() && secret.len() <= 1024 && info.len() <= 1024, "{id}");
        }
    }
    let groups = dh_groups();
    for (i, g) in groups.iter().take(3).enumerate() {
        let fields = rfc5114(i + 1);
        for name in ["xA", "yA", "xB", "yB", "Z"] {
            assert!(!fields[name].is_empty());
        }
        assert_eq!(g.p.len(), if i == 0 { 128 } else { 256 });
    }
    let base = &picky_crypto_testsuite::symmetric::cipher_records(picky_crypto_testsuite::algorithms::CIPHERS[3])[0].1;
    let derived = picky_crypto_testsuite::symmetric::weak_tdes_key(base);
    assert_eq!(derived.len(), 24);
    assert_eq!(&derived[8..], &base[8..]);
}

// Catches an accessor that pads odd-length hex as other parsers do: no published privateKey field is odd-length.
#[test]
#[should_panic(expected = "Odd number of digits")]
fn even_hex_rejects_odd_length() {
    picky_crypto_testsuite::vectors::even_hex("privateKey.modulus", "abc");
}
