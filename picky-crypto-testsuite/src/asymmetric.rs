use picky_crypto::*;
use serde_json::Value;

use crate::algorithms::*;
use crate::harness::{CheckedResult, Checks, Expect, malformed_public};
use crate::{Options, der, vectors as v};

pub const RSA_VERIFY_FILES: [&str; 8] = [
    "rsa_signature_2048_sha224_test.json",
    "rsa_signature_2048_sha256_test.json",
    "rsa_signature_2048_sha384_test.json",
    "rsa_signature_2048_sha512_test.json",
    "rsa_signature_2048_sha3_384_test.json",
    "rsa_signature_2048_sha3_512_test.json",
    "rsa_signature_3072_sha256_test.json",
    "rsa_signature_4096_sha512_test.json",
];
pub const RSA_SIGN_FILES: [&str; 3] = [
    "rsa_pkcs1_2048_sig_gen_test.json",
    "rsa_pkcs1_3072_sig_gen_test.json",
    "rsa_pkcs1_4096_sig_gen_test.json",
];
pub const RSA_DECRYPT_FILES: [(&str, AsymmetricEncryptionAlgorithm); 5] = [
    ("rsa_pkcs1_2048_test.json", AsymmetricEncryptionAlgorithm::RsaPkcs1v15),
    (
        "rsa_oaep_2048_sha1_mgf1sha1_test.json",
        AsymmetricEncryptionAlgorithm::RsaOaepSha1,
    ),
    (
        "rsa_oaep_2048_sha256_mgf1sha256_test.json",
        AsymmetricEncryptionAlgorithm::RsaOaepSha256,
    ),
    (
        "rsa_oaep_3072_sha256_mgf1sha256_test.json",
        AsymmetricEncryptionAlgorithm::RsaOaepSha256,
    ),
    (
        "rsa_oaep_4096_sha256_mgf1sha256_test.json",
        AsymmetricEncryptionAlgorithm::RsaOaepSha256,
    ),
];
pub const ECC_FILE: &str = "nist/kas/KASValidityTest_ECCEphemeralUnified_KDFConcat_NOKC_init.fax";
pub const FFC_FILE: &str = "nist/kas/KASValidityTest_FFCStatic_NOKC_ZZOnly_init.fax";

fn below_modulus_minus_one(value: &[u8], modulus: &[u8]) -> bool {
    let value = der::unsigned(value);
    let modulus = der::unsigned(modulus);
    let padded = der::padded(value, modulus.len());
    let Some(different) = padded.iter().zip(modulus).position(|(a, b)| a != b) else {
        return false;
    };
    if padded[different] > modulus[different] {
        return false;
    }
    // Adjacent integers differ by one digit and have complementary boundary suffixes.
    (padded[different]..modulus[different]).nth(1).is_some()
        || modulus[different + 1..].iter().any(|b| *b != 0)
        || padded[different + 1..].iter().any(|b| *b != 255)
}

#[allow(clippy::too_many_arguments)]
pub fn loaded(
    c: &mut Checks,
    p: &CryptoProvider,
    kind: KeyType,
    material: PrivateKeyMaterial<'_>,
    id: &str,
    bits: usize,
    outside: bool,
    optional_public: bool,
) -> Option<Box<dyn PrivateKey>> {
    let loader = match helpers::private_key_loader(p, kind) {
        Ok(e) => e,
        result => {
            c.absent(p, Algorithm::PrivateKeyLoading(kind), result);
            return None;
        }
    };
    let expected = if optional_public {
        Expect::Either(Error::Unsupported(Algorithm::PrivateKeyLoading(kind)))
    } else {
        Expect::Success
    };
    let key = c.outcome(
        id,
        expected,
        outside.then_some((Algorithm::PrivateKeyLoading(kind), false)),
        || loader.load(material),
    )?;
    let (reported_kind, reported_bits, fips, loader_fips, signs, decrypts, agrees, public_key) =
        c.metadata(id, || {
            (
                key.key_type(),
                key.key_size_bits(),
                key.fips(),
                loader.fips(),
                SIGNATURES.map(|a| key.supports(KeyOperation::Sign(a))),
                ENCRYPTIONS.map(|a| key.supports(KeyOperation::Decrypt(a))),
                AGREEMENTS.map(|a| key.supports(KeyOperation::Agree(a))),
                key.supports(KeyOperation::PublicKey),
            )
        })?;
    c.check(id, reported_kind == kind, "loaded wrong key type");
    c.check(
        id,
        reported_bits == bits,
        format!("key_size_bits expected {bits}, actual {reported_bits}"),
    );
    c.check(id, fips == loader_fips, "key and loader FIPS reports differ");
    match material {
        PrivateKeyMaterial::Pkcs8(bytes) => c.debug(id, &key, bytes),
        PrivateKeyMaterial::X25519(bytes) => c.debug(id, &key, bytes),
        PrivateKeyMaterial::Ffdh { private_value, .. } => c.debug(id, &key, private_value),
        _ => unreachable!(),
    }
    for (a, supported) in SIGNATURES.into_iter().zip(signs) {
        let compatible = match kind {
            KeyType::Rsa => SIGNATURES[..8].contains(&a),
            KeyType::EcP256 => a == SignatureAlgorithm::EcdsaP256Sha256,
            KeyType::EcP384 => a == SignatureAlgorithm::EcdsaP384Sha384,
            KeyType::EcP521 => a == SignatureAlgorithm::EcdsaP521Sha512,
            KeyType::Ed25519 => a == SignatureAlgorithm::Ed25519,
            _ => false,
        };
        c.check(
            id,
            !supported || compatible,
            format!("supports incompatible signature {a:?}"),
        );
        if !supported {
            c.call(
                &format!("{id}/{a:?}/unsupported sign"),
                Expect::Error(Error::Unsupported(Algorithm::Signature(a))),
                || key.sign(a, &[]),
            );
        }
    }
    for (a, supported) in ENCRYPTIONS.into_iter().zip(decrypts) {
        c.check(
            id,
            !supported || kind == KeyType::Rsa,
            "non-RSA key supports decryption",
        );
        if !supported {
            c.call(
                &format!("{id}/{a:?}/unsupported decrypt"),
                Expect::Error(Error::Unsupported(Algorithm::AsymmetricEncryption(a))),
                || key.decrypt(a, &[]),
            );
        } else {
            c.call(
                &format!("{id}/{a:?}/wrong ciphertext length"),
                Expect::Error(Error::InvalidInput),
                || key.decrypt(a, &[]),
            );
        }
    }
    for (a, supported) in AGREEMENTS.into_iter().zip(agrees) {
        let compatible = match kind {
            KeyType::EcP256 => a == KeyAgreementAlgorithm::EcdhP256,
            KeyType::EcP384 => a == KeyAgreementAlgorithm::EcdhP384,
            KeyType::EcP521 => a == KeyAgreementAlgorithm::EcdhP521,
            KeyType::X25519 => a == KeyAgreementAlgorithm::X25519,
            KeyType::Ffdh => a == KeyAgreementAlgorithm::Ffdh,
            _ => false,
        };
        c.check(
            id,
            !supported || compatible,
            format!("supports incompatible agreement {a:?}"),
        );
        if !supported {
            c.call(
                &format!("{id}/{a:?}/unsupported agree"),
                Expect::Error(Error::Unsupported(Algorithm::KeyAgreement(a))),
                || key.agree(a, &[]),
            );
        } else {
            c.call(
                &format!("{id}/{a:?}/wrong peer length"),
                Expect::Error(Error::InvalidInput),
                || key.agree(a, &[]),
            );
        }
    }
    if !public_key || kind == KeyType::Ffdh {
        c.check(
            id,
            kind != KeyType::Ffdh || !public_key,
            "FFDH cannot advertise public_key",
        );
        c.call(
            id,
            Expect::Error(Error::Unsupported(Algorithm::PublicKeyExport(kind))),
            || key.public_key(),
        );
    } else if let Some(output) = c.call(&format!("{id}/public key export"), Expect::Success, || key.public_key()) {
        let mut published_public = false;
        if let PrivateKeyMaterial::Pkcs8(encoded) = material {
            if let Some(expected) = der::encoded_public(kind, encoded) {
                c.bytes(id, &output, &expected);
                published_public = true;
            }
        }
        let expected_len = match kind {
            KeyType::EcP256 => Some(65),
            KeyType::EcP384 => Some(97),
            KeyType::EcP521 => Some(133),
            KeyType::Ed25519 | KeyType::X25519 => Some(32),
            _ => None,
        };
        if let Some(len) = expected_len {
            c.check(id, output.len() == len, "public key export length");
        }
        if matches!(kind, KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521) {
            c.check(id, output.first() == Some(&4), "public key export must be uncompressed");
        }
        if !published_public {
            let algorithm = match kind {
                KeyType::EcP256 => Some(KeyAgreementAlgorithm::EcdhP256),
                KeyType::EcP384 => Some(KeyAgreementAlgorithm::EcdhP384),
                KeyType::EcP521 => Some(KeyAgreementAlgorithm::EcdhP521),
                KeyType::X25519 => Some(KeyAgreementAlgorithm::X25519),
                _ => None,
            };
            if let Some(algorithm) =
                algorithm.filter(|a| AGREEMENTS.iter().position(|op| op == a).is_some_and(|i| agrees[i]))
            {
                if let Ok(entry) = helpers::key_agreement(p, algorithm) {
                    if let Some((local, peer)) =
                        c.call(&format!("{id}/export agreement control"), Expect::Success, || {
                            let ephemeral = entry.generate_ephemeral()?;
                            let public = ephemeral.public_key().checked()?;
                            Ok((
                                key.agree(algorithm, &public).checked()?,
                                ephemeral.agree(&output).checked()?,
                            ))
                        })
                    {
                        c.bytes(id, &local, &peer);
                    }
                } else if algorithm == KeyAgreementAlgorithm::X25519 {
                    let (base_point, _) = v::x25519_iterations();
                    if let Some(expected) = c.call(id, Expect::Success, || key.agree(algorithm, &base_point)) {
                        c.bytes(id, &output, &expected);
                    }
                }
            }
        }
    }
    if let PrivateKeyMaterial::Ffdh { parameters, .. } = material {
        let supported = agrees[AGREEMENTS
            .iter()
            .position(|a| *a == KeyAgreementAlgorithm::Ffdh)
            .unwrap()];
        let overlong = vec![0; der::bit_length(parameters.p).div_ceil(8) + 2];
        for (name, peer) in [
            ("empty", &[][..]),
            ("zero", &[0][..]),
            ("one", &[1][..]),
            ("modulus", parameters.p),
            ("overlong", overlong.as_slice()),
        ] {
            let expected = if supported {
                Expect::Error(Error::InvalidInput)
            } else {
                Expect::Error(Error::Unsupported(Algorithm::KeyAgreement(KeyAgreementAlgorithm::Ffdh)))
            };
            c.call(&format!("{id}/static FFDH peer={name}"), expected, || {
                key.agree(KeyAgreementAlgorithm::Ffdh, peer)
            });
        }
    }
    Some(key)
}

pub fn exported(c: &mut Checks, id: &str, key: &dyn PrivateKey, expected: &[u8]) {
    let supported = c.key_supports(id, key, KeyOperation::PublicKey);
    let Some(kind) = c.metadata(id, || key.key_type()) else {
        return;
    };
    c.check(
        id,
        kind != KeyType::Ffdh || !supported,
        "FFDH cannot advertise public key export",
    );
    let outcome = if supported && kind != KeyType::Ffdh {
        Expect::Success
    } else {
        Expect::Error(Error::Unsupported(Algorithm::PublicKeyExport(kind)))
    };
    if let Some(out) = c.call(&format!("{id}/public_key"), outcome, || key.public_key()) {
        c.bytes(id, &out, expected);
    }
}

pub fn x25519_export(c: &mut Checks, id: &str, key: &dyn PrivateKey) {
    let supported = c.key_supports(id, key, KeyOperation::PublicKey);
    let expected = if supported {
        Expect::Success
    } else {
        Expect::Error(Error::Unsupported(Algorithm::PublicKeyExport(KeyType::X25519)))
    };
    if let Some(public) = c.call(&format!("{id}/X25519 export"), expected, || key.public_key()) {
        c.check(id, public.len() == 32, "X25519 public key length");
        if c.key_supports(id, key, KeyOperation::Agree(KeyAgreementAlgorithm::X25519)) {
            let (base, _) = v::x25519_iterations();
            if let Some(reference) = c.call(id, Expect::Success, || key.agree(KeyAgreementAlgorithm::X25519, &base)) {
                c.bytes(id, &public, &reference);
            }
        }
    }
}

pub fn rsa_public_must(public: &[u8]) -> bool {
    let fields = der::children(public);
    (2048..=4096).contains(&der::bit_length(fields[0].value)) && der::unsigned(fields[1].value) == [1, 0, 1]
}

pub fn rsa_plaintext_limit(algorithm: AsymmetricEncryptionAlgorithm, modulus_len: usize) -> usize {
    modulus_len.saturating_sub(match algorithm {
        AsymmetricEncryptionAlgorithm::RsaPkcs1v15 => 11,
        AsymmetricEncryptionAlgorithm::RsaOaepSha1 => 42,
        AsymmetricEncryptionAlgorithm::RsaOaepSha256 => 66,
        _ => unreachable!(),
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_group(
    c: &mut Checks,
    p: &CryptoProvider,
    options: Options,
    a: SignatureAlgorithm,
    file: &str,
    g: &Value,
    public: &[u8],
    outside: bool,
) {
    let e = match helpers::signature_verifier(p, a) {
        Ok(e) => e,
        result => {
            c.absent(p, Algorithm::Signature(a), result);
            return;
        }
    };
    for t in v::tests(g) {
        let id = v::id(a, file, t);
        let expected =
            if v::flag(t, "MissingNull") || a == SignatureAlgorithm::Ed25519 && v::string(t, "comment") == "R==0" {
                Expect::Either(Error::VerificationFailed)
            } else if v::string(t, "result") == "invalid" {
                Expect::Error(Error::VerificationFailed)
            } else {
                Expect::Success
            };
        c.outcome(
            &id,
            expected,
            outside.then_some((Algorithm::Signature(a), options.opaque_public_key_errors)),
            || e.verify(PublicKey(public), &v::field(t, "msg"), &v::field(t, "sig")),
        );
        if v::string(t, "result") == "valid" && !outside {
            let msg = v::field(t, "msg");
            let sig = v::field(t, "sig");
            for length in [0, 1, sig.len().saturating_sub(1)] {
                c.call(
                    &format!("{id}/truncated signature/{length}"),
                    Expect::Error(Error::VerificationFailed),
                    || e.verify(PublicKey(public), &msg, &sig[..length]),
                );
            }
            for malformed in [&[][..], &[0][..], &public[..public.len() - 1]] {
                c.call(&format!("{id}/malformed public key"), malformed_public(options), || {
                    e.verify(PublicKey(malformed), &msg, &sig)
                });
            }
        }
    }
}

pub fn signature(p: &CryptoProvider, options: Options) {
    let mut c = Checks::default();
    let mut exercised_keys = std::collections::BTreeSet::new();
    for a in SIGNATURES {
        if let Err(error) = helpers::signature_verifier(p, a) {
            c.absent::<()>(p, Algorithm::Signature(a), Err(error));
        } else if SIGNATURES[..8].contains(&a) {
            let file = if a == SignatureAlgorithm::RsaPkcs1v15Sha256 {
                "rsa_signature_2048_sha384_test.json"
            } else {
                "rsa_signature_2048_sha256_test.json"
            };
            let vectors = v::wycheproof(file);
            let group = &vectors.test_groups[0];
            let t = v::tests(group)
                .iter()
                .find(|t| v::string(t, "result") == "valid")
                .unwrap();
            let public = v::field(group, "publicKeyAsn");
            assert!(rsa_public_must(&public));
            let message = v::field(t, "msg");
            let signature = v::field(t, "sig");
            let id = format!("{a:?}/{file}/tcId={}/wrong hash control", v::number(t, "tcId"));
            let verifier = helpers::signature_verifier(p, a).unwrap();
            c.call(&id, Expect::Error(Error::VerificationFailed), || {
                verifier.verify(PublicKey(&public), &message, &signature)
            });
            for len in [0, 1, signature.len() - 1] {
                c.call(
                    &format!("{id}/signature length={len}"),
                    Expect::Error(Error::VerificationFailed),
                    || verifier.verify(PublicKey(&public), &message, &signature[..len]),
                );
            }
            for malformed in [&[][..], &[0][..], &public[..public.len() - 1]] {
                c.call(&format!("{id}/malformed key"), malformed_public(options), || {
                    verifier.verify(PublicKey(malformed), &message, &signature)
                });
            }
        }
    }
    for file in RSA_VERIFY_FILES {
        for g in v::wycheproof(file).test_groups {
            let a = rsa_signature(v::string(&g, "sha"));
            let public = v::field(&g, "publicKeyAsn");
            verify_group(&mut c, p, options, a, file, &g, &public, !rsa_public_must(&public));
        }
    }
    for (kind, _, a, _, name) in CURVES {
        let file = format!(
            "ecdsa_{name}_sha{}_p1363_test.json",
            match kind {
                KeyType::EcP256 => 256,
                KeyType::EcP384 => 384,
                _ => 512,
            }
        );
        for g in v::wycheproof(&file).test_groups {
            verify_group(
                &mut c,
                p,
                options,
                a,
                &file,
                &g,
                &v::field(&g["publicKey"], "uncompressed"),
                false,
            );
        }
        if let Ok(verifier) = helpers::signature_verifier(p, a) {
            let signatures = v::wycheproof(&file);
            let valid_group = &signatures.test_groups[0];
            let valid = v::tests(valid_group)
                .iter()
                .find(|t| v::string(t, "result") == "valid")
                .unwrap();
            let ecpoint_file = format!("ecdh_{name}_ecpoint_test.json");
            for group in v::wycheproof(&ecpoint_file).test_groups {
                for t in v::tests(&group).iter().filter(|t| {
                    v::flag(t, "CompressedPoint")
                        || v::flag(t, "CompressedPublic")
                        || v::flag(t, "InvalidCurveAttack")
                        || v::flag(t, "WrongCurve")
                }) {
                    let id = format!(
                        "{a:?}/{ecpoint_file}/tcId={}/unusable verification key",
                        v::number(t, "tcId")
                    );
                    c.call(&id, malformed_public(options), || {
                        verifier.verify(
                            PublicKey(&v::field(t, "public")),
                            &v::field(valid, "msg"),
                            &v::field(valid, "sig"),
                        )
                    });
                }
            }
        }
    }
    let a = SignatureAlgorithm::Ed25519;
    for g in v::wycheproof("ed25519_test.json").test_groups {
        verify_group(
            &mut c,
            p,
            options,
            a,
            "ed25519_test.json",
            &g,
            &der::spki_public(&v::field(&g, "publicKeyDer")),
            false,
        );
    }
    if let Ok(verifier) = helpers::signature_verifier(p, SignatureAlgorithm::Ed25519) {
        let vectors = v::wycheproof("ed25519_test.json");
        let (group, t) = vectors
            .test_groups
            .iter()
            .find_map(|g| {
                v::tests(g)
                    .iter()
                    .find(|t| v::string(t, "comment") == "R==0")
                    .map(|t| (g, t))
            })
            .unwrap();
        let signature = v::field(t, "sig");
        // RFC 8032 uses the same point encoding for A and R.
        let small_order = &signature[..32];
        let public = v::field(&group["publicKey"], "pk");
        let spki = v::field(group, "publicKeyDer");
        let alg = der::children(&spki)[0].encoded.to_vec();
        assert_eq!(
            der::sequence(&[alg, der::tlv(3, &[&[0][..], &public].concat())]),
            spki,
            "Ed25519 SPKI split/reassemble control"
        );
        let positive = v::tests(group)
            .iter()
            .find(|t| v::string(t, "result") == "valid")
            .unwrap();
        let id = format!(
            "Ed25519/ed25519_test.json/tcId={}/public key from tcId={}/R",
            v::number(positive, "tcId"),
            v::number(t, "tcId")
        );
        c.call(&format!("{id}/positive control"), Expect::Success, || {
            verifier.verify(
                PublicKey(&public),
                &v::field(positive, "msg"),
                &v::field(positive, "sig"),
            )
        });
        c.call(&id, Expect::SmallOrderEd25519Key, || {
            verifier.verify(
                PublicKey(small_order),
                &v::field(positive, "msg"),
                &v::field(positive, "sig"),
            )
        });
    }
    for file in RSA_SIGN_FILES {
        for g in v::wycheproof(file).test_groups {
            let material = v::field(&g, "privateKeyPkcs8");
            let a = rsa_signature(v::string(&g, "sha"));
            let public = der::rsa_public(&material);
            verify_group(&mut c, p, options, a, file, &g, &public, !rsa_public_must(&public));
            let bits = der::bit_length(der::children(&der::rsa_public(&material))[0].value);
            let id = format!("{file}/private key/{bits}");
            let Some(key) = loaded(
                &mut c,
                p,
                KeyType::Rsa,
                PrivateKeyMaterial::Pkcs8(&material),
                &id,
                bits,
                !der::rsa_must(&material),
                false,
            ) else {
                continue;
            };
            exported(&mut c, &id, &*key, &der::rsa_public(&material));
            if exercised_keys.insert(material.clone()) {
                for algorithm in SIGNATURES[..8].iter().copied().filter(|alg| *alg != a) {
                    if !c.key_supports(&id, &*key, KeyOperation::Sign(algorithm)) {
                        continue;
                    }
                    let message = v::field(&v::tests(&g)[0], "msg");
                    let id = format!("{algorithm:?}/{file}/private-key round trip");
                    if let Some(sig) = c.outcome(
                        &id,
                        Expect::Success,
                        (!der::rsa_must(&material)).then_some((Algorithm::Signature(algorithm), false)),
                        || key.sign(algorithm, &message),
                    ) {
                        c.check(&id, sig.len() == bits.div_ceil(8), "RSA signature length");
                        if let Ok(verifier) = helpers::signature_verifier(p, algorithm) {
                            c.outcome(
                                &id,
                                Expect::Success,
                                (!rsa_public_must(&public))
                                    .then_some((Algorithm::Signature(algorithm), options.opaque_public_key_errors)),
                                || verifier.verify(PublicKey(&public), &message, &sig),
                            );
                        }
                    }
                }
            }
            for t in v::tests(&g) {
                let id = v::id(a, file, t);
                let supported = c.key_supports(&id, &*key, KeyOperation::Sign(a));
                let expected = if supported {
                    Expect::Success
                } else {
                    Expect::Error(Error::Unsupported(Algorithm::Signature(a)))
                };
                if let Some(out) = c.outcome(
                    &id,
                    expected,
                    (!der::rsa_must(&material) && supported).then_some((Algorithm::Signature(a), false)),
                    || key.sign(a, &v::field(t, "msg")),
                ) {
                    c.bytes(&id, &out, &v::field(t, "sig"));
                    c.check(&id, out.len() == bits.div_ceil(8), "RSA signature length");
                    if let Ok(verifier) = helpers::signature_verifier(p, a) {
                        c.outcome(
                            &id,
                            Expect::Success,
                            (!rsa_public_must(&public))
                                .then_some((Algorithm::Signature(a), options.opaque_public_key_errors)),
                            || verifier.verify(PublicKey(&der::rsa_public(&material)), &v::field(t, "msg"), &out),
                        );
                    }
                }
            }
        }
    }
    for (i, t) in v::ed25519().iter().enumerate() {
        let id = format!("Ed25519/rfc/rfc8032.txt/7.1/{i}");
        let encoding = der::ed(&t.seed, Some(&t.public));
        if let Ok(verifier) = helpers::signature_verifier(p, a) {
            c.call(&id, Expect::Success, || {
                verifier.verify(PublicKey(&t.public), &t.message, &t.signature)
            });
        }
        if let Some(key) = loaded(
            &mut c,
            p,
            KeyType::Ed25519,
            PrivateKeyMaterial::Pkcs8(&encoding),
            &id,
            255,
            false,
            false,
        ) {
            exported(&mut c, &id, &*key, &t.public);
            let expected = if c.key_supports(&id, &*key, KeyOperation::Sign(a)) {
                Expect::Success
            } else {
                Expect::Error(Error::Unsupported(Algorithm::Signature(a)))
            };
            if let Some(out) = c.call(&id, expected, || key.sign(a, &t.message)) {
                c.bytes(&id, &out, &t.signature);
                c.check(&id, out.len() == 64, "Ed25519 signature length");
            }
        }
    }
    c.finish();
}

pub fn asymmetric_encryption(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    for a in ENCRYPTIONS {
        if let Err(error) = helpers::asymmetric_encryptor(p, a) {
            c.absent::<()>(p, Algorithm::AsymmetricEncryption(a), Err(error));
        }
    }
    for (file, a) in RSA_DECRYPT_FILES {
        for g in v::wycheproof(file).test_groups {
            let material = v::field(&g, "privateKeyPkcs8");
            let public = der::rsa_public(&material);
            let bits = der::bit_length(der::children(&public)[0].value);
            let id = format!("{a:?}/{file}/key");
            let key = loaded(
                &mut c,
                p,
                KeyType::Rsa,
                PrivateKeyMaterial::Pkcs8(&material),
                &id,
                bits,
                !der::rsa_must(&material),
                false,
            );
            if let Some(key) = &key {
                exported(&mut c, &id, &**key, &public);
            }
            for t in v::tests(&g) {
                let nonempty_label = t["label"].as_str().is_some_and(|s| !s.is_empty());
                let id = v::id(a, file, t);
                let msg = v::field(t, "msg");
                let ciphertext = v::field(t, "ct");
                if let Some(key) = &key {
                    let supported = c.key_supports(&id, &**key, KeyOperation::Decrypt(a));
                    let expected = if !supported {
                        Expect::Error(Error::Unsupported(Algorithm::AsymmetricEncryption(a)))
                    } else if ciphertext.len() != bits.div_ceil(8) {
                        Expect::Error(Error::InvalidInput)
                    } else if nonempty_label || v::string(t, "result") == "invalid" {
                        Expect::Error(Error::VerificationFailed)
                    } else {
                        Expect::Success
                    };
                    if let Some(out) = c.outcome(
                        &id,
                        expected,
                        (!der::rsa_must(&material) && supported).then_some((Algorithm::AsymmetricEncryption(a), false)),
                        || key.decrypt(a, &ciphertext),
                    ) {
                        c.bytes(&id, &out, &msg);
                    }
                }
                if !nonempty_label && v::string(t, "result") == "valid" {
                    if let Ok(e) = helpers::asymmetric_encryptor(p, a) {
                        if let Some(encrypted) = c.outcome(
                            &id,
                            Expect::Success,
                            (!rsa_public_must(&public)).then_some((Algorithm::AsymmetricEncryption(a), false)),
                            || e.encrypt(PublicKey(&public), &msg),
                        ) {
                            c.check(&id, encrypted.len() == bits.div_ceil(8), "RSA ciphertext length");
                            c.debug(&id, &encrypted, &encrypted);
                            if let Some(key) = key
                                .as_ref()
                                .filter(|k| c.key_supports(&id, &***k, KeyOperation::Decrypt(a)))
                            {
                                if let Some(out) = c.call(&id, Expect::Success, || key.decrypt(a, &encrypted)) {
                                    c.bytes(&id, &out, &msg);
                                }
                            }
                        }
                        let overhead = match a {
                            AsymmetricEncryptionAlgorithm::RsaPkcs1v15 => 11,
                            AsymmetricEncryptionAlgorithm::RsaOaepSha1 => 42,
                            _ => 66,
                        };
                        c.call(
                            &format!("{id}/plaintext too long"),
                            Expect::Error(Error::InvalidInput),
                            || e.encrypt(PublicKey(&public), &vec![0; bits.div_ceil(8) - overhead + 1]),
                        );
                        c.call(
                            &format!("{id}/bad public key"),
                            Expect::Error(Error::InvalidKey),
                            || e.encrypt(PublicKey(&[]), &msg),
                        );
                    }
                }
            }
        }
    }
    for (i, published) in v::rsa_labs().into_iter().enumerate() {
        let mut fields = vec![der::integer(&[0])];
        fields.extend(published.fields.iter().map(|f| der::integer(f)));
        let material = der::rsa(&der::sequence(&fields));
        let bits = der::bit_length(&published.fields[0]);
        let id = format!("RsaOaepSha1/rsa-labs/oaep-vect.txt/key {}", i + 1);
        if let Some(key) = loaded(
            &mut c,
            p,
            KeyType::Rsa,
            PrivateKeyMaterial::Pkcs8(&material),
            &id,
            bits,
            !der::rsa_must(&material),
            false,
        ) {
            let a = AsymmetricEncryptionAlgorithm::RsaOaepSha1;
            exported(&mut c, &id, &*key, &der::rsa_public(&material));
            if c.key_supports(&id, &*key, KeyOperation::Decrypt(a)) {
                for (j, (msg, encrypted)) in published.cases.iter().enumerate() {
                    let id = format!("{id}/example {}", j + 1);
                    if let Some(out) = c.outcome(
                        &id,
                        Expect::Success,
                        (!der::rsa_must(&material)).then_some((Algorithm::AsymmetricEncryption(a), false)),
                        || key.decrypt(a, encrypted),
                    ) {
                        c.bytes(&id, &out, msg);
                    }
                }
            }
        }
    }
    c.finish();
}

pub fn ecc_cases() -> Vec<(KeyType, KeyAgreementAlgorithm, usize, v::Record)> {
    v::response(ECC_FILE)
        .into_iter()
        .map(|r| {
            let (kind, a, width) = if r.group.starts_with("EC -") {
                (KeyType::EcP256, KeyAgreementAlgorithm::EcdhP256, 32)
            } else if r.group.starts_with("ED -") {
                (KeyType::EcP384, KeyAgreementAlgorithm::EcdhP384, 48)
            } else if r.group.starts_with("EE -") {
                (KeyType::EcP521, KeyAgreementAlgorithm::EcdhP521, 66)
            } else {
                panic!("unsupported CAVP curve {}", r.group);
            };
            (kind, a, width, r)
        })
        .collect()
}

fn agree_kat(
    c: &mut Checks,
    id: &str,
    key: &dyn PrivateKey,
    a: KeyAgreementAlgorithm,
    peer: &[u8],
    secret: &[u8],
    invalid: bool,
) {
    let supported = c.key_supports(id, key, KeyOperation::Agree(a));
    let expected = if !supported {
        Expect::Error(Error::Unsupported(Algorithm::KeyAgreement(a)))
    } else if invalid {
        Expect::Error(Error::InvalidInput)
    } else {
        Expect::Success
    };
    if let Some(out) = c.call(id, expected, || key.agree(a, peer)) {
        c.bytes(id, &out, secret);
    }
}

pub fn key_agreement(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    for a in AGREEMENTS.into_iter().filter(|a| *a != KeyAgreementAlgorithm::Ffdh) {
        let e = match helpers::key_agreement(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::KeyAgreement(a), result);
                continue;
            }
        };
        let id = format!("{a:?}/ephemeral");
        let size = match a {
            KeyAgreementAlgorithm::EcdhP256 => 32,
            KeyAgreementAlgorithm::EcdhP384 => 48,
            KeyAgreementAlgorithm::EcdhP521 => 66,
            _ => 32,
        };
        if let Some((a_public, b_public, a_secret, b_secret)) = c.call(&id, Expect::Success, || {
            let a = e.generate_ephemeral()?;
            let b = e.generate_ephemeral()?;
            let ap = a.public_key().checked()?;
            let bp = b.public_key().checked()?;
            let sa = a.agree(&bp).checked()?;
            let sb = b.agree(&ap).checked()?;
            Ok((ap, bp, sa, sb))
        }) {
            c.bytes(&id, &a_secret, &b_secret);
            c.check(&id, a_secret.len() == size, "shared secret length");
            for public in [a_public, b_public] {
                c.debug(&id, &public, &public);
                c.check(
                    &id,
                    public.len()
                        == if a == KeyAgreementAlgorithm::X25519 {
                            32
                        } else {
                            1 + 2 * size
                        },
                    "ephemeral public length",
                );
                if a != KeyAgreementAlgorithm::X25519 {
                    c.check(&id, public.first() == Some(&4), "uncompressed point prefix");
                }
            }
        }
        for peer in [&[][..], &[0][..]] {
            c.call(
                &format!("{id}/invalid peer"),
                Expect::Error(Error::InvalidInput),
                || e.generate_ephemeral()?.agree(peer),
            );
        }
    }
    for (kind, a, width, r) in ecc_cases() {
        let id = format!("{a:?}/{}", r.id(ECC_FILE));
        let public = der::point(&r.bytes("QeIUTx"), &r.bytes("QeIUTy"), width);
        let material = der::ec(kind, &r.bytes("deIUT"), Some(&public), None);
        if let Some(key) = loaded(
            &mut c,
            p,
            kind,
            PrivateKeyMaterial::Pkcs8(&material),
            &id,
            if width == 66 { 521 } else { width * 8 },
            false,
            false,
        ) {
            exported(&mut c, &id, &*key, &public);
            let reason = r.text("Result");
            if reason.contains("Z changed") {
                continue;
            }
            let peer = der::point(&r.bytes("QeCAVSx"), &r.bytes("QeCAVSy"), width);
            agree_kat(
                &mut c,
                &id,
                &*key,
                a,
                &peer,
                &der::padded(&r.bytes("Z"), width),
                reason.contains("fails PKV"),
            );
            if reason.starts_with('P') && c.key_supports(&id, &*key, KeyOperation::Agree(a)) {
                if let Ok(ephemeral) = helpers::key_agreement(p, a) {
                    if let Some((static_secret, ephemeral_secret)) =
                        c.call(&format!("{id}/ephemeral with static"), Expect::Success, || {
                            let e = ephemeral.generate_ephemeral()?;
                            let ep = e.public_key().checked()?;
                            let static_secret = key.agree(a, &ep).checked()?;
                            let ephemeral_secret = e.agree(&public).checked()?;
                            Ok((static_secret, ephemeral_secret))
                        })
                    {
                        c.bytes(&id, &static_secret, &ephemeral_secret);
                    }
                }
            }
        }
    }
    for (i, (kind, a, _, width, _)) in CURVES.into_iter().enumerate() {
        let fields = v::rfc5114(i + 6);
        let own = der::point(&fields["x_qA"], &fields["y_qA"], width);
        let peer = der::point(&fields["x_qB"], &fields["y_qB"], width);
        let material = der::ec(kind, &fields["dA"], Some(&own), None);
        let id = format!("{a:?}/rfc/rfc5114.txt/A.{}", i + 6);
        if let Some(key) = loaded(
            &mut c,
            p,
            kind,
            PrivateKeyMaterial::Pkcs8(&material),
            &id,
            if width == 66 { 521 } else { width * 8 },
            false,
            false,
        ) {
            exported(&mut c, &id, &*key, &own);
            agree_kat(&mut c, &id, &*key, a, &peer, &der::padded(&fields["x_Z"], width), false);
        }
    }
    let a = KeyAgreementAlgorithm::X25519;
    for g in v::wycheproof("x25519_test.json").test_groups {
        for t in v::tests(&g) {
            let id = v::id(a, "x25519_test.json", t);
            let scalar: [u8; 32] = v::field(t, "private").try_into().expect("published X25519 scalar");
            let secret = v::field(t, "shared");
            let zero = secret.iter().all(|b| *b == 0);
            if let Ok(e) = helpers::key_agreement(p, a) {
                let expected = if zero {
                    Expect::Error(Error::InvalidInput)
                } else {
                    Expect::Success
                };
                if let Some(out) = c.call(&format!("{id}/ephemeral peer"), expected, || {
                    e.generate_ephemeral()?.agree(&v::field(t, "public"))
                }) {
                    c.check(
                        &id,
                        out.len() == 32 && out.iter().any(|b| *b != 0),
                        "X25519 ephemeral secret must be nonzero and 32 bytes",
                    );
                }
            }
            if let Some(key) = loaded(
                &mut c,
                p,
                KeyType::X25519,
                PrivateKeyMaterial::X25519(&scalar),
                &id,
                255,
                false,
                false,
            ) {
                agree_kat(&mut c, &id, &*key, a, &v::field(t, "public"), &secret, zero);
            }
        }
    }
    for (i, (scalar, peer, secret)) in v::x25519_rfc().into_iter().enumerate() {
        let scalar: [u8; 32] = scalar.try_into().unwrap();
        let id = format!("X25519/rfc/rfc7748.txt/5.2/{i}");
        if let Some(key) = loaded(
            &mut c,
            p,
            KeyType::X25519,
            PrivateKeyMaterial::X25519(&scalar),
            &id,
            255,
            false,
            false,
        ) {
            agree_kat(&mut c, &id, &*key, a, &peer, &secret, false);
        }
    }
    let (alice, alice_public, bob, bob_public, secret) = v::x25519_dh();
    for (name, scalar, public, peer) in [
        ("Alice", alice, alice_public.clone(), bob_public.clone()),
        ("Bob", bob, bob_public, alice_public),
    ] {
        let scalar: [u8; 32] = scalar.try_into().unwrap();
        let id = format!("X25519/rfc/rfc7748.txt/6.1/{name}");
        if let Some(key) = loaded(
            &mut c,
            p,
            KeyType::X25519,
            PrivateKeyMaterial::X25519(&scalar),
            &id,
            255,
            false,
            false,
        ) {
            exported(&mut c, &id, &*key, &public);
            agree_kat(&mut c, &id, &*key, a, &peer, &secret, false);
            if c.key_supports(&id, &*key, KeyOperation::Agree(a)) {
                if let Ok(e) = helpers::key_agreement(p, a) {
                    if let Some((sa, sb)) = c.call(&id, Expect::Success, || {
                        let ephemeral = e.generate_ephemeral()?;
                        let ep = ephemeral.public_key().checked()?;
                        Ok((key.agree(a, &ep).checked()?, ephemeral.agree(&public).checked()?))
                    }) {
                        c.bytes(&id, &sa, &sb);
                    }
                }
            }
        }
    }
    if let Ok(loader) = helpers::private_key_loader(p, KeyType::X25519) {
        let (seed, cases) = v::x25519_iterations();
        let base_point = seed.clone();
        let mut k: [u8; 32] = seed.clone().try_into().unwrap();
        let mut u = seed;
        let mut count = 0;
        for (target, expected) in cases {
            if target == 1_000_000 && !extended() {
                continue;
            }
            let id = format!("X25519/rfc/rfc7748.txt/5.2/iterations={target}");
            let success = c.call(&id, Expect::Success, || {
                while count < target {
                    let key = loader.load(PrivateKeyMaterial::X25519(&k))?;
                    let agreement = key.supports(KeyOperation::Agree(a));
                    let public = key.supports(KeyOperation::PublicKey);
                    if public {
                        let exported = key.public_key().checked()?;
                        if exported.len() != 32 {
                            return Err(Error::InvalidInput);
                        }
                        if agreement {
                            let expected = key.agree(a, &base_point).checked()?;
                            if exported.as_ref() != expected.as_ref() {
                                return Err(Error::InvalidInput);
                            }
                        }
                    } else if key.public_key().checked().err()
                        != Some(Error::Unsupported(Algorithm::PublicKeyExport(KeyType::X25519)))
                    {
                        return Err(Error::InvalidInput);
                    }
                    if !agreement {
                        return Ok(None);
                    }
                    let result = key.agree(a, &u).checked()?;
                    u = k.to_vec();
                    k = result.as_ref().try_into().map_err(|_| Error::InvalidInput)?;
                    count += 1;
                }
                Ok(Some(OutputBytes::new(Zeroizing::new(k.to_vec()))))
            });
            match success {
                Some(Some(out)) => c.bytes(&id, &out, &expected),
                _ => break,
            }
        }
    }
    // Without a published own public point, raw-scalar vectors use the contract's optional-public-key encoding.
    for (kind, a, _, width, name) in CURVES {
        let file = format!("ecdh_{name}_ecpoint_test.json");
        for g in v::wycheproof(&file).test_groups {
            let tests = v::tests(&g);
            let fallback_positive = tests.iter().find(|t| v::string(t, "result") == "valid").unwrap();
            for t in tests {
                let peer = v::field(t, "public");
                let invalid_peer =
                    v::string(t, "result") == "invalid" || peer.len() != 1 + width * 2 || peer.first() != Some(&4);
                if let Ok(e) = helpers::key_agreement(p, a) {
                    let id = format!("{}/ephemeral peer validation", v::id(a, &file, t));
                    let expected = if invalid_peer {
                        Expect::Error(Error::InvalidInput)
                    } else {
                        Expect::Success
                    };
                    if let Some(shared) = c.call(&id, expected, || e.generate_ephemeral()?.agree(&peer)) {
                        c.check(&id, shared.len() == width, "ephemeral shared-secret width");
                    }
                }
                let scalar = v::field(t, "private");
                let has_positive = tests.iter().any(|positive| {
                    v::string(positive, "result") == "valid" && v::field(positive, "private") == scalar
                });
                let scalar = if has_positive {
                    scalar
                } else {
                    v::field(fallback_positive, "private")
                };
                let material = der::ec(kind, &scalar, None, None);
                let id = v::id(a, &file, t);
                if let Some(key) = loaded(
                    &mut c,
                    p,
                    kind,
                    PrivateKeyMaterial::Pkcs8(&material),
                    &id,
                    if width == 66 { 521 } else { width * 8 },
                    false,
                    true,
                ) {
                    if !has_positive {
                        agree_kat(
                            &mut c,
                            &format!("{id}/positive scalar control/{}", v::number(fallback_positive, "tcId")),
                            &*key,
                            a,
                            &v::field(fallback_positive, "public"),
                            &v::field(fallback_positive, "shared"),
                            false,
                        );
                    }
                    agree_kat(&mut c, &id, &*key, a, &peer, &v::field(t, "shared"), invalid_peer);
                }
            }
        }
    }
    c.finish();
}

pub fn ffdh(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    let groups = v::dh_groups();
    match helpers::ffdh_key_agreement(p) {
        Err(error) => c.absent::<()>(p, Algorithm::KeyAgreement(KeyAgreementAlgorithm::Ffdh), Err(error)),
        Ok(e) => {
            for group in &groups {
                let id = &group.id;
                if let Some((ap, bp, sa, sb)) = c.call(id, Expect::Success, || {
                    let a = e.generate_ephemeral(group.parameters())?;
                    let b = e.generate_ephemeral(group.parameters())?;
                    let ap = a.public_key().checked()?;
                    let bp = b.public_key().checked()?;
                    let sa = a.agree(&bp).checked()?;
                    let sb = b.agree(&ap).checked()?;
                    Ok((ap, bp, sa, sb))
                }) {
                    c.bytes(id, &sa, &sb);
                    c.check(id, sa.len() == group.p.len(), "FFDH secret width");
                    for public in [ap, bp] {
                        c.debug(id, &public, &public);
                        c.check(id, public.len() == group.p.len(), "FFDH public width");
                        let unsigned = der::unsigned(&public);
                        let modulus = der::unsigned(&group.p);
                        c.check(
                            id,
                            unsigned.len() > 1 || unsigned.first().is_some_and(|b| *b >= 2),
                            "public value below 2",
                        );
                        c.check(
                            id,
                            unsigned.len() <= modulus.len() && below_modulus_minus_one(unsigned, modulus),
                            "public value greater than p - 2",
                        );
                    }
                }
                for invalid in [&[][..], &[0][..], &[1][..], &group.p[..]] {
                    c.call(
                        &format!("{id}/invalid peer"),
                        Expect::Error(Error::InvalidInput),
                        || e.generate_ephemeral(group.parameters())?.agree(invalid),
                    );
                    c.call(
                        &format!("{id}/invalid generator"),
                        Expect::Error(Error::InvalidInput),
                        || e.generate_ephemeral(FfdhParameters::new(&group.p, invalid, group.q.as_deref())),
                    );
                }
                c.call(
                    &format!("{id}/short modulus"),
                    Expect::Error(Error::InvalidInput),
                    || e.generate_ephemeral(FfdhParameters::new(&[1], &group.g, None)),
                );
                c.call(
                    &format!("{id}/overlong peer"),
                    Expect::Error(Error::InvalidInput),
                    || {
                        e.generate_ephemeral(group.parameters())?
                            .agree(&vec![0; group.p.len() + 2])
                    },
                );
                for invalid in [&[][..], &[0][..], &[1][..], &[4][..], &group.p[..]] {
                    c.call(
                        &format!("{id}/invalid subgroup order"),
                        Expect::Error(Error::InvalidInput),
                        || e.generate_ephemeral(FfdhParameters::new(&group.p, &group.g, Some(invalid))),
                    );
                }
                c.call(
                    &format!("{id}/overlong generator"),
                    Expect::Error(Error::InvalidInput),
                    || {
                        e.generate_ephemeral(FfdhParameters::new(
                            &group.p,
                            &vec![0; group.p.len() + 2],
                            group.q.as_deref(),
                        ))
                    },
                );
            }
        }
    }
    for (section, group) in (1..=3).zip(&groups) {
        let fields = v::rfc5114(section);
        let x = &fields["xA"];
        let id = format!("Ffdh/rfc/rfc5114.txt/A.{section}");
        let without_q = FfdhParameters::new(&group.p, &group.g, None);
        if let Some(key) = loaded(
            &mut c,
            p,
            KeyType::Ffdh,
            PrivateKeyMaterial::Ffdh {
                parameters: without_q,
                private_value: x,
            },
            &format!("{id}/optional q absent"),
            der::bit_length(&group.p),
            false,
            false,
        ) {
            agree_kat(
                &mut c,
                &id,
                &*key,
                KeyAgreementAlgorithm::Ffdh,
                &fields["yB"],
                &der::padded(&fields["Z"], group.p.len()),
                false,
            );
        }
        if let Some(key) = loaded(
            &mut c,
            p,
            KeyType::Ffdh,
            PrivateKeyMaterial::Ffdh {
                parameters: group.parameters(),
                private_value: x,
            },
            &id,
            der::bit_length(&group.p),
            false,
            false,
        ) {
            agree_kat(
                &mut c,
                &id,
                &*key,
                KeyAgreementAlgorithm::Ffdh,
                &fields["yB"],
                &der::padded(&fields["Z"], group.p.len()),
                false,
            );
            if c.key_supports(&id, &*key, KeyOperation::Agree(KeyAgreementAlgorithm::Ffdh)) {
                if let Some(own) = c.call(&id, Expect::Success, || {
                    helpers::ffdh_public_value(&*key, group.parameters())
                }) {
                    c.bytes(&id, &own, &der::padded(&fields["yA"], group.p.len()));
                }
            }
            if let Ok(loader) = helpers::private_key_loader(p, KeyType::Ffdh) {
                for invalid in [&[][..], &[0][..], &group.p[..], group.q.as_deref().unwrap()] {
                    c.call(
                        &format!("{id}/invalid exponent"),
                        Expect::Error(Error::InvalidKey),
                        || {
                            loader.load(PrivateKeyMaterial::Ffdh {
                                parameters: group.parameters(),
                                private_value: invalid,
                            })
                        },
                    );
                }
                for invalid in [&[][..], &[0][..], &[1][..], &group.p[..]] {
                    c.call(
                        &format!("{id}/invalid parameter generator"),
                        Expect::Error(Error::InvalidKey),
                        || {
                            loader.load(PrivateKeyMaterial::Ffdh {
                                parameters: FfdhParameters::new(&group.p, invalid, group.q.as_deref()),
                                private_value: x,
                            })
                        },
                    );
                    if invalid.len() <= 1 {
                        c.call(
                            &format!("{id}/invalid parameter modulus"),
                            Expect::Error(Error::InvalidKey),
                            || {
                                loader.load(PrivateKeyMaterial::Ffdh {
                                    parameters: FfdhParameters::new(invalid, &group.g, group.q.as_deref()),
                                    private_value: x,
                                })
                            },
                        );
                    }
                }
                for invalid in [&[][..], &[0][..], &[1][..], &[4][..], &group.p[..]] {
                    c.call(
                        &format!("{id}/invalid parameter q"),
                        Expect::Error(Error::InvalidKey),
                        || {
                            loader.load(PrivateKeyMaterial::Ffdh {
                                parameters: FfdhParameters::new(&group.p, &group.g, Some(invalid)),
                                private_value: x,
                            })
                        },
                    );
                }
                let prefix_zero = |field: &[u8]| [vec![0], field.to_vec()].concat();
                c.call(
                    &format!("{id}/overlong private value"),
                    Expect::Error(Error::InvalidKey),
                    || {
                        loader.load(PrivateKeyMaterial::Ffdh {
                            parameters: group.parameters(),
                            private_value: &vec![0; group.p.len() + 2],
                        })
                    },
                );
                let (padded_p, padded_g, padded_x) = (prefix_zero(&group.p), prefix_zero(&group.g), prefix_zero(x));
                let padded_q = group.q.as_ref().map(|q| prefix_zero(q));
                let padded_parameters = FfdhParameters::new(&padded_p, &padded_g, padded_q.as_deref());
                if let Some(padded) = loaded(
                    &mut c,
                    p,
                    KeyType::Ffdh,
                    PrivateKeyMaterial::Ffdh {
                        parameters: padded_parameters,
                        private_value: &padded_x,
                    },
                    &format!("{id}/leading zero"),
                    der::bit_length(&group.p),
                    false,
                    false,
                ) {
                    agree_kat(
                        &mut c,
                        &id,
                        &*padded,
                        KeyAgreementAlgorithm::Ffdh,
                        &fields["yB"],
                        &der::padded(&fields["Z"], group.p.len()),
                        false,
                    );
                }
            }
        }
    }
    for r in v::response(FFC_FILE) {
        let (modulus, generator, order, x) = (r.bytes("P"), r.bytes("G"), r.bytes("Q"), r.bytes("XstatIUT"));
        let parameters = FfdhParameters::new(&modulus, &generator, Some(&order));
        let id = r.id(FFC_FILE);
        let reason = r.text("Result");
        if reason.contains("private key changed") {
            loaded(
                &mut c,
                p,
                KeyType::Ffdh,
                PrivateKeyMaterial::Ffdh {
                    parameters,
                    private_value: &x,
                },
                &id,
                der::bit_length(&modulus),
                false,
                false,
            );
            continue;
        }
        if let Ok(e) = helpers::ffdh_key_agreement(p) {
            let invalid_peer = reason.contains("CAVS's Static public key");
            let expected = if invalid_peer {
                Expect::Error(Error::InvalidInput)
            } else {
                Expect::Success
            };
            if let Some(shared) = c.call(&format!("{id}/ephemeral peer"), expected, || {
                e.generate_ephemeral(parameters)?.agree(&r.bytes("YstatCAVS"))
            }) {
                c.check(&id, shared.len() == modulus.len(), "FFDH ephemeral secret width");
            }
        }
        if let Some(key) = loaded(
            &mut c,
            p,
            KeyType::Ffdh,
            PrivateKeyMaterial::Ffdh {
                parameters,
                private_value: &x,
            },
            &id,
            der::bit_length(&modulus),
            false,
            false,
        ) {
            if reason.contains("Z changed") || reason.contains("IUT's Static public key") {
                continue;
            }
            agree_kat(
                &mut c,
                &id,
                &*key,
                KeyAgreementAlgorithm::Ffdh,
                &r.bytes("YstatCAVS"),
                &der::padded(&r.bytes("Z"), modulus.len()),
                reason.contains("CAVS's Static public key"),
            );
            if reason.starts_with('P') && c.key_supports(&id, &*key, KeyOperation::Agree(KeyAgreementAlgorithm::Ffdh)) {
                if let Some(own) = c.call(&id, Expect::Success, || helpers::ffdh_public_value(&*key, parameters)) {
                    c.bytes(&id, &own, &der::padded(&r.bytes("YstatIUT"), modulus.len()));
                }
            }
        }
    }
    c.finish();
}

pub fn private_key(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    for kind in KEY_TYPES {
        match helpers::private_key_loader(p, kind) {
            Err(error) => c.absent::<()>(p, Algorithm::PrivateKeyLoading(kind), Err(error)),
            Ok(loader) => {
                c.call(&format!("{kind:?}/garbage"), Expect::Error(Error::InvalidKey), || {
                    loader.load(PrivateKeyMaterial::Pkcs8(&[]))
                });
                if kind != KeyType::X25519 {
                    c.call(
                        &format!("{kind:?}/wrong material"),
                        Expect::Error(Error::InvalidKey),
                        || loader.load(PrivateKeyMaterial::X25519(&[0; 32])),
                    );
                }
                if kind != KeyType::Ed25519 {
                    let t = &v::ed25519()[0];
                    let material = der::ed(&t.seed, Some(&t.public));
                    c.call(
                        &format!("{kind:?}/wrong encoded key type"),
                        Expect::Error(Error::InvalidKey),
                        || loader.load(PrivateKeyMaterial::Pkcs8(&material)),
                    );
                }
            }
        }
    }
    for (kind, a, width, r) in ecc_cases()
        .into_iter()
        .filter(|(_, _, _, r)| r.text("Result").starts_with('P'))
    {
        let id = format!("{kind:?}/{}", r.id(ECC_FILE));
        let public = der::point(&r.bytes("QeIUTx"), &r.bytes("QeIUTy"), width);
        let peer = der::point(&r.bytes("QeCAVSx"), &r.bytes("QeCAVSy"), width);
        let scalar = r.bytes("deIUT");
        let material = der::ec(kind, &scalar, Some(&public), None);
        let Some(loader) = helpers::private_key_loader(p, kind).ok() else {
            continue;
        };
        for parameters in [None, Some(kind)] {
            let material = der::ec(kind, &scalar, Some(&public), parameters);
            if let Some(key) = loaded(
                &mut c,
                p,
                kind,
                PrivateKeyMaterial::Pkcs8(&material),
                &id,
                if width == 66 { 521 } else { width * 8 },
                false,
                false,
            ) {
                exported(&mut c, &id, &*key, &public);
                agree_kat(&mut c, &id, &*key, a, &peer, &der::padded(&r.bytes("Z"), width), false);
                let sign = CURVES.iter().find(|(k, _, _, _, _)| *k == kind).unwrap().2;
                if c.key_supports(&id, &*key, KeyOperation::Sign(sign)) {
                    if let Some(signature) = c.call(&id, Expect::Success, || key.sign(sign, &r.bytes("OI"))) {
                        c.check(&id, signature.len() == width * 2, "ECDSA P1363 length");
                        c.debug(&id, &signature, &signature);
                        if let Ok(verifier) = helpers::signature_verifier(p, sign) {
                            c.call(&id, Expect::Success, || {
                                verifier.verify(PublicKey(&public), &r.bytes("OI"), &signature)
                            });
                        }
                    }
                }
            }
        }
        let other = if kind == KeyType::EcP256 {
            KeyType::EcP384
        } else {
            KeyType::EcP256
        };
        let mismatch_curve = der::ec(kind, &scalar, Some(&public), Some(other));
        c.call(
            &format!("{id}/mismatched parameters"),
            Expect::Error(Error::InvalidKey),
            || loader.load(PrivateKeyMaterial::Pkcs8(&mismatch_curve)),
        );
        let mismatched = der::ec(kind, &scalar, Some(&peer), None);
        c.call(
            &format!("{id}/mismatched public key"),
            Expect::Error(Error::InvalidKey),
            || loader.load(PrivateKeyMaterial::Pkcs8(&mismatched)),
        );
        let absent = der::ec(kind, &scalar, None, None);
        if let Some(key) = loaded(
            &mut c,
            p,
            kind,
            PrivateKeyMaterial::Pkcs8(&absent),
            &id,
            if width == 66 { 521 } else { width * 8 },
            false,
            true,
        ) {
            exported(&mut c, &id, &*key, &public);
            agree_kat(&mut c, &id, &*key, a, &peer, &der::padded(&r.bytes("Z"), width), false);
        }
        for length in [0, 1, material.len() / 2, material.len() - 1] {
            c.call(
                &format!("{id}/truncation/{length}"),
                Expect::Error(Error::InvalidKey),
                || loader.load(PrivateKeyMaterial::Pkcs8(&material[..length])),
            );
        }
        let mut fields: Vec<_> = der::children(&material).iter().map(|f| f.encoded.to_vec()).collect();
        fields[0] = der::integer(&[1]);
        fields.push(der::tlv(0x81, &[&[0][..], &public].concat()));
        let version1 = der::sequence(&fields);
        c.call(&format!("{id}/version 1"), Expect::Error(Error::InvalidKey), || {
            loader.load(PrivateKeyMaterial::Pkcs8(&version1))
        });
    }
    for (i, t) in v::ed25519().iter().enumerate() {
        let id = format!("Ed25519/rfc/rfc8032.txt/7.1/{i}/private key");
        let absent = der::ed(&t.seed, None);
        if let Some(key) = loaded(
            &mut c,
            p,
            KeyType::Ed25519,
            PrivateKeyMaterial::Pkcs8(&absent),
            &id,
            255,
            false,
            true,
        ) {
            exported(&mut c, &id, &*key, &t.public);
            if c.key_supports(&id, &*key, KeyOperation::Sign(SignatureAlgorithm::Ed25519)) {
                if let Some(sig) = c.call(&id, Expect::Success, || {
                    key.sign(SignatureAlgorithm::Ed25519, &t.message)
                }) {
                    c.bytes(&id, &sig, &t.signature);
                }
            }
        }
        let mismatched = der::ed(&t.seed, Some(&v::ed25519()[(i + 1) % v::ed25519().len()].public));
        if let Ok(loader) = helpers::private_key_loader(p, KeyType::Ed25519) {
            c.call(
                &format!("{id}/mismatched public key"),
                Expect::Error(Error::InvalidKey),
                || loader.load(PrivateKeyMaterial::Pkcs8(&mismatched)),
            );
        }
    }
    if let Ok(loader) = helpers::private_key_loader(p, KeyType::Ed25519) {
        let keys = v::ed8410();
        if let Some(key) = c.call(
            "Ed25519/rfc/rfc8410.txt/10.3/attributes",
            Expect::Either(Error::InvalidKey),
            || loader.load(PrivateKeyMaterial::Pkcs8(&keys[1])),
        ) {
            let public = der::encoded_public(KeyType::Ed25519, &keys[1]).unwrap();
            exported(&mut c, "Ed25519/rfc/rfc8410.txt/10.3/attributes", &*key, &public);
        }
    }
    inconsistent_rsa(&mut c, p);
    if let Ok(loader) = helpers::private_key_loader(p, KeyType::Rsa) {
        let vectors = v::wycheproof(RSA_SIGN_FILES[0]);
        let g = &vectors.test_groups[0];
        let encoded = v::field(g, "privateKeyPkcs8");
        let mut fields = der::children(&encoded)
            .iter()
            .map(|f| f.encoded.to_vec())
            .collect::<Vec<_>>();
        fields[0] = der::integer(&[1]);
        fields.push(der::tlv(0x81, &[&[0][..], &der::rsa_public(&encoded)].concat()));
        let version1 = der::sequence(&fields);
        c.call(
            &format!("{}/RSA version 1", RSA_SIGN_FILES[0]),
            Expect::Error(Error::InvalidKey),
            || loader.load(PrivateKeyMaterial::Pkcs8(&version1)),
        );
        for len in [0, 1, encoded.len() / 2, encoded.len() - 1] {
            c.call(
                &format!("{}/RSA truncation/{len}", RSA_SIGN_FILES[0]),
                Expect::Error(Error::InvalidKey),
                || loader.load(PrivateKeyMaterial::Pkcs8(&encoded[..len])),
            );
        }
    }
    c.finish();
}

fn inconsistent_rsa(c: &mut Checks, p: &CryptoProvider) {
    inconsistent_rsa_signing(c, p);
    inconsistent_rsa_decryption(c, p);
}

pub fn inconsistent_signatures(
    c: &mut Checks,
    local: &CryptoProvider,
    fallback: Option<&CryptoProvider>,
    base: &dyn PrivateKey,
    key: &dyn PrivateKey,
    id: &str,
    source: (&str, &Value),
) {
    let (file, group) = source;
    let public = der::rsa_public(&v::field(group, "privateKeyPkcs8"));
    let source_algorithm = rsa_signature(v::string(group, "sha"));
    for algorithm in SIGNATURES[..8].iter().copied() {
        let base_supported = c.key_supports(id, base, KeyOperation::Sign(algorithm));
        let derived_supported = c.key_supports(id, key, KeyOperation::Sign(algorithm));
        if !base_supported && !derived_supported {
            continue;
        }
        let verifiers = [
            helpers::signature_verifier(local, algorithm).ok(),
            fallback.and_then(|provider| helpers::signature_verifier(provider, algorithm).ok()),
        ];
        let tests = v::tests(group);
        let tests = if algorithm == source_algorithm {
            tests
        } else {
            &tests[..1]
        };
        for t in tests {
            let id = format!("{id}/{}", v::id(algorithm, file, t));
            let message = v::field(t, "msg");
            let positive = if base_supported {
                c.call(&format!("{id}/positive control"), Expect::Success, || {
                    base.sign(algorithm, &message)
                })
            } else {
                None
            };
            if let Some(signature) = &positive {
                if algorithm == source_algorithm {
                    c.bytes(&id, signature, &v::field(t, "sig"));
                }
                for verifier in verifiers.iter().flatten() {
                    c.call(&format!("{id}/positive verification"), Expect::Success, || {
                        verifier.verify(PublicKey(&public), &message, signature)
                    });
                }
            }
            let expected = if derived_supported {
                Expect::Either(Error::InvalidKey)
            } else {
                Expect::Error(Error::Unsupported(Algorithm::Signature(algorithm)))
            };
            if let Some(signature) = c.call(&id, expected, || key.sign(algorithm, &message)) {
                if algorithm == source_algorithm {
                    c.bytes(&id, &signature, &v::field(t, "sig"));
                }
                for verifier in verifiers.iter().flatten() {
                    c.call(&id, Expect::Success, || {
                        verifier.verify(PublicKey(&public), &message, &signature)
                    });
                }
                if verifiers.iter().all(Option::is_none) {
                    if let Some(positive) = &positive {
                        c.bytes(&id, &signature, positive);
                    } else {
                        c.check(
                            &id,
                            false,
                            "no verifier or deterministic positive control for inconsistent-key signature",
                        );
                    }
                }
            }
        }
    }
}

pub fn inconsistent_roundtrip(
    c: &mut Checks,
    providers: (&CryptoProvider, Option<&CryptoProvider>),
    keys: (&dyn PrivateKey, &dyn PrivateKey),
    id: &str,
    encoded: &[u8],
    algorithm: AsymmetricEncryptionAlgorithm,
) {
    let (local, other) = providers;
    let (base, key) = keys;
    if !c.key_supports(id, base, KeyOperation::Decrypt(algorithm))
        || !c.key_supports(id, key, KeyOperation::Decrypt(algorithm))
    {
        return;
    }
    let encryptor = helpers::asymmetric_encryptor(local, algorithm)
        .ok()
        .or_else(|| other.and_then(|provider| helpers::asymmetric_encryptor(provider, algorithm).ok()));
    let Some(encryptor) = encryptor else {
        return;
    };
    let public = der::rsa_public(encoded);
    let limit = rsa_plaintext_limit(algorithm, der::bit_length(der::children(&public)[0].value).div_ceil(8));
    let messages = crate::published::messages();
    let (source, message) = messages
        .iter()
        .find(|(_, message)| !message.is_empty() && message.len() <= limit)
        .expect("published RSA plaintext within limit");
    let id = format!("{id}/{algorithm:?}/round trip/{source}");
    if let Some(ciphertext) = c.call(&id, Expect::Success, || encryptor.encrypt(PublicKey(&public), message)) {
        if let Some(positive) = c.call(&format!("{id}/positive control"), Expect::Success, || {
            base.decrypt(algorithm, &ciphertext)
        }) {
            c.bytes(&id, &positive, message);
        }
        if let Some(plaintext) = c.call(&id, Expect::Either(Error::InvalidKey), || {
            key.decrypt(algorithm, &ciphertext)
        }) {
            c.bytes(&id, &plaintext, message);
        }
    }
}

fn inconsistent_rsa_signing(c: &mut Checks, p: &CryptoProvider) {
    let Ok(loader) = helpers::private_key_loader(p, KeyType::Rsa) else {
        return;
    };
    for file in RSA_SIGN_FILES {
        let vectors = v::wycheproof(file);
        let bases: Vec<_> = vectors
            .test_groups
            .iter()
            .filter(|g| der::rsa_must(&v::field(g, "privateKeyPkcs8")))
            .collect();
        for g in &bases {
            let encoding = v::field(g, "privateKeyPkcs8");
            let id = format!("{file}/inconsistent components");
            let Some(base) = c.call(&format!("{id}/positive control"), Expect::Success, || {
                loader.load(PrivateKeyMaterial::Pkcs8(&encoding))
            }) else {
                continue;
            };
            exported(c, &id, &*base, &der::rsa_public(&encoding));
            let other = bases
                .iter()
                .find(|other| v::field(other, "privateKeyPkcs8") != encoding)
                .map(|g| v::field(g, "privateKeyPkcs8"));
            for (i, malformed) in der::inconsistent_rsa(&encoding, other.as_deref())
                .into_iter()
                .enumerate()
            {
                let id = format!("{id}/variant {i}");
                if let Some(key) = c.call(&id, Expect::Either(Error::InvalidKey), || {
                    loader.load(PrivateKeyMaterial::Pkcs8(&malformed))
                }) {
                    exported(c, &id, &*key, &der::rsa_public(&encoding));
                    inconsistent_signatures(c, p, None, &*base, &*key, &id, (file, g));
                }
            }
        }
    }
}

fn inconsistent_rsa_decryption(c: &mut Checks, p: &CryptoProvider) {
    let Ok(loader) = helpers::private_key_loader(p, KeyType::Rsa) else {
        return;
    };
    for (file, a) in RSA_DECRYPT_FILES {
        let vectors = v::wycheproof(file);
        for g in &vectors.test_groups {
            let encoded = v::field(g, "privateKeyPkcs8");
            if !der::rsa_must(&encoded) {
                continue;
            }
            let Some(t) = v::tests(g)
                .iter()
                .find(|t| v::string(t, "result") == "valid" && t["label"].as_str().is_none_or(str::is_empty))
            else {
                continue;
            };
            let id = format!("{file}/tcId={}/inconsistent components", v::number(t, "tcId"));
            let Some(base) = c.call(&format!("{id}/positive control"), Expect::Success, || {
                loader.load(PrivateKeyMaterial::Pkcs8(&encoded))
            }) else {
                continue;
            };
            exported(c, &id, &*base, &der::rsa_public(&encoded));
            if !c
                .metadata(&id, || base.supports(KeyOperation::Decrypt(a)))
                .unwrap_or(false)
            {
                continue;
            }
            let ciphertext = v::field(t, "ct");
            let plaintext = v::field(t, "msg");
            if let Some(out) = c.call(&id, Expect::Success, || base.decrypt(a, &ciphertext)) {
                c.bytes(&id, &out, &plaintext);
            }
            let other = vectors
                .test_groups
                .iter()
                .find(|other| {
                    v::field(other, "privateKeyPkcs8") != encoded
                        && v::number(other, "keySize") == v::number(g, "keySize")
                })
                .map(|g| v::field(g, "privateKeyPkcs8"));
            for (i, derived) in der::inconsistent_rsa(&encoded, other.as_deref())
                .into_iter()
                .enumerate()
            {
                let id = format!("{id}/variant {i}");
                if let Some(key) = c.call(&id, Expect::Either(Error::InvalidKey), || {
                    loader.load(PrivateKeyMaterial::Pkcs8(&derived))
                }) {
                    exported(c, &id, &*key, &der::rsa_public(&encoded));
                    if c.metadata(&id, || key.supports(KeyOperation::Decrypt(a)))
                        .unwrap_or(false)
                    {
                        if let Some(out) =
                            c.call(&id, Expect::Either(Error::InvalidKey), || key.decrypt(a, &ciphertext))
                        {
                            c.bytes(&id, &out, &plaintext);
                        }
                    }
                    inconsistent_roundtrip(c, (p, None), (&*base, &*key), &id, &encoded, a);
                }
            }
        }
    }
}

pub fn key_generation(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    for a in GENERATIONS {
        let generator = match helpers::key_generator(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::KeyGeneration(a), result);
                continue;
            }
        };
        let (kind, bits, sign) = match a {
            KeyGenerationAlgorithm::Rsa2048 => (KeyType::Rsa, 2048, SignatureAlgorithm::RsaPkcs1v15Sha256),
            KeyGenerationAlgorithm::Rsa3072 => (KeyType::Rsa, 3072, SignatureAlgorithm::RsaPkcs1v15Sha256),
            KeyGenerationAlgorithm::Rsa4096 => (KeyType::Rsa, 4096, SignatureAlgorithm::RsaPkcs1v15Sha256),
            KeyGenerationAlgorithm::EcP256 => (KeyType::EcP256, 256, SignatureAlgorithm::EcdsaP256Sha256),
            KeyGenerationAlgorithm::EcP384 => (KeyType::EcP384, 384, SignatureAlgorithm::EcdsaP384Sha384),
            KeyGenerationAlgorithm::EcP521 => (KeyType::EcP521, 521, SignatureAlgorithm::EcdsaP521Sha512),
            KeyGenerationAlgorithm::Ed25519 => (KeyType::Ed25519, 255, SignatureAlgorithm::Ed25519),
            _ => unreachable!(),
        };
        if kind == KeyType::Rsa && !extended() {
            continue;
        }
        let mut first_public = None;
        for invocation in 0..2 {
            let id = format!("{a:?}/generation/{invocation}");
            if let Some(out) = c.call(&id, Expect::Success, || generator.generate()) {
                c.debug(&id, &out, &out);
                let validation = der::generated_public(kind, bits, &out);
                c.check(
                    &id,
                    validation.is_ok(),
                    format!("generated PKCS#8 encoding: {:?}", validation.as_ref().err()),
                );
                let Ok(public) = validation else {
                    continue;
                };
                if let Some(first) = &first_public {
                    c.check(&id, first != &public, "successive generated public keys are identical");
                } else {
                    first_public = Some(public.clone());
                }
                if let Some(key) = loaded(
                    &mut c,
                    p,
                    kind,
                    PrivateKeyMaterial::Pkcs8(&out),
                    &id,
                    bits,
                    false,
                    false,
                ) {
                    exported(&mut c, &id, &*key, &public);
                    if c.key_supports(&id, &*key, KeyOperation::Sign(sign)) {
                        let message = &v::ed25519()[1].message;
                        if let Some(sig) = c.call(&id, Expect::Success, || key.sign(sign, message)) {
                            c.debug(&id, &sig, &sig);
                            if let Ok(verifier) = helpers::signature_verifier(p, sign) {
                                c.call(&id, Expect::Success, || {
                                    verifier.verify(PublicKey(&public), message, &sig)
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    c.finish();
}
#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone)]
    struct BranchKey {
        kind: KeyType,
        bits: usize,
        enabled: Option<KeyOperation>,
        input: Vec<u8>,
        output: Vec<u8>,
        calls: Arc<std::sync::Mutex<Vec<KeyOperation>>>,
    }
    struct BranchLoader(BranchKey);
    impl PrivateKeyLoader for BranchLoader {
        fn key_type(&self) -> KeyType {
            self.0.kind
        }
        fn fips(&self) -> bool {
            false
        }
        fn load(&self, _: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error> {
            Ok(Box::new(self.0.clone()))
        }
    }
    impl BranchKey {
        fn operation(&self, operation: KeyOperation, input: &[u8]) -> Result<OutputBytes, Error> {
            self.calls.lock().unwrap().push(operation);
            let algorithm = match operation {
                KeyOperation::Sign(a) => Algorithm::Signature(a),
                KeyOperation::Decrypt(a) => Algorithm::AsymmetricEncryption(a),
                KeyOperation::Agree(a) => Algorithm::KeyAgreement(a),
                KeyOperation::PublicKey => Algorithm::PublicKeyExport(self.kind),
                _ => unreachable!(),
            };
            if !self.supports(operation) {
                return Err(Error::Unsupported(algorithm));
            }
            if matches!(operation, KeyOperation::Decrypt(_) | KeyOperation::Agree(_)) && input.is_empty() {
                return Err(Error::InvalidInput);
            }
            if operation != KeyOperation::PublicKey && input != self.input {
                return Err(Error::InvalidInput);
            }
            Ok(OutputBytes::new(Zeroizing::new(self.output.clone())))
        }
    }
    impl PrivateKey for BranchKey {
        fn key_type(&self) -> KeyType {
            self.kind
        }
        fn key_size_bits(&self) -> usize {
            self.bits
        }
        fn fips(&self) -> bool {
            false
        }
        fn supports(&self, operation: KeyOperation) -> bool {
            self.enabled == Some(operation)
        }
        fn sign(&self, a: SignatureAlgorithm, input: &[u8]) -> Result<OutputBytes, Error> {
            self.operation(KeyOperation::Sign(a), input)
        }
        fn decrypt(&self, a: AsymmetricEncryptionAlgorithm, input: &[u8]) -> Result<OutputBytes, Error> {
            self.operation(KeyOperation::Decrypt(a), input)
        }
        fn agree(&self, a: KeyAgreementAlgorithm, input: &[u8]) -> Result<OutputBytes, Error> {
            self.operation(KeyOperation::Agree(a), input)
        }
        fn public_key(&self) -> Result<OutputBytes, Error> {
            self.operation(KeyOperation::PublicKey, &[])
        }
    }

    #[rstest]
    #[case(0, false)]
    #[case(0, true)]
    #[case(1, false)]
    #[case(1, true)]
    #[case(2, false)]
    #[case(2, true)]
    #[case(3, false)]
    #[case(3, true)]
    fn private_operation_branches_use_advertisement(#[case] area: usize, #[case] advertised: bool) {
        let (kind, bits, operation, encoded, input, output, id) = match area {
            0 => {
                let corpus = v::wycheproof(RSA_SIGN_FILES[0]);
                let group = &corpus.test_groups[0];
                let t = &v::tests(group)[0];
                (
                    KeyType::Rsa,
                    2048,
                    KeyOperation::Sign(rsa_signature(v::string(group, "sha"))),
                    v::field(group, "privateKeyPkcs8"),
                    v::field(t, "msg"),
                    v::field(t, "sig"),
                    v::id(SignatureAlgorithm::RsaPkcs1v15Sha1, RSA_SIGN_FILES[0], t),
                )
            }
            1 => {
                let file = RSA_DECRYPT_FILES[0].0;
                let corpus = v::wycheproof(file);
                let group = &corpus.test_groups[0];
                let t = v::tests(group)
                    .iter()
                    .find(|t| v::string(t, "result") == "valid" && !v::field(t, "msg").is_empty())
                    .unwrap();
                (
                    KeyType::Rsa,
                    2048,
                    KeyOperation::Decrypt(AsymmetricEncryptionAlgorithm::RsaPkcs1v15),
                    v::field(group, "privateKeyPkcs8"),
                    v::field(t, "ct"),
                    v::field(t, "msg"),
                    v::id(AsymmetricEncryptionAlgorithm::RsaPkcs1v15, file, t),
                )
            }
            2 => {
                let fields = v::rfc5114(6);
                let public = der::point(&fields["x_qA"], &fields["y_qA"], 32);
                (
                    KeyType::EcP256,
                    256,
                    KeyOperation::Agree(KeyAgreementAlgorithm::EcdhP256),
                    der::ec(KeyType::EcP256, &fields["dA"], Some(&public), None),
                    der::point(&fields["x_qB"], &fields["y_qB"], 32),
                    der::padded(&fields["x_Z"], 32),
                    "rfc/rfc5114.txt/A.6".to_owned(),
                )
            }
            _ => {
                let corpus = v::wycheproof(RSA_SIGN_FILES[0]);
                let group = &corpus.test_groups[0];
                let encoded = v::field(group, "privateKeyPkcs8");
                let public = der::rsa_public(&encoded);
                (
                    KeyType::Rsa,
                    2048,
                    KeyOperation::PublicKey,
                    encoded,
                    v::field(&v::tests(group)[0], "msg"),
                    public,
                    format!(
                        "{}/tcId={}/public key",
                        RSA_SIGN_FILES[0],
                        v::number(&v::tests(group)[0], "tcId")
                    ),
                )
            }
        };
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mock = BranchKey {
            kind,
            bits,
            enabled: advertised.then_some(operation),
            input: input.clone(),
            output: output.clone(),
            calls: Arc::clone(&calls),
        };
        let provider = CryptoProvider::builder()
            .with(Entry::PrivateKeyLoader(Arc::new(BranchLoader(mock))))
            .build()
            .unwrap();
        let mut checks = Checks::default();
        let key = loaded(
            &mut checks,
            &provider,
            kind,
            PrivateKeyMaterial::Pkcs8(&encoded),
            &id,
            bits,
            false,
            false,
        )
        .unwrap();
        let selection_calls = calls.lock().unwrap().clone();
        let selected_count = selection_calls.iter().filter(|&&call| call == operation).count();
        assert_eq!(selected_count, if advertised && area == 0 { 0 } else { 1 });
        if !advertised {
            for algorithm in SIGNATURES {
                assert!(selection_calls.contains(&KeyOperation::Sign(algorithm)));
            }
            for algorithm in ENCRYPTIONS {
                assert!(selection_calls.contains(&KeyOperation::Decrypt(algorithm)));
            }
            for algorithm in AGREEMENTS {
                assert!(selection_calls.contains(&KeyOperation::Agree(algorithm)));
            }
            assert!(selection_calls.contains(&KeyOperation::PublicKey));
        }
        let algorithm = match operation {
            KeyOperation::Sign(a) => Algorithm::Signature(a),
            KeyOperation::Decrypt(a) => Algorithm::AsymmetricEncryption(a),
            KeyOperation::Agree(a) => Algorithm::KeyAgreement(a),
            KeyOperation::PublicKey => Algorithm::PublicKeyExport(kind),
            _ => unreachable!(),
        };
        let expected = if advertised {
            Expect::Success
        } else {
            Expect::Error(Error::Unsupported(algorithm))
        };
        match operation {
            KeyOperation::Agree(a) => agree_kat(&mut checks, &id, &*key, a, &input, &output, false),
            KeyOperation::PublicKey => exported(&mut checks, &id, &*key, &output),
            KeyOperation::Sign(a) => {
                if let Some(value) = checks.call(&id, expected, || key.sign(a, &input)) {
                    checks.bytes(&id, &value, &output);
                }
            }
            KeyOperation::Decrypt(a) => {
                if let Some(value) = checks.call(&id, expected, || key.decrypt(a, &input)) {
                    checks.bytes(&id, &value, &output);
                }
            }
            _ => unreachable!(),
        }
        checks.finish();
    }

    struct RepeatedGenerator {
        encodings: Vec<Vec<u8>>,
        calls: Arc<AtomicUsize>,
    }
    impl KeyGenerator for RepeatedGenerator {
        fn algorithm(&self) -> KeyGenerationAlgorithm {
            KeyGenerationAlgorithm::EcP256
        }
        fn fips(&self) -> bool {
            false
        }
        fn generate(&self) -> Result<OutputBytes, Error> {
            let index = self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(OutputBytes::new(Zeroizing::new(
                self.encodings[index % self.encodings.len()].clone(),
            )))
        }
    }

    struct StaticFfdhLoader {
        peers: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }
    struct StaticFfdhKey {
        bits: usize,
        peers: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }
    impl PrivateKeyLoader for StaticFfdhLoader {
        fn key_type(&self) -> KeyType {
            KeyType::Ffdh
        }
        fn fips(&self) -> bool {
            false
        }
        fn load(&self, material: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error> {
            let PrivateKeyMaterial::Ffdh { parameters, .. } = material else {
                return Err(Error::InvalidKey);
            };
            Ok(Box::new(StaticFfdhKey {
                bits: der::bit_length(parameters.p),
                peers: Arc::clone(&self.peers),
            }))
        }
    }
    impl PrivateKey for StaticFfdhKey {
        fn key_type(&self) -> KeyType {
            KeyType::Ffdh
        }
        fn key_size_bits(&self) -> usize {
            self.bits
        }
        fn fips(&self) -> bool {
            false
        }
        fn supports(&self, operation: KeyOperation) -> bool {
            operation == KeyOperation::Agree(KeyAgreementAlgorithm::Ffdh)
        }
        fn agree(&self, algorithm: KeyAgreementAlgorithm, peer: &[u8]) -> Result<OutputBytes, Error> {
            if algorithm != KeyAgreementAlgorithm::Ffdh {
                return Err(Error::Unsupported(Algorithm::KeyAgreement(algorithm)));
            }
            self.peers.lock().unwrap().push(peer.to_vec());
            Err(Error::InvalidInput)
        }
    }

    #[test]
    fn generated_key_freshness_compares_public_fields() {
        let (scalar, x, y, _) = v::ec9500().into_iter().next().unwrap();
        let public = der::point(&x, &y, 32);
        let encodings = vec![
            der::ec(KeyType::EcP256, &scalar, Some(&public), None),
            der::ec(KeyType::EcP256, &scalar, Some(&public), Some(KeyType::EcP256)),
        ];
        assert_ne!(encodings[0], encodings[1]);
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = CryptoProvider::builder()
            .with(Entry::KeyGenerator(Arc::new(RepeatedGenerator {
                encodings,
                calls: Arc::clone(&calls),
            })))
            .build()
            .unwrap();
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            key_generation(&provider, Options::default())
        }))
        .unwrap_err();
        let message = failure.downcast_ref::<String>().unwrap();
        assert!(message.contains("generated public keys are identical"));
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn static_ffdh_peer_errors_need_no_ephemeral_entry() {
        let group = &v::dh_groups()[0];
        let fields = v::rfc5114(1);
        for q in [group.q.as_deref(), None] {
            let peers = Arc::new(std::sync::Mutex::new(Vec::new()));
            let provider = CryptoProvider::builder()
                .with(Entry::PrivateKeyLoader(Arc::new(StaticFfdhLoader {
                    peers: Arc::clone(&peers),
                })))
                .build()
                .unwrap();
            assert!(helpers::ffdh_key_agreement(&provider).is_err());
            let mut c = Checks::default();
            loaded(
                &mut c,
                &provider,
                KeyType::Ffdh,
                PrivateKeyMaterial::Ffdh {
                    parameters: FfdhParameters::new(&group.p, &group.g, q),
                    private_value: &fields["xA"],
                },
                "rfc/rfc5114.txt/A.1/static peer controls",
                der::bit_length(&group.p),
                false,
                false,
            )
            .unwrap();
            c.finish();
            let peers = peers.lock().unwrap();
            assert!(peers.iter().any(Vec::is_empty));
            assert!(peers.iter().any(|peer| peer == &[0]));
            assert!(peers.iter().any(|peer| peer == &[1]));
            assert!(peers.contains(&group.p));
            assert!(peers.iter().any(|peer| peer.len() > group.p.len() + 1));
        }
    }

    struct DecryptOnlyLoader {
        base: Vec<u8>,
        derived: Vec<Vec<u8>>,
        ciphertext: Vec<u8>,
        plaintext: Vec<u8>,
        decrypts: Arc<AtomicUsize>,
        derived_loads: Arc<AtomicUsize>,
    }
    struct DecryptOnlyKey {
        ciphertext: Vec<u8>,
        plaintext: Vec<u8>,
        decrypts: Arc<AtomicUsize>,
    }
    struct ReferenceEncryptor {
        ciphertext: Vec<u8>,
        calls: Arc<AtomicUsize>,
    }
    impl AsymmetricEncryptor for ReferenceEncryptor {
        fn algorithm(&self) -> AsymmetricEncryptionAlgorithm {
            AsymmetricEncryptionAlgorithm::RsaPkcs1v15
        }
        fn fips(&self) -> bool {
            false
        }
        fn encrypt(&self, _: PublicKey<'_>, _: &[u8]) -> Result<OutputBytes, Error> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(OutputBytes::new(Zeroizing::new(self.ciphertext.clone())))
        }
    }

    #[test]
    fn inconsistent_roundtrip_can_use_another_provider_encryptor() {
        let corpus = v::wycheproof(RSA_DECRYPT_FILES[0].0);
        let group = &corpus.test_groups[0];
        let encoded = v::field(group, "privateKeyPkcs8");
        let t = v::tests(group)
            .iter()
            .find(|t| v::string(t, "result") == "valid")
            .unwrap();
        let ciphertext = v::field(t, "ct");
        let messages = crate::published::messages();
        let message = messages
            .iter()
            .find(|(_, m)| !m.is_empty() && m.len() <= 245)
            .unwrap()
            .1
            .clone();
        let decrypts = Arc::new(AtomicUsize::new(0));
        let encrypts = Arc::new(AtomicUsize::new(0));
        let base = DecryptOnlyKey {
            ciphertext: ciphertext.clone(),
            plaintext: message.clone(),
            decrypts: Arc::clone(&decrypts),
        };
        let derived = DecryptOnlyKey {
            ciphertext: ciphertext.clone(),
            plaintext: message,
            decrypts: Arc::clone(&decrypts),
        };
        let local = CryptoProvider::builder().build().unwrap();
        let other = CryptoProvider::builder()
            .with(Entry::AsymmetricEncryptor(Arc::new(ReferenceEncryptor {
                ciphertext,
                calls: Arc::clone(&encrypts),
            })))
            .build()
            .unwrap();
        let mut checks = Checks::default();
        inconsistent_roundtrip(
            &mut checks,
            (&local, Some(&other)),
            (&base, &derived),
            "published reference encryption",
            &encoded,
            AsymmetricEncryptionAlgorithm::RsaPkcs1v15,
        );
        checks.finish();
        assert_eq!(encrypts.load(Ordering::Relaxed), 1);
        assert_eq!(decrypts.load(Ordering::Relaxed), 2);
    }
    impl PrivateKeyLoader for DecryptOnlyLoader {
        fn key_type(&self) -> KeyType {
            KeyType::Rsa
        }
        fn fips(&self) -> bool {
            false
        }
        fn load(&self, material: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error> {
            let PrivateKeyMaterial::Pkcs8(encoded) = material else {
                return Err(Error::InvalidKey);
            };
            if self.derived.iter().any(|key| key == encoded) {
                self.derived_loads.fetch_add(1, Ordering::Relaxed);
                return Err(Error::InvalidKey);
            }
            if encoded != self.base {
                return Err(Error::InvalidKey);
            }
            Ok(Box::new(DecryptOnlyKey {
                ciphertext: self.ciphertext.clone(),
                plaintext: self.plaintext.clone(),
                decrypts: Arc::clone(&self.decrypts),
            }))
        }
    }
    impl PrivateKey for DecryptOnlyKey {
        fn key_type(&self) -> KeyType {
            KeyType::Rsa
        }
        fn key_size_bits(&self) -> usize {
            2048
        }
        fn fips(&self) -> bool {
            false
        }
        fn supports(&self, operation: KeyOperation) -> bool {
            operation == KeyOperation::Decrypt(AsymmetricEncryptionAlgorithm::RsaPkcs1v15)
        }
        fn decrypt(&self, algorithm: AsymmetricEncryptionAlgorithm, ciphertext: &[u8]) -> Result<OutputBytes, Error> {
            if algorithm != AsymmetricEncryptionAlgorithm::RsaPkcs1v15 {
                return Err(Error::Unsupported(Algorithm::AsymmetricEncryption(algorithm)));
            }
            if ciphertext.len() != self.ciphertext.len() {
                return Err(Error::InvalidInput);
            }
            if ciphertext != self.ciphertext {
                return Err(Error::VerificationFailed);
            }
            self.decrypts.fetch_add(1, Ordering::Relaxed);
            Ok(OutputBytes::new(Zeroizing::new(self.plaintext.clone())))
        }
    }

    #[test]
    fn inconsistent_decryption_does_not_require_signing() {
        let corpus = v::wycheproof(RSA_DECRYPT_FILES[0].0);
        let group = &corpus.test_groups[0];
        let base = v::field(group, "privateKeyPkcs8");
        let t = v::tests(group)
            .iter()
            .find(|t| v::string(t, "result") == "valid")
            .unwrap();
        let decrypts = Arc::new(AtomicUsize::new(0));
        let derived_loads = Arc::new(AtomicUsize::new(0));
        let loader = DecryptOnlyLoader {
            derived: der::inconsistent_rsa(&base, None),
            base,
            ciphertext: v::field(t, "ct"),
            plaintext: v::field(t, "msg"),
            decrypts: Arc::clone(&decrypts),
            derived_loads: Arc::clone(&derived_loads),
        };
        let provider = CryptoProvider::builder()
            .with(Entry::PrivateKeyLoader(Arc::new(loader)))
            .build()
            .unwrap();
        let mut c = Checks::default();
        inconsistent_rsa(&mut c, &provider);
        assert!(decrypts.load(Ordering::Relaxed) > 0);
        assert!(derived_loads.load(Ordering::Relaxed) >= 2);
    }

    #[test]
    fn public_range_comparison() {
        for (i, group) in v::dh_groups().iter().take(3).enumerate() {
            let published = v::rfc5114(i + 1);
            assert!(below_modulus_minus_one(&published["yA"], &group.p));
            assert!(below_modulus_minus_one(&published["yB"], &group.p));
            assert!(!below_modulus_minus_one(&group.p, &group.p));
        }
    }

    #[test]
    fn changed_ffc_exponents_are_in_range() {
        let cases = v::response(FFC_FILE)
            .into_iter()
            .filter(|r| r.text("Result").contains("private key changed"))
            .collect::<Vec<_>>();
        assert_eq!(cases.len(), 4);
        for r in cases {
            let x = r.bytes("XstatIUT");
            let q = r.bytes("Q");
            let x = der::unsigned(&x);
            let q = der::unsigned(&q);
            assert!(!x.is_empty());
            assert!(x.len() < q.len() || x.len() == q.len() && x < q, "{}", r.id(FFC_FILE));
        }
    }
}
