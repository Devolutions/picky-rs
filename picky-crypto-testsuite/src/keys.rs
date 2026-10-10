//! Private-key checks and published key sources shared by several areas.

use picky_crypto::*;

use crate::algorithms::*;
use crate::areas::ffdh;
use crate::harness::{CheckedResult, Checks, Expect};
use crate::{der, vectors as v};

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
            if a == KeyAgreementAlgorithm::X25519 {
                for peer in x25519_wrong_length_peers() {
                    c.call(
                        &format!("{id}/{a:?}/peer length {}", peer.len()),
                        Expect::Error(Error::InvalidInput),
                        || key.agree(a, &peer),
                    );
                }
            }
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
        let overlong = ffdh::overlong(parameters.g, parameters.p);
        assert!(
            ffdh::failed_checks(parameters.p, parameters.g, parameters.q, None).is_empty(),
            "{id}: g is a peer value in range, and of order q by the trusted group property"
        );
        let below_modulus = modulus_minus_one(parameters.p);
        for (name, peer) in [
            ("empty", &[][..]),
            ("zero", &[0][..]),
            ("one", &[1][..]),
            ("modulus minus one", below_modulus.as_slice()),
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

/// Returns p − 1 for a published odd p by clearing the low bit of its last byte, asserting that no other byte changes.
/// The result is a boundary input that only ever expects an error.
pub fn modulus_minus_one(p: &[u8]) -> Vec<u8> {
    let (&last, rest) = p.split_last().expect("published modulus is not empty");
    assert_eq!(last & 1, 1, "published modulus is odd");
    let mut y = p.to_vec();
    y[rest.len()] = last & !1;
    assert_eq!(y.len(), p.len(), "p - 1 has the length of p");
    assert_eq!(&y[..rest.len()], rest, "p - 1 differs from p only in the last byte");
    assert_eq!(y[rest.len()], last - 1, "p - 1 ends with the last byte of p minus one");
    y
}

/// Returns the published X25519 base point u = 9 truncated to 31 bytes and extended with a zero byte to 33 bytes.
/// Both still read as u = 9, whose secret is the nonzero public key, so only the 32-byte length check can reject them.
pub fn x25519_wrong_length_peers() -> [Vec<u8>; 2] {
    let (base_point, _) = v::x25519_iterations();
    assert_eq!(base_point.len(), 32, "rfc/rfc7748.txt: base point length");
    assert_eq!(base_point[31], 0, "rfc/rfc7748.txt: truncation drops a zero byte");
    [base_point[..31].to_vec(), [base_point.as_slice(), &[0]].concat()]
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

pub fn agree_kat(
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
