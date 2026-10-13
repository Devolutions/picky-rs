//! Private-key loading: encodings, mismatched and truncated keys, and inconsistent RSA components.

use picky_crypto::*;
use serde_json::Value;

use crate::algorithms::*;
use crate::harness::{Checks, Expect, Options};
use crate::keys::*;
use crate::{der, select, vectors as v};

pub fn run(p: &CryptoProvider, options: Options) {
    let mut c = Checks::default();
    c.metadata("published key encoding controls", der::encoding_controls);
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
                    let t = select::ed25519_empty();
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
        // The key agreement area loads the same key without parameters.
        let explicit = der::ec(kind, &scalar, Some(&public), Some(kind));
        if let Some(key) = loaded(
            &mut c,
            p,
            kind,
            PrivateKeyMaterial::Pkcs8(&explicit),
            &id,
            ec_bits(width),
            false,
            false,
        ) {
            agree_kat(&mut c, &id, &*key, a, &peer, &der::padded(&r.bytes("Z"), width), false);
            let sign = CURVES.iter().find(|(k, _, _, _, _)| *k == kind).unwrap().2;
            if c.key_supports(&id, &*key, KeyOperation::Sign(sign)) {
                if let Some(signature) = c.call(&id, Expect::Success, || key.sign(sign, &r.bytes("OI"))) {
                    c.check(&id, signature.len() == width * 2, "ECDSA P1363 length");
                    if let Ok(verifier) = helpers::signature_verifier(p, sign) {
                        c.call(&id, Expect::Success, || {
                            verifier.verify(PublicKey(&public), &r.bytes("OI"), &signature)
                        });
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
            ec_bits(width),
            false,
            true,
        ) {
            exported(&mut c, &id, &*key, &public);
            agree_kat(&mut c, &id, &*key, a, &peer, &der::padded(&r.bytes("Z"), width), false);
        }
        malformed_pkcs8(&mut c, loader, (&id, &format!("{id}/")), &material, &public);
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
        let mismatched = der::ed(&t.seed, Some(select::ed25519_other_public(&t.public)));
        if let Ok(loader) = helpers::private_key_loader(p, KeyType::Ed25519) {
            c.call(
                &format!("{id}/mismatched public key"),
                Expect::Error(Error::InvalidKey),
                || loader.load(PrivateKeyMaterial::Pkcs8(&mismatched)),
            );
        }
    }
    if let Ok(loader) = helpers::private_key_loader(p, KeyType::Ed25519) {
        let encoded = select::ed25519_attributes();
        if let Some(key) = c.call(
            "Ed25519/rfc/rfc8410.txt/10.3/attributes",
            Expect::Either(Error::InvalidKey),
            || loader.load(PrivateKeyMaterial::Pkcs8(&encoded)),
        ) {
            let public = der::encoded_public(KeyType::Ed25519, &encoded).unwrap();
            exported(&mut c, "Ed25519/rfc/rfc8410.txt/10.3/attributes", &*key, &public);
        }
    }
    inconsistent_rsa(&mut c, p, options);
    if let Ok(loader) = helpers::private_key_loader(p, KeyType::Rsa) {
        let vectors = v::wycheproof(RSA_SIGN_FILES[0]);
        let g = select::rsa_private_group(RSA_SIGN_FILES[0], &vectors);
        let encoded = v::field(g, "privateKeyPkcs8");
        let prefix = format!("{}/RSA ", RSA_SIGN_FILES[0]);
        malformed_pkcs8(
            &mut c,
            loader,
            (RSA_SIGN_FILES[0], &prefix),
            &encoded,
            &der::rsa_public(&encoded),
        );
    }
    c.finish();
}

/// Checks that truncations of a published PKCS#8 key, and its version 1 form with the published public key added, fail to load.
/// `ids` holds the source named by the split/reassemble control and the prefix of each check.
fn malformed_pkcs8(c: &mut Checks, loader: &dyn PrivateKeyLoader, ids: (&str, &str), encoded: &[u8], public: &[u8]) {
    let (source, prefix) = ids;
    for length in [0, 1, encoded.len() / 2, encoded.len() - 1] {
        c.call(
            &format!("{prefix}truncation/{length}"),
            Expect::Error(Error::InvalidKey),
            || loader.load(PrivateKeyMaterial::Pkcs8(&encoded[..length])),
        );
    }
    let mut fields: Vec<_> = der::children(encoded).iter().map(|f| f.encoded.to_vec()).collect();
    assert_eq!(der::sequence(&fields), encoded, "{source}: split/reassemble control");
    fields[0] = der::integer(&[1]);
    fields.push(der::tlv(0x81, &[&[0][..], public].concat()));
    let version1 = der::sequence(&fields);
    c.call(&format!("{prefix}version 1"), Expect::Error(Error::InvalidKey), || {
        loader.load(PrivateKeyMaterial::Pkcs8(&version1))
    });
}

pub fn inconsistent_rsa(c: &mut Checks, p: &CryptoProvider, options: Options) {
    inconsistent_rsa_signing(c, p, options);
    inconsistent_rsa_decryption(c, p, options);
}

pub fn inconsistent_signatures(
    c: &mut Checks,
    p: &CryptoProvider,
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
        let verifier = helpers::signature_verifier(p, algorithm).ok();
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
                if let Some(verifier) = verifier {
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
                if let Some(verifier) = verifier {
                    c.call(&id, Expect::Success, || {
                        verifier.verify(PublicKey(&public), &message, &signature)
                    });
                } else if let Some(positive) = &positive {
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

/// Where the ciphertext of a derived key's decryption check comes from, in order of preference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiphertextSource {
    /// A published ciphertext of the base key, which decrypts to its published plaintext.
    Published,
    /// The encryptor of [`Options::reference_provider`], a different backend in the build.
    Reference,
    /// The encryptor of the provider under test, as a round trip.
    Own,
}

/// A published ciphertext of the base key, with its algorithm and plaintext.
pub type PublishedCiphertext<'a> = (AsymmetricEncryptionAlgorithm, &'a [u8], &'a [u8]);

/// Checks decryption with an RSA key derived with inconsistent components, for every encryption algorithm the contract defines.
///
/// A derived key that doesn't advertise an algorithm must return `Unsupported` for it.
/// Otherwise the ciphertext comes from the first [`CiphertextSource`] that produces one, and the check fails if none does.
/// Each check counts its source in the coverage report.
pub fn inconsistent_decryption(
    c: &mut Checks,
    p: &CryptoProvider,
    options: Options,
    keys: (&dyn PrivateKey, &dyn PrivateKey),
    id: &str,
    encoded: &[u8],
    published: Option<PublishedCiphertext<'_>>,
) {
    let (base, key) = keys;
    let public = der::rsa_public(encoded);
    let modulus_len = der::bit_length(der::children(&public)[0].value).div_ceil(8);
    for algorithm in ENCRYPTIONS {
        let id = format!("{id}/{algorithm:?}");
        if !c.key_supports(&id, key, KeyOperation::Decrypt(algorithm)) {
            // A modulus-length ciphertext of value zero is in the valid domain, so only the advertisement decides the outcome.
            let ciphertext = vec![0; modulus_len];
            c.call(
                &format!("{id}/not advertised"),
                Expect::Error(Error::Unsupported(Algorithm::AsymmetricEncryption(algorithm))),
                || key.decrypt(algorithm, &ciphertext),
            );
            continue;
        }
        let Some((source, ciphertext, expected)) =
            ciphertext_source(p, options, algorithm, &public, modulus_len, published)
        else {
            c.check(&id, false, "no source produced a ciphertext for the derived key");
            continue;
        };
        c.count(format!("inconsistent RSA decryption ciphertext from {source:?}"));
        let id = format!("{id}/{source:?} ciphertext");
        if c.key_supports(&id, base, KeyOperation::Decrypt(algorithm)) {
            if let Some(positive) = c.call(&format!("{id}/positive control"), Expect::Success, || {
                base.decrypt(algorithm, &ciphertext)
            }) {
                c.bytes(&id, &positive, &expected);
            }
        }
        if let Some(plaintext) = c.call(&id, Expect::Either(Error::InvalidKey), || {
            key.decrypt(algorithm, &ciphertext)
        }) {
            c.bytes(&id, &plaintext, &expected);
        }
    }
}

/// Returns the first ciphertext a [`CiphertextSource`] produces, with its source and expected plaintext.
fn ciphertext_source(
    p: &CryptoProvider,
    options: Options,
    algorithm: AsymmetricEncryptionAlgorithm,
    public: &[u8],
    modulus_len: usize,
    published: Option<PublishedCiphertext<'_>>,
) -> Option<(CiphertextSource, Vec<u8>, Vec<u8>)> {
    if let Some((_, ciphertext, plaintext)) = published.filter(|(a, _, _)| *a == algorithm) {
        return Some((CiphertextSource::Published, ciphertext.to_vec(), plaintext.to_vec()));
    }
    let (_, message) = select::rsa_plaintext(rsa_plaintext_limit(algorithm, modulus_len));
    [
        (CiphertextSource::Reference, options.reference_provider),
        (CiphertextSource::Own, Some(p)),
    ]
    .into_iter()
    .find_map(|(source, provider)| {
        let encryptor = helpers::asymmetric_encryptor(provider?, algorithm).ok()?;
        let ciphertext = encryptor.encrypt(PublicKey(public), &message).ok()?;
        Some((source, ciphertext.to_vec(), message.clone()))
    })
}

/// Checks public-key export from an RSA key derived with inconsistent components: `InvalidKey`, or exactly the base key's encoding.
pub fn derived_export(c: &mut Checks, id: &str, key: &dyn PrivateKey, expected: &[u8]) {
    let outcome = if c.key_supports(id, key, KeyOperation::PublicKey) {
        Expect::Either(Error::InvalidKey)
    } else {
        Expect::Error(Error::Unsupported(Algorithm::PublicKeyExport(KeyType::Rsa)))
    };
    if let Some(out) = c.call(&format!("{id}/public_key"), outcome, || key.public_key()) {
        c.bytes(id, &out, expected);
    }
}

fn inconsistent_rsa_signing(c: &mut Checks, p: &CryptoProvider, options: Options) {
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
        let mut decrypted = std::collections::BTreeSet::new();
        for g in &bases {
            let encoding = v::field(g, "privateKeyPkcs8");
            // Groups of one file can share a key; export and decryption don't depend on the group.
            let first = decrypted.insert(encoding.clone());
            let id = format!("{file}/inconsistent components");
            let Some(base) = c.call(&format!("{id}/positive control"), Expect::Success, || {
                loader.load(PrivateKeyMaterial::Pkcs8(&encoding))
            }) else {
                continue;
            };
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
                    inconsistent_signatures(c, p, &*base, &*key, &id, (file, g));
                    if first {
                        derived_export(c, &id, &*key, &der::rsa_public(&encoding));
                        inconsistent_decryption(c, p, options, (&*base, &*key), &id, &encoding, None);
                    }
                }
            }
        }
    }
}

/// A published test, its group's PKCS#8 key and another key of the same size.
type DecryptionBase<'a> = (&'a Value, Vec<u8>, Option<Vec<u8>>);

/// Returns each must-support key of an RSA decryption file with its first valid unlabeled test and another key of the same size for the `qInv` substitution.
fn decryption_bases(vectors: &v::Wycheproof) -> Vec<DecryptionBase<'_>> {
    let groups = &vectors.test_groups;
    groups
        .iter()
        .filter_map(|g| {
            let encoded = v::field(g, "privateKeyPkcs8");
            if !der::rsa_must(&encoded) {
                return None;
            }
            let t = v::tests(g)
                .iter()
                .find(|t| v::string(t, "result") == "valid" && t["label"].as_str().is_none_or(str::is_empty))?;
            let other = groups
                .iter()
                .find(|other| {
                    v::field(other, "privateKeyPkcs8") != encoded
                        && v::number(other, "keySize") == v::number(g, "keySize")
                })
                .map(|g| v::field(g, "privateKeyPkcs8"));
            Some((t, encoded, other))
        })
        .collect()
}

fn inconsistent_rsa_decryption(c: &mut Checks, p: &CryptoProvider, options: Options) {
    let Ok(loader) = helpers::private_key_loader(p, KeyType::Rsa) else {
        return;
    };
    for (file, a) in RSA_DECRYPT_FILES {
        let vectors = v::wycheproof(file);
        for (t, encoded, other) in decryption_bases(&vectors) {
            let id = format!("{file}/tcId={}/inconsistent components", v::number(t, "tcId"));
            let Some(base) = c.call(&format!("{id}/positive control"), Expect::Success, || {
                loader.load(PrivateKeyMaterial::Pkcs8(&encoded))
            }) else {
                continue;
            };
            let ciphertext = v::field(t, "ct");
            let plaintext = v::field(t, "msg");
            for (i, derived) in der::inconsistent_rsa(&encoded, other.as_deref())
                .into_iter()
                .enumerate()
            {
                let id = format!("{id}/variant {i}");
                if let Some(key) = c.call(&id, Expect::Either(Error::InvalidKey), || {
                    loader.load(PrivateKeyMaterial::Pkcs8(&derived))
                }) {
                    derived_export(c, &id, &*key, &der::rsa_public(&encoded));
                    let published = Some((a, ciphertext.as_slice(), plaintext.as_slice()));
                    inconsistent_decryption(c, p, options, (&*base, &*key), &id, &encoded, published);
                }
            }
        }
    }
}
