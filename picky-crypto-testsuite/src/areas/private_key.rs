//! Private-key loading: encodings, mismatched and truncated keys, and inconsistent RSA components.

use picky_crypto::*;
use serde_json::Value;

use crate::algorithms::*;
use crate::harness::{Checks, Expect, Options};
use crate::keys::*;
use crate::{der, select, vectors as v};

pub fn run(p: &CryptoProvider, _: Options) {
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
    inconsistent_rsa(&mut c, p);
    if let Ok(loader) = helpers::private_key_loader(p, KeyType::Rsa) {
        let vectors = v::wycheproof(RSA_SIGN_FILES[0]);
        let g = select::rsa_private_group(RSA_SIGN_FILES[0], &vectors);
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

pub fn inconsistent_rsa(c: &mut Checks, p: &CryptoProvider) {
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
    let (source, message) = select::rsa_plaintext(limit);
    let id = format!("{id}/{algorithm:?}/round trip/{source}");
    if let Some(ciphertext) = c.call(&id, Expect::Success, || encryptor.encrypt(PublicKey(&public), &message)) {
        if let Some(positive) = c.call(&format!("{id}/positive control"), Expect::Success, || {
            base.decrypt(algorithm, &ciphertext)
        }) {
            c.bytes(&id, &positive, &message);
        }
        if let Some(plaintext) = c.call(&id, Expect::Either(Error::InvalidKey), || {
            key.decrypt(algorithm, &ciphertext)
        }) {
            c.bytes(&id, &plaintext, &message);
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
