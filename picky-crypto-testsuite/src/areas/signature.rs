//! Signature verification and private-key signing against published vectors.

use picky_crypto::*;
use serde_json::Value;

use crate::algorithms::*;
use crate::harness::{Checks, Expect, Options, malformed_public};
use crate::keys::*;
use crate::{der, select, vectors as v};

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

/// Structural Ed25519 point encodings (RFC 8032 section 5.1.2) whose expected outcome is an error.
/// Returns the identity encoding, used as `R`, and two public keys `A` that fail section 5.1.3 decoding.
pub fn ed25519_undecodable_keys() -> ([u8; 32], [(&'static str, [u8; 32]); 2]) {
    // p = 2^255 - 19, little-endian.
    let mut p = [0xff; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    // y = p + 1 is not below p, so decoding fails at step 1; the sign bit stays clear.
    let mut non_canonical = p;
    non_canonical[0] += 1;
    // y = 1 gives x = 0, so the set sign bit makes decoding fail at step 4.
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut negative_zero = identity;
    negative_zero[31] |= 0x80;
    (
        identity,
        [
            ("y = p + 1", non_canonical),
            ("x = 0 with the sign bit set", negative_zero),
        ],
    )
}

pub fn run(p: &CryptoProvider, options: Options) {
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
            let (group, t) = select::signature_control(file, &vectors);
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
            let (_, valid) = select::signature_control(&file, &signatures);
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
        let t = select::ed25519_small_order_r(&vectors);
        let (group, positive) = select::signature_control("ed25519_test.json", &vectors);
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
        let (identity, keys) = ed25519_undecodable_keys();
        let identity_signature = [identity, [0; 32]].concat();
        for (name, key) in keys {
            c.call(
                &format!("Ed25519/rfc/rfc8032.txt/5.1.3/A {name}"),
                malformed_public(options),
                || verifier.verify(PublicKey(&key), &[], &identity_signature),
            );
        }
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
                    let message = v::field(select::group_message(file, &g), "msg");
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
