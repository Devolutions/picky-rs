//! Signatures the signing provider can't verify against a published answer, verified by the other provider.
//!
//! ECDSA signatures are randomized, and the published RSA keys have published signatures only for their group's hash.
//! A provider that signs with an algorithm it has no verifier for can show only the signature's length, so the other provider's verifier checks it.
//! RSA PKCS#1 v1.5 with MD5 has no published vectors at all, so a provider's own verifier can't pin its signatures, and the other provider always verifies them.

use picky_crypto::*;

use crate::algorithms::*;
use crate::harness::{Checks, Expect};
use crate::keys::*;
use crate::{der, select, vectors as v};

pub fn run(a: &CryptoProvider, b: &CryptoProvider) {
    let mut c = Checks::default();
    for (source, dest) in [(a, b), (b, a)] {
        cross_verify(&mut c, source, dest);
    }
    c.finish();
}

/// Returns `dest`'s verifier for `algorithm` when `source` has none, or when no published vector checks `source`'s.
fn unverifiable<'a>(
    source: &CryptoProvider,
    dest: &'a CryptoProvider,
    algorithm: SignatureAlgorithm,
) -> Option<&'a dyn SignatureVerifier> {
    if algorithm != SignatureAlgorithm::RsaPkcs1v15Md5 && helpers::signature_verifier(source, algorithm).is_ok() {
        return None;
    }
    helpers::signature_verifier(dest, algorithm).ok()
}

fn cross_verify(c: &mut Checks, source: &CryptoProvider, dest: &CryptoProvider) {
    if let Ok(loader) = helpers::private_key_loader(source, KeyType::Rsa) {
        let mut keys = std::collections::BTreeSet::new();
        for file in RSA_SIGN_FILES {
            for g in v::wycheproof(file).test_groups {
                let encoded = v::field(&g, "privateKeyPkcs8");
                if !der::rsa_must(&encoded) || !keys.insert(encoded.clone()) {
                    continue;
                }
                let published = rsa_signature(v::string(&g, "sha"));
                let verifiers: Vec<_> = SIGNATURES[..8]
                    .iter()
                    .filter(|algorithm| **algorithm != published)
                    .filter_map(|algorithm| {
                        unverifiable(source, dest, *algorithm).map(|verifier| (*algorithm, verifier))
                    })
                    .collect();
                if verifiers.is_empty() {
                    continue;
                }
                let id = format!("{file}/cross verification");
                let Some(key) = c.call(&id, Expect::Success, || {
                    loader.load(PrivateKeyMaterial::Pkcs8(&encoded))
                }) else {
                    continue;
                };
                let message = v::field(select::group_nonempty_message(file, &g), "msg");
                let public = der::rsa_public(&encoded);
                for (algorithm, verifier) in verifiers {
                    sign_and_verify(
                        c,
                        &format!("{algorithm:?}/{id}"),
                        &*key,
                        algorithm,
                        verifier,
                        &public,
                        &message,
                    );
                }
            }
        }
    }
    for (kind, _, width, r) in ecc_cases()
        .into_iter()
        .filter(|(_, _, _, r)| r.text("Result").starts_with('P'))
    {
        let algorithm = CURVES.iter().find(|(k, _, _, _, _)| *k == kind).unwrap().2;
        let (Some(verifier), Ok(loader)) = (
            unverifiable(source, dest, algorithm),
            helpers::private_key_loader(source, kind),
        ) else {
            continue;
        };
        let id = format!("{algorithm:?}/{}/cross verification", r.id(ECC_FILE));
        let public = der::point(&r.bytes("QeIUTx"), &r.bytes("QeIUTy"), width);
        let encoded = der::ec(kind, &r.bytes("deIUT"), Some(&public), None);
        if let Some(key) = c.call(&id, Expect::Success, || {
            loader.load(PrivateKeyMaterial::Pkcs8(&encoded))
        }) {
            sign_and_verify(c, &id, &*key, algorithm, verifier, &public, &r.bytes("OI"));
        }
    }
}

fn sign_and_verify(
    c: &mut Checks,
    id: &str,
    key: &dyn PrivateKey,
    algorithm: SignatureAlgorithm,
    verifier: &dyn SignatureVerifier,
    public: &[u8],
    message: &[u8],
) {
    if !c.key_supports(id, key, KeyOperation::Sign(algorithm)) {
        return;
    }
    if let Some(signature) = c.call(id, Expect::Success, || key.sign(algorithm, message)) {
        c.call(id, Expect::Success, || {
            verifier.verify(PublicKey(public), message, &signature)
        });
    }
}
