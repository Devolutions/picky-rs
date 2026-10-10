//! Key generation: encoding, uniqueness, loading and signing with generated keys.

use picky_crypto::*;

use crate::algorithms::*;
use crate::harness::{Checks, Expect, Options};
use crate::keys::*;
use crate::{der, select};

pub fn run(p: &CryptoProvider, _: Options) {
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
                        let message = &select::ed25519_nonempty().message;
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
