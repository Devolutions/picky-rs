//! Published private keys loaded by both providers: signatures, cross verification, cross decryption and static ECDH.

use picky_crypto::*;

use super::{outputs, selected};
use crate::algorithms::*;
use crate::harness::{CheckedResult, Checks, Expect};
use crate::keys::*;
use crate::{der, published, select, vectors as v};

pub fn run(a: &CryptoProvider, b: &CryptoProvider) {
    let mut c = Checks::default();
    for (source, dest) in [(a, b), (b, a)] {
        cross_keys(&mut c, source, dest);
    }
    c.finish();
}

fn cross_keys(c: &mut Checks, source: &CryptoProvider, dest: &CryptoProvider) {
    let messages = published::messages();
    let mut rsa_keys = std::collections::BTreeSet::new();
    for file in RSA_SIGN_FILES {
        let Ok(sl) = helpers::private_key_loader(source, KeyType::Rsa) else {
            continue;
        };
        let dl = helpers::private_key_loader(dest, KeyType::Rsa).ok();
        for g in v::wycheproof(file).test_groups {
            let encoded = v::field(&g, "privateKeyPkcs8");
            if !der::rsa_must(&encoded) {
                continue;
            }
            let key_id = format!("{file}/cross keys");
            let Some(sk) = c.call(&key_id, Expect::Success, || {
                sl.load(PrivateKeyMaterial::Pkcs8(&encoded))
            }) else {
                continue;
            };
            let dk = dl.and_then(|dl| {
                c.call(&key_id, Expect::Success, || {
                    dl.load(PrivateKeyMaterial::Pkcs8(&encoded))
                })
            });
            let public = der::rsa_public(&encoded);
            let k = der::bit_length(der::children(&public)[0].value).div_ceil(8);
            let sign = rsa_signature(v::string(&g, "sha"));
            if rsa_keys.insert(encoded.clone()) {
                let t = select::group_nonempty_message(file, &g);
                let data = v::field(t, "msg");
                for algorithm in SIGNATURES[..8].iter().copied().filter(|alg| *alg != sign) {
                    let id = format!("{}/all RSA signing algorithms", v::id(algorithm, file, t));
                    let ss = c.key_supports(&id, &*sk, KeyOperation::Sign(algorithm));
                    let ds = dk
                        .as_ref()
                        .is_some_and(|key| c.key_supports(&id, &**key, KeyOperation::Sign(algorithm)));
                    let verifier = helpers::signature_verifier(dest, algorithm).ok();
                    if !ss || verifier.is_none() && !ds {
                        continue;
                    }
                    if let Some(signature) = c.call(&id, Expect::Success, || sk.sign(algorithm, &data)) {
                        if let Some(verifier) = verifier {
                            c.call(&id, Expect::Success, || {
                                verifier.verify(PublicKey(&public), &data, &signature)
                            });
                        }
                        if ds {
                            if let Some(other) =
                                c.call(&id, Expect::Success, || dk.as_ref().unwrap().sign(algorithm, &data))
                            {
                                c.bytes(&id, &signature, &other);
                            }
                        }
                    }
                }
            }
            let ss = c.key_supports(&key_id, &*sk, KeyOperation::Sign(sign));
            let ds = dk
                .as_ref()
                .is_some_and(|key| c.key_supports(&key_id, &**key, KeyOperation::Sign(sign)));
            let decrypts = ENCRYPTIONS.map(|a| {
                dk.as_ref()
                    .is_some_and(|key| c.key_supports(&key_id, &**key, KeyOperation::Decrypt(a)))
            });
            for t in v::tests(&g) {
                let msg = v::field(t, "msg");
                let id = format!("{}/cross keys", v::id(sign, file, t));
                if ss {
                    if let Some(sig) = c.call(&id, Expect::Success, || sk.sign(sign, &msg)) {
                        if let Ok(verifier) = helpers::signature_verifier(dest, sign) {
                            c.call(&id, Expect::Success, || verifier.verify(PublicKey(&public), &msg, &sig));
                        }
                        if ds {
                            if let Some(other) = c.call(&id, Expect::Success, || dk.as_ref().unwrap().sign(sign, &msg))
                            {
                                c.bytes(&id, &sig, &other);
                            }
                        }
                    }
                }
                for (i, a) in ENCRYPTIONS.into_iter().enumerate() {
                    let Ok(encryptor) = helpers::asymmetric_encryptor(source, a) else {
                        continue;
                    };
                    let id = format!("{a:?}/{file}/tcId={}/cross encryption", v::number(t, "tcId"));
                    if msg.len() > rsa_plaintext_limit(a, k) {
                        c.call(&id, Expect::Error(Error::InvalidInput), || {
                            encryptor.encrypt(PublicKey(&public), &msg)
                        });
                        continue;
                    }
                    if !decrypts[i] {
                        continue;
                    }
                    if let Some(ciphertext) =
                        c.call(&id, Expect::Success, || encryptor.encrypt(PublicKey(&public), &msg))
                    {
                        if let Some(out) = c.call(&id, Expect::Success, || dk.as_ref().unwrap().decrypt(a, &ciphertext))
                        {
                            c.bytes(&id, &out, &msg);
                        }
                    }
                }
            }
            if ss && ds {
                selected(
                    c,
                    &format!("{file}/{sign:?}/published deterministic signatures"),
                    &messages,
                    |(_, data)| {
                        let sig = sk.sign(sign, data).checked()?;
                        if let Ok(verifier) = helpers::signature_verifier(dest, sign) {
                            verifier.verify(PublicKey(&public), data, &sig)?;
                        }
                        Ok((sig, dk.as_ref().unwrap().sign(sign, data).checked()?))
                    },
                );
            }
        }
    }
    for (i, t) in v::ed25519().iter().enumerate() {
        let Ok(sl) = helpers::private_key_loader(source, KeyType::Ed25519) else {
            continue;
        };
        let dl = helpers::private_key_loader(dest, KeyType::Ed25519).ok();
        let encoded = der::ed(&t.seed, Some(&t.public));
        let id = format!("Ed25519/rfc/rfc8032.txt/7.1/{i}/cross keys");
        let Some(sk) = c.call(&id, Expect::Success, || sl.load(PrivateKeyMaterial::Pkcs8(&encoded))) else {
            continue;
        };
        let dk = dl.and_then(|dl| c.call(&id, Expect::Success, || dl.load(PrivateKeyMaterial::Pkcs8(&encoded))));
        let algorithm = SignatureAlgorithm::Ed25519;
        let ss = c.key_supports(&id, &*sk, KeyOperation::Sign(algorithm));
        let ds = dk
            .as_ref()
            .is_some_and(|key| c.key_supports(&id, &**key, KeyOperation::Sign(algorithm)));
        if ss {
            if let Some(sig) = c.call(&id, Expect::Success, || sk.sign(algorithm, &t.message)) {
                if let Ok(verifier) = helpers::signature_verifier(dest, algorithm) {
                    c.call(&id, Expect::Success, || {
                        verifier.verify(PublicKey(&t.public), &t.message, &sig)
                    });
                }
                if ds {
                    if let Some(other) = c.call(&id, Expect::Success, || {
                        dk.as_ref().unwrap().sign(algorithm, &t.message)
                    }) {
                        c.bytes(&id, &sig, &other);
                    }
                }
            }
            if ds {
                selected(
                    c,
                    &format!("{id}/published deterministic signatures"),
                    &messages,
                    |(_, data)| {
                        let sig = sk.sign(algorithm, data).checked()?;
                        if let Ok(verifier) = helpers::signature_verifier(dest, algorithm) {
                            verifier.verify(PublicKey(&t.public), data, &sig)?;
                        }
                        Ok((sig, dk.as_ref().unwrap().sign(algorithm, data).checked()?))
                    },
                );
            }
        }
    }
    for (kind, a, width, r) in ecc_cases()
        .into_iter()
        .filter(|(_, _, _, r)| r.text("Result").starts_with('P'))
    {
        let Ok(sl) = helpers::private_key_loader(source, kind) else {
            continue;
        };
        let dl = helpers::private_key_loader(dest, kind).ok();
        let own = der::point(&r.bytes("QeIUTx"), &r.bytes("QeIUTy"), width);
        let peer = der::point(&r.bytes("QeCAVSx"), &r.bytes("QeCAVSy"), width);
        let encoded = der::ec(kind, &r.bytes("deIUT"), Some(&own), None);
        let id = r.id(ECC_FILE);
        let Some(sk) = c.call(&id, Expect::Success, || sl.load(PrivateKeyMaterial::Pkcs8(&encoded))) else {
            continue;
        };
        let dk = dl.and_then(|dl| c.call(&id, Expect::Success, || dl.load(PrivateKeyMaterial::Pkcs8(&encoded))));
        let ss = c.key_supports(&id, &*sk, KeyOperation::Agree(a));
        let ds = dk
            .as_ref()
            .is_some_and(|key| c.key_supports(&id, &**key, KeyOperation::Agree(a)));
        if ss && ds {
            outputs(c, &id, || sk.agree(a, &peer), || dk.as_ref().unwrap().agree(a, &peer));
        }
        let sign = CURVES.iter().find(|(k, _, _, _, _)| *k == kind).unwrap().2;
        if c.key_supports(&id, &*sk, KeyOperation::Sign(sign)) {
            if let Ok(verifier) = helpers::signature_verifier(dest, sign) {
                if let Some(sig) = c.call(&id, Expect::Success, || sk.sign(sign, &r.bytes("OI"))) {
                    c.call(&id, Expect::Success, || {
                        verifier.verify(PublicKey(&own), &r.bytes("OI"), &sig)
                    });
                }
            }
        }
    }
}
