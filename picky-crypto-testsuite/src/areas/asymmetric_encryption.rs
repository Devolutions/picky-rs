//! RSA encryption and private-key decryption against published vectors.

use picky_crypto::*;

use crate::algorithms::*;
use crate::harness::{Checks, Expect, Options};
use crate::keys::*;
use crate::{der, vectors as v};

pub fn run(p: &CryptoProvider, _: Options) {
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
            let key = loaded(
                &mut c,
                p,
                KeyType::Rsa,
                PrivateKeyMaterial::Pkcs8(&material),
                &format!("{a:?}/{file}/key"),
                bits,
                !der::rsa_must(&material),
                false,
            );
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
                            if let Some(key) = key
                                .as_ref()
                                .filter(|k| c.key_supports(&id, &***k, KeyOperation::Decrypt(a)))
                            {
                                if let Some(out) = c.call(&id, Expect::Success, || key.decrypt(a, &encrypted)) {
                                    c.bytes(&id, &out, &msg);
                                }
                            }
                        }
                        let too_long = rsa_plaintext_limit(a, bits.div_ceil(8)) + 1;
                        c.call(
                            &format!("{id}/plaintext too long"),
                            Expect::Error(Error::InvalidInput),
                            || e.encrypt(PublicKey(&public), &vec![0; too_long]),
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
