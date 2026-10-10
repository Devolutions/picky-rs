//! RSA keys with inconsistent components, checked against the other provider's verifier and encryptor.

use picky_crypto::*;

use crate::algorithms::*;
use crate::areas::private_key::{inconsistent_roundtrip, inconsistent_signatures};
use crate::harness::{Checks, Expect};
use crate::keys::*;
use crate::{der, select, vectors as v};

pub fn run(a: &CryptoProvider, b: &CryptoProvider) {
    let mut c = Checks::default();
    for (source, dest) in [(a, b), (b, a)] {
        cross_inconsistent(&mut c, source, dest);
    }
    c.finish();
}

fn cross_inconsistent(c: &mut Checks, source: &CryptoProvider, dest: &CryptoProvider) {
    let Ok(loader) = helpers::private_key_loader(source, KeyType::Rsa) else {
        return;
    };
    for file in RSA_SIGN_FILES {
        let vectors = v::wycheproof(file);
        for g in &vectors.test_groups {
            let encoded = v::field(g, "privateKeyPkcs8");
            if !der::rsa_must(&encoded) {
                continue;
            }
            let other = vectors
                .test_groups
                .iter()
                .find(|g| v::field(g, "privateKeyPkcs8") != encoded)
                .map(|g| v::field(g, "privateKeyPkcs8"));
            let t = select::group_message(file, g);
            let data = v::field(t, "msg");
            let sign = rsa_signature(v::string(g, "sha"));
            let id = format!("{}/cross inconsistent key", v::id(sign, file, t));
            let public = der::rsa_public(&encoded);
            let k = der::bit_length(der::children(&public)[0].value).div_ceil(8);
            let Some(base) = c.call(&format!("{id}/positive control"), Expect::Success, || {
                loader.load(PrivateKeyMaterial::Pkcs8(&encoded))
            }) else {
                continue;
            };
            exported(c, &id, &*base, &public);
            let base_decrypts = ENCRYPTIONS.map(|a| c.key_supports(&id, &*base, KeyOperation::Decrypt(a)));
            for derived in der::inconsistent_rsa(&encoded, other.as_deref()) {
                let Some(key) = c.call(&id, Expect::Either(Error::InvalidKey), || {
                    loader.load(PrivateKeyMaterial::Pkcs8(&derived))
                }) else {
                    continue;
                };
                exported(c, &id, &*key, &public);
                inconsistent_signatures(c, source, Some(dest), &*base, &*key, &id, (file, g));
                for (i, a) in ENCRYPTIONS.into_iter().enumerate() {
                    let Ok(encryptor) = helpers::asymmetric_encryptor(dest, a) else {
                        continue;
                    };
                    if !base_decrypts[i]
                        || !c.key_supports(&id, &*key, KeyOperation::Decrypt(a))
                        || data.len() > rsa_plaintext_limit(a, k)
                    {
                        continue;
                    }
                    if let Some(ciphertext) =
                        c.call(&id, Expect::Success, || encryptor.encrypt(PublicKey(&public), &data))
                    {
                        if let Some(plain) =
                            c.call(&format!("{id}/positive decryption control"), Expect::Success, || {
                                base.decrypt(a, &ciphertext)
                            })
                        {
                            c.bytes(&id, &plain, &data);
                        }
                        if let Some(plain) =
                            c.call(&id, Expect::Either(Error::InvalidKey), || key.decrypt(a, &ciphertext))
                        {
                            c.bytes(&id, &plain, &data);
                        }
                    }
                }
            }
        }
    }
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
            let id = format!("{}/cross inconsistent decryption", v::id(a, file, t));
            let Some(base) = c.call(&format!("{id}/positive control"), Expect::Success, || {
                loader.load(PrivateKeyMaterial::Pkcs8(&encoded))
            }) else {
                continue;
            };
            exported(c, &id, &*base, &der::rsa_public(&encoded));
            if !c.key_supports(&id, &*base, KeyOperation::Decrypt(a)) {
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
            for derived in der::inconsistent_rsa(&encoded, other.as_deref()) {
                if let Some(key) = c.call(&id, Expect::Either(Error::InvalidKey), || {
                    loader.load(PrivateKeyMaterial::Pkcs8(&derived))
                }) {
                    exported(c, &id, &*key, &der::rsa_public(&encoded));
                    if c.key_supports(&id, &*key, KeyOperation::Decrypt(a)) {
                        if let Some(out) =
                            c.call(&id, Expect::Either(Error::InvalidKey), || key.decrypt(a, &ciphertext))
                        {
                            c.bytes(&id, &out, &plaintext);
                        }
                    }
                    inconsistent_roundtrip(c, (source, Some(dest)), (&*base, &*key), &id, &encoded, a);
                }
            }
        }
    }
}
