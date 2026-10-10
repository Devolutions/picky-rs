//! RSA encryption by one provider and decryption by the other.

use picky_crypto::*;

use super::selected;
use crate::algorithms::*;
use crate::harness::{CheckedResult, Checks, Expect};
use crate::keys::*;
use crate::{der, select, vectors as v};

pub fn run(a: &CryptoProvider, b: &CryptoProvider) {
    let mut c = Checks::default();
    for (source, dest) in [(a, b), (b, a)] {
        cross_encryption(&mut c, source, dest);
    }
    c.finish();
}

fn cross_encryption(c: &mut Checks, source: &CryptoProvider, dest: &CryptoProvider) {
    let Ok(loader) = helpers::private_key_loader(dest, KeyType::Rsa) else {
        return;
    };
    let vectors = v::wycheproof(RSA_SIGN_FILES[0]);
    let g = select::rsa_private_group(RSA_SIGN_FILES[0], &vectors);
    let encoded = v::field(g, "privateKeyPkcs8");
    let id = format!("{}/published cross encryption", RSA_SIGN_FILES[0]);
    let Some(key) = c.call(&id, Expect::Success, || {
        loader.load(PrivateKeyMaterial::Pkcs8(&encoded))
    }) else {
        return;
    };
    let public = der::rsa_public(&encoded);
    let k = der::bit_length(der::children(&public)[0].value).div_ceil(8);
    for a in ENCRYPTIONS {
        let Ok(encryptor) = helpers::asymmetric_encryptor(source, a) else {
            continue;
        };
        if !c.key_supports(&id, &*key, KeyOperation::Decrypt(a)) {
            continue;
        }
        let messages = select::rsa_messages(rsa_plaintext_limit(a, k));
        selected(c, &format!("{a:?}/{id}"), &messages, |(_, data)| {
            let encrypted = encryptor.encrypt(PublicKey(&public), data).checked()?;
            Ok((
                key.decrypt(a, &encrypted).checked()?,
                OutputBytes::new(Zeroizing::new(data.clone())),
            ))
        });
    }
}
