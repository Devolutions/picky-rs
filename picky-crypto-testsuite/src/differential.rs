use picky_crypto::*;
use proptest::prelude::*;

use crate::algorithms::*;
use crate::asymmetric::{
    RSA_DECRYPT_FILES, RSA_SIGN_FILES, ecc_cases, exported, inconsistent_roundtrip, inconsistent_signatures,
    rsa_plaintext_limit, x25519_export,
};
use crate::harness::{CheckedResult, Checks, Expect};
use crate::{der, published, vectors as v};

fn outputs(
    c: &mut Checks,
    id: &str,
    a: impl FnOnce() -> Result<OutputBytes, Error>,
    b: impl FnOnce() -> Result<OutputBytes, Error>,
) {
    let left = c.call(&format!("{id}/A"), Expect::Success, a);
    let right = c.call(&format!("{id}/B"), Expect::Success, b);
    if let (Some(a), Some(b)) = (left, right) {
        c.bytes(id, &a, &b);
    }
}

fn selected<T>(
    c: &mut Checks,
    id: &str,
    inputs: &[T],
    operation: impl Fn(&T) -> Result<(OutputBytes, OutputBytes), Error>,
) {
    c.property(id, 0..inputs.len(), |index| {
        let (left, right) = operation(&inputs[index])
            .checked()
            .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{id}/index={index}: {e}")))?;
        prop_assert_eq!(left.as_ref(), right.as_ref());
        Ok(())
    });
}

pub fn differential(a: &CryptoProvider, b: &CryptoProvider) {
    let mut c = Checks::default();
    let messages = published::messages();
    for algorithm in HASHES {
        let (Ok(ae), Ok(_)) = (helpers::hash(a, algorithm), helpers::hash(b, algorithm)) else {
            continue;
        };
        for (id, data) in &messages {
            outputs(
                &mut c,
                &format!("{algorithm:?}/{id}"),
                || helpers::digest(a, algorithm, data),
                || helpers::digest(b, algorithm, data),
            );
        }
        c.property(
            &format!("{algorithm:?}/published message chunking differential"),
            (0..messages.len(), any::<usize>()),
            |(index, split)| {
                let (id, data) = &messages[index];
                let split = split % (data.len() + 1);
                let mut context = ae
                    .start()
                    .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
                context
                    .update(&data[..split])
                    .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
                context
                    .update(&data[split..])
                    .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
                let left = context
                    .finish()
                    .checked()
                    .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
                let right = helpers::digest(b, algorithm, data)
                    .checked()
                    .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
                prop_assert_eq!(left.as_ref(), right.as_ref(), "{}", id);
                Ok(())
            },
        );
    }
    for (index, algorithm) in MACS.into_iter().enumerate() {
        let (Ok(ae), Ok(be)) = (helpers::mac(a, algorithm), helpers::mac(b, algorithm)) else {
            continue;
        };
        let ap = c.protections(&format!("{algorithm:?}/A supports"), |p| ae.supports(p));
        let bp = c.protections(&format!("{algorithm:?}/B supports"), |p| be.supports(p));
        let inputs = published::mac(index);
        let mut pairs = inputs
            .iter()
            .map(|(id, key, data, _)| (id.clone(), key.clone(), data.clone()))
            .collect::<Vec<_>>();
        pairs.push(published::empty_mac(index));
        for (id, key, data) in &pairs {
            if ap[0] && bp[0] {
                let left = c.call(id, Expect::Success, || helpers::compute_mac(a, algorithm, key, data));
                let right = c.call(id, Expect::Success, || helpers::compute_mac(b, algorithm, key, data));
                if let (Some(left), Some(right)) = (left, right) {
                    c.check(
                        id,
                        left.into_inner().as_slice() == right.into_inner().as_slice(),
                        "MAC differential",
                    );
                }
            }
            for (source, dest, sp, dp) in [(a, b, ap, bp), (b, a, bp, ap)] {
                if !(sp[0] && dp[1]) {
                    continue;
                }
                if let Some(tag) = c.call(id, Expect::Success, || {
                    helpers::compute_mac(source, algorithm, key, data)
                }) {
                    let tag = tag.into_inner();
                    if let Some(verified) = c.call(id, Expect::Success, || {
                        helpers::verify_mac(dest, algorithm, key, data, &tag, tag.len())
                    }) {
                        c.check(id, verified, "cross MAC verification");
                    }
                }
            }
        }
        if ap[0] && bp[0] {
            selected(
                &mut c,
                &format!("{algorithm:?}/published MAC differential"),
                &pairs,
                |(_, key, data)| {
                    Ok((
                        OutputBytes::new(helpers::compute_mac(a, algorithm, key, data).checked()?.into_inner()),
                        OutputBytes::new(helpers::compute_mac(b, algorithm, key, data).checked()?.into_inner()),
                    ))
                },
            );
        }
    }
    for (index, algorithm) in PASSWORD_KDFS.into_iter().enumerate() {
        let (Ok(ae), Ok(be)) = (helpers::password_kdf(a, algorithm), helpers::password_kdf(b, algorithm)) else {
            continue;
        };
        let file = format!("pbkdf2_hmac{}_test.json", SHAS[index]);
        for group in v::wycheproof(&file).test_groups {
            for t in v::tests(&group) {
                let key = v::field(t, "password");
                let salt = v::field(t, "salt");
                let iterations = v::number(t, "iterationCount") as u32;
                let len = v::number(t, "dkLen");
                if iterations > 10_000_000 || len > 1024 {
                    continue;
                }
                outputs(
                    &mut c,
                    &v::id(algorithm, &file, t),
                    || ae.derive(&key, &salt, iterations, len),
                    || be.derive(&key, &salt, iterations, len),
                );
            }
        }
        let inputs = published::password(index);
        c.property(
            &format!("{algorithm:?}/published PBKDF2 differential"),
            (0..inputs.len(), 1usize..65),
            |(index, len)| {
                let (id, key, salt, iterations) = &inputs[index];
                let left = ae
                    .derive(key, salt, *iterations, len)
                    .checked()
                    .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
                let right = be
                    .derive(key, salt, *iterations, len)
                    .checked()
                    .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
                prop_assert_eq!(left.as_ref(), right.as_ref(), "{}", id);
                Ok(())
            },
        );
    }
    for (index, algorithm) in KDFS.into_iter().enumerate() {
        let (Ok(ae), Ok(be)) = (helpers::kdf(a, algorithm), helpers::kdf(b, algorithm)) else {
            continue;
        };
        let inputs = published::kdf(index);
        for (id, key, info) in &inputs {
            outputs(
                &mut c,
                &format!("{algorithm:?}/{id}"),
                || ae.derive(key, info, 64),
                || be.derive(key, info, 64),
            );
        }
        c.property(
            &format!("{algorithm:?}/published KDF differential"),
            (0..inputs.len(), 1usize..65),
            |(index, len)| {
                let (id, key, info) = &inputs[index];
                let left = ae
                    .derive(key, info, len)
                    .checked()
                    .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
                let right = be
                    .derive(key, info, len)
                    .checked()
                    .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
                prop_assert_eq!(left.as_ref(), right.as_ref(), "{}", id);
                Ok(())
            },
        );
    }
    for algorithm in CIPHERS {
        let (Ok(ae), Ok(be)) = (helpers::cipher(a, algorithm), helpers::cipher(b, algorithm)) else {
            continue;
        };
        let ap = c.protections(&format!("{algorithm:?}/A supports"), |p| ae.supports(p));
        let bp = c.protections(&format!("{algorithm:?}/B supports"), |p| be.supports(p));
        let inputs = crate::symmetric::cipher_records(algorithm)
            .into_iter()
            .filter(|r| !r.5)
            .collect::<Vec<_>>();
        for (id, key, iv, plain, encrypted, _) in &inputs {
            for (encryptor, decryptor, sp, dp) in [(ae, be, ap, bp), (be, ae, bp, ap)] {
                if !(sp[0] && dp[1]) {
                    continue;
                }
                if let Some(ciphertext) = c.call(id, Expect::Success, || encryptor.encrypt(key, iv, plain)) {
                    if let Some(restored) = c.call(id, Expect::Success, || decryptor.decrypt(key, iv, &ciphertext)) {
                        c.bytes(id, &restored, plain);
                    }
                }
            }
            for protection in [Protection::Apply, Protection::Process] {
                let index = usize::from(protection == Protection::Process);
                if !(ap[index] && bp[index]) {
                    continue;
                }
                outputs(
                    &mut c,
                    &format!("{algorithm:?}/{id}/{protection:?}"),
                    || {
                        if index == 0 {
                            ae.encrypt(key, iv, plain)
                        } else {
                            ae.decrypt(key, iv, encrypted)
                        }
                    },
                    || {
                        if index == 0 {
                            be.encrypt(key, iv, plain)
                        } else {
                            be.decrypt(key, iv, encrypted)
                        }
                    },
                );
            }
        }
        for (index, protection) in [Protection::Apply, Protection::Process].into_iter().enumerate() {
            if !(ap[index] && bp[index]) {
                continue;
            }
            selected(
                &mut c,
                &format!("{algorithm:?}/{protection:?}/published CBC differential"),
                &inputs,
                |(_, key, iv, plain, encrypted, _)| {
                    Ok(if index == 0 {
                        (ae.encrypt(key, iv, plain)?, be.encrypt(key, iv, plain)?)
                    } else {
                        (ae.decrypt(key, iv, encrypted)?, be.decrypt(key, iv, encrypted)?)
                    })
                },
            );
        }
    }
    if let (Ok(ae), Ok(be)) = (
        helpers::stream_cipher(a, StreamCipherAlgorithm::Rc4),
        helpers::stream_cipher(b, StreamCipherAlgorithm::Rc4),
    ) {
        let inputs = published::rc4();
        for (id, key, data) in &inputs {
            outputs(&mut c, id, || ae.start(key)?.apply(data), || be.start(key)?.apply(data));
        }
        selected(
            &mut c,
            "RC4/published inputs differential",
            &inputs,
            |(_, key, data)| Ok((ae.start(key)?.apply(data)?, be.start(key)?.apply(data)?)),
        );
    }
    for (source, dest) in [(a, b), (b, a)] {
        for (index, algorithm) in AEADS.into_iter().enumerate() {
            let (Ok(sealer), Ok(opener)) = (helpers::aead(source, algorithm), helpers::aead(dest, algorithm)) else {
                continue;
            };
            let sp = c.protections(&format!("{algorithm:?}/seal supports"), |p| sealer.supports(p));
            let dp = c.protections(&format!("{algorithm:?}/open supports"), |p| opener.supports(p));
            if !(sp[0] && dp[1]) {
                continue;
            }
            let inputs = published::aead(index);
            for (id, key, aad, data) in &inputs {
                if let Some(sealed) = c.call(id, Expect::Success, || sealer.seal(key, aad, data)) {
                    c.check(id, sealed.nonce.len() == 12, "cross seal nonce length");
                    if let Some(plain) = c.call(id, Expect::Success, || {
                        opener.open(key, &sealed.nonce, aad, &sealed.ciphertext_and_tag)
                    }) {
                        c.bytes(id, &plain, data);
                    }
                }
            }
            selected(
                &mut c,
                &format!("{algorithm:?}/published cross open"),
                &inputs,
                |(_, key, aad, data)| {
                    let sealed = sealer.seal(key, aad, data).checked()?;
                    if sealed.nonce.len() != 12 {
                        return Err(Error::InvalidInput);
                    }
                    Ok((
                        opener
                            .open(key, &sealed.nonce, aad, &sealed.ciphertext_and_tag)
                            .checked()?,
                        OutputBytes::new(Zeroizing::new(data.clone())),
                    ))
                },
            );
        }
        for (index, algorithm) in WRAPS.into_iter().enumerate() {
            let (Ok(wrapper), Ok(unwrapper)) =
                (helpers::key_wrap(source, algorithm), helpers::key_wrap(dest, algorithm))
            else {
                continue;
            };
            let sp = c.protections(&format!("{algorithm:?}/wrap supports"), |p| wrapper.supports(p));
            let dp = c.protections(&format!("{algorithm:?}/unwrap supports"), |p| unwrapper.supports(p));
            if !(sp[0] && dp[1]) {
                continue;
            }
            let inputs = published::wrap(index);
            for (id, key, data) in &inputs {
                if let Some(wrapped) = c.call(id, Expect::Success, || wrapper.wrap(key, data)) {
                    if dp[0] {
                        if let Some(other) = c.call(id, Expect::Success, || unwrapper.wrap(key, data)) {
                            c.bytes(id, &wrapped, &other);
                        }
                    }
                    if let Some(plain) = c.call(id, Expect::Success, || unwrapper.unwrap(key, &wrapped)) {
                        c.bytes(id, &plain, data);
                    }
                }
            }
            selected(
                &mut c,
                &format!("{algorithm:?}/published cross unwrap"),
                &inputs,
                |(_, key, data)| {
                    Ok((
                        unwrapper.unwrap(key, &wrapper.wrap(key, data).checked()?).checked()?,
                        OutputBytes::new(Zeroizing::new(data.clone())),
                    ))
                },
            );
        }
        for algorithm in AGREEMENTS.into_iter().filter(|a| *a != KeyAgreementAlgorithm::Ffdh) {
            let (Ok(ae), Ok(be)) = (
                helpers::key_agreement(source, algorithm),
                helpers::key_agreement(dest, algorithm),
            ) else {
                continue;
            };
            c.call(&format!("{algorithm:?}/cross ephemeral"), Expect::Success, || {
                let a = ae.generate_ephemeral()?;
                let b = be.generate_ephemeral()?;
                let ap = a.public_key().checked()?;
                let bp = b.public_key().checked()?;
                let sa = a.agree(&bp).checked()?;
                let sb = b.agree(&ap).checked()?;
                if sa.as_ref() != sb.as_ref() {
                    return Err(Error::InvalidInput);
                }
                Ok(())
            });
        }
        cross_keys(&mut c, source, dest);
        cross_encryption(&mut c, source, dest);
        cross_inconsistent(&mut c, source, dest);
    }
    if let (Ok(ae), Ok(be)) = (helpers::ffdh_key_agreement(a), helpers::ffdh_key_agreement(b)) {
        for group in v::dh_groups() {
            c.call(&format!("{}/cross FFDH ephemeral", group.id), Expect::Success, || {
                let a = ae.generate_ephemeral(group.parameters())?;
                let b = be.generate_ephemeral(group.parameters())?;
                let ap = a.public_key().checked()?;
                let bp = b.public_key().checked()?;
                let sa = a.agree(&bp).checked()?;
                let sb = b.agree(&ap).checked()?;
                if sa.as_ref() != sb.as_ref() {
                    return Err(Error::InvalidInput);
                }
                Ok(())
            });
        }
    }
    if let (Ok(al), Ok(bl)) = (
        helpers::private_key_loader(a, KeyType::X25519),
        helpers::private_key_loader(b, KeyType::X25519),
    ) {
        for g in v::wycheproof("x25519_test.json").test_groups {
            for t in v::tests(&g) {
                if v::field(t, "shared").iter().all(|b| *b == 0) {
                    continue;
                }
                let scalar: [u8; 32] = v::field(t, "private").try_into().unwrap();
                let id = v::id(KeyAgreementAlgorithm::X25519, "x25519_test.json", t);
                let left = c.call(&id, Expect::Success, || al.load(PrivateKeyMaterial::X25519(&scalar)));
                let right = c.call(&id, Expect::Success, || bl.load(PrivateKeyMaterial::X25519(&scalar)));
                if let (Some(left), Some(right)) = (left, right) {
                    x25519_export(&mut c, &id, &*left);
                    x25519_export(&mut c, &id, &*right);
                    let ls = c.key_supports(&id, &*left, KeyOperation::Agree(KeyAgreementAlgorithm::X25519));
                    let rs = c.key_supports(&id, &*right, KeyOperation::Agree(KeyAgreementAlgorithm::X25519));
                    if ls && rs {
                        outputs(
                            &mut c,
                            &id,
                            || left.agree(KeyAgreementAlgorithm::X25519, &v::field(t, "public")),
                            || right.agree(KeyAgreementAlgorithm::X25519, &v::field(t, "public")),
                        );
                    }
                }
            }
        }
    }
    if let (Ok(al), Ok(bl)) = (
        helpers::private_key_loader(a, KeyType::Ffdh),
        helpers::private_key_loader(b, KeyType::Ffdh),
    ) {
        for (i, group) in v::dh_groups().into_iter().take(3).enumerate() {
            let fields = v::rfc5114(i + 1);
            let id = format!("{}/A.{}/cross static FFDH", group.id, i + 1);
            let material = PrivateKeyMaterial::Ffdh {
                parameters: group.parameters(),
                private_value: &fields["xA"],
            };
            let left = c.call(&id, Expect::Success, || al.load(material));
            let right = c.call(&id, Expect::Success, || bl.load(material));
            if let (Some(left), Some(right)) = (left, right) {
                exported(&mut c, &id, &*left, &[]);
                exported(&mut c, &id, &*right, &[]);
                let ls = c.key_supports(&id, &*left, KeyOperation::Agree(KeyAgreementAlgorithm::Ffdh));
                let rs = c.key_supports(&id, &*right, KeyOperation::Agree(KeyAgreementAlgorithm::Ffdh));
                if ls && rs {
                    outputs(
                        &mut c,
                        &id,
                        || left.agree(KeyAgreementAlgorithm::Ffdh, &fields["yB"]),
                        || right.agree(KeyAgreementAlgorithm::Ffdh, &fields["yB"]),
                    );
                }
            }
        }
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
            exported(c, &key_id, &*sk, &public);
            if let Some(key) = &dk {
                exported(c, &key_id, &**key, &public);
            }
            let k = der::bit_length(der::children(&public)[0].value).div_ceil(8);
            if rsa_keys.insert(encoded.clone()) {
                let t = v::tests(&g)
                    .iter()
                    .find(|t| !v::field(t, "msg").is_empty())
                    .unwrap_or(&v::tests(&g)[0]);
                let data = v::field(t, "msg");
                for algorithm in SIGNATURES[..8].iter().copied() {
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
            let sign = rsa_signature(v::string(&g, "sha"));
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
        exported(c, &id, &*sk, &t.public);
        if let Some(key) = &dk {
            exported(c, &id, &**key, &t.public);
        }
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
        let id = r.id(crate::asymmetric::ECC_FILE);
        let Some(sk) = c.call(&id, Expect::Success, || sl.load(PrivateKeyMaterial::Pkcs8(&encoded))) else {
            continue;
        };
        let dk = dl.and_then(|dl| c.call(&id, Expect::Success, || dl.load(PrivateKeyMaterial::Pkcs8(&encoded))));
        exported(c, &id, &*sk, &own);
        if let Some(key) = &dk {
            exported(c, &id, &**key, &own);
        }
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

fn cross_encryption(c: &mut Checks, source: &CryptoProvider, dest: &CryptoProvider) {
    let Ok(loader) = helpers::private_key_loader(dest, KeyType::Rsa) else {
        return;
    };
    let vectors = v::wycheproof(RSA_SIGN_FILES[0]);
    let g = vectors
        .test_groups
        .iter()
        .find(|g| der::rsa_must(&v::field(g, "privateKeyPkcs8")))
        .unwrap();
    let encoded = v::field(g, "privateKeyPkcs8");
    let id = format!("{}/published cross encryption", RSA_SIGN_FILES[0]);
    let Some(key) = c.call(&id, Expect::Success, || {
        loader.load(PrivateKeyMaterial::Pkcs8(&encoded))
    }) else {
        return;
    };
    let public = der::rsa_public(&encoded);
    exported(c, &id, &*key, &public);
    let k = der::bit_length(der::children(&public)[0].value).div_ceil(8);
    for a in ENCRYPTIONS {
        let Ok(encryptor) = helpers::asymmetric_encryptor(source, a) else {
            continue;
        };
        if !c.key_supports(&id, &*key, KeyOperation::Decrypt(a)) {
            continue;
        }
        let messages = published::messages()
            .into_iter()
            .filter(|(_, msg)| msg.len() <= rsa_plaintext_limit(a, k))
            .collect::<Vec<_>>();
        selected(c, &format!("{a:?}/{id}"), &messages, |(_, data)| {
            let encrypted = encryptor.encrypt(PublicKey(&public), data).checked()?;
            Ok((
                key.decrypt(a, &encrypted).checked()?,
                OutputBytes::new(Zeroizing::new(data.clone())),
            ))
        });
    }
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
            let t = &v::tests(g)[0];
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct SigningLoader {
        signature: Vec<u8>,
    }
    struct SigningKey {
        signature: Vec<u8>,
    }
    struct Verifier {
        algorithm: SignatureAlgorithm,
        signature: Vec<u8>,
        calls: Arc<Mutex<Vec<SignatureAlgorithm>>>,
    }
    impl PrivateKeyLoader for SigningLoader {
        fn key_type(&self) -> KeyType {
            KeyType::Rsa
        }
        fn fips(&self) -> bool {
            false
        }
        fn load(&self, _: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error> {
            Ok(Box::new(SigningKey {
                signature: self.signature.clone(),
            }))
        }
    }
    impl PrivateKey for SigningKey {
        fn key_type(&self) -> KeyType {
            KeyType::Rsa
        }
        fn key_size_bits(&self) -> usize {
            2048
        }
        fn fips(&self) -> bool {
            false
        }
        fn supports(&self, operation: KeyOperation) -> bool {
            matches!(
                operation,
                KeyOperation::Sign(
                    SignatureAlgorithm::RsaPkcs1v15Md5
                        | SignatureAlgorithm::RsaPkcs1v15Sha3_384
                        | SignatureAlgorithm::RsaPkcs1v15Sha3_512
                )
            )
        }
        fn sign(&self, algorithm: SignatureAlgorithm, _: &[u8]) -> Result<OutputBytes, Error> {
            if !self.supports(KeyOperation::Sign(algorithm)) {
                return Err(Error::Unsupported(Algorithm::Signature(algorithm)));
            }
            Ok(OutputBytes::new(Zeroizing::new(self.signature.clone())))
        }
    }
    impl SignatureVerifier for Verifier {
        fn algorithm(&self) -> SignatureAlgorithm {
            self.algorithm
        }
        fn fips(&self) -> bool {
            false
        }
        fn verify(&self, _: PublicKey<'_>, _: &[u8], signature: &[u8]) -> Result<(), Error> {
            self.calls.lock().unwrap().push(self.algorithm);
            if signature == self.signature {
                Ok(())
            } else {
                Err(Error::VerificationFailed)
            }
        }
    }
    fn mock(signature: &[u8], calls: Arc<Mutex<Vec<SignatureAlgorithm>>>) -> CryptoProvider {
        let mut builder = CryptoProvider::builder().with(Entry::PrivateKeyLoader(Arc::new(SigningLoader {
            signature: signature.to_vec(),
        })));
        for algorithm in [
            SignatureAlgorithm::RsaPkcs1v15Md5,
            SignatureAlgorithm::RsaPkcs1v15Sha3_384,
            SignatureAlgorithm::RsaPkcs1v15Sha3_512,
        ] {
            builder = builder.with(Entry::SignatureVerifier(Arc::new(Verifier {
                algorithm,
                signature: signature.to_vec(),
                calls: Arc::clone(&calls),
            })));
        }
        builder.build().unwrap()
    }

    #[test]
    fn rsa_cross_signing_includes_algorithms_without_generation_vectors() {
        let source = v::wycheproof(RSA_SIGN_FILES[0]);
        let signature = v::field(&v::tests(&source.test_groups[0])[0], "sig");
        let a_calls = Arc::new(Mutex::new(Vec::new()));
        let b_calls = Arc::new(Mutex::new(Vec::new()));
        let a = mock(&signature, Arc::clone(&a_calls));
        let b = mock(&signature, Arc::clone(&b_calls));
        let mut c = Checks::default();
        cross_keys(&mut c, &a, &b);
        cross_keys(&mut c, &b, &a);
        c.finish();
        for calls in [a_calls, b_calls] {
            let calls = calls.lock().unwrap();
            for algorithm in [
                SignatureAlgorithm::RsaPkcs1v15Md5,
                SignatureAlgorithm::RsaPkcs1v15Sha3_384,
                SignatureAlgorithm::RsaPkcs1v15Sha3_512,
            ] {
                assert!(calls.contains(&algorithm));
            }
        }
    }

    #[test]
    fn inconsistent_signatures_cover_partial_keys_and_fallback_verification() {
        let source = v::wycheproof(RSA_SIGN_FILES[0]);
        let group = &source.test_groups[0];
        let signature = v::field(&v::tests(group)[0], "sig");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let other_calls = Arc::new(Mutex::new(Vec::new()));
        let verifier = mock(&signature, Arc::clone(&calls));
        let other = mock(&signature, Arc::clone(&other_calls));
        let empty = CryptoProvider::builder().build().unwrap();
        let base = SigningKey {
            signature: signature.clone(),
        };
        let derived = SigningKey { signature };
        for local in [&verifier, &empty] {
            calls.lock().unwrap().clear();
            other_calls.lock().unwrap().clear();
            let mut c = Checks::default();
            inconsistent_signatures(
                &mut c,
                local,
                Some(&other),
                &base,
                &derived,
                "inconsistent RSA routing",
                (RSA_SIGN_FILES[0], group),
            );
            c.finish();
            let calls = calls.lock().unwrap();
            let other_calls = other_calls.lock().unwrap();
            for algorithm in [
                SignatureAlgorithm::RsaPkcs1v15Md5,
                SignatureAlgorithm::RsaPkcs1v15Sha3_384,
                SignatureAlgorithm::RsaPkcs1v15Sha3_512,
            ] {
                assert_eq!(
                    calls.iter().filter(|&&actual| actual == algorithm).count(),
                    if local.entries().next().is_some() { 2 } else { 0 }
                );
                assert_eq!(other_calls.iter().filter(|&&actual| actual == algorithm).count(), 2);
            }
        }
    }
}
