//! Property tests over published inputs: chunking, prefixes and round trips.

use picky_crypto::*;
use proptest::prelude::*;

use crate::algorithms::*;
use crate::areas::cipher::cipher_records;
use crate::harness::{CheckedResult, Checks, Expect, Options};
use crate::keys::{ECC_FILE, RSA_SIGN_FILES, exported, rsa_plaintext_limit};
use crate::{der, published, select, vectors as v};

fn error(e: Error) -> TestCaseError {
    TestCaseError::fail(format!("unexpected provider error: {e:?}"))
}

pub fn run(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    let messages = published::messages();
    for a in HASHES {
        let Ok(entry) = helpers::hash(p, a) else {
            continue;
        };
        c.property(
            &format!("{a:?}/published message chunking"),
            (0..messages.len(), any::<usize>()),
            |(index, split)| {
                let (id, data) = &messages[index];
                let split = split % (data.len() + 1);
                let one = helpers::digest(p, a, data).checked().map_err(error)?;
                let mut context = entry.start().map_err(error)?;
                context.update(&data[..split]).map_err(error)?;
                context.update(&[]).map_err(error)?;
                context.update(&data[split..]).map_err(error)?;
                let chunked = context.finish().checked().map_err(error)?;
                prop_assert_eq!(one.as_ref(), chunked.as_ref(), "{}", id);
                Ok(())
            },
        );
    }
    for (index, a) in MACS.into_iter().enumerate() {
        let Ok(e) = helpers::mac(p, a) else {
            continue;
        };
        let protections = c.protections(&format!("{a:?}/supports"), |p| e.supports(p));
        let inputs = published::mac(index);
        c.property(
            &format!("{a:?}/published MAC chunking"),
            (0..inputs.len(), any::<usize>()),
            |(index, split)| {
                let (id, key, data, tag) = &inputs[index];
                let split = split % (data.len() + 1);
                let generated = if protections[0] {
                    let one = helpers::compute_mac(p, a, key, data)
                        .checked()
                        .map_err(error)?
                        .into_inner();
                    let mut context = MacGeneration::start(e, key).map_err(error)?;
                    context.update(&data[..split]).map_err(error)?;
                    context.update(&[]).map_err(error)?;
                    context.update(&data[split..]).map_err(error)?;
                    let chunked = context.finish().checked().map_err(error)?.into_inner();
                    prop_assert_eq!(one.as_slice(), chunked.as_slice(), "{}", id);
                    Some(one)
                } else {
                    None
                };
                if protections[1] {
                    let mut context = MacVerification::start(e, key).map_err(error)?;
                    context.update(&data[..split]).map_err(error)?;
                    context.update(&[]).map_err(error)?;
                    context.update(&data[split..]).map_err(error)?;
                    let verifier = context.finish().checked().map_err(error)?;
                    prop_assert!(verifier.verify(tag, tag.len()), "{id}");
                    prop_assert!(
                        helpers::verify_mac(p, a, key, data, tag, tag.len()).map_err(error)?,
                        "{id}"
                    );
                    if let Some(tag) = generated {
                        prop_assert!(verifier.verify(&tag, tag.len()), "{id}");
                    }
                }
                Ok(())
            },
        );
        let (id, key, data) = published::empty_mac(index);
        if protections[1] && !protections[0] {
            let probe = &select::mac_probe(index, &inputs).3;
            c.property(&format!("{id}/verification chunking"), any::<usize>(), |split| {
                let split = split % (data.len() + 1);
                let mut whole = MacVerification::start(e, &key).map_err(error)?;
                whole.update(&data).map_err(error)?;
                let whole = whole.finish().checked().map_err(error)?;
                let mut chunks = MacVerification::start(e, &key).map_err(error)?;
                chunks.update(&data[..split]).map_err(error)?;
                chunks.update(&data[split..]).map_err(error)?;
                let chunks = chunks.finish().checked().map_err(error)?;
                for len in [probe.len(), 8, 12] {
                    if let Some(prefix) = probe.get(..len) {
                        prop_assert_eq!(whole.verify(prefix, len), chunks.verify(prefix, len), "{}", id);
                    }
                }
                Ok(())
            });
        }
        if protections[0] {
            if let Some(tag) = c.call(&id, Expect::Success, || helpers::compute_mac(p, a, &key, &data)) {
                let tag = tag.into_inner();
                c.check(
                    &id,
                    tag.len() == HASHES[index + 2].output_len(),
                    "empty-key MAC must return a full tag",
                );
                if protections[1] {
                    if let Some(verified) = c.call(&id, Expect::Success, || {
                        helpers::verify_mac(p, a, &key, &data, &tag, tag.len())
                    }) {
                        c.check(&id, verified, "empty-key generated tag did not verify");
                    }
                }
                c.property(&format!("{id}/chunking"), any::<usize>(), |split| {
                    let split = split % (data.len() + 1);
                    let mut context = MacGeneration::start(e, &key).map_err(error)?;
                    context.update(&data[..split]).map_err(error)?;
                    context.update(&data[split..]).map_err(error)?;
                    let chunked = context.finish().checked().map_err(error)?.into_inner();
                    prop_assert_eq!(chunked.as_slice(), tag.as_slice(), "{}", id);
                    if protections[1] {
                        let mut verifier = MacVerification::start(e, &key).map_err(error)?;
                        verifier.update(&data[..split]).map_err(error)?;
                        verifier.update(&data[split..]).map_err(error)?;
                        prop_assert!(
                            verifier.finish().checked().map_err(error)?.verify(&tag, tag.len()),
                            "{}",
                            id
                        );
                    }
                    Ok(())
                });
            }
        }
    }
    if let Ok(e) = helpers::stream_cipher(p, StreamCipherAlgorithm::Rc4) {
        let inputs = published::rc4();
        c.property(
            "RC4/published key and message chunking",
            (0..inputs.len(), any::<usize>()),
            |(index, split)| {
                let (id, key, data) = &inputs[index];
                let split = split % (data.len() + 1);
                let one = e.start(key).map_err(error)?.apply(data).checked().map_err(error)?;
                let mut context = e.start(key).map_err(error)?;
                let first = context.apply(&data[..split]).checked().map_err(error)?;
                context.apply(&[]).checked().map_err(error)?;
                let second = context.apply(&data[split..]).checked().map_err(error)?;
                prop_assert_eq!(one.as_ref(), [first.as_ref(), second.as_ref()].concat(), "{}", id);
                Ok(())
            },
        );
    }
    for a in CIPHERS {
        let Ok(e) = helpers::cipher(p, a) else {
            continue;
        };
        let protections = c.protections(&format!("{a:?}/supports"), |p| e.supports(p));
        if !(protections[0] && protections[1]) {
            continue;
        }
        let inputs = cipher_records(a).into_iter().filter(|r| !r.5).collect::<Vec<_>>();
        c.property(&format!("{a:?}/published CBC round trip"), 0..inputs.len(), |index| {
            let (id, key, iv, data, _, _) = &inputs[index];
            let encrypted = e.encrypt(key, iv, data).checked().map_err(error)?;
            let plaintext = e.decrypt(key, iv, &encrypted).checked().map_err(error)?;
            prop_assert_eq!(plaintext.as_ref(), data.as_slice(), "{}", id);
            Ok(())
        });
        let (_, key, iv, _, _, _) = select::cbc_control(a, &inputs);
        c.property(
            &format!("{a:?}/out-of-domain"),
            (0..iv.len(), 0..iv.len()),
            |(ivlen, len)| {
                prop_assert_eq!(
                    e.encrypt(key, &vec![0; ivlen], &vec![0; len]).checked().err(),
                    Some(Error::InvalidInput)
                );
                Ok(())
            },
        );
    }
    for (index, a) in AEADS.into_iter().enumerate() {
        let Ok(e) = helpers::aead(p, a) else {
            continue;
        };
        let protections = c.protections(&format!("{a:?}/supports"), |p| e.supports(p));
        if !(protections[0] && protections[1]) {
            continue;
        }
        let inputs = published::aead(index);
        c.property(&format!("{a:?}/published AEAD round trip"), 0..inputs.len(), |index| {
            let (id, key, aad, data) = &inputs[index];
            let sealed = e.seal(key, aad, data).checked().map_err(error)?;
            prop_assert_eq!(sealed.nonce.len(), 12, "{}", id);
            let plaintext = e
                .open(key, &sealed.nonce, aad, &sealed.ciphertext_and_tag)
                .checked()
                .map_err(error)?;
            prop_assert_eq!(plaintext.as_ref(), data.as_slice(), "{}", id);
            Ok(())
        });
    }
    for (index, a) in WRAPS.into_iter().enumerate() {
        let Ok(e) = helpers::key_wrap(p, a) else {
            continue;
        };
        let protections = c.protections(&format!("{a:?}/supports"), |p| e.supports(p));
        if !(protections[0] && protections[1]) {
            continue;
        }
        let inputs = published::wrap(index);
        c.property(&format!("{a:?}/published wrap round trip"), 0..inputs.len(), |index| {
            let (id, key, data) = &inputs[index];
            let wrapped = e.wrap(key, data).checked().map_err(error)?;
            prop_assert_eq!(wrapped.len(), data.len() + 8, "{}", id);
            let plaintext = e.unwrap(key, &wrapped).checked().map_err(error)?;
            prop_assert_eq!(plaintext.as_ref(), data.as_slice(), "{}", id);
            Ok(())
        });
    }
    for (index, a) in KDFS.into_iter().enumerate() {
        let Ok(e) = helpers::kdf(p, a) else {
            continue;
        };
        let inputs = published::kdf(index);
        c.property(
            &format!("{a:?}/published KDF prefix"),
            (0..inputs.len(), 1usize..64),
            |(index, len)| {
                let (id, secret, info) = &inputs[index];
                let short = e.derive(secret, info, len).checked().map_err(error)?;
                let long = e.derive(secret, info, 64).checked().map_err(error)?;
                prop_assert_eq!(short.len(), len, "{}", id);
                prop_assert_eq!(long.len(), 64, "{}", id);
                prop_assert_eq!(short.as_ref(), &long[..len], "{}", id);
                Ok(())
            },
        );
    }
    for (index, a) in PASSWORD_KDFS.into_iter().enumerate() {
        let Ok(e) = helpers::password_kdf(p, a) else {
            continue;
        };
        let inputs = published::password(index);
        c.property(
            &format!("{a:?}/published PBKDF2 prefix"),
            (0..inputs.len(), 1usize..64),
            |(index, len)| {
                let (id, password, salt, iterations) = &inputs[index];
                let short = e.derive(password, salt, *iterations, len).checked().map_err(error)?;
                let long = e.derive(password, salt, *iterations, 64).checked().map_err(error)?;
                prop_assert_eq!(short.len(), len, "{}", id);
                prop_assert_eq!(long.len(), 64, "{}", id);
                prop_assert_eq!(short.as_ref(), &long[..len], "{}", id);
                Ok(())
            },
        );
    }
    for a in AGREEMENTS.into_iter().filter(|a| *a != KeyAgreementAlgorithm::Ffdh) {
        let Ok(e) = helpers::key_agreement(p, a) else {
            continue;
        };
        c.property(&format!("{a:?}/ephemeral round trip"), Just(()), |_| {
            let a = e.generate_ephemeral().map_err(error)?;
            let b = e.generate_ephemeral().map_err(error)?;
            let ap = a.public_key().checked().map_err(error)?;
            let bp = b.public_key().checked().map_err(error)?;
            let sa = a.agree(&bp).checked().map_err(error)?;
            let sb = b.agree(&ap).checked().map_err(error)?;
            prop_assert_eq!(sa.as_ref(), sb.as_ref());
            Ok(())
        });
    }
    if let Ok(loader) = helpers::private_key_loader(p, KeyType::Rsa) {
        let vectors = v::wycheproof(RSA_SIGN_FILES[0]);
        let g = select::rsa_private_group(RSA_SIGN_FILES[0], &vectors);
        let encoded = v::field(g, "privateKeyPkcs8");
        let id = format!("{}/RSA property key", RSA_SIGN_FILES[0]);
        if let Some(key) = c.call(&id, Expect::Success, || {
            loader.load(PrivateKeyMaterial::Pkcs8(&encoded))
        }) {
            let public = der::rsa_public(&encoded);
            exported(&mut c, &id, &*key, &public);
            let k = der::bit_length(der::children(&public)[0].value).div_ceil(8);
            for a in ENCRYPTIONS {
                let Ok(e) = helpers::asymmetric_encryptor(p, a) else {
                    continue;
                };
                if !c.key_supports(&id, &*key, KeyOperation::Decrypt(a)) {
                    continue;
                }
                let inputs = select::rsa_messages(rsa_plaintext_limit(a, k));
                c.property(&format!("{a:?}/published RSA round trip"), 0..inputs.len(), |index| {
                    let (id, data) = &inputs[index];
                    let encrypted = e.encrypt(PublicKey(&public), data).checked().map_err(error)?;
                    let plain = key.decrypt(a, &encrypted).checked().map_err(error)?;
                    prop_assert_eq!(plain.as_ref(), data.as_slice(), "{}", id);
                    Ok(())
                });
            }
        }
    }
    if let Ok(loader) = helpers::private_key_loader(p, KeyType::Ed25519) {
        let t = select::ed25519_empty();
        let encoded = der::ed(&t.seed, Some(&t.public));
        let id = "rfc/rfc8032.txt/7.1/Ed25519 property key";
        if let Some(key) = c.call(id, Expect::Success, || loader.load(PrivateKeyMaterial::Pkcs8(&encoded))) {
            exported(&mut c, id, &*key, &t.public);
            let a = SignatureAlgorithm::Ed25519;
            if c.key_supports(id, &*key, KeyOperation::Sign(a)) {
                if let Ok(verifier) = helpers::signature_verifier(p, a) {
                    c.property("Ed25519/published message sign verify", 0..messages.len(), |index| {
                        let (id, data) = &messages[index];
                        let sig = key.sign(a, data).checked().map_err(error)?;
                        verifier
                            .verify(PublicKey(&t.public), data, &sig)
                            .map_err(error)
                            .map_err(|e| TestCaseError::fail(format!("{id}: {e}")))?;
                        Ok(())
                    });
                }
            }
        }
    }
    for (kind, _, width, r) in CURVES
        .into_iter()
        .map(|(kind, _, _, _, _)| select::ecc_private_control(kind))
    {
        let Ok(loader) = helpers::private_key_loader(p, kind) else {
            continue;
        };
        let public = der::point(&r.bytes("QeIUTx"), &r.bytes("QeIUTy"), width);
        let encoded = der::ec(kind, &r.bytes("deIUT"), Some(&public), None);
        let id = r.id(ECC_FILE);
        let Some(key) = c.call(&id, Expect::Success, || {
            loader.load(PrivateKeyMaterial::Pkcs8(&encoded))
        }) else {
            continue;
        };
        exported(&mut c, &id, &*key, &public);
        let sign = CURVES.iter().find(|(k, _, _, _, _)| *k == kind).unwrap().2;
        if c.key_supports(&id, &*key, KeyOperation::Sign(sign)) {
            if let Ok(verifier) = helpers::signature_verifier(p, sign) {
                c.property(
                    &format!("{id}/published message sign verify"),
                    0..messages.len(),
                    |index| {
                        let (id, data) = &messages[index];
                        let sig = key.sign(sign, data).checked().map_err(error)?;
                        verifier
                            .verify(PublicKey(&public), data, &sig)
                            .map_err(error)
                            .map_err(|e| TestCaseError::fail(format!("{id}: {e}")))?;
                        Ok(())
                    },
                );
            }
        }
    }
    if let Ok(e) = helpers::ffdh_key_agreement(p) {
        let groups = v::dh_groups();
        c.property("published FFDH group round trip", 0..groups.len(), |index| {
            let group = &groups[index];
            let id = &group.id;
            let a = e.generate_ephemeral(group.parameters()).map_err(error)?;
            let b = e.generate_ephemeral(group.parameters()).map_err(error)?;
            let ap = a.public_key().checked().map_err(error)?;
            let bp = b.public_key().checked().map_err(error)?;
            let sa = a.agree(&bp).checked().map_err(error)?;
            let sb = b.agree(&ap).checked().map_err(error)?;
            prop_assert_eq!(ap.len(), group.p.len(), "{}", id);
            prop_assert_eq!(bp.len(), group.p.len(), "{}", id);
            prop_assert_eq!(sa.len(), group.p.len(), "{}", id);
            prop_assert_eq!(sa.as_ref(), sb.as_ref(), "{}", id);
            Ok(())
        });
    }
    c.finish();
}
