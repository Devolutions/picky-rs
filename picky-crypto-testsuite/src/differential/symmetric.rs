//! Deterministic symmetric outputs compared between providers, and cross-provider AEAD and key wrap.

use picky_crypto::*;
use proptest::prelude::*;

use super::{outputs, selected};
use crate::algorithms::*;
use crate::harness::{CheckedResult, Checks, Expect};
use crate::{published, vectors as v};

pub fn run(a: &CryptoProvider, b: &CryptoProvider) {
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
        let inputs = crate::areas::cipher::cipher_records(algorithm)
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
    }
    c.finish();
}
