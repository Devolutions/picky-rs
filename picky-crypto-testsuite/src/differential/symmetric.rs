//! Deterministic symmetric outputs compared between providers, and cross-provider AEAD and key wrap.

use picky_crypto::*;
use proptest::prelude::*;

use super::outputs;
use crate::algorithms::*;
use crate::areas::cipher::{cipher_records, transform};
use crate::harness::{CheckedResult, Checks, Expect};
use crate::{published, vectors as v};

pub fn run(a: &CryptoProvider, b: &CryptoProvider) {
    let mut c = Checks::default();
    let messages = published::messages();
    for algorithm in HASHES {
        let (Ok(_), Ok(_)) = (helpers::hash(a, algorithm), helpers::hash(b, algorithm)) else {
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
            let tags = [(a, ap), (b, bp)].map(|(provider, protections)| {
                protections[0]
                    .then(|| {
                        c.call(id, Expect::Success, || {
                            helpers::compute_mac(provider, algorithm, key, data)
                        })
                    })
                    .flatten()
                    .map(MacTag::into_inner)
            });
            if let [Some(left), Some(right)] = &tags {
                c.check(id, left.as_slice() == right.as_slice(), "MAC differential");
            }
            for (tag, dest, dp) in [(&tags[0], b, bp), (&tags[1], a, ap)] {
                let Some(tag) = tag.as_ref().filter(|_| dp[1]) else {
                    continue;
                };
                if let Some(verified) = c.call(id, Expect::Success, || {
                    helpers::verify_mac(dest, algorithm, key, data, tag, tag.len())
                }) {
                    c.check(id, verified, "cross MAC verification");
                }
            }
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
                let left = ae.derive(key, salt, *iterations, len).checked().map_err(fail)?;
                let right = be.derive(key, salt, *iterations, len).checked().map_err(fail)?;
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
                let left = ae.derive(key, info, len).checked().map_err(fail)?;
                let right = be.derive(key, info, len).checked().map_err(fail)?;
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
        let inputs = cipher_records(algorithm)
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
            for (protection, input) in [(Protection::Apply, plain), (Protection::Process, encrypted)] {
                let index = usize::from(protection == Protection::Process);
                if !(ap[index] && bp[index]) {
                    continue;
                }
                outputs(
                    &mut c,
                    &format!("{algorithm:?}/{id}/{protection:?}"),
                    || transform(ae, protection, key, iv, input),
                    || transform(be, protection, key, iv, input),
                );
            }
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
        }
    }
    c.finish();
}

fn fail(e: Error) -> TestCaseError {
    TestCaseError::fail(e.to_string())
}
