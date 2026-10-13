//! Checks one provider alone can't make: derived lengths and empty-key HMAC tags without published answers, and AEAD sealed by one provider and opened by the other.

use picky_crypto::*;
use proptest::prelude::*;

use crate::algorithms::*;
use crate::harness::{Checks, Expect};
use crate::published;

pub fn run(a: &CryptoProvider, b: &CryptoProvider) {
    let mut c = Checks::default();
    // Published answers fix one output length per input; the providers must also agree at every other length.
    for (index, algorithm) in PASSWORD_KDFS.into_iter().enumerate() {
        let (Ok(ae), Ok(be)) = (helpers::password_kdf(a, algorithm), helpers::password_kdf(b, algorithm)) else {
            continue;
        };
        let inputs = published::password(index);
        c.property(
            &format!("{algorithm:?}/published PBKDF2 differential"),
            (0..inputs.len(), 1usize..65),
            |(index, len)| {
                let (id, key, salt, iterations) = &inputs[index];
                let left = ae.derive(key, salt, *iterations, len).map_err(fail)?;
                let right = be.derive(key, salt, *iterations, len).map_err(fail)?;
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
        c.property(
            &format!("{algorithm:?}/published KDF differential"),
            (0..inputs.len(), 1usize..65),
            |(index, len)| {
                let (id, key, info) = &inputs[index];
                let left = ae.derive(key, info, len).map_err(fail)?;
                let right = be.derive(key, info, len).map_err(fail)?;
                prop_assert_eq!(left.as_ref(), right.as_ref(), "{}", id);
                Ok(())
            },
        );
    }
    // No published HMAC vector has an empty key, so the providers must agree on its tag.
    for (index, algorithm) in MACS.into_iter().enumerate() {
        let generates = |p| helpers::mac(p, algorithm).is_ok_and(|e| e.supports(Protection::Apply));
        if !(generates(a) && generates(b)) {
            continue;
        }
        let (id, key, data) = published::empty_mac(index);
        let id = format!("{algorithm:?}/{id}/differential");
        if let Some((left, right)) = c.call(&id, Expect::Success, || {
            Ok((
                helpers::compute_mac(a, algorithm, &key, &data)?.into_inner(),
                helpers::compute_mac(b, algorithm, &key, &data)?.into_inner(),
            ))
        }) {
            c.check(&id, left == right, "the providers' empty-key tags differ");
        }
    }
    // Sealing picks a random nonce, so no published answer covers a sealed message.
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
            for (id, key, aad, data) in &published::aead(index) {
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
    }
    c.finish();
}

fn fail(e: Error) -> TestCaseError {
    TestCaseError::fail(e.to_string())
}
