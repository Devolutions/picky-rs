//! Checks one provider alone can't make: derived lengths, empty-key HMAC tags and boundary controls without published
//! answers, and AEAD sealed by one provider and opened by the other.

use picky_crypto::*;
use proptest::prelude::*;

use crate::algorithms::*;
use crate::areas::cipher::{cipher_records, transform};
use crate::areas::password_kdf::MUST_SUPPORT_OUTPUT_LEN;
use crate::harness::{Checks, Expect};
use crate::{published, select, vectors as v};

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
    boundary_controls(&mut c, a, b);
    c.finish();
}

/// Compares the outputs of boundary controls that have no published answer, whenever both providers produce one.
fn boundary_controls(c: &mut Checks, a: &CryptoProvider, b: &CryptoProvider) {
    fn compare(c: &mut Checks, id: &str, left: Result<OutputBytes, Error>, right: Result<OutputBytes, Error>) {
        if let (Ok(left), Ok(right)) = (left, right) {
            c.check(id, left.as_ref() == right.as_ref(), "the providers' outputs differ");
        }
    }
    let algorithm = CipherAlgorithm::Rc2Cbc;
    if let (Ok(ae), Ok(be)) = (helpers::cipher(a, algorithm), helpers::cipher(b, algorithm)) {
        let records = cipher_records(algorithm);
        let (_, _, iv, data, _, _) = select::cbc_control(algorithm, &records);
        for length in [1, 128] {
            let (source, key) = select::message_of_length(length);
            for protection in [Protection::Apply, Protection::Process] {
                if !(ae.supports(protection) && be.supports(protection)) {
                    continue;
                }
                let id = format!("{algorithm:?}/{protection:?}/key length={length}/{source}/differential");
                compare(
                    c,
                    &id,
                    transform(ae, protection, &key, iv, data),
                    transform(be, protection, &key, iv, data),
                );
            }
        }
    }
    let algorithm = StreamCipherAlgorithm::Rc4;
    if let (Ok(ae), Ok(be)) = (
        helpers::stream_cipher(a, algorithm),
        helpers::stream_cipher(b, algorithm),
    ) {
        let apply = |e: &dyn StreamCipher, key: &[u8]| e.start(key)?.apply(key);
        for (source, key) in [select::message_of_length(1), select::rc4_longest_key()] {
            let id = format!("{algorithm:?}/key length={}/{source}/differential", key.len());
            compare(c, &id, apply(ae, &key), apply(be, &key));
        }
    }
    for (algorithm, sha) in PASSWORD_KDFS.into_iter().zip(SHAS) {
        let (Ok(ae), Ok(be)) = (helpers::password_kdf(a, algorithm), helpers::password_kdf(b, algorithm)) else {
            continue;
        };
        let file = format!("pbkdf2_hmac{sha}_test.json");
        let (source, password, salt) = select::pbkdf2_password_salt(&file, &v::wycheproof(&file));
        for length in [1, MUST_SUPPORT_OUTPUT_LEN + 1] {
            compare(
                c,
                &format!("{algorithm:?}/bounds/1/{length}/{source}/differential"),
                ae.derive(&password, &salt, 1, length),
                be.derive(&password, &salt, 1, length),
            );
        }
    }
}

fn fail(e: Error) -> TestCaseError {
    TestCaseError::fail(e.to_string())
}
