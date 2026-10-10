//! AES-GCM sealing and opening against Wycheproof vectors.

use picky_crypto::*;

use crate::algorithms::*;
use crate::harness::{CheckedResult, Checks, Expect, Options};
use crate::{select, vectors as v};

pub fn run(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    let file = "aes_gcm_test.json";
    let vectors = v::wycheproof(file);
    for (index, a) in AEADS.into_iter().enumerate() {
        let e = match helpers::aead(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::Aead(a), result);
                continue;
            }
        };
        let Some(protections) = c.metadata(&format!("{a:?}/supports"), || {
            [e.supports(Protection::Apply), e.supports(Protection::Process)]
        }) else {
            continue;
        };
        for (protection, supported) in [Protection::Apply, Protection::Process].into_iter().zip(protections) {
            c.direction(p, Algorithm::Aead(a), protection, supported);
        }
        for g in &vectors.test_groups {
            if v::number(g, "keySize") != [128, 192, 256][index] {
                continue;
            }
            for t in v::tests(g) {
                let id = v::id(a, file, t);
                let (key, nonce, aad, plaintext) = (
                    v::field(t, "key"),
                    v::field(t, "iv"),
                    v::field(t, "aad"),
                    v::field(t, "msg"),
                );
                let encrypted = [v::field(t, "ct"), v::field(t, "tag")].concat();
                for protection in [Protection::Apply, Protection::Process] {
                    let supported = protections[usize::from(protection == Protection::Process)];
                    if !supported {
                        c.call(
                            &format!("{id}/{protection:?}"),
                            Expect::Error(Error::Unsupported(Algorithm::Aead(a))),
                            || {
                                if protection == Protection::Apply {
                                    e.seal(&key, &aad, &plaintext).checked().map(|s| s.nonce)
                                } else {
                                    e.open(&key, &nonce, &aad, &encrypted)
                                }
                            },
                        );
                        continue;
                    }
                    if protection == Protection::Process {
                        let expected = if nonce.len() != 12 || encrypted.len() < 16 {
                            Expect::Error(Error::InvalidInput)
                        } else if v::number(g, "tagSize") != 128 || v::string(t, "result") == "invalid" {
                            Expect::Error(Error::VerificationFailed)
                        } else {
                            Expect::Success
                        };
                        if let Some(out) = c.call(&id, expected, || e.open(&key, &nonce, &aad, &encrypted)) {
                            c.bytes(&id, &out, &plaintext);
                        }
                    } else if let Some(sealed) = c.call(&id, Expect::Success, || e.seal(&key, &aad, &plaintext)) {
                        c.check(&id, sealed.nonce.len() == 12, "seal nonce length");
                        c.check(
                            &id,
                            sealed.ciphertext_and_tag.len() == plaintext.len() + 16,
                            "seal ciphertext length",
                        );
                        c.debug(&id, &sealed, &sealed.nonce);
                        c.debug(&id, &sealed, &sealed.ciphertext_and_tag);
                        if protections[1] {
                            if let Some(out) = c.call(&id, Expect::Success, || {
                                e.open(&key, &sealed.nonce, &aad, &sealed.ciphertext_and_tag)
                            }) {
                                c.bytes(&id, &out, &plaintext);
                            }
                        }
                    }
                }
            }
        }
        let valid = select::gcm_control(&vectors, [128, 192, 256][index]);
        let key = v::field(valid, "key");
        let nonce = v::field(valid, "iv");
        let data = [v::field(valid, "ct"), v::field(valid, "tag")].concat();
        if protections[0] {
            c.call(
                &format!("{a:?}/seal invalid key"),
                Expect::Error(Error::InvalidKey),
                || e.seal(&[], &[], &[]),
            );
        }
        if protections[1] {
            for (k, n, d, error) in [
                (&[][..], &nonce[..], &data[..], Error::InvalidKey),
                (&key[..], &[][..], &data[..], Error::InvalidInput),
                (&key[..], &nonce[..], &[0][..], Error::InvalidInput),
            ] {
                c.call(&format!("{a:?}/open lengths"), Expect::Error(error), || {
                    e.open(k, n, &[], d)
                });
            }
        }
    }
    c.finish();
}
