//! AES key wrap and unwrap against Wycheproof vectors.

use picky_crypto::*;

use crate::algorithms::*;
use crate::harness::{Checks, Expect, Options};
use crate::{select, vectors as v};

pub fn run(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    let file = "aes_wrap_test.json";
    let vectors = v::wycheproof(file);
    for (index, a) in WRAPS.into_iter().enumerate() {
        let e = match helpers::key_wrap(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::KeyWrap(a), result);
                continue;
            }
        };
        let Some(protections) = c.directions(p, &format!("{a:?}/supports"), Algorithm::KeyWrap(a), |p| e.supports(p))
        else {
            continue;
        };
        for g in &vectors.test_groups {
            if v::number(g, "keySize") != [128, 192, 256][index] {
                continue;
            }
            for t in v::tests(g) {
                let id = v::id(a, file, t);
                let (key, plaintext, ciphertext) = (v::field(t, "key"), v::field(t, "msg"), v::field(t, "ct"));
                for (protection, supported) in [Protection::Apply, Protection::Process].into_iter().zip(protections) {
                    let (input, output) = if protection == Protection::Apply {
                        (&plaintext, &ciphertext)
                    } else {
                        (&ciphertext, &plaintext)
                    };
                    let expected = if !supported {
                        Expect::Error(Error::Unsupported(Algorithm::KeyWrap(a)))
                    } else if key.len() != [16, 24, 32][index] {
                        Expect::Error(Error::InvalidKey)
                    } else if !valid_length(protection, input.len()) {
                        Expect::Error(Error::InvalidInput)
                    } else if protection == Protection::Process && v::string(t, "result") == "invalid" {
                        Expect::Error(Error::VerificationFailed)
                    } else {
                        Expect::Success
                    };
                    if let Some(out) = c.call(&format!("{id}/{protection:?}"), expected, || {
                        transform(e, protection, &key, input)
                    }) {
                        if protection == Protection::Process || v::string(t, "result") == "valid" {
                            c.bytes(&id, &out, output);
                        }
                    }
                }
            }
        }
        let bits = [128, 192, 256][index];
        let base = select::wrap_control(&vectors, bits);
        let key = v::field(base, "key");
        assert!(
            key.len() * 8 == bits && v::field(base, "ct").len() == v::field(base, "msg").len() + 8,
            "{a:?} control KEK and wrapped lengths"
        );
        for (protection, supported) in [Protection::Apply, Protection::Process].into_iter().zip(protections) {
            if !supported {
                continue;
            }
            for length in [0, 1, 8, 15, 17, 23, 25, 31, 33, 39, 41] {
                if valid_length(protection, length) {
                    continue;
                }
                c.call(
                    &format!("{a:?}/{protection:?}/length={length}"),
                    Expect::Error(Error::InvalidInput),
                    || transform(e, protection, &key, &vec![0; length]),
                );
            }
            let input = v::field(base, if protection == Protection::Apply { "msg" } else { "ct" });
            c.call(
                &format!("{a:?}/{protection:?}/bad KEK"),
                Expect::Error(Error::InvalidKey),
                || transform(e, protection, &[], &input),
            );
        }
    }
    c.finish();
}

fn valid_length(protection: Protection, length: usize) -> bool {
    let lengths = if protection == Protection::Apply {
        [16, 24, 32]
    } else {
        [24, 32, 40]
    };
    lengths.contains(&length)
}

fn transform(e: &dyn KeyWrap, protection: Protection, key: &[u8], input: &[u8]) -> Result<OutputBytes, Error> {
    if protection == Protection::Apply {
        e.wrap(key, input)
    } else {
        e.unwrap(key, input)
    }
}
