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
        let Some(protections) = c.metadata(&format!("{a:?}/supports"), || {
            [e.supports(Protection::Apply), e.supports(Protection::Process)]
        }) else {
            continue;
        };
        for (protection, supported) in [Protection::Apply, Protection::Process].into_iter().zip(protections) {
            c.direction(p, Algorithm::KeyWrap(a), protection, supported);
        }
        for g in &vectors.test_groups {
            if v::number(g, "keySize") != [128, 192, 256][index] {
                continue;
            }
            for t in v::tests(g) {
                let id = v::id(a, file, t);
                let (key, plaintext, ciphertext) = (v::field(t, "key"), v::field(t, "msg"), v::field(t, "ct"));
                for protection in [Protection::Apply, Protection::Process] {
                    let supported = protections[usize::from(protection == Protection::Process)];
                    let len = if protection == Protection::Apply {
                        plaintext.len()
                    } else {
                        ciphertext.len()
                    };
                    let lengths = if protection == Protection::Apply {
                        [16, 24, 32]
                    } else {
                        [24, 32, 40]
                    };
                    let expected = if !supported {
                        Expect::Error(Error::Unsupported(Algorithm::KeyWrap(a)))
                    } else if key.len() != [16, 24, 32][index] {
                        Expect::Error(Error::InvalidKey)
                    } else if !lengths.contains(&len) {
                        Expect::Error(Error::InvalidInput)
                    } else if protection == Protection::Process && v::string(t, "result") == "invalid" {
                        Expect::Error(Error::VerificationFailed)
                    } else {
                        Expect::Success
                    };
                    if let Some(out) = c.call(&format!("{id}/{protection:?}"), expected, || {
                        if protection == Protection::Apply {
                            e.wrap(&key, &plaintext)
                        } else {
                            e.unwrap(&key, &ciphertext)
                        }
                    }) {
                        if protection == Protection::Process || v::string(t, "result") == "valid" {
                            c.bytes(
                                &id,
                                &out,
                                if protection == Protection::Apply {
                                    &ciphertext
                                } else {
                                    &plaintext
                                },
                            );
                        } else {
                            c.debug(&id, &out, &out);
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
        for protection in [Protection::Apply, Protection::Process] {
            if !protections[usize::from(protection == Protection::Process)] {
                continue;
            }
            for length in [0, 1, 8, 15, 17, 23, 25, 31, 33, 39, 41] {
                if (protection == Protection::Apply && [16, 24, 32].contains(&length))
                    || (protection == Protection::Process && [24, 32, 40].contains(&length))
                {
                    continue;
                }
                c.call(
                    &format!("{a:?}/{protection:?}/length={length}"),
                    Expect::Error(Error::InvalidInput),
                    || {
                        if protection == Protection::Apply {
                            e.wrap(&key, &vec![0; length])
                        } else {
                            e.unwrap(&key, &vec![0; length])
                        }
                    },
                );
            }
            c.call(
                &format!("{a:?}/{protection:?}/bad KEK"),
                Expect::Error(Error::InvalidKey),
                || {
                    if protection == Protection::Apply {
                        e.wrap(&[], &v::field(base, "msg"))
                    } else {
                        e.unwrap(&[], &v::field(base, "ct"))
                    }
                },
            );
        }
    }
    c.finish();
}
