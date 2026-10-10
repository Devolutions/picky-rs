//! CBC block cipher known answers, key and input lengths, and weak triple-DES keys.

use picky_crypto::*;

use crate::algorithms::*;
use crate::harness::{Checks, Expect, Options};
use crate::{select, vectors as v};

pub type CipherVector = (String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, bool);
pub fn cipher_records(a: CipherAlgorithm) -> Vec<CipherVector> {
    let mut result = Vec::new();
    if a == CipherAlgorithm::Rc2Cbc {
        for r in v::rc2() {
            result.push((
                r.id("rfc/rfc2268.txt"),
                r.bytes("Key"),
                vec![0; 8],
                r.bytes("Plaintext"),
                r.bytes("Ciphertext"),
                false,
            ));
        }
    } else {
        let files = if a == CipherAlgorithm::TdesEde3Cbc {
            vec!["nist/tdes/TCBCMMT3.rsp".to_owned(), "nist/tdes/TCBCMMT2.rsp".to_owned()]
        } else {
            let bits = match a {
                CipherAlgorithm::Aes128Cbc => 128,
                CipherAlgorithm::Aes192Cbc => 192,
                _ => 256,
            };
            vec![format!("nist/aes/CBCMMT{bits}.rsp")]
        };
        for file in files {
            for r in v::response(&file) {
                let key = if a == CipherAlgorithm::TdesEde3Cbc {
                    [r.bytes("KEY1"), r.bytes("KEY2"), r.bytes("KEY3")].concat()
                } else {
                    r.bytes("KEY")
                };
                result.push((
                    r.id(&file),
                    key,
                    r.bytes("IV"),
                    r.bytes("PLAINTEXT"),
                    r.bytes("CIPHERTEXT"),
                    file.ends_with("TCBCMMT2.rsp"),
                ));
            }
        }
    }
    select::cbc_control(a, &result);
    result
}

pub fn run(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    for a in CIPHERS {
        let e = match helpers::cipher(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::Cipher(a), result);
                continue;
            }
        };
        let Some(protections) = c.metadata(&format!("{a:?}/supports"), || {
            [e.supports(Protection::Apply), e.supports(Protection::Process)]
        }) else {
            continue;
        };
        let records = cipher_records(a);
        for (protection, supported) in [Protection::Apply, Protection::Process].into_iter().zip(protections) {
            c.direction(p, Algorithm::Cipher(a), protection, supported);
        }
        for (id, key, iv, plaintext, ciphertext, variable) in &records {
            for protection in [Protection::Apply, Protection::Process] {
                let supported = protections[usize::from(protection == Protection::Process)];
                let expected = if !supported {
                    Expect::Error(Error::Unsupported(Algorithm::Cipher(a)))
                } else if *variable {
                    Expect::Either(Error::InvalidKey)
                } else {
                    Expect::Success
                };
                let result = c.call(&format!("{a:?}/{id}/{protection:?}"), expected, || {
                    if protection == Protection::Apply {
                        e.encrypt(key, iv, plaintext)
                    } else {
                        e.decrypt(key, iv, ciphertext)
                    }
                });
                if let Some(result) = result {
                    c.bytes(
                        id,
                        &result,
                        if protection == Protection::Apply {
                            ciphertext
                        } else {
                            plaintext
                        },
                    );
                }
            }
        }
        let (id, key, iv, data, _, _) = select::cbc_control(a, &records);
        for protection in [Protection::Apply, Protection::Process] {
            if !protections[usize::from(protection == Protection::Process)] {
                continue;
            }
            for (k, i, d, error) in [
                (&[][..], &iv[..], &data[..], Error::InvalidKey),
                (&key[..], &[][..], &data[..], Error::InvalidInput),
                (&key[..], &iv[..], &[0][..], Error::InvalidInput),
                (&[][..], &[][..], &[0][..], Error::InvalidKey),
            ] {
                c.call(
                    &format!("{a:?}/{id}/length/{protection:?}"),
                    Expect::Error(error),
                    || {
                        if protection == Protection::Apply {
                            e.encrypt(k, i, d)
                        } else {
                            e.decrypt(k, i, d)
                        }
                    },
                );
            }
            if matches!(
                a,
                CipherAlgorithm::Aes128Cbc | CipherAlgorithm::Aes192Cbc | CipherAlgorithm::Aes256Cbc
            ) {
                let empty = &select::ed25519_empty().message;
                if let Some(out) = c.call(&format!("{a:?}/{id}/empty"), Expect::Success, || {
                    if protection == Protection::Apply {
                        e.encrypt(key, iv, empty)
                    } else {
                        e.decrypt(key, iv, empty)
                    }
                }) {
                    c.check(id, out.is_empty(), "empty CBC result must be empty");
                }
            }
            for length in [0, 1, 15, 16, 17, 23, 24, 25, 31, 32, 33, 129] {
                let valid = match a {
                    CipherAlgorithm::Aes128Cbc => length == 16,
                    CipherAlgorithm::Aes192Cbc => length == 24,
                    CipherAlgorithm::Aes256Cbc => length == 32,
                    CipherAlgorithm::TdesEde3Cbc => length == 24,
                    CipherAlgorithm::Rc2Cbc => (1..=128).contains(&length),
                    _ => false,
                };
                if valid {
                    continue;
                }
                c.call(
                    &format!("{a:?}/{protection:?}/key length={length}"),
                    Expect::Error(Error::InvalidKey),
                    || {
                        if protection == Protection::Apply {
                            e.encrypt(&vec![0; length], iv, data)
                        } else {
                            e.decrypt(&vec![0; length], iv, data)
                        }
                    },
                );
            }
        }
        if a == CipherAlgorithm::TdesEde3Cbc {
            weak_tdes_checks(&mut c, e, select::cbc_control(a, &records), protections);
        }
    }
    c.finish();
}

fn weak_tdes_checks(c: &mut Checks, e: &dyn Cipher, record: &CipherVector, protections: [bool; 2]) {
    let (base_id, base, iv, plain, encrypted, _) = record;
    let weak = weak_tdes_key(base);
    let id = format!("{base_id}/KEY1 from rfc/rfc2268.txt/section 5/all-one key");
    if protections[0] {
        if let Some(out) = c.call(&id, Expect::Either(Error::InvalidKey), || e.encrypt(&weak, iv, plain)) {
            c.check(&id, out.len() == plain.len(), "weak-key CBC length");
            if protections[1] {
                if let Some(restored) = c.call(&id, Expect::Either(Error::InvalidKey), || e.decrypt(&weak, iv, &out)) {
                    c.bytes(&id, &restored, plain);
                }
            }
        }
    }
    if protections[1] {
        if let Some(out) = c.call(&id, Expect::Either(Error::InvalidKey), || {
            e.decrypt(&weak, iv, encrypted)
        }) {
            c.check(&id, out.len() == encrypted.len(), "weak-key CBC length");
            if protections[0] {
                if let Some(restored) = c.call(&id, Expect::Either(Error::InvalidKey), || e.encrypt(&weak, iv, &out)) {
                    c.bytes(&id, &restored, encrypted);
                }
            }
        }
    }
}

pub fn weak_tdes_key(base: &[u8]) -> Vec<u8> {
    let fields = base.chunks_exact(8).map(<[u8]>::to_vec).collect::<Vec<_>>();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields.concat(), base, "TCBCMMT3 split/reassemble control");
    let published = select::weak_des_component();
    [published, fields[1].clone(), fields[2].clone()].concat()
}
