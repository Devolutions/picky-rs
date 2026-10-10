//! Message digests: NIST and RFC known answers, streaming and Monte Carlo chains.

use picky_crypto::*;

use crate::algorithms::*;
use crate::harness::{CheckedResult, Checks, Expect, Options};
use crate::{select, vectors as v};

pub fn run(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    for (index, a) in HASHES.into_iter().enumerate() {
        let entry = match helpers::hash(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::Hash(a), result);
                continue;
            }
        };
        let stem = match a {
            HashAlgorithm::Sha1 => Some("nist/shs/SHA1"),
            HashAlgorithm::Sha224 => Some("nist/shs/SHA224"),
            HashAlgorithm::Sha256 => Some("nist/shs/SHA256"),
            HashAlgorithm::Sha384 => Some("nist/shs/SHA384"),
            HashAlgorithm::Sha512 => Some("nist/shs/SHA512"),
            HashAlgorithm::Sha3_384 => Some("nist/sha3/SHA3_384"),
            HashAlgorithm::Sha3_512 => Some("nist/sha3/SHA3_512"),
            _ => None,
        };
        let cases = if index < 2 {
            v::md(if index == 0 { 1320 } else { 1321 })
                .into_iter()
                .enumerate()
                .map(|(i, (m, d))| {
                    (
                        format!("{a:?}/rfc{}/A.5/{i}", if index == 0 { 1320 } else { 1321 }),
                        m,
                        d,
                    )
                })
                .collect::<Vec<_>>()
        } else {
            let file = format!("{}ShortMsg.rsp", stem.expect("NIST hash file stem"));
            v::response(&file)
                .into_iter()
                .map(|r| {
                    let mut msg = r.bytes("Msg");
                    assert_eq!(r.number("Len") % 8, 0);
                    msg.truncate(r.number("Len") / 8);
                    (format!("{a:?}/{}", r.id(&file)), msg, r.bytes("MD"))
                })
                .collect()
        };
        for (id, msg, digest) in cases {
            if let Some(out) = c.call(&id, Expect::Success, || helpers::digest(p, a, &msg)) {
                c.bytes(&id, &out, &digest);
            }
            for zero_updates in [false, true] {
                if !msg.is_empty() && zero_updates {
                    continue;
                }
                if let Some(out) = c.call(&format!("{id}/streaming/{zero_updates}"), Expect::Success, || {
                    let mut ctx = entry.start()?;
                    if !zero_updates {
                        ctx.update(&[])?;
                        for chunk in msg.chunks(7) {
                            ctx.update(chunk)?;
                            ctx.update(&[])?;
                        }
                    }
                    ctx.finish()
                }) {
                    c.bytes(&id, &out, &digest);
                    c.check(&id, out.len() == a.output_len(), "output_len mismatch");
                }
            }
        }
        if let Some(stem) = stem {
            let file = format!("{stem}Monte.rsp");
            let records = v::response(&file);
            let mut seed = select::monte_seed(&file, &records);
            for r in records {
                let id = format!("{a:?}/{}", r.id(&file));
                let next = c.call(&id, Expect::Success, || {
                    if matches!(a, HashAlgorithm::Sha3_384 | HashAlgorithm::Sha3_512) {
                        let mut out = seed.clone();
                        for _ in 0..1000 {
                            out = helpers::digest(p, a, &out).checked()?.into_inner().to_vec();
                        }
                        Ok(OutputBytes::new(Zeroizing::new(out)))
                    } else {
                        let mut digests = [seed.clone(), seed.clone(), seed.clone()];
                        for _ in 0..1000 {
                            let next = helpers::digest(p, a, &digests.concat()).checked()?;
                            digests.rotate_left(1);
                            digests[2] = next.into_inner().to_vec();
                        }
                        Ok(OutputBytes::new(Zeroizing::new(digests[2].clone())))
                    }
                });
                if let Some(out) = next {
                    c.bytes(&id, &out, &r.bytes("MD"));
                }
                seed = r.bytes("MD");
            }
        }
    }
    c.finish();
}
