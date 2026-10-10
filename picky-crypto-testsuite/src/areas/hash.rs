//! Message digests: NIST and RFC known answers and streaming.

use picky_crypto::*;

use crate::algorithms::*;
use crate::harness::{Checks, Expect, Options};
use crate::vectors as v;

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
        let file = match a {
            HashAlgorithm::Sha1 => "nist/shs/SHA1ShortMsg.rsp",
            HashAlgorithm::Sha224 => "nist/shs/SHA224ShortMsg.rsp",
            HashAlgorithm::Sha256 => "nist/shs/SHA256ShortMsg.rsp",
            HashAlgorithm::Sha384 => "nist/shs/SHA384ShortMsg.rsp",
            HashAlgorithm::Sha512 => "nist/shs/SHA512ShortMsg.rsp",
            HashAlgorithm::Sha3_384 => "nist/sha3/SHA3_384ShortMsg.rsp",
            HashAlgorithm::Sha3_512 => "nist/sha3/SHA3_512ShortMsg.rsp",
            _ => "",
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
            v::response(file)
                .into_iter()
                .map(|r| {
                    let mut msg = r.bytes("Msg");
                    assert_eq!(r.number("Len") % 8, 0);
                    msg.truncate(r.number("Len") / 8);
                    (format!("{a:?}/{}", r.id(file)), msg, r.bytes("MD"))
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
    }
    c.finish();
}
