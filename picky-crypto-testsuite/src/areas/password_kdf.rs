//! PBKDF2 known answers and iteration and length bounds.

use picky_crypto::*;

use crate::algorithms::*;
use crate::harness::{Checks, Expect, Options};
use crate::vectors as v;

use super::kdf::maximum;

pub fn run(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    for (index, (a, sha)) in PASSWORD_KDFS.into_iter().zip(SHAS).enumerate() {
        let e = match helpers::password_kdf(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::PasswordKdf(a), result);
                continue;
            }
        };
        let file = format!("pbkdf2_hmac{sha}_test.json");
        for group in v::wycheproof(&file).test_groups {
            for t in v::tests(&group) {
                let id = v::id(a, &file, t);
                let iterations = v::number(t, "iterationCount");
                if iterations > 10_000_000 && !extended() {
                    continue;
                }
                let expected = v::field(t, "dk");
                let outside = (iterations > 10_000_000 || v::number(t, "dkLen") > 1024)
                    .then_some((Algorithm::PasswordKdf(a), false));
                if let Some(out) = c.outcome(&id, Expect::Success, outside, || {
                    e.derive(
                        &v::field(t, "password"),
                        &v::field(t, "salt"),
                        iterations as u32,
                        v::number(t, "dkLen"),
                    )
                }) {
                    c.bytes(&id, &out, &expected);
                }
            }
        }
        for (iterations, length) in [(0, 1), (1, 0)]
            .into_iter()
            .chain(maximum(HASHES[index + 2].output_len()).map(|n| (1, n)))
        {
            c.call(
                &format!("{a:?}/bounds/{iterations}/{length}"),
                Expect::Error(Error::InvalidInput),
                || e.derive(&[], &[], iterations, length),
            );
        }
        if a == PasswordKdfAlgorithm::Pbkdf2HmacSha1 {
            for r in v::pbkdf2_rfc() {
                let iterations = r.number("c") as u32;
                if iterations > 10_000_000 && !extended() {
                    continue;
                }
                let id = format!("{a:?}/{}/iterations={iterations}", r.id("rfc/rfc6070.txt"));
                if let Some(out) = c.outcome(
                    &id,
                    Expect::Success,
                    (iterations > 10_000_000).then_some((Algorithm::PasswordKdf(a), false)),
                    || e.derive(&r.bytes("P"), &r.bytes("S"), iterations, r.number("dkLen")),
                ) {
                    c.bytes(&id, &out, &r.bytes("DK"));
                }
            }
        }
    }
    c.finish();
}
