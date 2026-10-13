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
        let vectors = v::wycheproof(&file);
        // Bound checks use a published password and salt, so they can fail only for the bound under test.
        let (source, password, salt) = vectors
            .test_groups
            .iter()
            .flat_map(v::tests)
            .find(|t| v::string(t, "result") == "valid")
            .map(|t| {
                let source = format!("{file}/tcId={}", v::number(t, "tcId"));
                (source, v::field(t, "password"), v::field(t, "salt"))
            })
            .expect("a valid PBKDF2 test");
        for group in vectors.test_groups {
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
        let maximum = maximum(HASHES[index + 2].output_len());
        for (iterations, length) in [(0, 1), (1, 0)].into_iter().chain(maximum.map(|n| (1, n))) {
            c.call(
                &format!("{a:?}/bounds/{iterations}/{length}/{source}"),
                Expect::Error(Error::InvalidInput),
                || e.derive(&password, &salt, iterations, length),
            );
        }
        // Controls: one iteration with a one-byte output is in the must-support set, and the RFC 8018 maximum is in the valid domain.
        let id = format!("{a:?}/bounds/1/1/{source}");
        if let Some(out) = c.call(&id, Expect::Success, || e.derive(&password, &salt, 1, 1)) {
            c.check(&id, out.len() == 1, "output length");
        }
        if let Some(n) = maximum {
            c.outcome(
                &format!("{a:?}/bounds/1/{}/{source}", n - 1),
                Expect::Success,
                Some((Algorithm::PasswordKdf(a), false)),
                || e.derive(&password, &salt, 1, n - 1).map(|_| ()),
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
