//! PBKDF2 known answers and iteration and length bounds.

use picky_crypto::*;

use crate::algorithms::*;
use crate::harness::{Checks, Expect, Options};
use crate::{select, vectors as v};

use super::kdf::maximum;

/// The largest PBKDF2 output length in the must-support set (contract section 6.3).
pub const MUST_SUPPORT_OUTPUT_LEN: usize = 1024;

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
        let (source, password, salt) = select::pbkdf2_password_salt(&file, &vectors);
        for group in vectors.test_groups {
            for t in v::tests(&group) {
                let id = v::id(a, &file, t);
                let iterations = v::number(t, "iterationCount");
                if iterations > 10_000_000 && !extended() {
                    continue;
                }
                let expected = v::field(t, "dk");
                let outside = (iterations > 10_000_000 || v::number(t, "dkLen") > MUST_SUPPORT_OUTPUT_LEN)
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
        // Control for zero iterations and an empty output: one iteration with a one-byte output, in the must-support
        // set.
        // No control sits at the RFC 8018 maximum: deriving that much output could exhaust time or memory.
        let id = format!("{a:?}/bounds/1/1/{source}");
        if let Some(out) = c.call(&id, Expect::Success, || e.derive(&password, &salt, 1, 1)) {
            c.check(&id, out.len() == 1, "output length");
        }
        // Control at the edge of the must-support set: one byte above it is valid, so only success or Unsupported.
        let length = MUST_SUPPORT_OUTPUT_LEN + 1;
        let id = format!("{a:?}/bounds/1/{length}/{source}");
        if let Some(out) = c.outcome(&id, Expect::Success, Some((Algorithm::PasswordKdf(a), false)), || {
            e.derive(&password, &salt, 1, length)
        }) {
            c.check(&id, out.len() == length, "output length");
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
