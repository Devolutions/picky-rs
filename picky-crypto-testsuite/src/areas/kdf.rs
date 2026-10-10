//! One-step and counter-mode key derivation known answers and length bounds.

use picky_crypto::*;

use crate::algorithms::*;
use crate::harness::{Checks, Expect, Options};
use crate::vectors as v;

pub(super) fn maximum(hlen: usize) -> Option<usize> {
    usize::try_from(u32::MAX).ok()?.checked_mul(hlen)?.checked_add(1)
}

pub fn run(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    let counter = "nist/kbkdf/KDFCTR_gen.rsp";
    let ecc = "nist/kas/KASValidityTest_ECCEphemeralUnified_KDFConcat_NOKC_init.fax";
    for (index, a) in KDFS.into_iter().enumerate() {
        let e = match helpers::kdf(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::Kdf(a), result);
                continue;
            }
        };
        let digest_length = [20, 32, 48, 64][index % 4];
        let records = if index >= 4 {
            v::response(counter)
        } else {
            v::response(ecc)
        };
        for r in records {
            let (secret, info, expected, id) = if index >= 4 {
                let name = ["HMAC_SHA1", "HMAC_SHA256", "HMAC_SHA384", "HMAC_SHA512"][index - 4];
                if !r.group.contains(&format!("PRF={name};")) {
                    continue;
                }
                (r.bytes("KI"), r.bytes("FixedInputData"), r.bytes("KO"), r.id(counter))
            } else {
                if index == 0 || !r.group.contains(["SHA1", "SHA256", "SHA384", "SHA512"][index]) {
                    continue;
                }
                // Changed Z, OtherInfo, or DKM no longer forms a known-answer pair.
                let reason = r.text("Result");
                if reason.contains("Z changed")
                    || reason.contains("OI changed")
                    || reason.contains("DKM changed")
                    || reason.contains("fails PKV")
                {
                    continue;
                }
                (r.bytes("Z"), r.bytes("OI"), r.bytes("DKM"), r.id(ecc))
            };
            if let Some(out) = c.outcome(
                &format!("{a:?}/{id}"),
                Expect::Success,
                (expected.len() > 64).then_some((Algorithm::Kdf(a), false)),
                || e.derive(&secret, &info, expected.len()),
            ) {
                c.bytes(&id, &out, &expected);
            }
        }
        for (secret, length) in [(vec![], 1), (vec![1], 0)]
            .into_iter()
            .chain(maximum(digest_length).map(|n| (vec![1], n)))
        {
            c.call(
                &format!("{a:?}/bounds/{length}"),
                Expect::Error(Error::InvalidInput),
                || e.derive(&secret, &[], length),
            );
        }
    }
    c.finish();
}
