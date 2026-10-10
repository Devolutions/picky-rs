//! HMAC generation and verification, including truncated tags and directional support.

use picky_crypto::*;

use crate::algorithms::*;
use crate::harness::{Checks, Expect, Options};
use crate::vectors as v;

pub fn run(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    for (index, (a, sha)) in MACS.into_iter().zip(SHAS).enumerate() {
        let e = match helpers::mac(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::Mac(a), result);
                continue;
            }
        };
        let Some(protections) = c.metadata(&format!("{a:?}/supports"), || {
            [e.supports(Protection::Apply), e.supports(Protection::Process)]
        }) else {
            continue;
        };
        for (protection, supported) in [Protection::Apply, Protection::Process].into_iter().zip(protections) {
            c.direction(p, Algorithm::Mac(a), protection, supported);
        }
        let file = format!("hmac_{sha}_test.json");
        for group in v::wycheproof(&file).test_groups {
            for t in v::tests(&group) {
                let id = v::id(a, &file, t);
                let (key, msg, tag) = (v::field(t, "key"), v::field(t, "msg"), v::field(t, "tag"));
                let valid = v::string(t, "result") != "invalid";
                let len = v::number(&group, "tagSize") / 8;
                mac_case(
                    &mut c,
                    p,
                    e,
                    a,
                    protections,
                    HASHES[index + 2].output_len(),
                    &id,
                    &key,
                    &msg,
                    &tag,
                    len,
                    valid,
                );
            }
        }
        if a != MacAlgorithm::HmacSha1 {
            for r in v::hmac_rfc() {
                let id = format!("{a:?}/{}", r.id("rfc/rfc4231.txt"));
                let tag = r.bytes(&format!("HMAC-SHA-{}", sha.trim_start_matches("sha")));
                mac_case(
                    &mut c,
                    p,
                    e,
                    a,
                    protections,
                    HASHES[index + 2].output_len(),
                    &id,
                    &r.bytes("Key"),
                    &r.bytes("Data"),
                    &tag,
                    tag.len(),
                    true,
                );
            }
        }
    }
    c.finish();
}

#[allow(clippy::too_many_arguments)]
fn mac_case(
    c: &mut Checks,
    p: &CryptoProvider,
    e: &dyn Mac,
    a: MacAlgorithm,
    protections: [bool; 2],
    full_len: usize,
    id: &str,
    key: &[u8],
    msg: &[u8],
    tag: &[u8],
    len: usize,
    valid: bool,
) {
    let mut generated = None;
    if protections[0] {
        if let Some(tagged) = c.call(id, Expect::Success, || helpers::compute_mac(p, a, key, msg)) {
            let bytes = tagged.into_inner();
            c.check(id, bytes.len() == full_len, "generation must return the full tag");
            if valid {
                c.check(
                    id,
                    bytes.get(..len) == Some(tag),
                    "generated tag disagrees with published prefix",
                );
            }
            generated = Some(bytes);
        }
    } else {
        c.call(id, Expect::Error(Error::Unsupported(Algorithm::Mac(a))), || {
            e.start(key, Protection::Apply)
        });
    }
    if protections[1] {
        let verifier = c.call(id, Expect::Success, || {
            let mut context = MacVerification::start(e, key)?;
            context.update(&[])?;
            for chunk in msg.chunks(7) {
                context.update(chunk)?;
            }
            context.finish()
        });
        if let Some(verifier) = verifier {
            c.debug(id, &verifier, tag);
            c.check(
                id,
                verifier.verify(tag, len) == valid,
                "streaming verifier disagrees with vector label",
            );
            let correct = generated
                .as_deref()
                .map(Vec::as_slice)
                .or_else(|| (valid && tag.len() == full_len).then_some(tag));
            if let Some(correct) = correct {
                c.debug(id, &verifier, correct);
                c.check(
                    id,
                    verifier.verify(correct, correct.len()),
                    "MacTag bytes do not verify",
                );
                for length in [0, correct.len() + 1, 8, 12, correct.len()] {
                    let prefix = &correct[..length.min(correct.len())];
                    c.check(
                        id,
                        verifier.verify(prefix, length) == (length > 0 && length <= correct.len()),
                        "prefix or length check",
                    );
                    if length > 0 && length <= correct.len() {
                        let wrong = vec![0; length];
                        if wrong != prefix {
                            c.check(id, !verifier.verify(&wrong, length), "wrong prefix verified");
                        }
                        c.check(
                            id,
                            !verifier.verify(&prefix[..length - 1], length),
                            "mismatched expected length verified",
                        );
                    }
                }
            }
        }
        if let Some(verified) = c.call(id, Expect::Success, || helpers::verify_mac(p, a, key, msg, tag, len)) {
            c.check(id, verified == valid, "one-shot verifier disagrees with vector label");
        }
    } else {
        c.call(id, Expect::Error(Error::Unsupported(Algorithm::Mac(a))), || {
            e.start(key, Protection::Process)
        });
    }
}
