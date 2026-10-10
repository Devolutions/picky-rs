//! Secure random fills and X25519 scalar clamping.

use picky_crypto::*;

use crate::harness::{Checks, Expect, Options};

pub fn run(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    let a = Algorithm::Random(RandomAlgorithm::SecureRandom);
    match helpers::secure_random(p, RandomAlgorithm::SecureRandom) {
        Err(error) => {
            c.absent::<()>(p, a, Err(error));
            c.call(
                "random_x25519_private_key/absent",
                Expect::Error(Error::Unsupported(a)),
                || helpers::random_x25519_private_key(p),
            );
        }
        Ok(e) => {
            for length in [0, 1, 32, 65_536] {
                c.call(&format!("random/fill/{length}"), Expect::Success, || {
                    e.fill(&mut vec![0; length])
                });
            }
            if let Some((a, b)) = c.call("random/independent fills", Expect::Success, || {
                let mut a = [0; 32];
                let mut b = [0; 32];
                e.fill(&mut a)?;
                e.fill(&mut b)?;
                Ok((a, b))
            }) {
                c.check("random", a != b, "two random fills were identical");
            }
            if let Some(key) = c.call("random/clamping", Expect::Success, || {
                helpers::random_x25519_private_key(p)
            }) {
                c.check(
                    "random/clamping",
                    key[0] & 7 == 0 && key[31] & 128 == 0 && key[31] & 64 != 0,
                    "scalar not clamped",
                );
            }
        }
    }
    c.finish();
}
