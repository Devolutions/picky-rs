//! Ephemeral agreement between the two providers: each must accept the public values the other generates.

use picky_crypto::*;

use crate::algorithms::*;
use crate::harness::{Checks, Expect};
use crate::keys::*;
use crate::vectors as v;

pub fn run(a: &CryptoProvider, b: &CryptoProvider) {
    let mut c = Checks::default();
    for (source, dest) in [(a, b), (b, a)] {
        for algorithm in AGREEMENTS.into_iter().filter(|a| *a != KeyAgreementAlgorithm::Ffdh) {
            let (Ok(ae), Ok(be)) = (
                helpers::key_agreement(source, algorithm),
                helpers::key_agreement(dest, algorithm),
            ) else {
                continue;
            };
            c.call(&format!("{algorithm:?}/cross ephemeral"), Expect::Success, || {
                agreed(exchange(ae.generate_ephemeral()?, be.generate_ephemeral()?)?)
            });
        }
    }
    if let (Ok(ae), Ok(be)) = (helpers::ffdh_key_agreement(a), helpers::ffdh_key_agreement(b)) {
        for group in v::dh_groups() {
            c.call(&format!("{}/cross FFDH ephemeral", group.id), Expect::Success, || {
                agreed(exchange(
                    ae.generate_ephemeral(group.parameters())?,
                    be.generate_ephemeral(group.parameters())?,
                )?)
            });
        }
    }
    c.finish();
}

/// Fails with `InvalidInput` when the two sides of an exchange derive different secrets.
fn agreed((_, _, sa, sb): Exchange) -> Result<(), Error> {
    if sa.as_ref() != sb.as_ref() {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
