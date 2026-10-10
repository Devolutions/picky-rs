//! Cross-provider ephemeral agreement and static agreement with the same published keys.

use picky_crypto::*;

use super::outputs;
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
    if let (Ok(al), Ok(bl)) = (
        helpers::private_key_loader(a, KeyType::X25519),
        helpers::private_key_loader(b, KeyType::X25519),
    ) {
        for g in v::wycheproof("x25519_test.json").test_groups {
            for t in v::tests(&g) {
                if v::field(t, "shared").iter().all(|b| *b == 0) {
                    continue;
                }
                let scalar: [u8; 32] = v::field(t, "private").try_into().unwrap();
                let id = v::id(KeyAgreementAlgorithm::X25519, "x25519_test.json", t);
                let left = c.call(&id, Expect::Success, || al.load(PrivateKeyMaterial::X25519(&scalar)));
                let right = c.call(&id, Expect::Success, || bl.load(PrivateKeyMaterial::X25519(&scalar)));
                if let (Some(left), Some(right)) = (left, right) {
                    let ls = c.key_supports(&id, &*left, KeyOperation::Agree(KeyAgreementAlgorithm::X25519));
                    let rs = c.key_supports(&id, &*right, KeyOperation::Agree(KeyAgreementAlgorithm::X25519));
                    if ls && rs {
                        outputs(
                            &mut c,
                            &id,
                            || left.agree(KeyAgreementAlgorithm::X25519, &v::field(t, "public")),
                            || right.agree(KeyAgreementAlgorithm::X25519, &v::field(t, "public")),
                        );
                    }
                }
            }
        }
    }
    if let (Ok(al), Ok(bl)) = (
        helpers::private_key_loader(a, KeyType::Ffdh),
        helpers::private_key_loader(b, KeyType::Ffdh),
    ) {
        for (i, group) in v::dh_groups().into_iter().take(3).enumerate() {
            let fields = v::rfc5114(i + 1);
            let id = format!("{}/A.{}/cross static FFDH", group.id, i + 1);
            let material = PrivateKeyMaterial::Ffdh {
                parameters: group.parameters(),
                private_value: &fields["xA"],
            };
            let left = c.call(&id, Expect::Success, || al.load(material));
            let right = c.call(&id, Expect::Success, || bl.load(material));
            if let (Some(left), Some(right)) = (left, right) {
                let ls = c.key_supports(&id, &*left, KeyOperation::Agree(KeyAgreementAlgorithm::Ffdh));
                let rs = c.key_supports(&id, &*right, KeyOperation::Agree(KeyAgreementAlgorithm::Ffdh));
                if ls && rs {
                    outputs(
                        &mut c,
                        &id,
                        || left.agree(KeyAgreementAlgorithm::Ffdh, &fields["yB"]),
                        || right.agree(KeyAgreementAlgorithm::Ffdh, &fields["yB"]),
                    );
                }
            }
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
