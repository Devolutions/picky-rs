//! Cross-provider ephemeral agreement and static agreement with the same published keys.

use picky_crypto::*;

use super::outputs;
use crate::algorithms::*;
use crate::harness::{CheckedResult, Checks, Expect};
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
                let a = ae.generate_ephemeral()?;
                let b = be.generate_ephemeral()?;
                let ap = a.public_key().checked()?;
                let bp = b.public_key().checked()?;
                let sa = a.agree(&bp).checked()?;
                let sb = b.agree(&ap).checked()?;
                if sa.as_ref() != sb.as_ref() {
                    return Err(Error::InvalidInput);
                }
                Ok(())
            });
        }
    }
    if let (Ok(ae), Ok(be)) = (helpers::ffdh_key_agreement(a), helpers::ffdh_key_agreement(b)) {
        for group in v::dh_groups() {
            c.call(&format!("{}/cross FFDH ephemeral", group.id), Expect::Success, || {
                let a = ae.generate_ephemeral(group.parameters())?;
                let b = be.generate_ephemeral(group.parameters())?;
                let ap = a.public_key().checked()?;
                let bp = b.public_key().checked()?;
                let sa = a.agree(&bp).checked()?;
                let sb = b.agree(&ap).checked()?;
                if sa.as_ref() != sb.as_ref() {
                    return Err(Error::InvalidInput);
                }
                Ok(())
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
                    x25519_export(&mut c, &id, &*left);
                    x25519_export(&mut c, &id, &*right);
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
                exported(&mut c, &id, &*left, &[]);
                exported(&mut c, &id, &*right, &[]);
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

fn x25519_export(c: &mut Checks, id: &str, key: &dyn PrivateKey) {
    let supported = c.key_supports(id, key, KeyOperation::PublicKey);
    let expected = if supported {
        Expect::Success
    } else {
        Expect::Error(Error::Unsupported(Algorithm::PublicKeyExport(KeyType::X25519)))
    };
    if let Some(public) = c.call(&format!("{id}/X25519 export"), expected, || key.public_key()) {
        c.check(id, public.len() == 32, "X25519 public key length");
        if c.key_supports(id, key, KeyOperation::Agree(KeyAgreementAlgorithm::X25519)) {
            let (base, _) = v::x25519_iterations();
            if let Some(reference) = c.call(id, Expect::Success, || key.agree(KeyAgreementAlgorithm::X25519, &base)) {
                c.bytes(id, &public, &reference);
            }
        }
    }
}
