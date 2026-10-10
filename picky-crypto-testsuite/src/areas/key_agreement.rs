//! ECDH and X25519 agreement with ephemeral and static keys.

use picky_crypto::*;

use crate::algorithms::*;
use crate::harness::{CheckedResult, Checks, Expect, Options};
use crate::keys::*;
use crate::{der, select, vectors as v};

pub fn run(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    for a in AGREEMENTS.into_iter().filter(|a| *a != KeyAgreementAlgorithm::Ffdh) {
        let e = match helpers::key_agreement(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::KeyAgreement(a), result);
                continue;
            }
        };
        let id = format!("{a:?}/ephemeral");
        let size = match a {
            KeyAgreementAlgorithm::EcdhP256 => 32,
            KeyAgreementAlgorithm::EcdhP384 => 48,
            KeyAgreementAlgorithm::EcdhP521 => 66,
            _ => 32,
        };
        if let Some((a_public, b_public, a_secret, b_secret)) = c.call(&id, Expect::Success, || {
            exchange(e.generate_ephemeral()?, e.generate_ephemeral()?)
        }) {
            c.bytes(&id, &a_secret, &b_secret);
            c.check(&id, a_secret.len() == size, "shared secret length");
            for public in [a_public, b_public] {
                c.check(
                    &id,
                    public.len()
                        == if a == KeyAgreementAlgorithm::X25519 {
                            32
                        } else {
                            1 + 2 * size
                        },
                    "ephemeral public length",
                );
                if a != KeyAgreementAlgorithm::X25519 {
                    c.check(&id, public.first() == Some(&4), "uncompressed point prefix");
                }
            }
        }
        let wrong_lengths = if a == KeyAgreementAlgorithm::X25519 {
            Vec::from(x25519_wrong_length_peers())
        } else {
            Vec::new()
        };
        for peer in [vec![], vec![0]].into_iter().chain(wrong_lengths) {
            c.call(
                &format!("{id}/invalid peer of {} bytes", peer.len()),
                Expect::Error(Error::InvalidInput),
                || e.generate_ephemeral()?.agree(&peer),
            );
        }
    }
    for (kind, a, width, r) in ecc_cases() {
        let id = format!("{a:?}/{}", r.id(ECC_FILE));
        let public = der::point(&r.bytes("QeIUTx"), &r.bytes("QeIUTy"), width);
        let material = der::ec(kind, &r.bytes("deIUT"), Some(&public), None);
        if let Some(key) = loaded(
            &mut c,
            p,
            kind,
            PrivateKeyMaterial::Pkcs8(&material),
            &id,
            ec_bits(width),
            false,
            false,
        ) {
            let reason = r.text("Result");
            if reason.contains("Z changed") {
                continue;
            }
            let peer = der::point(&r.bytes("QeCAVSx"), &r.bytes("QeCAVSy"), width);
            agree_kat(
                &mut c,
                &id,
                &*key,
                a,
                &peer,
                &der::padded(&r.bytes("Z"), width),
                reason.contains("fails PKV"),
            );
            if reason.starts_with('P') && c.key_supports(&id, &*key, KeyOperation::Agree(a)) {
                if let Ok(ephemeral) = helpers::key_agreement(p, a) {
                    if let Some((static_secret, ephemeral_secret)) =
                        c.call(&format!("{id}/ephemeral with static"), Expect::Success, || {
                            let e = ephemeral.generate_ephemeral()?;
                            let ep = e.public_key().checked()?;
                            let static_secret = key.agree(a, &ep).checked()?;
                            let ephemeral_secret = e.agree(&public).checked()?;
                            Ok((static_secret, ephemeral_secret))
                        })
                    {
                        c.bytes(&id, &static_secret, &ephemeral_secret);
                    }
                }
            }
        }
    }
    for (i, (kind, a, _, width, _)) in CURVES.into_iter().enumerate() {
        let fields = v::rfc5114(i + 6);
        let own = der::point(&fields["x_qA"], &fields["y_qA"], width);
        let peer = der::point(&fields["x_qB"], &fields["y_qB"], width);
        let material = der::ec(kind, &fields["dA"], Some(&own), None);
        let id = format!("{a:?}/rfc/rfc5114.txt/A.{}", i + 6);
        if let Some(key) = loaded(
            &mut c,
            p,
            kind,
            PrivateKeyMaterial::Pkcs8(&material),
            &id,
            ec_bits(width),
            false,
            false,
        ) {
            agree_kat(&mut c, &id, &*key, a, &peer, &der::padded(&fields["x_Z"], width), false);
        }
    }
    let a = KeyAgreementAlgorithm::X25519;
    for g in v::wycheproof("x25519_test.json").test_groups {
        for t in v::tests(&g) {
            let id = v::id(a, "x25519_test.json", t);
            let scalar: [u8; 32] = v::field(t, "private").try_into().expect("published X25519 scalar");
            let secret = v::field(t, "shared");
            let zero = secret.iter().all(|b| *b == 0);
            if let Ok(e) = helpers::key_agreement(p, a) {
                let expected = if zero {
                    Expect::Error(Error::InvalidInput)
                } else {
                    Expect::Success
                };
                if let Some(out) = c.call(&format!("{id}/ephemeral peer"), expected, || {
                    e.generate_ephemeral()?.agree(&v::field(t, "public"))
                }) {
                    c.check(
                        &id,
                        out.len() == 32 && out.iter().any(|b| *b != 0),
                        "X25519 ephemeral secret must be nonzero and 32 bytes",
                    );
                }
            }
            if let Some(key) = loaded(
                &mut c,
                p,
                KeyType::X25519,
                PrivateKeyMaterial::X25519(&scalar),
                &id,
                255,
                false,
                false,
            ) {
                agree_kat(&mut c, &id, &*key, a, &v::field(t, "public"), &secret, zero);
            }
        }
    }
    for (i, (scalar, peer, secret)) in v::x25519_rfc().into_iter().enumerate() {
        let scalar: [u8; 32] = scalar.try_into().unwrap();
        let id = format!("X25519/rfc/rfc7748.txt/5.2/{i}");
        if let Some(key) = loaded(
            &mut c,
            p,
            KeyType::X25519,
            PrivateKeyMaterial::X25519(&scalar),
            &id,
            255,
            false,
            false,
        ) {
            agree_kat(&mut c, &id, &*key, a, &peer, &secret, false);
        }
    }
    let (alice, alice_public, bob, bob_public, secret) = v::x25519_dh();
    for (name, scalar, public, peer) in [
        ("Alice", alice, alice_public.clone(), bob_public.clone()),
        ("Bob", bob, bob_public, alice_public),
    ] {
        let scalar: [u8; 32] = scalar.try_into().unwrap();
        let id = format!("X25519/rfc/rfc7748.txt/6.1/{name}");
        if let Some(key) = loaded(
            &mut c,
            p,
            KeyType::X25519,
            PrivateKeyMaterial::X25519(&scalar),
            &id,
            255,
            false,
            false,
        ) {
            exported(&mut c, &id, &*key, &public);
            agree_kat(&mut c, &id, &*key, a, &peer, &secret, false);
            if c.key_supports(&id, &*key, KeyOperation::Agree(a)) {
                if let Ok(e) = helpers::key_agreement(p, a) {
                    if let Some((sa, sb)) = c.call(&id, Expect::Success, || {
                        let ephemeral = e.generate_ephemeral()?;
                        let ep = ephemeral.public_key().checked()?;
                        Ok((key.agree(a, &ep).checked()?, ephemeral.agree(&public).checked()?))
                    }) {
                        c.bytes(&id, &sa, &sb);
                    }
                }
            }
        }
    }
    if let Ok(loader) = helpers::private_key_loader(p, KeyType::X25519) {
        let (seed, cases) = v::x25519_iterations();
        let base_point = seed.clone();
        let mut k: [u8; 32] = seed.clone().try_into().unwrap();
        let mut u = seed;
        let mut count = 0;
        for (target, expected) in cases {
            if target == 1_000_000 && !extended() {
                continue;
            }
            let id = format!("X25519/rfc/rfc7748.txt/5.2/iterations={target}");
            let success = c.call(&id, Expect::Success, || {
                while count < target {
                    let key = loader.load(PrivateKeyMaterial::X25519(&k))?;
                    let agreement = key.supports(KeyOperation::Agree(a));
                    let public = key.supports(KeyOperation::PublicKey);
                    if public {
                        let exported = key.public_key().checked()?;
                        if exported.len() != 32 {
                            return Err(Error::InvalidInput);
                        }
                        if agreement {
                            let expected = key.agree(a, &base_point).checked()?;
                            if exported.as_ref() != expected.as_ref() {
                                return Err(Error::InvalidInput);
                            }
                        }
                    } else if key.public_key().checked().err()
                        != Some(Error::Unsupported(Algorithm::PublicKeyExport(KeyType::X25519)))
                    {
                        return Err(Error::InvalidInput);
                    }
                    if !agreement {
                        return Ok(None);
                    }
                    let result = key.agree(a, &u).checked()?;
                    u = k.to_vec();
                    k = result.as_ref().try_into().map_err(|_| Error::InvalidInput)?;
                    count += 1;
                }
                Ok(Some(OutputBytes::new(Zeroizing::new(k.to_vec()))))
            });
            match success {
                Some(Some(out)) => c.bytes(&id, &out, &expected),
                _ => break,
            }
        }
    }
    // Without a published own public point, raw-scalar vectors use the contract's optional-public-key encoding.
    for (kind, a, _, width, name) in CURVES {
        let file = format!("ecdh_{name}_ecpoint_test.json");
        let vectors = v::wycheproof(&file);
        let fallback_positive = select::ecdh_control(&file, &vectors);
        for g in &vectors.test_groups {
            let tests = v::tests(g);
            for t in tests {
                let peer = v::field(t, "public");
                let invalid_peer =
                    v::string(t, "result") == "invalid" || peer.len() != 1 + width * 2 || peer.first() != Some(&4);
                if let Ok(e) = helpers::key_agreement(p, a) {
                    let id = format!("{}/ephemeral peer validation", v::id(a, &file, t));
                    let expected = if invalid_peer {
                        Expect::Error(Error::InvalidInput)
                    } else {
                        Expect::Success
                    };
                    if let Some(shared) = c.call(&id, expected, || e.generate_ephemeral()?.agree(&peer)) {
                        c.check(&id, shared.len() == width, "ephemeral shared-secret width");
                    }
                }
                let scalar = v::field(t, "private");
                let has_positive = tests.iter().any(|positive| {
                    v::string(positive, "result") == "valid" && v::field(positive, "private") == scalar
                });
                let scalar = if has_positive {
                    scalar
                } else {
                    v::field(fallback_positive, "private")
                };
                let material = der::ec(kind, &scalar, None, None);
                let id = v::id(a, &file, t);
                if let Some(key) = loaded(
                    &mut c,
                    p,
                    kind,
                    PrivateKeyMaterial::Pkcs8(&material),
                    &id,
                    ec_bits(width),
                    false,
                    true,
                ) {
                    if !has_positive {
                        agree_kat(
                            &mut c,
                            &format!("{id}/positive scalar control/{}", v::number(fallback_positive, "tcId")),
                            &*key,
                            a,
                            &v::field(fallback_positive, "public"),
                            &v::field(fallback_positive, "shared"),
                            false,
                        );
                    }
                    agree_kat(&mut c, &id, &*key, a, &peer, &v::field(t, "shared"), invalid_peer);
                }
            }
        }
    }
    c.finish();
}
