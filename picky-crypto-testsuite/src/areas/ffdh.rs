//! Finite-field Diffie-Hellman with ephemeral and static keys, and domain parameter bounds.

use picky_crypto::*;

use crate::harness::{CheckedResult, Checks, Expect, Options};
use crate::keys::*;
use crate::{der, select, vectors as v};

pub const FFC_FILE: &str = "nist/kas/KASValidityTest_FFCStatic_NOKC_ZZOnly_init.fax";

pub fn below_modulus_minus_one(value: &[u8], modulus: &[u8]) -> bool {
    let value = der::unsigned(value);
    let modulus = der::unsigned(modulus);
    let padded = der::padded(value, modulus.len());
    let Some(different) = padded.iter().zip(modulus).position(|(a, b)| a != b) else {
        return false;
    };
    if padded[different] > modulus[different] {
        return false;
    }
    // Adjacent integers differ by one digit and have complementary boundary suffixes.
    (padded[different]..modulus[different]).nth(1).is_some()
        || modulus[different + 1..].iter().any(|b| *b != 0)
        || padded[different + 1..].iter().any(|b| *b != 255)
}

pub fn ffdh_parameter_boundaries(c: &mut Checks, p: &CryptoProvider) {
    let even = [[0x80].as_slice(), &[0; 127]].concat();
    let odd = [[0x80].as_slice(), &[0; 126], &[1]].concat();
    for (name, parameters) in [
        ("even 1024-bit p", FfdhParameters::new(&even, &[2], None)),
        ("g equals p minus one", FfdhParameters::new(&odd, &even, None)),
    ] {
        let id = format!("Ffdh/valid-domain/{name}");
        if let Ok(entry) = helpers::ffdh_key_agreement(p) {
            c.call(&format!("{id}/ephemeral"), Expect::Error(Error::InvalidInput), || {
                entry.generate_ephemeral(parameters)
            });
        }
        if let Ok(loader) = helpers::private_key_loader(p, KeyType::Ffdh) {
            c.call(&format!("{id}/static load"), Expect::Error(Error::InvalidKey), || {
                loader.load(PrivateKeyMaterial::Ffdh {
                    parameters,
                    private_value: &[1],
                })
            });
        }
    }
}

pub fn ffdh_exponent_boundaries(c: &mut Checks, p: &CryptoProvider, groups: &[v::DhGroup]) {
    let Ok(loader) = helpers::private_key_loader(p, KeyType::Ffdh) else {
        return;
    };
    for group in groups.iter().filter(|group| group.id.starts_with("rfc/rfc7919.txt/")) {
        let order = select::ffdh_order(group);
        for q in [None, Some(order)] {
            let id = format!(
                "Ffdh/{}/x = published q/q {}",
                group.id,
                if q.is_some() { "present" } else { "absent" }
            );
            c.call(&id, Expect::Error(Error::InvalidKey), || {
                loader.load(PrivateKeyMaterial::Ffdh {
                    parameters: FfdhParameters::new(&group.p, &group.g, q),
                    private_value: order,
                })
            });
        }
    }
}

pub fn run(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    let groups = v::dh_groups();
    ffdh_parameter_boundaries(&mut c, p);
    ffdh_exponent_boundaries(&mut c, p, &groups);
    match helpers::ffdh_key_agreement(p) {
        Err(error) => c.absent::<()>(p, Algorithm::KeyAgreement(KeyAgreementAlgorithm::Ffdh), Err(error)),
        Ok(e) => {
            for group in &groups {
                let id = &group.id;
                if let Some((ap, bp, sa, sb)) = c.call(id, Expect::Success, || {
                    let a = e.generate_ephemeral(group.parameters())?;
                    let b = e.generate_ephemeral(group.parameters())?;
                    let ap = a.public_key().checked()?;
                    let bp = b.public_key().checked()?;
                    let sa = a.agree(&bp).checked()?;
                    let sb = b.agree(&ap).checked()?;
                    Ok((ap, bp, sa, sb))
                }) {
                    c.bytes(id, &sa, &sb);
                    c.check(id, sa.len() == group.p.len(), "FFDH secret width");
                    for public in [ap, bp] {
                        c.debug(id, &public, &public);
                        c.check(id, public.len() == group.p.len(), "FFDH public width");
                        let unsigned = der::unsigned(&public);
                        let modulus = der::unsigned(&group.p);
                        c.check(
                            id,
                            unsigned.len() > 1 || unsigned.first().is_some_and(|b| *b >= 2),
                            "public value below 2",
                        );
                        c.check(
                            id,
                            unsigned.len() <= modulus.len() && below_modulus_minus_one(unsigned, modulus),
                            "public value greater than p - 2",
                        );
                    }
                }
                let below_modulus = modulus_minus_one(&group.p);
                for invalid in [&[][..], &[0][..], &[1][..], &below_modulus[..], &group.p[..]] {
                    c.call(
                        &format!("{id}/invalid peer of {} bytes", invalid.len()),
                        Expect::Error(Error::InvalidInput),
                        || e.generate_ephemeral(group.parameters())?.agree(invalid),
                    );
                    c.call(
                        &format!("{id}/invalid generator"),
                        Expect::Error(Error::InvalidInput),
                        || e.generate_ephemeral(FfdhParameters::new(&group.p, invalid, group.q.as_deref())),
                    );
                }
                c.call(
                    &format!("{id}/short modulus"),
                    Expect::Error(Error::InvalidInput),
                    || e.generate_ephemeral(FfdhParameters::new(&[1], &group.g, None)),
                );
                c.call(
                    &format!("{id}/overlong peer"),
                    Expect::Error(Error::InvalidInput),
                    || {
                        e.generate_ephemeral(group.parameters())?
                            .agree(&vec![0; group.p.len() + 2])
                    },
                );
                for invalid in [&[][..], &[0][..], &[1][..], &[4][..], &group.p[..]] {
                    c.call(
                        &format!("{id}/invalid subgroup order"),
                        Expect::Error(Error::InvalidInput),
                        || e.generate_ephemeral(FfdhParameters::new(&group.p, &group.g, Some(invalid))),
                    );
                }
                c.call(
                    &format!("{id}/overlong generator"),
                    Expect::Error(Error::InvalidInput),
                    || {
                        e.generate_ephemeral(FfdhParameters::new(
                            &group.p,
                            &vec![0; group.p.len() + 2],
                            group.q.as_deref(),
                        ))
                    },
                );
            }
        }
    }
    for (section, group) in (1..=3).zip(&groups) {
        let fields = v::rfc5114(section);
        let x = &fields["xA"];
        let id = format!("Ffdh/rfc/rfc5114.txt/A.{section}");
        let without_q = FfdhParameters::new(&group.p, &group.g, None);
        if let Some(key) = loaded(
            &mut c,
            p,
            KeyType::Ffdh,
            PrivateKeyMaterial::Ffdh {
                parameters: without_q,
                private_value: x,
            },
            &format!("{id}/optional q absent"),
            der::bit_length(&group.p),
            false,
            false,
        ) {
            agree_kat(
                &mut c,
                &id,
                &*key,
                KeyAgreementAlgorithm::Ffdh,
                &fields["yB"],
                &der::padded(&fields["Z"], group.p.len()),
                false,
            );
        }
        if let Some(key) = loaded(
            &mut c,
            p,
            KeyType::Ffdh,
            PrivateKeyMaterial::Ffdh {
                parameters: group.parameters(),
                private_value: x,
            },
            &id,
            der::bit_length(&group.p),
            false,
            false,
        ) {
            agree_kat(
                &mut c,
                &id,
                &*key,
                KeyAgreementAlgorithm::Ffdh,
                &fields["yB"],
                &der::padded(&fields["Z"], group.p.len()),
                false,
            );
            if c.key_supports(&id, &*key, KeyOperation::Agree(KeyAgreementAlgorithm::Ffdh)) {
                if let Some(own) = c.call(&id, Expect::Success, || {
                    helpers::ffdh_public_value(&*key, group.parameters())
                }) {
                    c.bytes(&id, &own, &der::padded(&fields["yA"], group.p.len()));
                }
            }
            if let Ok(loader) = helpers::private_key_loader(p, KeyType::Ffdh) {
                for invalid in [&[][..], &[0][..], &group.p[..], select::ffdh_order(group)] {
                    c.call(
                        &format!("{id}/invalid exponent"),
                        Expect::Error(Error::InvalidKey),
                        || {
                            loader.load(PrivateKeyMaterial::Ffdh {
                                parameters: group.parameters(),
                                private_value: invalid,
                            })
                        },
                    );
                }
                for invalid in [&[][..], &[0][..], &[1][..], &group.p[..]] {
                    c.call(
                        &format!("{id}/invalid parameter generator"),
                        Expect::Error(Error::InvalidKey),
                        || {
                            loader.load(PrivateKeyMaterial::Ffdh {
                                parameters: FfdhParameters::new(&group.p, invalid, group.q.as_deref()),
                                private_value: x,
                            })
                        },
                    );
                    if invalid.len() <= 1 {
                        c.call(
                            &format!("{id}/invalid parameter modulus"),
                            Expect::Error(Error::InvalidKey),
                            || {
                                loader.load(PrivateKeyMaterial::Ffdh {
                                    parameters: FfdhParameters::new(invalid, &group.g, group.q.as_deref()),
                                    private_value: x,
                                })
                            },
                        );
                    }
                }
                for invalid in [&[][..], &[0][..], &[1][..], &[4][..], &group.p[..]] {
                    c.call(
                        &format!("{id}/invalid parameter q"),
                        Expect::Error(Error::InvalidKey),
                        || {
                            loader.load(PrivateKeyMaterial::Ffdh {
                                parameters: FfdhParameters::new(&group.p, &group.g, Some(invalid)),
                                private_value: x,
                            })
                        },
                    );
                }
                let prefix_zero = |field: &[u8]| [vec![0], field.to_vec()].concat();
                c.call(
                    &format!("{id}/overlong private value"),
                    Expect::Error(Error::InvalidKey),
                    || {
                        loader.load(PrivateKeyMaterial::Ffdh {
                            parameters: group.parameters(),
                            private_value: &vec![0; group.p.len() + 2],
                        })
                    },
                );
                let (padded_p, padded_g, padded_x) = (prefix_zero(&group.p), prefix_zero(&group.g), prefix_zero(x));
                let padded_q = group.q.as_ref().map(|q| prefix_zero(q));
                let padded_parameters = FfdhParameters::new(&padded_p, &padded_g, padded_q.as_deref());
                if let Some(padded) = loaded(
                    &mut c,
                    p,
                    KeyType::Ffdh,
                    PrivateKeyMaterial::Ffdh {
                        parameters: padded_parameters,
                        private_value: &padded_x,
                    },
                    &format!("{id}/leading zero"),
                    der::bit_length(&group.p),
                    false,
                    false,
                ) {
                    agree_kat(
                        &mut c,
                        &id,
                        &*padded,
                        KeyAgreementAlgorithm::Ffdh,
                        &fields["yB"],
                        &der::padded(&fields["Z"], group.p.len()),
                        false,
                    );
                }
            }
        }
    }
    for r in v::response(FFC_FILE) {
        let (modulus, generator, order, x) = (r.bytes("P"), r.bytes("G"), r.bytes("Q"), r.bytes("XstatIUT"));
        let parameters = FfdhParameters::new(&modulus, &generator, Some(&order));
        let id = r.id(FFC_FILE);
        let reason = r.text("Result");
        if reason.contains("private key changed") {
            loaded(
                &mut c,
                p,
                KeyType::Ffdh,
                PrivateKeyMaterial::Ffdh {
                    parameters,
                    private_value: &x,
                },
                &id,
                der::bit_length(&modulus),
                false,
                false,
            );
            continue;
        }
        if let Ok(e) = helpers::ffdh_key_agreement(p) {
            let invalid_peer = reason.contains("CAVS's Static public key");
            let expected = if invalid_peer {
                Expect::Error(Error::InvalidInput)
            } else {
                Expect::Success
            };
            if let Some(shared) = c.call(&format!("{id}/ephemeral peer"), expected, || {
                e.generate_ephemeral(parameters)?.agree(&r.bytes("YstatCAVS"))
            }) {
                c.check(&id, shared.len() == modulus.len(), "FFDH ephemeral secret width");
            }
        }
        if let Some(key) = loaded(
            &mut c,
            p,
            KeyType::Ffdh,
            PrivateKeyMaterial::Ffdh {
                parameters,
                private_value: &x,
            },
            &id,
            der::bit_length(&modulus),
            false,
            false,
        ) {
            if reason.contains("Z changed") || reason.contains("IUT's Static public key") {
                continue;
            }
            agree_kat(
                &mut c,
                &id,
                &*key,
                KeyAgreementAlgorithm::Ffdh,
                &r.bytes("YstatCAVS"),
                &der::padded(&r.bytes("Z"), modulus.len()),
                reason.contains("CAVS's Static public key"),
            );
            if reason.starts_with('P') && c.key_supports(&id, &*key, KeyOperation::Agree(KeyAgreementAlgorithm::Ffdh)) {
                if let Some(own) = c.call(&id, Expect::Success, || helpers::ffdh_public_value(&*key, parameters)) {
                    c.bytes(&id, &own, &der::padded(&r.bytes("YstatIUT"), modulus.len()));
                }
            }
        }
    }
    c.finish();
}
