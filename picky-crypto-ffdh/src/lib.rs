//! Finite-field Diffie-Hellman entries for the picky cryptographic provider contract, implemented over crypto-bigint.
//! See the crate README for the checks, the capacity limit and the exponent generation.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

// UNTESTED: every secret this crate holds (private exponents, rejected candidates, generator output, shared secrets in
// integer and Montgomery form, and their encodings) stays in `Zeroizing`.
// A copy left in freed memory can outlive the operation and leak through a later read or a memory dump.
// When adding code, wrap every secret this crate owns in `Zeroizing`, and never resize an owned secret `BoxedUint`,
// which reallocates without wiping the old limbs.
// UNTESTED: no type holding secret material implements or derives `Debug`.
// crypto-bigint's `BoxedUint` and `BoxedMontyForm` print their value, so a derived `Debug` can carry a secret into logs
// or panic messages.
// When adding a type holding an exponent or a shared secret, don't derive `Debug` on it or on any type containing it.

mod group;

use crypto_bigint::BoxedUint;
use group::Group;
use picky_crypto::{
    Algorithm, CryptoProvider, Entry, EphemeralSecret, Error, FfdhKeyAgreement, FfdhParameters, KeyAgreementAlgorithm,
    KeyOperation, KeyType, OutputBytes, PrivateKey, PrivateKeyLoader, PrivateKeyMaterial, RandomAlgorithm,
    SecureRandom, Zeroizing,
};
use std::sync::Arc;

/// Builds the FFDH provider over `base`'s secure random entry: ephemeral agreement and static key loading.
/// The entry is taken when this function runs, and ephemeral exponents come only from it.
/// The provider is empty when `base` has no secure random entry.
/// Both entries, and every key the loader returns, report `fips() == false`.
pub fn provider(base: &CryptoProvider) -> CryptoProvider {
    let builder = CryptoProvider::builder();
    let builder = match base.get(Algorithm::Random(RandomAlgorithm::SecureRandom)) {
        Some(Entry::SecureRandom(random)) => builder
            .with(Entry::FfdhKeyAgreement(Arc::new(Agreement {
                random: Arc::clone(random),
            })))
            .with(Entry::PrivateKeyLoader(Arc::new(Loader))),
        _ => builder,
    };
    builder.build().expect("at most two distinct FFDH entries")
}

struct Agreement {
    random: Arc<dyn SecureRandom>,
}

impl FfdhKeyAgreement for Agreement {
    fn fips(&self) -> bool {
        false
    }

    fn generate_ephemeral(&self, parameters: FfdhParameters<'_>) -> Result<Box<dyn EphemeralSecret>, Error> {
        let group = Group::new(
            parameters,
            None,
            Algorithm::KeyAgreement(KeyAgreementAlgorithm::Ffdh),
            Error::InvalidInput,
        )?;
        let exponent = group.sample(&*self.random)?;
        let public = group.power(group.generator(), &exponent);
        Ok(Box::new(Ephemeral {
            group,
            exponent,
            public,
        }))
    }
}

struct Ephemeral {
    group: Group,
    exponent: Zeroizing<BoxedUint>,
    public: OutputBytes,
}

impl EphemeralSecret for Ephemeral {
    fn public_key(&self) -> Result<OutputBytes, Error> {
        Ok(self.public.clone())
    }

    fn agree(self: Box<Self>, peer_public_key: &[u8]) -> Result<OutputBytes, Error> {
        let peer = self.group.peer(peer_public_key)?;
        Ok(self.group.power(&peer, &self.exponent))
    }
}

struct Loader;

impl PrivateKeyLoader for Loader {
    fn key_type(&self) -> KeyType {
        KeyType::Ffdh
    }

    fn fips(&self) -> bool {
        false
    }

    fn load(&self, private_key: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error> {
        let PrivateKeyMaterial::Ffdh {
            parameters,
            private_value,
        } = private_key
        else {
            return Err(Error::InvalidKey);
        };
        let group = Group::new(
            parameters,
            Some(private_value),
            Algorithm::PrivateKeyLoading(KeyType::Ffdh),
            Error::InvalidKey,
        )?;
        let exponent = group.private_value(private_value)?;
        Ok(Box::new(StaticKey { group, exponent }))
    }
}

struct StaticKey {
    group: Group,
    exponent: Zeroizing<BoxedUint>,
}

impl PrivateKey for StaticKey {
    fn key_type(&self) -> KeyType {
        KeyType::Ffdh
    }

    fn key_size_bits(&self) -> usize {
        self.group.bits()
    }

    fn supports(&self, operation: KeyOperation) -> bool {
        operation == KeyOperation::Agree(KeyAgreementAlgorithm::Ffdh)
    }

    fn fips(&self) -> bool {
        false
    }

    fn agree(&self, algorithm: KeyAgreementAlgorithm, peer_public_key: &[u8]) -> Result<OutputBytes, Error> {
        if algorithm != KeyAgreementAlgorithm::Ffdh {
            return Err(Error::Unsupported(Algorithm::KeyAgreement(algorithm)));
        }
        let peer = self.group.peer(peer_public_key)?;
        Ok(self.group.power(&peer, &self.exponent))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use picky_crypto::helpers;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A generator that copies the scripted draws into the buffer in turn, and panics once they run out.
    pub(crate) struct Scripted {
        draws: Vec<Result<Vec<u8>, Error>>,
        calls: AtomicUsize,
    }

    impl Scripted {
        pub(crate) fn new(draws: impl IntoIterator<Item = Result<Vec<u8>, Error>>) -> Self {
            Self {
                draws: draws.into_iter().collect(),
                calls: AtomicUsize::new(0),
            }
        }

        pub(crate) fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl SecureRandom for Scripted {
        fn algorithm(&self) -> RandomAlgorithm {
            RandomAlgorithm::SecureRandom
        }

        fn fips(&self) -> bool {
            false
        }

        fn fill(&self, dest: &mut [u8]) -> Result<(), Error> {
            let draw = self.draws[self.calls.fetch_add(1, Ordering::SeqCst)].clone()?;
            dest.copy_from_slice(&draw);
            Ok(())
        }
    }

    /// Returns 2^(bits − 1) + 1: an odd modulus of exactly `bits` bits, used only for its size.
    pub(crate) fn structural_modulus(bits: usize) -> Vec<u8> {
        let mut p = vec![0; bits.div_ceil(8)];
        p[0] = 1 << ((bits - 1) % 8);
        p[bits.div_ceil(8) - 1] |= 1;
        p
    }

    /// Builds the FFDH provider over a base whose only entry is a generator scripted with `draws`.
    fn ffdh(draws: impl IntoIterator<Item = Result<Vec<u8>, Error>>) -> CryptoProvider {
        let base = CryptoProvider::builder()
            .with(Entry::SecureRandom(Arc::new(Scripted::new(draws))))
            .build()
            .unwrap();
        provider(&base)
    }

    /// Loads a static key with g = 2.
    fn load(p: &[u8], q: Option<&[u8]>, x: &[u8]) -> Result<Box<dyn PrivateKey>, Error> {
        let provider = ffdh([]);
        helpers::private_key_loader(&provider, KeyType::Ffdh)?.load(PrivateKeyMaterial::Ffdh {
            parameters: FfdhParameters::new(p, &[2], q),
            private_value: x,
        })
    }

    // Faults: the ephemeral exponent is not drawn from the given generator, or the public value is not g^x for it.
    // The conformance suite's round trips and range checks hold for any exponent and any base shared by both sides.
    #[test]
    fn ephemeral_public_value_uses_the_drawn_exponent() {
        let p = structural_modulus(1024);
        // With q = 5, the draw 3 is accepted as the exponent 4, so the public value is 2^4.
        let provider = ffdh([Ok(vec![3])]);
        let ephemeral = helpers::ffdh_key_agreement(&provider)
            .unwrap()
            .generate_ephemeral(FfdhParameters::new(&p, &[2], Some(&[5])))
            .unwrap();
        assert_eq!(
            ephemeral.public_key().unwrap().as_ref(),
            [&[0; 127][..], &[16]].concat()
        );
    }

    // Faults: an entry reports FIPS approval, the provider has an entry other than its two FFDH entries, or it has
    // entries over a base without a secure random entry.
    #[test]
    fn entries_follow_the_base_random_entry() {
        let provider = ffdh([]);
        assert_eq!(provider.entries().count(), 2);
        assert!(!provider.entries().any(helpers::entry_fips));
        let empty = CryptoProvider::builder().build().unwrap();
        assert_eq!(super::provider(&empty).entries().count(), 0);
    }

    // Faults: the minimum size check or `key_size_bits` counts whole bytes instead of bits, or the capacity limit is
    // off by one, yields to the parity check, or names the other entry's algorithm.
    // Published groups are whole bytes long and stop at 4096 bits.
    #[test]
    fn modulus_size_bounds() {
        assert_eq!(
            load(&structural_modulus(1023), None, &[1]).err(),
            Some(Error::InvalidKey)
        );
        assert_eq!(
            load(&structural_modulus(8191), None, &[1]).unwrap().key_size_bits(),
            8191
        );
        assert!(load(&structural_modulus(8192), None, &[1]).is_ok());
        // 2^8192: an even modulus one bit above the capacity limit.
        let even = [&[1][..], &[0; 1024]].concat();
        assert_eq!(
            load(&even, None, &[1]).err(),
            Some(Error::Unsupported(Algorithm::PrivateKeyLoading(KeyType::Ffdh)))
        );
        let provider = ffdh([]);
        let agreement = helpers::ffdh_key_agreement(&provider).unwrap();
        assert_eq!(
            agreement
                .generate_ephemeral(FfdhParameters::new(&even, &[2], None))
                .err(),
            Some(Error::Unsupported(Algorithm::KeyAgreement(KeyAgreementAlgorithm::Ffdh)))
        );
    }

    // Faults: the capacity limit takes precedence over the encoding bound, or the bound misses an empty encoding or
    // the private value.
    // Published groups stay within the capacity limit.
    #[test]
    fn encoding_bound_precedes_capacity_limit() {
        // 2^8192, one bit above the capacity limit; its encoding bound is 1026 bytes.
        let p = [&[1][..], &[0; 1024]].concat();
        let padded = [&[0, 0][..], &p].concat();
        let overlong = vec![1; 1027];
        let provider = ffdh([]);
        let loader = helpers::private_key_loader(&provider, KeyType::Ffdh).unwrap();
        let load = |p: &[u8], g: &[u8], q: Option<&[u8]>, x: &[u8]| {
            loader
                .load(PrivateKeyMaterial::Ffdh {
                    parameters: FfdhParameters::new(p, g, q),
                    private_value: x,
                })
                .err()
        };
        for error in [
            load(&padded, &[2], None, &[1]),
            load(&p, &[], None, &[1]),
            load(&p, &[2], Some(&[]), &[1]),
            load(&p, &[2], None, &[]),
            load(&p, &[2], None, &overlong),
        ] {
            assert_eq!(error, Some(Error::InvalidKey));
        }
        let agreement = helpers::ffdh_key_agreement(&provider).unwrap();
        assert_eq!(
            agreement.generate_ephemeral(FfdhParameters::new(&p, &[], None)).err(),
            Some(Error::InvalidInput)
        );
    }

    // Faults: the encoding bound skips p or q, or a private value equal to B − 1 is refused.
    // The conformance suite checks the encoding bound only on g, x and peer values, and x only at B and beyond.
    #[test]
    fn encoding_and_private_value_bounds() {
        let p = structural_modulus(1024);
        // 130 bytes, one more than the encoding bound for this p.
        let overlong = |value: &[u8]| [vec![0; 130 - value.len()], value.to_vec()].concat();
        assert_eq!(load(&overlong(&p), Some(&[5]), &[1]).err(), Some(Error::InvalidKey));
        assert_eq!(load(&p, Some(&overlong(&[5])), &[1]).err(), Some(Error::InvalidKey));
        // Without q, B = (p − 1) / 2 = 2^1022 for this p.
        assert!(load(&p, None, &[&[0x3F][..], &[0xFF; 127]].concat()).is_ok());
    }
}
