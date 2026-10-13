//! Randomized operations must not repeat their output: a mock that repeats it fails the area that checks it.

use picky_crypto::*;
use picky_crypto_testsuite::areas::{aead, asymmetric_encryption, ffdh, key_agreement};
use picky_crypto_testsuite::harness::Options;
use rstest::rstest;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

/// Returns a different output on every call when `fresh`, and the same one otherwise.
struct Randomized {
    fresh: bool,
    calls: AtomicU8,
}
impl Randomized {
    fn output(&self, len: usize) -> OutputBytes {
        let byte = if self.fresh {
            self.calls.fetch_add(1, Ordering::Relaxed).wrapping_add(2)
        } else {
            2
        };
        OutputBytes::new(Zeroizing::new(vec![byte; len]))
    }
}
impl Aead for Randomized {
    fn algorithm(&self) -> AeadAlgorithm {
        AeadAlgorithm::Aes128Gcm
    }
    fn fips(&self) -> bool {
        false
    }
    fn supports(&self, protection: Protection) -> bool {
        protection == Protection::Apply
    }
    fn seal(&self, _: &[u8], _: &[u8], plaintext: &[u8]) -> Result<Sealed, Error> {
        Ok(Sealed::new(
            self.output(12),
            OutputBytes::new(Zeroizing::new(vec![0; plaintext.len() + 16])),
        ))
    }
    fn open(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<OutputBytes, Error> {
        Err(Error::Unsupported(Algorithm::Aead(AeadAlgorithm::Aes128Gcm)))
    }
}
impl AsymmetricEncryptor for Randomized {
    fn algorithm(&self) -> AsymmetricEncryptionAlgorithm {
        AsymmetricEncryptionAlgorithm::RsaPkcs1v15
    }
    fn fips(&self) -> bool {
        false
    }
    fn encrypt(&self, _: PublicKey<'_>, _: &[u8]) -> Result<OutputBytes, Error> {
        Ok(self.output(256))
    }
}
struct Ephemeral(OutputBytes);
impl EphemeralSecret for Ephemeral {
    fn public_key(&self) -> Result<OutputBytes, Error> {
        Ok(self.0.clone())
    }
    fn agree(self: Box<Self>, _: &[u8]) -> Result<OutputBytes, Error> {
        Ok(OutputBytes::new(Zeroizing::new(vec![1; 32])))
    }
}
impl KeyAgreement for Randomized {
    fn algorithm(&self) -> KeyAgreementAlgorithm {
        KeyAgreementAlgorithm::X25519
    }
    fn fips(&self) -> bool {
        false
    }
    fn generate_ephemeral(&self) -> Result<Box<dyn EphemeralSecret>, Error> {
        Ok(Box::new(Ephemeral(self.output(32))))
    }
}
impl FfdhKeyAgreement for Randomized {
    fn fips(&self) -> bool {
        false
    }
    fn generate_ephemeral(&self, parameters: FfdhParameters<'_>) -> Result<Box<dyn EphemeralSecret>, Error> {
        Ok(Box::new(Ephemeral(self.output(parameters.p.len()))))
    }
}

type Area = fn(&CryptoProvider, Options);

#[rstest]
#[case::aead(|m: Arc<Randomized>| Entry::Aead(m), aead::run as Area, "two seals of one input returned the same nonce")]
#[case::rsa_encryption(|m: Arc<Randomized>| Entry::AsymmetricEncryptor(m), asymmetric_encryption::run as Area, "two encryptions of one message are identical")]
#[case::ecdh(|m: Arc<Randomized>| Entry::KeyAgreement(m), key_agreement::run as Area, "two ephemeral public keys are identical")]
#[case::ffdh(|m: Arc<Randomized>| Entry::FfdhKeyAgreement(m), ffdh::run as Area, "two ephemeral public keys are identical")]
fn repeated_random_output_fails(
    #[case] entry: fn(Arc<Randomized>) -> Entry,
    #[case] run: Area,
    #[case] message: &str,
    #[values(false, true)] fresh: bool,
) {
    let mock = Arc::new(Randomized {
        fresh,
        calls: AtomicU8::new(0),
    });
    let provider = CryptoProvider::builder().with(entry(mock)).build().unwrap();
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&provider, Options::default())))
        .err()
        .map(|panic| panic.downcast_ref::<String>().cloned().unwrap_or_default())
        .unwrap_or_default();
    assert_eq!(failure.contains(message), !fresh, "{failure}");
}
