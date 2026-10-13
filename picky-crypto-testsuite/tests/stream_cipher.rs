//! RC4 key lengths: an entry that rejects a must-support key length fails the area.

use picky_crypto::*;
use picky_crypto_testsuite::areas::stream_cipher;
use picky_crypto_testsuite::harness::Options;
use rstest::rstest;
use std::sync::Arc;

/// Accepts keys of 1 to `max` bytes and XORs data with a keystream of zeros.
struct Capped(usize);
struct Identity;
impl StreamCipherContext for Identity {
    fn apply(&mut self, data: &[u8]) -> Result<OutputBytes, Error> {
        Ok(OutputBytes::new(Zeroizing::new(data.to_vec())))
    }
}
impl StreamCipher for Capped {
    fn algorithm(&self) -> StreamCipherAlgorithm {
        StreamCipherAlgorithm::Rc4
    }
    fn fips(&self) -> bool {
        false
    }
    fn start(&self, key: &[u8]) -> Result<Box<dyn StreamCipherContext>, Error> {
        if key.is_empty() || key.len() > self.0 {
            return Err(Error::InvalidKey);
        }
        Ok(Box::new(Identity))
    }
}

#[rstest]
#[case::capped_at_32(32, true)]
#[case::full_domain(256, false)]
fn longest_must_support_key(#[case] max: usize, #[case] fails: bool) {
    let provider = CryptoProvider::builder()
        .with(Entry::StreamCipher(Arc::new(Capped(max))))
        .build()
        .unwrap();
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        stream_cipher::run(&provider, Options::default())
    }))
    .err()
    .and_then(|panic| panic.downcast_ref::<String>().cloned())
    .unwrap_or_default();
    // The keystream of zeros fails the RFC 6229 known answers either way; only the 256-byte key check differs.
    assert!(failure.contains("rfc6229"), "{failure}");
    assert_eq!(failure.contains("key length=256"), fails, "{failure}");
}
