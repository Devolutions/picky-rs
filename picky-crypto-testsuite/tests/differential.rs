use std::sync::{Arc, Mutex};

use picky_crypto::*;
use picky_crypto_testsuite::differential;
use picky_crypto_testsuite::keys::RSA_SIGN_FILES;
use picky_crypto_testsuite::vectors as v;

use crate::asymmetric::{PARTIAL, signing_provider};

// Catches cross verification that skips a signer without its own verifier or one without published vectors, or runs where the signer's own verifier is checked by published vectors.
#[test]
fn cross_verification_runs_only_where_the_signer_cannot_verify() {
    let source = v::wycheproof(RSA_SIGN_FILES[0]);
    let signature = v::field(&v::tests(&source.test_groups[0])[0], "sig");
    for signer_verifies in [false, true] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let signer = signing_provider(&signature, signer_verifies, &calls);
        let verifier = signing_provider(&signature, true, &calls);
        differential::signature::run(&signer, &verifier);
        let calls = calls.lock().unwrap();
        for algorithm in PARTIAL {
            let unpublished = algorithm == SignatureAlgorithm::RsaPkcs1v15Md5;
            assert_eq!(
                calls.contains(&algorithm),
                !signer_verifies || unpublished,
                "{algorithm:?}"
            );
        }
    }
}

/// HMAC-SHA1 that returns `tag` for every key and message, and advertises only verification unless `generates`.
struct FixedMac {
    tag: u8,
    generates: bool,
}
struct FixedTag(u8);
impl MacContext for FixedTag {
    fn update(&mut self, _: &[u8]) -> Result<(), Error> {
        Ok(())
    }
    fn finish(self: Box<Self>) -> Result<MacOutput, Error> {
        Ok(MacOutput::new(Zeroizing::new(vec![self.0; 20])))
    }
}
impl Mac for FixedMac {
    fn algorithm(&self) -> MacAlgorithm {
        MacAlgorithm::HmacSha1
    }
    fn fips(&self) -> bool {
        false
    }
    fn supports(&self, protection: Protection) -> bool {
        (protection == Protection::Apply) == self.generates
    }
    fn start(&self, _: &[u8], protection: Protection) -> Result<Box<dyn MacContext>, Error> {
        if !self.supports(protection) {
            return Err(Error::Unsupported(Algorithm::Mac(MacAlgorithm::HmacSha1)));
        }
        Ok(Box::new(FixedTag(self.tag)))
    }
}

#[rstest::rstest]
#[case::same_tags(1, true, false)]
#[case::different_tags(2, true, true)]
#[case::one_cannot_generate(2, false, false)]
fn empty_key_hmac_tags_must_agree(#[case] tag: u8, #[case] generates: bool, #[case] fails: bool) {
    let provider = |tag, generates| {
        CryptoProvider::builder()
            .with(Entry::Mac(Arc::new(FixedMac { tag, generates })))
            .build()
            .unwrap()
    };
    let (a, b) = (provider(1, true), provider(tag, generates));
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| differential::symmetric::run(&a, &b)))
        .err()
        .and_then(|panic| panic.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    assert_eq!(failure.contains("empty-key tags differ"), fails, "{failure}");
}
