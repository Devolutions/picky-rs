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

/// RC4 whose keystream XORs every byte with `pad`.
struct FixedRc4(u8);
struct FixedKeystream(u8);
impl StreamCipherContext for FixedKeystream {
    fn apply(&mut self, data: &[u8]) -> Result<OutputBytes, Error> {
        Ok(OutputBytes::new(Zeroizing::new(
            data.iter().map(|b| b ^ self.0).collect(),
        )))
    }
}
impl StreamCipher for FixedRc4 {
    fn algorithm(&self) -> StreamCipherAlgorithm {
        StreamCipherAlgorithm::Rc4
    }
    fn fips(&self) -> bool {
        false
    }
    fn start(&self, _: &[u8]) -> Result<Box<dyn StreamCipherContext>, Error> {
        Ok(Box::new(FixedKeystream(self.0)))
    }
}

/// RC2-CBC that XORs every byte with `pad`, in both directions.
struct FixedRc2(u8);
impl Cipher for FixedRc2 {
    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Rc2Cbc
    }
    fn fips(&self) -> bool {
        false
    }
    fn supports(&self, _: Protection) -> bool {
        true
    }
    fn encrypt(&self, _: &[u8], _: &[u8], data: &[u8]) -> Result<OutputBytes, Error> {
        Ok(OutputBytes::new(Zeroizing::new(
            data.iter().map(|b| b ^ self.0).collect(),
        )))
    }
    fn decrypt(&self, key: &[u8], iv: &[u8], data: &[u8]) -> Result<OutputBytes, Error> {
        self.encrypt(key, iv, data)
    }
}

/// PBKDF2-HMAC-SHA1 that returns `output_len` copies of `pad` above 64 bytes, beyond the published-input property's lengths, and zeros otherwise.
struct FixedPbkdf2(u8);
impl PasswordKdf for FixedPbkdf2 {
    fn algorithm(&self) -> PasswordKdfAlgorithm {
        PasswordKdfAlgorithm::Pbkdf2HmacSha1
    }
    fn fips(&self) -> bool {
        false
    }
    fn derive(&self, _: &[u8], _: &[u8], _: u32, output_len: usize) -> Result<OutputBytes, Error> {
        let byte = if output_len > 64 { self.0 } else { 0 };
        Ok(OutputBytes::new(Zeroizing::new(vec![byte; output_len])))
    }
}

/// Each boundary-control comparison fails exactly when the two providers' entries for it disagree.
#[rstest::rstest]
#[case::all_agree([1, 1, 1], None)]
#[case::rc4_differs([2, 1, 1], Some("Rc4/key length="))]
#[case::rc2_differs([1, 2, 1], Some("Rc2Cbc/"))]
#[case::pbkdf2_differs([1, 1, 2], Some("Pbkdf2HmacSha1/bounds/1/"))]
fn boundary_control_outputs_must_agree(#[case] pads: [u8; 3], #[case] differing: Option<&str>) {
    let provider = |[rc4, rc2, pbkdf2]: [u8; 3]| {
        CryptoProvider::builder()
            .with(Entry::StreamCipher(Arc::new(FixedRc4(rc4))))
            .with(Entry::Cipher(Arc::new(FixedRc2(rc2))))
            .with(Entry::PasswordKdf(Arc::new(FixedPbkdf2(pbkdf2))))
            .build()
            .unwrap()
    };
    let (a, b) = (provider([1, 1, 1]), provider(pads));
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| differential::symmetric::run(&a, &b)))
        .err()
        .and_then(|panic| panic.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    let differ = |marker: &str| {
        failure
            .lines()
            .any(|line| line.contains(marker) && line.contains("/differential") && line.contains("outputs differ"))
    };
    for marker in ["Rc4/key length=", "Rc2Cbc/", "Pbkdf2HmacSha1/bounds/1/"] {
        assert_eq!(differ(marker), differing == Some(marker), "{marker}: {failure}");
    }
}
