use picky_crypto::*;
use picky_crypto_testsuite::asymmetric::{RSA_SIGN_FILES, inconsistent_signatures};
use picky_crypto_testsuite::differential::*;
use picky_crypto_testsuite::harness::Checks;
use picky_crypto_testsuite::vectors as v;
use std::sync::{Arc, Mutex};

struct SigningLoader {
    signature: Vec<u8>,
}
struct SigningKey {
    signature: Vec<u8>,
}
struct Verifier {
    algorithm: SignatureAlgorithm,
    signature: Vec<u8>,
    calls: Arc<Mutex<Vec<SignatureAlgorithm>>>,
}
impl PrivateKeyLoader for SigningLoader {
    fn key_type(&self) -> KeyType {
        KeyType::Rsa
    }
    fn fips(&self) -> bool {
        false
    }
    fn load(&self, _: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error> {
        Ok(Box::new(SigningKey {
            signature: self.signature.clone(),
        }))
    }
}
impl PrivateKey for SigningKey {
    fn key_type(&self) -> KeyType {
        KeyType::Rsa
    }
    fn key_size_bits(&self) -> usize {
        2048
    }
    fn fips(&self) -> bool {
        false
    }
    fn supports(&self, operation: KeyOperation) -> bool {
        matches!(
            operation,
            KeyOperation::Sign(
                SignatureAlgorithm::RsaPkcs1v15Md5
                    | SignatureAlgorithm::RsaPkcs1v15Sha3_384
                    | SignatureAlgorithm::RsaPkcs1v15Sha3_512
            )
        )
    }
    fn sign(&self, algorithm: SignatureAlgorithm, _: &[u8]) -> Result<OutputBytes, Error> {
        if !self.supports(KeyOperation::Sign(algorithm)) {
            return Err(Error::Unsupported(Algorithm::Signature(algorithm)));
        }
        Ok(OutputBytes::new(Zeroizing::new(self.signature.clone())))
    }
}
impl SignatureVerifier for Verifier {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
    fn fips(&self) -> bool {
        false
    }
    fn verify(&self, _: PublicKey<'_>, _: &[u8], signature: &[u8]) -> Result<(), Error> {
        self.calls.lock().unwrap().push(self.algorithm);
        if signature == self.signature {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}
fn mock(signature: &[u8], calls: Arc<Mutex<Vec<SignatureAlgorithm>>>) -> CryptoProvider {
    let mut builder = CryptoProvider::builder().with(Entry::PrivateKeyLoader(Arc::new(SigningLoader {
        signature: signature.to_vec(),
    })));
    for algorithm in [
        SignatureAlgorithm::RsaPkcs1v15Md5,
        SignatureAlgorithm::RsaPkcs1v15Sha3_384,
        SignatureAlgorithm::RsaPkcs1v15Sha3_512,
    ] {
        builder = builder.with(Entry::SignatureVerifier(Arc::new(Verifier {
            algorithm,
            signature: signature.to_vec(),
            calls: Arc::clone(&calls),
        })));
    }
    builder.build().unwrap()
}

#[test]
fn rsa_cross_signing_includes_algorithms_without_generation_vectors() {
    let source = v::wycheproof(RSA_SIGN_FILES[0]);
    let signature = v::field(&v::tests(&source.test_groups[0])[0], "sig");
    let a_calls = Arc::new(Mutex::new(Vec::new()));
    let b_calls = Arc::new(Mutex::new(Vec::new()));
    let a = mock(&signature, Arc::clone(&a_calls));
    let b = mock(&signature, Arc::clone(&b_calls));
    let mut c = Checks::default();
    cross_keys(&mut c, &a, &b);
    cross_keys(&mut c, &b, &a);
    c.finish();
    for calls in [a_calls, b_calls] {
        let calls = calls.lock().unwrap();
        for algorithm in [
            SignatureAlgorithm::RsaPkcs1v15Md5,
            SignatureAlgorithm::RsaPkcs1v15Sha3_384,
            SignatureAlgorithm::RsaPkcs1v15Sha3_512,
        ] {
            assert!(calls.contains(&algorithm));
        }
    }
}

#[test]
fn inconsistent_signatures_cover_partial_keys_and_fallback_verification() {
    let source = v::wycheproof(RSA_SIGN_FILES[0]);
    let group = &source.test_groups[0];
    let signature = v::field(&v::tests(group)[0], "sig");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let other_calls = Arc::new(Mutex::new(Vec::new()));
    let verifier = mock(&signature, Arc::clone(&calls));
    let other = mock(&signature, Arc::clone(&other_calls));
    let empty = CryptoProvider::builder().build().unwrap();
    let base = SigningKey {
        signature: signature.clone(),
    };
    let derived = SigningKey { signature };
    for local in [&verifier, &empty] {
        calls.lock().unwrap().clear();
        other_calls.lock().unwrap().clear();
        let mut c = Checks::default();
        inconsistent_signatures(
            &mut c,
            local,
            Some(&other),
            &base,
            &derived,
            "inconsistent RSA routing",
            (RSA_SIGN_FILES[0], group),
        );
        c.finish();
        let calls = calls.lock().unwrap();
        let other_calls = other_calls.lock().unwrap();
        for algorithm in [
            SignatureAlgorithm::RsaPkcs1v15Md5,
            SignatureAlgorithm::RsaPkcs1v15Sha3_384,
            SignatureAlgorithm::RsaPkcs1v15Sha3_512,
        ] {
            assert_eq!(
                calls.iter().filter(|&&actual| actual == algorithm).count(),
                if local.entries().next().is_some() { 2 } else { 0 }
            );
            assert_eq!(other_calls.iter().filter(|&&actual| actual == algorithm).count(), 2);
        }
    }
}
