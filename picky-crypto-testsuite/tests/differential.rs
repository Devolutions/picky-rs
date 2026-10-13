use std::sync::{Arc, Mutex};

use picky_crypto_testsuite::differential;
use picky_crypto_testsuite::keys::RSA_SIGN_FILES;
use picky_crypto_testsuite::vectors as v;

use crate::asymmetric::{PARTIAL, signing_provider};

// Catches cross verification that skips a signer without its own verifier, or runs where the signer can already verify.
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
            assert_eq!(calls.contains(&algorithm), !signer_verifies, "{algorithm:?}");
        }
    }
}
