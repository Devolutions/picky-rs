use picky_crypto::CryptoProvider;

fn provider() -> CryptoProvider {
    CryptoProvider::builder().build().unwrap()
}

picky_crypto_testsuite::conformance_tests!(provider());
picky_crypto_testsuite::differential_tests!(provider(), provider());
