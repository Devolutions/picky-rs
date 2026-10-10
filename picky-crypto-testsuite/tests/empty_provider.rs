use picky_crypto::CryptoProvider;
use picky_crypto_testsuite::harness::Options;

fn provider() -> CryptoProvider {
    CryptoProvider::builder().build().unwrap()
}

macro_rules! conformance {
    ($($area:ident),* $(,)?) => {
        mod conformance {
            $(
                #[test]
                fn $area() {
                    picky_crypto_testsuite::areas::$area::run(&super::provider(), super::Options::default());
                }
            )*
        }
    };
}

macro_rules! differential {
    ($($area:ident),* $(,)?) => {
        mod differential {
            $(
                #[test]
                fn $area() {
                    picky_crypto_testsuite::differential::$area::run(&super::provider(), &super::provider());
                }
            )*
        }
    };
}

picky_crypto_testsuite::for_each_area!(conformance);
picky_crypto_testsuite::for_each_differential_area!(differential);
