//! One test per (provider, area) and per (provider pair, differential area).
//! Filter with `cargo test -p picky-crypto-conformance <provider>::<area>`.

use picky_crypto::CryptoProvider;
use picky_crypto_testsuite::harness::Options;

/// Defines one test per conformance area, calling the enclosing module's `provider_under_test` and `options_under_test`.
macro_rules! area_tests {
    ($($area:ident),+) => {
        $(
            #[test]
            fn $area() {
                picky_crypto_testsuite::areas::$area::run(&provider_under_test(), options_under_test());
            }
        )+
    };
}

/// Defines one test per differential area, calling the enclosing module's `providers_under_test`.
macro_rules! differential_tests {
    ($($area:ident),+) => {
        $(
            #[test]
            fn $area() {
                let (a, b) = providers_under_test();
                picky_crypto_testsuite::differential::$area::run(&a, &b);
            }
        )+
    };
}

/// Defines a module per provider, with one test per conformance area.
macro_rules! providers {
    ($($name:ident => $provider:expr, $options:expr;)+) => {
        $(
            mod $name {
                use super::*;

                fn provider_under_test() -> CryptoProvider {
                    $provider
                }

                fn options_under_test() -> Options {
                    $options
                }

                picky_crypto_testsuite::for_each_area!(area_tests);
            }
        )+
    };
}

/// Defines a module per provider pair, with one test per differential area.
macro_rules! pairs {
    ($($name:ident => ($a:expr, $b:expr);)+) => {
        $(
            mod $name {
                use super::*;

                fn providers_under_test() -> (CryptoProvider, CryptoProvider) {
                    ($a, $b)
                }

                picky_crypto_testsuite::for_each_differential_area!(differential_tests);
            }
        )+
    };
}

fn empty() -> CryptoProvider {
    CryptoProvider::builder().build().expect("an empty provider builds")
}

providers! {
    empty => empty(), Options::default();
}

pairs! {
    empty_empty => (empty(), empty());
}
