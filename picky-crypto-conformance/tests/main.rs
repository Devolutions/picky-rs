//! One test per (provider, area) and per (provider pair, differential area).
//! Filter with `cargo test -p picky-crypto-conformance <provider>::<area>`.

use std::sync::OnceLock;

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

/// Defines a module per provider, with one test per conformance area, and the registry of every provider with its backend.
/// Attributes on an entry, such as `#[cfg(feature = "...")]` for a feature-gated backend, apply to its module and its registry element.
macro_rules! providers {
    ($($(#[$attr:meta])* $name:ident ($backend:literal) => $provider:expr, $options:expr;)+) => {
        fn registry() -> &'static [(&'static str, CryptoProvider)] {
            static REGISTRY: OnceLock<Vec<(&'static str, CryptoProvider)>> = OnceLock::new();
            REGISTRY.get_or_init(|| Vec::from([$($(#[$attr])* ($backend, $provider)),+]))
        }

        $(
            $(#[$attr])*
            mod $name {
                use super::*;

                fn provider_under_test() -> CryptoProvider {
                    $provider
                }

                fn options_under_test() -> Options {
                    let mut options: Options = $options;
                    options.reference_provider = reference_provider($backend);
                    options
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

/// Returns the providers of every other backend combined with `with_fallback`, which supply reference ciphertexts to the decryption checks on inconsistent RSA keys.
fn reference_provider(backend: &str) -> Option<&'static CryptoProvider> {
    static REFERENCES: OnceLock<Vec<(&'static str, Option<CryptoProvider>)>> = OnceLock::new();
    let references = REFERENCES.get_or_init(|| {
        registry()
            .iter()
            .map(|(backend, _)| {
                let others = registry().iter().filter(|(other, _)| other != backend);
                (
                    *backend,
                    others.map(|(_, p)| p.clone()).reduce(|a, b| a.with_fallback(&b)),
                )
            })
            .collect()
    });
    references.iter().find(|(b, _)| *b == backend)?.1.as_ref()
}

fn empty() -> CryptoProvider {
    CryptoProvider::builder().build().expect("an empty provider builds")
}

providers! {
    empty ("none") => empty(), Options::default();
}

pairs! {
    empty_empty => (empty(), empty());
}
