//! Published-vector conformance tests for unwrapped `picky-crypto` providers.
//! Invoke the macros in a backend's integration test:
//!
//! ```text
//! picky_crypto_testsuite::conformance_tests!(my_backend::provider());
//! picky_crypto_testsuite::differential_tests!(my_backend::provider(), another_backend::provider());
//! ```
//!
//! The macros need no test dependencies beyond this crate and `picky-crypto`.
//! The Wycheproof vectors are a git submodule: run `git submodule update --init` before running tests.
//! Set `PICKY_CRYPTO_TESTSUITE_EXTENDED=1` for expensive iteration tests, RSA generation, and larger property runs.
//! `PROPTEST_CASES` overrides the property case count.
//! [`Options`] permits only the contract's opaque public-key verification failure tolerance.
#![forbid(unsafe_code)]

mod algorithms;
mod asymmetric;
mod der;
mod differential;
mod harness;
mod properties;
#[cfg(test)]
mod provider_value;
mod published;
mod symmetric;
mod vectors;

/// Contract-sanctioned variations in verification diagnostics.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// Accept `VerificationFailed` for an unusable public key (contract section 4).
    pub opaque_public_key_errors: bool,
}

#[doc(hidden)]
pub use asymmetric::{asymmetric_encryption, ffdh, key_agreement, key_generation, private_key, signature};
#[doc(hidden)]
pub use differential::differential;
#[doc(hidden)]
pub use harness::provider;
#[doc(hidden)]
pub use picky_crypto::CryptoProvider as __Provider;
#[doc(hidden)]
pub use properties::properties;
#[doc(hidden)]
pub use symmetric::{aead, cipher, hash, kdf, key_wrap, mac, password_kdf, random, stream_cipher};

/// Instantiates one conformance test per capability area.
#[macro_export]
macro_rules! conformance_tests {
    ($provider:expr) => {
        $crate::conformance_tests!($provider, $crate::Options::default());
    };
    ($provider:expr, $options:expr) => {
        fn __crypto_conformance_provider() -> $crate::__Provider {
            $provider
        }
        fn __crypto_conformance_options() -> $crate::Options {
            $options
        }
        mod crypto_conformance {
            macro_rules! area {
                ($name:ident) => {
                    #[test]
                    fn $name() {
                        $crate::$name(
                            &super::__crypto_conformance_provider(),
                            super::__crypto_conformance_options(),
                        );
                    }
                };
            }
            area!(hash);
            area!(mac);
            area!(password_kdf);
            area!(kdf);
            area!(cipher);
            area!(stream_cipher);
            area!(aead);
            area!(key_wrap);
            area!(signature);
            area!(asymmetric_encryption);
            area!(key_agreement);
            area!(ffdh);
            area!(private_key);
            area!(key_generation);
            area!(random);
            area!(provider);
            area!(properties);
        }
    };
}

/// Instantiates cross-provider deterministic and interoperability tests.
#[macro_export]
macro_rules! differential_tests {
    ($a:expr, $b:expr) => {
        fn __crypto_differential_providers() -> ($crate::__Provider, $crate::__Provider) {
            ($a, $b)
        }
        mod crypto_differential {
            #[test]
            fn interoperability() {
                let (a, b) = super::__crypto_differential_providers();
                $crate::differential(&a, &b);
            }
        }
    };
}
