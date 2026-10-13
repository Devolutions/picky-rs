//! Single-provider conformance areas.
//!
//! Each module's `run` function checks one capability area of a provider and panics with a report of every failed check.

pub mod aead;
pub mod asymmetric_encryption;
pub mod cipher;
pub mod ffdh;
pub mod hash;
pub mod kdf;
pub mod key_agreement;
pub mod key_generation;
pub mod key_wrap;
pub mod mac;
pub mod password_kdf;
pub mod private_key;
pub mod properties;
pub mod provider;
pub mod random;
pub mod signature;
pub mod stream_cipher;

/// Invokes the macro `$m` with the name of every module in [`areas`](crate::areas).
///
/// A runner defines one test per area, calling `picky_crypto_testsuite::areas::$name::run`.
#[macro_export]
macro_rules! for_each_area {
    ($m:ident) => {
        $m! {
            hash,
            mac,
            password_kdf,
            kdf,
            cipher,
            stream_cipher,
            aead,
            key_wrap,
            signature,
            asymmetric_encryption,
            key_agreement,
            ffdh,
            private_key,
            key_generation,
            random,
            provider,
            properties
        }
    };
}
