//! Cryptographic capability entries, provider composition and zeroizing outputs.
//! See [`contract`] for the normative behavior.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod algorithm;
mod buffers;
mod default;
mod error;
mod keys;
mod provider;
mod traits;

pub use algorithm::{
    AeadAlgorithm, Algorithm, AsymmetricEncryptionAlgorithm, CipherAlgorithm, HashAlgorithm, KdfAlgorithm,
    KeyAgreementAlgorithm, KeyGenerationAlgorithm, KeyType, KeyWrapAlgorithm, MacAlgorithm, PasswordKdfAlgorithm,
    Protection, RandomAlgorithm, Requirement, SignatureAlgorithm, StreamCipherAlgorithm,
};
pub use buffers::{MacGeneration, MacOutput, MacTag, MacVerification, MacVerifier, OutputBytes, Sealed, X25519Scalar};
pub use default::{get_default, get_or_install_default, install_default};
pub use error::{BuildError, Error};
pub use keys::{FfdhParameters, KeyOperation, PrivateKeyMaterial, PublicKey};
pub use provider::{CryptoProvider, Entry, ProviderBuilder};
pub use traits::{
    Aead, AsymmetricEncryptor, Cipher, EphemeralSecret, FfdhKeyAgreement, Hash, HashContext, Kdf, KeyAgreement,
    KeyGenerator, KeyWrap, Mac, MacContext, PasswordKdf, PrivateKey, PrivateKeyLoader, SecureRandom, SignatureVerifier,
    StreamCipher, StreamCipherContext,
};

/// Zeroizing storage for contract outputs.
/// See CONTRACT.md section 2.
pub use zeroize::Zeroizing;

/// Convenience functions over the provider contract.
/// See CONTRACT.md section 10.
pub mod helpers;

/// Normative provider behavior.
/// See CONTRACT.md section 1.
pub mod contract {
    #![doc = include_str!("../CONTRACT.md")]
    #[allow(unused_imports)]
    use super::*;
}

#[cfg(test)]
mod tests;
