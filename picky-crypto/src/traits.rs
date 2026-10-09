use crate::{
    AeadAlgorithm, Algorithm, AsymmetricEncryptionAlgorithm, CipherAlgorithm, Error, FfdhParameters, HashAlgorithm,
    KdfAlgorithm, KeyAgreementAlgorithm, KeyGenerationAlgorithm, KeyOperation, KeyType, KeyWrapAlgorithm, MacAlgorithm,
    MacOutput, OutputBytes, PasswordKdfAlgorithm, PrivateKeyMaterial, Protection, PublicKey, RandomAlgorithm, Sealed,
    SignatureAlgorithm, StreamCipherAlgorithm,
};
use std::fmt;

macro_rules! capability {
    ($name:ident, $algorithm:ty, $citation:literal, {$($operations:tt)*}) => {
        /// Capability for one algorithm.
        #[doc = $citation]
        pub trait $name: Send + Sync {
            /// The entry's algorithm.
            #[doc = $citation]
            fn algorithm(&self) -> $algorithm;
            /// Whether computations execute in a positively established FIPS module.
            /// See CONTRACT.md section 6.15.
            fn fips(&self) -> bool;
            $($operations)*
        }
        impl fmt::Debug for dyn $name + '_ {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("algorithm", &self.algorithm()).field("fips", &self.fips()).finish()
            }
        }
    };
}

capability!(Hash, HashAlgorithm, "See CONTRACT.md section 6.1.", {
    /// Starts an empty streaming context.
    /// See CONTRACT.md section 6.1.
    fn start(&self) -> Result<Box<dyn HashContext>, Error>;
});

/// Streaming hash context; unusable after an update error.
/// See CONTRACT.md sections 2 and 6.1.
pub trait HashContext: Send {
    /// Adds data, including empty slices.
    /// See CONTRACT.md section 6.1.
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;
    /// Consumes the context and returns the full digest.
    /// See CONTRACT.md section 6.1.
    fn finish(self: Box<Self>) -> Result<OutputBytes, Error>;
}

capability!(Mac, MacAlgorithm, "See CONTRACT.md section 6.2.", {
    /// Whether the named protection is available.
    /// See CONTRACT.md section 8.
    fn supports(&self, protection: Protection) -> bool;
    /// Starts a context for the protection, or returns Unsupported when refused.
    /// See CONTRACT.md section 6.2.
    fn start(&self, key: &[u8], protection: Protection) -> Result<Box<dyn MacContext>, Error>;
});

/// Streaming MAC context; unusable after an update error.
/// See CONTRACT.md sections 2 and 6.2.
pub trait MacContext: Send {
    /// Adds data, including empty slices.
    /// See CONTRACT.md section 6.2.
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;
    /// Consumes the context and returns the full, untruncated tag.
    /// See CONTRACT.md section 6.2.
    fn finish(self: Box<Self>) -> Result<MacOutput, Error>;
}

capability!(PasswordKdf, PasswordKdfAlgorithm, "See CONTRACT.md section 6.3.", {
    /// Derives bytes using PBKDF2 with the named PRF.
    /// See CONTRACT.md section 6.3.
    fn derive(&self, password: &[u8], salt: &[u8], iterations: u32, output_len: usize) -> Result<OutputBytes, Error>;
});
capability!(Kdf, KdfAlgorithm, "See CONTRACT.md section 6.4.", {
    /// Derives bytes from Z and OtherInfo, or K_IN and complete fixed input.
    /// See CONTRACT.md section 6.4.
    fn derive(&self, secret: &[u8], fixed_info: &[u8], output_len: usize) -> Result<OutputBytes, Error>;
});
capability!(Cipher, CipherAlgorithm, "See CONTRACT.md section 6.5.", {
    /// Whether the named protection is available.
    /// See CONTRACT.md section 8.
    fn supports(&self, protection: Protection) -> bool;
    /// Encrypts CBC data without padding.
    /// See CONTRACT.md section 6.5.
    fn encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<OutputBytes, Error>;
    /// Decrypts CBC data without removing padding.
    /// See CONTRACT.md section 6.5.
    fn decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<OutputBytes, Error>;
});
capability!(StreamCipher, StreamCipherAlgorithm, "See CONTRACT.md section 6.6.", {
    /// Starts an RC4 keystream.
    /// See CONTRACT.md section 6.6.
    fn start(&self, key: &[u8]) -> Result<Box<dyn StreamCipherContext>, Error>;
});

/// Stateful keystream; unusable after an apply error.
/// See CONTRACT.md sections 2 and 6.6.
pub trait StreamCipherContext: Send {
    /// XORs data with the next keystream bytes, advancing the state.
    /// See CONTRACT.md section 6.6.
    fn apply(&mut self, data: &[u8]) -> Result<OutputBytes, Error>;
}

capability!(Aead, AeadAlgorithm, "See CONTRACT.md section 6.7.", {
    /// Whether the named protection is available.
    /// See CONTRACT.md section 8.
    fn supports(&self, protection: Protection) -> bool;
    /// Seals with an internally generated nonce; the caller enforces per-key call limits.
    /// See CONTRACT.md section 6.7.
    fn seal(&self, key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Sealed, Error>;
    /// Opens ciphertext and tag; releases no plaintext on authentication failure.
    /// See CONTRACT.md section 6.7.
    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext_and_tag: &[u8]) -> Result<OutputBytes, Error>;
});
capability!(KeyWrap, KeyWrapAlgorithm, "See CONTRACT.md section 6.8.", {
    /// Whether the named protection is available.
    /// See CONTRACT.md section 8.
    fn supports(&self, protection: Protection) -> bool;
    /// Wraps an AES content-encryption key with the RFC 3394 default IV.
    /// See CONTRACT.md section 6.8.
    fn wrap(&self, kek: &[u8], key_data: &[u8]) -> Result<OutputBytes, Error>;
    /// Unwraps a key, failing without an integrity-check reason.
    /// See CONTRACT.md section 6.8.
    fn unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<OutputBytes, Error>;
});
capability!(SignatureVerifier, SignatureAlgorithm, "See CONTRACT.md section 6.9.", {
    /// Verifies a signature over a message, not a precomputed digest.
    /// See CONTRACT.md section 6.9.
    fn verify(&self, public_key: PublicKey<'_>, message: &[u8], signature: &[u8]) -> Result<(), Error>;
});
capability!(
    AsymmetricEncryptor,
    AsymmetricEncryptionAlgorithm,
    "See CONTRACT.md section 6.10.",
    {
        /// Encrypts a message using the backend's own randomness.
        /// See CONTRACT.md section 6.10.
        fn encrypt(&self, public_key: PublicKey<'_>, plaintext: &[u8]) -> Result<OutputBytes, Error>;
    }
);
capability!(KeyAgreement, KeyAgreementAlgorithm, "See CONTRACT.md section 6.11.", {
    /// Generates a single-use ECDH or X25519 secret; FFDH uses FfdhKeyAgreement.
    /// See CONTRACT.md section 6.11.
    fn generate_ephemeral(&self) -> Result<Box<dyn EphemeralSecret>, Error>;
});

/// FFDH ephemeral agreement with explicit parameters; its algorithm is always Ffdh.
/// See CONTRACT.md section 6.11.
pub trait FfdhKeyAgreement: Send + Sync {
    /// Whether computations execute in a positively established FIPS module.
    /// See CONTRACT.md section 6.15.
    fn fips(&self) -> bool;
    /// Generates a single-use secret with checked domain parameters.
    /// See CONTRACT.md section 6.11.
    fn generate_ephemeral(&self, parameters: FfdhParameters<'_>) -> Result<Box<dyn EphemeralSecret>, Error>;
}

/// Ephemeral secret held inside the backend, used for one agreement.
/// See CONTRACT.md section 6.11.
pub trait EphemeralSecret: Send {
    /// Returns the encoded public value.
    /// See CONTRACT.md sections 5.3 and 6.11.
    fn public_key(&self) -> Result<OutputBytes, Error>;
    /// Consumes the secret and returns the shared secret.
    /// See CONTRACT.md section 6.11.
    fn agree(self: Box<Self>, peer_public_key: &[u8]) -> Result<OutputBytes, Error>;
}

/// Loader for one private-key type in the contract's encoding.
/// See CONTRACT.md section 6.12.
pub trait PrivateKeyLoader: Send + Sync {
    /// The loader's key type.
    /// See CONTRACT.md section 6.12.
    fn key_type(&self) -> KeyType;
    /// Whether computations execute in a positively established FIPS module.
    /// See CONTRACT.md section 6.15.
    fn fips(&self) -> bool;
    /// Validates and loads private material, including embedded public-key consistency.
    /// See CONTRACT.md sections 5.2 and 6.12.
    fn load(&self, private_key: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error>;
}
capability!(KeyGenerator, KeyGenerationAlgorithm, "See CONTRACT.md section 6.13.", {
    /// Generates a fresh, exportable PKCS#8 key.
    /// See CONTRACT.md section 6.13.
    fn generate(&self) -> Result<OutputBytes, Error>;
});
capability!(SecureRandom, RandomAlgorithm, "See CONTRACT.md section 6.14.", {
    /// Fills the caller's buffer; its contents are unspecified on failure.
    /// See CONTRACT.md sections 2 and 6.14.
    fn fill(&self, dest: &mut [u8]) -> Result<(), Error>;
});

/// Provider-loaded, hardware or external private key.
/// See CONTRACT.md section 7.
pub trait PrivateKey: Send + Sync {
    /// The key's type.
    /// See CONTRACT.md section 7.
    fn key_type(&self) -> KeyType;
    /// Exact key size in bits; cached for hardware keys, zero if not meaningful.
    /// See CONTRACT.md section 7.
    fn key_size_bits(&self) -> usize;
    /// Cached availability, without performing the operation or accessing a device.
    /// See CONTRACT.md section 7.
    fn supports(&self, operation: KeyOperation) -> bool;
    /// Whether the key's computations execute in positively established FIPS modules.
    /// See CONTRACT.md sections 6.15 and 7.
    fn fips(&self) -> bool;
    /// Signs a message using the named algorithm; unavailable by default.
    /// See CONTRACT.md sections 6.9 and 7.
    fn sign(&self, algorithm: SignatureAlgorithm, _message: &[u8]) -> Result<OutputBytes, Error> {
        Err(Error::Unsupported(Algorithm::Signature(algorithm)))
    }
    /// Decrypts ciphertext; unavailable by default.
    /// See CONTRACT.md sections 6.10 and 7.
    fn decrypt(&self, algorithm: AsymmetricEncryptionAlgorithm, _ciphertext: &[u8]) -> Result<OutputBytes, Error> {
        Err(Error::Unsupported(Algorithm::AsymmetricEncryption(algorithm)))
    }
    /// Performs static key agreement; unavailable by default.
    /// See CONTRACT.md sections 6.11 and 7.
    fn agree(&self, algorithm: KeyAgreementAlgorithm, _peer_public_key: &[u8]) -> Result<OutputBytes, Error> {
        Err(Error::Unsupported(Algorithm::KeyAgreement(algorithm)))
    }
    /// Optionally exports subjectPublicKey contents; not offered for FFDH.
    /// See CONTRACT.md sections 5.1 and 7.
    fn public_key(&self) -> Result<OutputBytes, Error> {
        Err(Error::Unsupported(Algorithm::PublicKeyExport(self.key_type())))
    }
}

impl fmt::Debug for dyn FfdhKeyAgreement + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FfdhKeyAgreement")
            .field("algorithm", &KeyAgreementAlgorithm::Ffdh)
            .field("fips", &self.fips())
            .finish()
    }
}
macro_rules! key_debug {
    ($name:ident) => {
        impl fmt::Debug for dyn $name + '_ {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("key_type", &self.key_type())
                    .field("fips", &self.fips())
                    .finish()
            }
        }
    };
}
key_debug!(PrivateKeyLoader);
key_debug!(PrivateKey);
