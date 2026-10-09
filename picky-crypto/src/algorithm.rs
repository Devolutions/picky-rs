macro_rules! identifiers {
    ($name:ident { $($variant:ident $(($payload:ty))?),+ $(,)? }) => {
        #[doc = concat!("Identifiers for ", stringify!($name), ".")]
        /// See CONTRACT.md section 3.
        #[non_exhaustive]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $name {
            $(
                #[doc = concat!("The ", stringify!($variant), " identifier.")]
                /// See CONTRACT.md section 3.
                $variant $(($payload))?,
            )+
        }
    };
}

identifiers!(HashAlgorithm {
    Md4,
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_384,
    Sha3_512
});
identifiers!(MacAlgorithm {
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512
});
identifiers!(PasswordKdfAlgorithm {
    Pbkdf2HmacSha1,
    Pbkdf2HmacSha224,
    Pbkdf2HmacSha256,
    Pbkdf2HmacSha384,
    Pbkdf2HmacSha512
});
identifiers!(KdfAlgorithm {
    OneStepSha1,
    OneStepSha256,
    OneStepSha384,
    OneStepSha512,
    CounterHmacSha1,
    CounterHmacSha256,
    CounterHmacSha384,
    CounterHmacSha512
});
identifiers!(CipherAlgorithm {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    TdesEde3Cbc,
    Rc2Cbc
});
identifiers!(StreamCipherAlgorithm { Rc4 });
identifiers!(AeadAlgorithm {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm
});
identifiers!(KeyWrapAlgorithm {
    Aes128Kw,
    Aes192Kw,
    Aes256Kw
});
identifiers!(SignatureAlgorithm {
    RsaPkcs1v15Md5,
    RsaPkcs1v15Sha1,
    RsaPkcs1v15Sha224,
    RsaPkcs1v15Sha256,
    RsaPkcs1v15Sha384,
    RsaPkcs1v15Sha512,
    RsaPkcs1v15Sha3_384,
    RsaPkcs1v15Sha3_512,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    EcdsaP521Sha512,
    Ed25519
});
identifiers!(AsymmetricEncryptionAlgorithm {
    RsaPkcs1v15,
    RsaOaepSha1,
    RsaOaepSha256
});
identifiers!(KeyAgreementAlgorithm {
    EcdhP256,
    EcdhP384,
    EcdhP521,
    X25519,
    Ffdh
});
identifiers!(KeyType {
    Rsa,
    EcP256,
    EcP384,
    EcP521,
    Ed25519,
    X25519,
    Ffdh
});
identifiers!(KeyGenerationAlgorithm {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcP256,
    EcP384,
    EcP521,
    Ed25519
});
identifiers!(RandomAlgorithm { SecureRandom });
identifiers!(Algorithm {
    Hash(HashAlgorithm), Mac(MacAlgorithm), PasswordKdf(PasswordKdfAlgorithm),
    Kdf(KdfAlgorithm), Cipher(CipherAlgorithm), StreamCipher(StreamCipherAlgorithm),
    Aead(AeadAlgorithm), KeyWrap(KeyWrapAlgorithm), Signature(SignatureAlgorithm),
    AsymmetricEncryption(AsymmetricEncryptionAlgorithm), KeyAgreement(KeyAgreementAlgorithm),
    PrivateKeyLoading(KeyType), KeyGeneration(KeyGenerationAlgorithm), Random(RandomAlgorithm),
    PublicKeyExport(KeyType)
});

impl HashAlgorithm {
    /// Digest length in bytes, not an operation.
    /// See CONTRACT.md section 3.
    pub const fn output_len(self) -> usize {
        match self {
            Self::Md4 | Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
        }
    }
}

/// Applying protection or processing already protected information.
/// See CONTRACT.md section 8.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protection {
    /// Generate a tag, encrypt, seal or wrap.
    /// See CONTRACT.md section 8.
    Apply,
    /// Verify a tag, decrypt, open or unwrap.
    /// See CONTRACT.md section 8.
    Process,
}

/// An operation required from a provider.
/// See CONTRACT.md section 8.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Requirement {
    /// Every operation of the algorithm's trait.
    /// See CONTRACT.md section 8.
    Algorithm(Algorithm),
    /// One MAC protection.
    /// See CONTRACT.md section 8.
    Mac(MacAlgorithm, Protection),
    /// One cipher protection.
    /// See CONTRACT.md section 8.
    Cipher(CipherAlgorithm, Protection),
    /// One AEAD protection.
    /// See CONTRACT.md section 8.
    Aead(AeadAlgorithm, Protection),
    /// One key-wrap protection.
    /// See CONTRACT.md section 8.
    KeyWrap(KeyWrapAlgorithm, Protection),
}

impl From<Algorithm> for Requirement {
    fn from(algorithm: Algorithm) -> Self {
        Self::Algorithm(algorithm)
    }
}
