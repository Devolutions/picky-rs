use crate::{
    Aead, AeadAlgorithm, Algorithm, AsymmetricEncryptionAlgorithm, AsymmetricEncryptor, Cipher, CipherAlgorithm,
    CryptoProvider, Entry, Error, FfdhKeyAgreement, FfdhParameters, Hash, HashAlgorithm, Kdf, KdfAlgorithm,
    KeyAgreement, KeyAgreementAlgorithm, KeyGenerationAlgorithm, KeyGenerator, KeyType, KeyWrap, KeyWrapAlgorithm, Mac,
    MacAlgorithm, MacGeneration, MacTag, MacVerification, OutputBytes, PasswordKdf, PasswordKdfAlgorithm, PrivateKey,
    PrivateKeyLoader, Protection, RandomAlgorithm, Requirement, SecureRandom, SignatureAlgorithm, SignatureVerifier,
    StreamCipher, StreamCipherAlgorithm, X25519Scalar, Zeroizing, get_default,
};

/// Returns the default, panicking with installation instructions if absent.
/// See CONTRACT.md sections 9 and 10.
pub fn default_provider() -> &'static CryptoProvider {
    get_default().expect("install a provider with picky_crypto::install_default using picky-crypto-rustcrypto-bundle or another picky-crypto-* backend; consuming libraries may enable their rustcrypto convenience feature")
}

/// Identifies the algorithm advertised by an entry.
/// See CONTRACT.md section 10.
pub fn entry_algorithm(entry: &Entry) -> Algorithm {
    match entry {
        Entry::Hash(e) => Algorithm::Hash(e.algorithm()),
        Entry::Mac(e) => Algorithm::Mac(e.algorithm()),
        Entry::PasswordKdf(e) => Algorithm::PasswordKdf(e.algorithm()),
        Entry::Kdf(e) => Algorithm::Kdf(e.algorithm()),
        Entry::Cipher(e) => Algorithm::Cipher(e.algorithm()),
        Entry::StreamCipher(e) => Algorithm::StreamCipher(e.algorithm()),
        Entry::Aead(e) => Algorithm::Aead(e.algorithm()),
        Entry::KeyWrap(e) => Algorithm::KeyWrap(e.algorithm()),
        Entry::SignatureVerifier(e) => Algorithm::Signature(e.algorithm()),
        Entry::AsymmetricEncryptor(e) => Algorithm::AsymmetricEncryption(e.algorithm()),
        Entry::KeyAgreement(e) => Algorithm::KeyAgreement(e.algorithm()),
        Entry::FfdhKeyAgreement(_) => Algorithm::KeyAgreement(KeyAgreementAlgorithm::Ffdh),
        Entry::PrivateKeyLoader(e) => Algorithm::PrivateKeyLoading(e.key_type()),
        Entry::KeyGenerator(e) => Algorithm::KeyGeneration(e.algorithm()),
        Entry::SecureRandom(e) => Algorithm::Random(e.algorithm()),
    }
}

/// Reports an entry's established FIPS status.
/// See CONTRACT.md sections 6.15 and 10.
pub fn entry_fips(entry: &Entry) -> bool {
    match entry {
        Entry::Hash(e) => e.fips(),
        Entry::Mac(e) => e.fips(),
        Entry::PasswordKdf(e) => e.fips(),
        Entry::Kdf(e) => e.fips(),
        Entry::Cipher(e) => e.fips(),
        Entry::StreamCipher(e) => e.fips(),
        Entry::Aead(e) => e.fips(),
        Entry::KeyWrap(e) => e.fips(),
        Entry::SignatureVerifier(e) => e.fips(),
        Entry::AsymmetricEncryptor(e) => e.fips(),
        Entry::KeyAgreement(e) => e.fips(),
        Entry::FfdhKeyAgreement(e) => e.fips(),
        Entry::PrivateKeyLoader(e) => e.fips(),
        Entry::KeyGenerator(e) => e.fips(),
        Entry::SecureRandom(e) => e.fips(),
    }
}

macro_rules! accessor {
    ($name:ident, $algorithm:ty, $category:ident, $variant:ident) => {
        #[doc = concat!("Looks up a ", stringify!($variant), " entry, or returns Unsupported.")]
        /// See CONTRACT.md section 10.
        pub fn $name(provider: &CryptoProvider, algorithm: $algorithm) -> Result<&dyn $variant, Error> {
            match provider.get(Algorithm::$category(algorithm)) {
                Some(Entry::$variant(entry)) => Ok(&**entry),
                _ => Err(Error::Unsupported(Algorithm::$category(algorithm))),
            }
        }
    };
}
accessor!(hash, HashAlgorithm, Hash, Hash);
accessor!(mac, MacAlgorithm, Mac, Mac);
accessor!(password_kdf, PasswordKdfAlgorithm, PasswordKdf, PasswordKdf);
accessor!(kdf, KdfAlgorithm, Kdf, Kdf);
accessor!(cipher, CipherAlgorithm, Cipher, Cipher);
accessor!(stream_cipher, StreamCipherAlgorithm, StreamCipher, StreamCipher);
accessor!(aead, AeadAlgorithm, Aead, Aead);
accessor!(key_wrap, KeyWrapAlgorithm, KeyWrap, KeyWrap);
accessor!(signature_verifier, SignatureAlgorithm, Signature, SignatureVerifier);
accessor!(
    asymmetric_encryptor,
    AsymmetricEncryptionAlgorithm,
    AsymmetricEncryption,
    AsymmetricEncryptor
);
accessor!(private_key_loader, KeyType, PrivateKeyLoading, PrivateKeyLoader);
accessor!(key_generator, KeyGenerationAlgorithm, KeyGeneration, KeyGenerator);
accessor!(secure_random, RandomAlgorithm, Random, SecureRandom);

/// Looks up ECDH or X25519; Ffdh is InvalidInput and uses ffdh_key_agreement.
/// See CONTRACT.md section 10.
pub fn key_agreement(provider: &CryptoProvider, algorithm: KeyAgreementAlgorithm) -> Result<&dyn KeyAgreement, Error> {
    if algorithm == KeyAgreementAlgorithm::Ffdh {
        return Err(Error::InvalidInput);
    }
    match provider.get(Algorithm::KeyAgreement(algorithm)) {
        Some(Entry::KeyAgreement(entry)) => Ok(&**entry),
        _ => Err(Error::Unsupported(Algorithm::KeyAgreement(algorithm))),
    }
}

/// Looks up FFDH ephemeral agreement.
/// See CONTRACT.md section 10.
pub fn ffdh_key_agreement(provider: &CryptoProvider) -> Result<&dyn FfdhKeyAgreement, Error> {
    match provider.get(Algorithm::KeyAgreement(KeyAgreementAlgorithm::Ffdh)) {
        Some(Entry::FfdhKeyAgreement(entry)) => Ok(&**entry),
        _ => Err(Error::Unsupported(Algorithm::KeyAgreement(KeyAgreementAlgorithm::Ffdh))),
    }
}

/// Hashes one slice using a streaming context.
/// See CONTRACT.md sections 6.1 and 10.
pub fn digest(provider: &CryptoProvider, algorithm: HashAlgorithm, data: &[u8]) -> Result<OutputBytes, Error> {
    let mut context = hash(provider, algorithm)?.start()?;
    context.update(data)?;
    context.finish()
}

/// Generates a full tag using applying protection.
/// See CONTRACT.md sections 6.2 and 10.
pub fn compute_mac(
    provider: &CryptoProvider,
    algorithm: MacAlgorithm,
    key: &[u8],
    data: &[u8],
) -> Result<MacTag, Error> {
    let mut context = MacGeneration::start(mac(provider, algorithm)?, key)?;
    context.update(data)?;
    context.finish()
}

/// Checks a received tag using processing protection and a protocol-fixed length.
/// See CONTRACT.md sections 6.2 and 10.
pub fn verify_mac(
    provider: &CryptoProvider,
    algorithm: MacAlgorithm,
    key: &[u8],
    data: &[u8],
    expected: &[u8],
    len: usize,
) -> Result<bool, Error> {
    let mut context = MacVerification::start(mac(provider, algorithm)?, key)?;
    context.update(data)?;
    Ok(context.finish()?.verify(expected, len))
}

/// Draws 32 random bytes and applies RFC 7748 scalar clamping.
/// See CONTRACT.md sections 6.13 and 10.
pub fn random_x25519_private_key(provider: &CryptoProvider) -> Result<X25519Scalar, Error> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    secure_random(provider, RandomAlgorithm::SecureRandom)?.fill(&mut bytes[..])?;
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    Ok(X25519Scalar::new(bytes))
}

/// Computes g^x using static agreement; parameters must match those loaded with the key.
/// See CONTRACT.md sections 6.11 and 10.
pub fn ffdh_public_value(key: &dyn PrivateKey, parameters: FfdhParameters<'_>) -> Result<OutputBytes, Error> {
    key.agree(KeyAgreementAlgorithm::Ffdh, parameters.g)
}

fn protection_supported(entry: &Entry, protection: Protection) -> bool {
    match entry {
        Entry::Mac(e) => e.supports(protection),
        Entry::Cipher(e) => e.supports(protection),
        Entry::Aead(e) => e.supports(protection),
        Entry::KeyWrap(e) => e.supports(protection),
        _ => true,
    }
}

/// Returns every unmet requirement, preserving input order and duplicates.
/// See CONTRACT.md sections 8 and 10.
pub fn missing(provider: &CryptoProvider, required: &[Requirement]) -> Vec<Requirement> {
    required
        .iter()
        .copied()
        .filter(|requirement| {
            let (algorithm, protection) = match *requirement {
                Requirement::Algorithm(a) => (a, None),
                Requirement::Mac(a, p) => (Algorithm::Mac(a), Some(p)),
                Requirement::Cipher(a, p) => (Algorithm::Cipher(a), Some(p)),
                Requirement::Aead(a, p) => (Algorithm::Aead(a), Some(p)),
                Requirement::KeyWrap(a, p) => (Algorithm::KeyWrap(a), Some(p)),
            };
            match provider.get(algorithm) {
                None => true,
                Some(entry) => match protection {
                    Some(p) => !protection_supported(entry, p),
                    None => ![Protection::Apply, Protection::Process]
                        .into_iter()
                        .all(|p| protection_supported(entry, p)),
                },
            }
        })
        .collect()
}
