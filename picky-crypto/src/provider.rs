use crate::{
    Aead, AeadAlgorithm, Algorithm, AsymmetricEncryptor, BuildError, Cipher, CipherAlgorithm, Error, FfdhKeyAgreement,
    Hash, Kdf, KeyAgreement, KeyAgreementAlgorithm, KeyGenerator, KeyWrap, KeyWrapAlgorithm, Mac, MacAlgorithm,
    MacContext, OutputBytes, PasswordKdf, PrivateKeyLoader, Protection, Sealed, SecureRandom, SignatureVerifier,
    StreamCipher, helpers,
};
use std::{collections::HashMap, sync::Arc};

/// One algorithm entry, shared for runtime composition.
/// See CONTRACT.md section 8.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum Entry {
    /// Hash capability.
    /// See CONTRACT.md section 6.1.
    Hash(Arc<dyn Hash>),
    /// MAC capability.
    /// See CONTRACT.md section 6.2.
    Mac(Arc<dyn Mac>),
    /// Password KDF capability.
    /// See CONTRACT.md section 6.3.
    PasswordKdf(Arc<dyn PasswordKdf>),
    /// Key-based KDF capability.
    /// See CONTRACT.md section 6.4.
    Kdf(Arc<dyn Kdf>),
    /// CBC cipher capability.
    /// See CONTRACT.md section 6.5.
    Cipher(Arc<dyn Cipher>),
    /// Stream cipher capability.
    /// See CONTRACT.md section 6.6.
    StreamCipher(Arc<dyn StreamCipher>),
    /// AEAD capability.
    /// See CONTRACT.md section 6.7.
    Aead(Arc<dyn Aead>),
    /// Key-wrap capability.
    /// See CONTRACT.md section 6.8.
    KeyWrap(Arc<dyn KeyWrap>),
    /// Signature verification capability.
    /// See CONTRACT.md section 6.9.
    SignatureVerifier(Arc<dyn SignatureVerifier>),
    /// Asymmetric encryption capability.
    /// See CONTRACT.md section 6.10.
    AsymmetricEncryptor(Arc<dyn AsymmetricEncryptor>),
    /// ECDH or X25519 ephemeral agreement.
    /// See CONTRACT.md section 6.11.
    KeyAgreement(Arc<dyn KeyAgreement>),
    /// FFDH ephemeral agreement.
    /// See CONTRACT.md section 6.11.
    FfdhKeyAgreement(Arc<dyn FfdhKeyAgreement>),
    /// Private-key loading capability.
    /// See CONTRACT.md section 6.12.
    PrivateKeyLoader(Arc<dyn PrivateKeyLoader>),
    /// Key generation capability.
    /// See CONTRACT.md section 6.13.
    KeyGenerator(Arc<dyn KeyGenerator>),
    /// Secure random generator.
    /// See CONTRACT.md section 6.14.
    SecureRandom(Arc<dyn SecureRandom>),
}

/// Immutable algorithm entries and the FIPS status of their composition.
/// See CONTRACT.md sections 8 and 8.1.
#[derive(Clone, Debug)]
pub struct CryptoProvider {
    entries: HashMap<Algorithm, Entry>,
    members_fips: bool,
}
impl CryptoProvider {
    /// Starts an empty provider builder.
    /// See CONTRACT.md section 8.
    pub fn builder() -> ProviderBuilder {
        ProviderBuilder { entries: Vec::new() }
    }
    /// Looks up an advertised algorithm.
    /// See CONTRACT.md section 8.
    pub fn get(&self, algorithm: Algorithm) -> Option<&Entry> {
        self.entries.get(&algorithm)
    }
    /// Iterates over all entries, in unspecified order.
    /// See CONTRACT.md section 8.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }
    /// Requires nonempty entries, all FIPS entries and all FIPS composition members.
    /// See CONTRACT.md section 8.1.
    pub fn fips(&self) -> bool {
        !self.entries.is_empty() && self.members_fips && self.entries().all(helpers::entry_fips)
    }
    /// Fills absent algorithms and protections without retrying refused inputs.
    /// See CONTRACT.md section 8.1.
    pub fn with_fallback(&self, fallback: &CryptoProvider) -> CryptoProvider {
        let mut entries = self.entries.clone();
        for (&algorithm, secondary) in &fallback.entries {
            let entry = match entries.get(&algorithm) {
                None => secondary.clone(),
                Some(primary) => combine(primary, secondary),
            };
            entries.insert(algorithm, entry);
        }
        Self {
            entries,
            members_fips: self.fips() && fallback.fips(),
        }
    }
}

/// Insertion-ordered collection checked when built.
/// See CONTRACT.md section 8.
#[derive(Debug)]
pub struct ProviderBuilder {
    entries: Vec<Entry>,
}
impl ProviderBuilder {
    /// Adds an entry for validation when built.
    /// See CONTRACT.md section 8.
    pub fn with(mut self, entry: Entry) -> Self {
        self.entries.push(entry);
        self
    }
    /// Rejects mismatches, missing protections and duplicates in insertion order.
    /// See CONTRACT.md section 8.
    pub fn build(self) -> Result<CryptoProvider, BuildError> {
        let mut entries = HashMap::new();
        for entry in self.entries {
            let algorithm = helpers::entry_algorithm(&entry);
            if matches!(&entry, Entry::KeyAgreement(e) if e.algorithm() == KeyAgreementAlgorithm::Ffdh) {
                return Err(BuildError::Mismatched(algorithm));
            }
            let no_protection = match &entry {
                Entry::Mac(e) => !e.supports(Protection::Apply) && !e.supports(Protection::Process),
                Entry::Cipher(e) => !e.supports(Protection::Apply) && !e.supports(Protection::Process),
                Entry::Aead(e) => !e.supports(Protection::Apply) && !e.supports(Protection::Process),
                Entry::KeyWrap(e) => !e.supports(Protection::Apply) && !e.supports(Protection::Process),
                _ => false,
            };
            if no_protection {
                return Err(BuildError::NoProtection(algorithm));
            }
            if entries.insert(algorithm, entry).is_some() {
                return Err(BuildError::Duplicate(algorithm));
            }
        }
        Ok(CryptoProvider {
            entries,
            members_fips: true,
        })
    }
}

struct Composite<T: ?Sized> {
    primary: Arc<T>,
    fallback: Arc<T>,
}

macro_rules! composite {
    ($trait:ident, $algorithm:ty, {$($operations:tt)*}) => {
        impl Composite<dyn $trait> {
            fn member(&self, protection: Protection) -> &dyn $trait {
                if self.primary.supports(protection) || !self.fallback.supports(protection) {
                    &*self.primary
                } else {
                    &*self.fallback
                }
            }
        }
        impl $trait for Composite<dyn $trait> {
            fn algorithm(&self) -> $algorithm { self.primary.algorithm() }
            fn supports(&self, protection: Protection) -> bool {
                self.primary.supports(protection) || self.fallback.supports(protection)
            }
            fn fips(&self) -> bool {
                [Protection::Apply, Protection::Process].into_iter()
                    .all(|p| !self.supports(p) || self.member(p).fips())
            }
            $($operations)*
        }
    };
}
composite!(Mac, MacAlgorithm, {
    fn start(&self, key: &[u8], protection: Protection) -> Result<Box<dyn MacContext>, Error> {
        self.member(protection).start(key, protection)
    }
});
composite!(Cipher, CipherAlgorithm, {
    fn encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<OutputBytes, Error> {
        self.member(Protection::Apply).encrypt(key, iv, plaintext)
    }
    fn decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<OutputBytes, Error> {
        self.member(Protection::Process).decrypt(key, iv, ciphertext)
    }
});
composite!(Aead, AeadAlgorithm, {
    fn seal(&self, key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Sealed, Error> {
        self.member(Protection::Apply).seal(key, aad, plaintext)
    }
    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext_and_tag: &[u8]) -> Result<OutputBytes, Error> {
        self.member(Protection::Process)
            .open(key, nonce, aad, ciphertext_and_tag)
    }
});
composite!(KeyWrap, KeyWrapAlgorithm, {
    fn wrap(&self, kek: &[u8], key_data: &[u8]) -> Result<OutputBytes, Error> {
        self.member(Protection::Apply).wrap(kek, key_data)
    }
    fn unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<OutputBytes, Error> {
        self.member(Protection::Process).unwrap(kek, wrapped)
    }
});

fn combine(primary: &Entry, fallback: &Entry) -> Entry {
    macro_rules! directional {
        ($($variant:ident),+) => {
            match (primary, fallback) {
                $((Entry::$variant(a), Entry::$variant(b)) if [Protection::Apply, Protection::Process].into_iter()
                    .any(|p| !a.supports(p) && b.supports(p)) => {
                        Entry::$variant(Arc::new(Composite { primary: Arc::clone(a), fallback: Arc::clone(b) }))
                    },)+
                _ => primary.clone(),
            }
        };
    }
    directional!(Mac, Cipher, Aead, KeyWrap)
}
