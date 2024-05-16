use crate::key::{EcCurve, PrivateKey, PublicKey};
use crate::ssh::{SshPrivateKey, SshPublicKey};

use wasm_bindgen::prelude::*;

define_error!(PuttyError, picky::putty::PuttyError);

impl From<picky::ssh::private_key::SshPrivateKeyError> for PuttyError {
    fn from(e: picky::ssh::private_key::SshPrivateKeyError) -> Self {
        Self(picky::putty::PuttyError::from(e))
    }
}

/// PuTTY Private Key (PPK) version.
#[wasm_bindgen]
#[derive(Clone, Copy)]
pub enum PuttyPpkVersion {
    V2,
    V3,
}

impl From<picky::putty::PpkVersion> for PuttyPpkVersion {
    fn from(value: picky::putty::PpkVersion) -> Self {
        match value {
            picky::putty::PpkVersion::V2 => Self::V2,
            picky::putty::PpkVersion::V3 => Self::V3,
        }
    }
}

impl From<PuttyPpkVersion> for picky::putty::PpkVersion {
    fn from(value: PuttyPpkVersion) -> Self {
        match value {
            PuttyPpkVersion::V2 => Self::V2,
            PuttyPpkVersion::V3 => Self::V3,
        }
    }
}

/// PuTTY Private Key (PPK) algorithm.
#[wasm_bindgen]
#[derive(Clone, Copy)]
pub enum PuttyPpkKeyAlgorithm {
    Rsa,
    Dss,
    EcdsaSha2Nistp256,
    EcdsaSha2Nistp384,
    EcdsaSha2Nistp521,
    Ed25519,
    Ed448,
}

impl From<picky::putty::PpkKeyAlgorithm> for PuttyPpkKeyAlgorithm {
    fn from(value: picky::putty::PpkKeyAlgorithm) -> Self {
        match value {
            picky::putty::PpkKeyAlgorithm::Rsa => Self::Rsa,
            picky::putty::PpkKeyAlgorithm::Dss => Self::Dss,
            picky::putty::PpkKeyAlgorithm::EcdsaSha2Nistp256 => Self::EcdsaSha2Nistp256,
            picky::putty::PpkKeyAlgorithm::EcdsaSha2Nistp384 => Self::EcdsaSha2Nistp384,
            picky::putty::PpkKeyAlgorithm::EcdsaSha2Nistp521 => Self::EcdsaSha2Nistp521,
            picky::putty::PpkKeyAlgorithm::Ed25519 => Self::Ed25519,
            picky::putty::PpkKeyAlgorithm::Ed448 => Self::Ed448,
        }
    }
}

impl From<PuttyPpkKeyAlgorithm> for picky::putty::PpkKeyAlgorithm {
    fn from(value: PuttyPpkKeyAlgorithm) -> Self {
        match value {
            PuttyPpkKeyAlgorithm::Rsa => Self::Rsa,
            PuttyPpkKeyAlgorithm::Dss => Self::Dss,
            PuttyPpkKeyAlgorithm::EcdsaSha2Nistp256 => Self::EcdsaSha2Nistp256,
            PuttyPpkKeyAlgorithm::EcdsaSha2Nistp384 => Self::EcdsaSha2Nistp384,
            PuttyPpkKeyAlgorithm::EcdsaSha2Nistp521 => Self::EcdsaSha2Nistp521,
            PuttyPpkKeyAlgorithm::Ed25519 => Self::Ed25519,
            PuttyPpkKeyAlgorithm::Ed448 => Self::Ed448,
        }
    }
}

/// Argon2 key derivation function flavour.
#[wasm_bindgen]
#[derive(Clone, Copy)]
pub enum PuttyArgon2Flavour {
    Argon2d,
    Argon2i,
    Argon2id,
}

impl From<picky::putty::Argon2Flavour> for PuttyArgon2Flavour {
    fn from(value: picky::putty::Argon2Flavour) -> Self {
        match value {
            picky::putty::Argon2Flavour::Argon2d => Self::Argon2d,
            picky::putty::Argon2Flavour::Argon2i => Self::Argon2i,
            picky::putty::Argon2Flavour::Argon2id => Self::Argon2id,
        }
    }
}

impl From<PuttyArgon2Flavour> for picky::putty::Argon2Flavour {
    fn from(value: PuttyArgon2Flavour) -> Self {
        match value {
            PuttyArgon2Flavour::Argon2d => Self::Argon2d,
            PuttyArgon2Flavour::Argon2i => Self::Argon2i,
            PuttyArgon2Flavour::Argon2id => Self::Argon2id,
        }
    }
}

/// Argon2 key derivation function parameters.
#[wasm_bindgen]
pub struct PuttyArgon2Params(picky::putty::Argon2Params);

#[wasm_bindgen]
impl PuttyArgon2Params {
    pub fn flavor(&self) -> PuttyArgon2Flavour {
        self.0.flavor.into()
    }

    pub fn memory(&self) -> u32 {
        self.0.memory
    }

    pub fn passes(&self) -> u32 {
        self.0.passes
    }

    pub fn parallelism(&self) -> u32 {
        self.0.parallelism
    }

    pub fn salt(&self) -> Vec<u8> {
        self.0.salt.to_vec()
    }
}

/// PPK encryption configuration.
///
/// Could be either constructed via `PuttyPpkEncryptionConfig::default()` or `PuttyPpkEncryptionConfig::builder()`
///
/// Defaults are the same as in PuTTY.
#[wasm_bindgen]
pub struct PuttyPpkEncryptionConfig(picky::putty::PpkEncryptionConfig);

#[wasm_bindgen]
impl PuttyPpkEncryptionConfig {
    pub fn builder() -> PuttyPpkEncryptionConfigBuilder {
        PuttyPpkEncryptionConfigBuilder(picky::putty::PpkEncryptionConfig::builder())
    }
}

/// PPK encryption configuration builder.
///
/// Could be constructed via `PuttyPpkEncryptionConfig::builder()`.
#[wasm_bindgen]
pub struct PuttyPpkEncryptionConfigBuilder(picky::putty::PpkEncryptionConfigBuilder);

#[wasm_bindgen]
impl PuttyPpkEncryptionConfigBuilder {
    pub fn argon2_flavour(&mut self, argon2_flavour: PuttyArgon2Flavour) {
        self.0.clone().argon2_flavour(argon2_flavour.into());
    }

    pub fn argon2_memory(&mut self, argon2_memory: u32) {
        self.0.clone().argon2_memory(argon2_memory);
    }

    pub fn argon2_passes(&mut self, argon2_passes: u32) {
        self.0.clone().argon2_passes(argon2_passes);
    }

    pub fn argon2_parallelism(&mut self, argon2_parallelism: u32) {
        self.0.clone().argon2_parallelism(argon2_parallelism);
    }

    pub fn argon2_salt_size(&mut self, argon2_salt_size: u32) {
        self.0.clone().argon2_salt_size(argon2_salt_size);
    }

    pub fn build(&self) -> PuttyPpkEncryptionConfig {
        PuttyPpkEncryptionConfig(self.0.clone().build())
    }
}

/// PuTTY public key format.
///
/// ### Functionality:
/// - Conversion to/from OpenSSH format.
/// - Encoding/decoding to/from string.
/// - Could be extracted from `PuttyPpk` private keys.
///
/// ### Notes
/// - Although top-level containeris similar to PEM, it is not compatible with it because of
///   additional comment field after the header.
#[wasm_bindgen]
pub struct PuttyPublicKey(picky::putty::PuttyPublicKey);

#[wasm_bindgen]
impl PuttyPublicKey {
    /// Converts an OpenSSH public key to a PuTTY public key.
    pub fn from_openssh(key: &SshPublicKey) -> Result<PuttyPublicKey, PuttyError> {
        let key = picky::putty::PuttyPublicKey::from_openssh(&key.0)?;
        Ok(PuttyPublicKey(key))
    }

    /// Converts the key to an OpenSSH public key.
    pub fn to_openssh(&self) -> Result<SshPublicKey, PuttyError> {
        let key = self.0.to_openssh()?;
        Ok(SshPublicKey(key))
    }

    /// Get the comment of the public key.
    pub fn comment(&self) -> String {
        self.0.comment().to_string()
    }

    /// Returns a new PPK key instance with a different comment.
    pub fn with_comment(&self, comment: &str) -> PuttyPublicKey {
        let ppk = self.0.with_comment(comment);
        PuttyPublicKey(ppk)
    }

    /// Converts the public key to a string (PuTTY format).
    pub fn to_repr(&self) -> String {
        self.0.to_string()
    }

    /// Parses and returns the inner key as standard picky key type.
    pub fn to_inner_key(&self) -> Result<PublicKey, PuttyError> {
        Ok(PublicKey(self.0.to_inner_key()?))
    }
}

/// PuTTY Private Key (PPK) format.
///
/// ### Functionality
/// - Generation of new keys.
/// - Conversion to/from OpenSSH format.
/// - Encoding/decoding to/from string.
/// - Version upgrade/downgrade.
///
/// ### Usage notes
/// - Ppk structure is immutable. All operations that modify the key return a new instance.
/// - When input file is encrypted, all operations with the private key will be unavailable until
///   ppk is decrypted via `PuttyPpk::decrypt`.
/// - Newly generated keys are always unencrypted. They should be encrypted via `PuttyPpk::encrypt`
///   when required
#[wasm_bindgen]
pub struct PuttyPpk(picky::putty::Ppk);

#[wasm_bindgen]
impl PuttyPpk {
    /// Generate a new RSA key file.
    pub fn generate_rsa(bits: usize, comment: &str) -> Result<PuttyPpk, PuttyError> {
        let comment = if comment.is_empty() { None } else { Some(comment) };
        let ppk = picky::putty::Ppk::generate_rsa(bits, comment)?;
        Ok(Self(ppk))
    }

    /// Generate a new EC key file.
    pub fn generate_ec(curve: EcCurve, comment: &str) -> Result<PuttyPpk, PuttyError> {
        let comment = if comment.is_empty() { None } else { Some(comment) };
        let ppk = picky::putty::Ppk::generate_ec(curve.into(), comment)?;
        Ok(Self(ppk))
    }

    /// Generate a new Ed25519 key file.
    pub fn generate_ed25519(comment: &str) -> Result<PuttyPpk, PuttyError> {
        let comment = if comment.is_empty() { None } else { Some(comment) };
        let ppk = picky::putty::Ppk::generate_ed25519(comment)?;
        Ok(Self(ppk))
    }

    /// Encode PPK key file to a string.
    pub fn to_repr(&self) -> Result<String, PuttyError> {
        Ok(self.0.to_string()?)
    }

    /// Parse a PPK key file from a string.
    pub fn parse(ppk: &str) -> Result<PuttyPpk, PuttyError> {
        let ppk: picky::putty::Ppk = ppk.parse()?;
        Ok(Self(ppk))
    }

    /// Convert an OpenSSH private key to a PPK key file.
    pub fn from_openssh(key: &SshPrivateKey) -> Result<PuttyPpk, PuttyError> {
        let ppk = picky::putty::Ppk::from_openssh_private_key(&key.0)?;
        Ok(Self(ppk))
    }

    /// Convert a PPK key file to an OpenSSH private key.
    pub fn to_openssh(&self, passphrase: &str) -> Result<SshPrivateKey, PuttyError> {
        let passphrase = if passphrase.is_empty() { None } else { Some(passphrase) };
        let key = self.0.to_openssh_private_key(passphrase)?;
        Ok(SshPrivateKey(key))
    }

    /// Wrap a private key
    pub fn from_key(private_key: &PrivateKey) -> Result<PuttyPpk, PuttyError> {
        let key = picky::ssh::private_key::SshPrivateKey::try_from(private_key.0.clone())?;
        let ppk = picky::putty::Ppk::from_openssh_private_key(&key)?;
        Ok(Self(ppk))
    }

    /// Get the public key from the PPK key file.
    pub fn public_key(&self) -> Result<PublicKey, PuttyError> {
        let key = self.0.public_key()?;
        Ok(PublicKey(key))
    }

    /// Get the private key from the PPK key file.
    pub fn private_key(&self) -> Result<PrivateKey, PuttyError> {
        let key = self.0.private_key()?;
        Ok(PrivateKey(key))
    }

    /// Extract the public key file (PuTTY format) from the PPK key file.
    pub fn extract_putty_public_key(&self) -> Result<PuttyPublicKey, PuttyError> {
        let key = self.0.extract_putty_public_key()?;
        Ok(PuttyPublicKey(key))
    }

    /// Get the PPK key file version.
    pub fn version(&self) -> PuttyPpkVersion {
        self.0.version().into()
    }

    /// Get the PPK key file algorithm.
    pub fn algorithm(&self) -> PuttyPpkKeyAlgorithm {
        self.0.algorithm().into()
    }

    /// Get the PPK key file comment.
    pub fn comment(&self) -> Result<String, PuttyError> {
        Ok(self.0.comment().to_string())
    }

    /// Returns a new PPK key instance with a different comment.
    pub fn with_comment(&self, comment: &str) -> Result<PuttyPpk, PuttyError> {
        let ppk = self.0.with_comment(comment)?;
        Ok(PuttyPpk(ppk))
    }

    /// Convert the PPK key file to a different version.
    pub fn to_version(&self, version: PuttyPpkVersion) -> Result<PuttyPpk, PuttyError> {
        let ppk = self.0.to_version(version.into())?;
        Ok(Self(ppk))
    }

    /// Check if the PPK key file is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.0.is_encrypted()
    }

    /// Get the Argon2 key derivation function parameters (if the key is encrypted).
    pub fn argon2_params(&self) -> Option<PuttyArgon2Params> {
        self.0.argon2_params().map(|params| PuttyArgon2Params(params.clone()))
    }

    /// Decrypt the PPK key file and return as a new instance.
    pub fn decrypt(&self, passphrase: &str) -> Result<PuttyPpk, PuttyError> {
        let ppk = self.0.decrypt(passphrase)?;
        Ok(Self(ppk))
    }

    /// Encrypt the PPK key file and return as a new instance.
    pub fn encrypt(&self, passphrase: &str, config: Option<PuttyPpkEncryptionConfig>) -> Result<PuttyPpk, PuttyError> {
        let ppk = self
            .0
            .encrypt(passphrase, config.map(|config| config.0).unwrap_or_default())?;
        Ok(Self(ppk))
    }
}
