impl From<picky::putty::PpkVersion> for ffi::PuttyPpkVersion {
    fn from(version: picky::putty::PpkVersion) -> Self {
        match version {
            picky::putty::PpkVersion::V2 => ffi::PuttyPpkVersion::V2,
            picky::putty::PpkVersion::V3 => ffi::PuttyPpkVersion::V3,
        }
    }
}

impl From<ffi::PuttyPpkVersion> for picky::putty::PpkVersion {
    fn from(version: ffi::PuttyPpkVersion) -> Self {
        match version {
            ffi::PuttyPpkVersion::V2 => picky::putty::PpkVersion::V2,
            ffi::PuttyPpkVersion::V3 => picky::putty::PpkVersion::V3,
        }
    }
}

impl From<picky::putty::PpkKeyAlgorithm> for ffi::PuttyPpkKeyAlgorithm {
    fn from(algorithm: picky::putty::PpkKeyAlgorithm) -> Self {
        match algorithm {
            picky::putty::PpkKeyAlgorithm::Rsa => ffi::PuttyPpkKeyAlgorithm::Rsa,
            picky::putty::PpkKeyAlgorithm::Dss => ffi::PuttyPpkKeyAlgorithm::Dss,
            picky::putty::PpkKeyAlgorithm::EcdsaSha2Nistp256 => ffi::PuttyPpkKeyAlgorithm::EcdsaSha2Nistp256,
            picky::putty::PpkKeyAlgorithm::EcdsaSha2Nistp384 => ffi::PuttyPpkKeyAlgorithm::EcdsaSha2Nistp384,
            picky::putty::PpkKeyAlgorithm::EcdsaSha2Nistp521 => ffi::PuttyPpkKeyAlgorithm::EcdsaSha2Nistp521,
            picky::putty::PpkKeyAlgorithm::Ed25519 => ffi::PuttyPpkKeyAlgorithm::Ed25519,
            picky::putty::PpkKeyAlgorithm::Ed448 => ffi::PuttyPpkKeyAlgorithm::Ed448,
        }
    }
}

impl From<ffi::PuttyPpkKeyAlgorithm> for picky::putty::PpkKeyAlgorithm {
    fn from(algorithm: ffi::PuttyPpkKeyAlgorithm) -> Self {
        match algorithm {
            ffi::PuttyPpkKeyAlgorithm::Rsa => picky::putty::PpkKeyAlgorithm::Rsa,
            ffi::PuttyPpkKeyAlgorithm::Dss => picky::putty::PpkKeyAlgorithm::Dss,
            ffi::PuttyPpkKeyAlgorithm::EcdsaSha2Nistp256 => picky::putty::PpkKeyAlgorithm::EcdsaSha2Nistp256,
            ffi::PuttyPpkKeyAlgorithm::EcdsaSha2Nistp384 => picky::putty::PpkKeyAlgorithm::EcdsaSha2Nistp384,
            ffi::PuttyPpkKeyAlgorithm::EcdsaSha2Nistp521 => picky::putty::PpkKeyAlgorithm::EcdsaSha2Nistp521,
            ffi::PuttyPpkKeyAlgorithm::Ed25519 => picky::putty::PpkKeyAlgorithm::Ed25519,
            ffi::PuttyPpkKeyAlgorithm::Ed448 => picky::putty::PpkKeyAlgorithm::Ed448,
        }
    }
}

impl From<picky::putty::Argon2Flavour> for ffi::PuttyArgon2Flavour {
    fn from(flavour: picky::putty::Argon2Flavour) -> Self {
        match flavour {
            picky::putty::Argon2Flavour::Argon2d => ffi::PuttyArgon2Flavour::Argon2d,
            picky::putty::Argon2Flavour::Argon2i => ffi::PuttyArgon2Flavour::Argon2i,
            picky::putty::Argon2Flavour::Argon2id => ffi::PuttyArgon2Flavour::Argon2id,
        }
    }
}

impl From<ffi::PuttyArgon2Flavour> for picky::putty::Argon2Flavour {
    fn from(flavour: ffi::PuttyArgon2Flavour) -> Self {
        match flavour {
            ffi::PuttyArgon2Flavour::Argon2d => picky::putty::Argon2Flavour::Argon2d,
            ffi::PuttyArgon2Flavour::Argon2i => picky::putty::Argon2Flavour::Argon2i,
            ffi::PuttyArgon2Flavour::Argon2id => picky::putty::Argon2Flavour::Argon2id,
        }
    }
}

#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use crate::key::ffi::{EcCurve, PrivateKey, PublicKey};
    use crate::ssh::ffi::SshPrivateKey;
    use crate::ssh::ffi::SshPublicKey;
    use crate::utils::ffi::VecU8;
    use diplomat_runtime::DiplomatWriteable;
    use std::fmt::Write;

    /// PuTTY Private Key (PPK) version.
    pub enum PuttyPpkVersion {
        V2,
        V3,
    }

    /// PuTTY Private Key (PPK) algorithm.
    pub enum PuttyPpkKeyAlgorithm {
        Rsa,
        Dss,
        EcdsaSha2Nistp256,
        EcdsaSha2Nistp384,
        EcdsaSha2Nistp521,
        Ed25519,
        Ed448,
    }

    /// Argon2 key derivation function flavour.
    pub enum PuttyArgon2Flavour {
        Argon2d,
        Argon2i,
        Argon2id,
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
    #[diplomat::opaque]
    pub struct PuttyPpk(picky::putty::Ppk);

    impl PuttyPpk {
        /// Generate a new RSA key file.
        pub fn generate_rsa(bits: usize, comment: &str) -> Result<Box<PuttyPpk>, Box<PickyError>> {
            let comment = if comment.is_empty() { None } else { Some(comment) };
            let ppk = picky::putty::Ppk::generate_rsa(bits, comment)?;
            Ok(Box::new(PuttyPpk(ppk)))
        }

        /// Generate a new EC key file.
        pub fn generate_ec(curve: EcCurve, comment: &str) -> Result<Box<PuttyPpk>, Box<PickyError>> {
            let comment = if comment.is_empty() { None } else { Some(comment) };
            let ppk = picky::putty::Ppk::generate_ec(curve.into(), comment)?;
            Ok(Box::new(PuttyPpk(ppk)))
        }

        /// Generate a new Ed25519 key file.
        pub fn generate_ed25519(comment: &str) -> Result<Box<PuttyPpk>, Box<PickyError>> {
            let comment = if comment.is_empty() { None } else { Some(comment) };
            let ppk = picky::putty::Ppk::generate_ed25519(comment)?;
            Ok(Box::new(PuttyPpk(ppk)))
        }

        /// Encode PPK key file to a string.
        pub fn to_string(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            writeable.write_str(&self.0.to_string()?)?;
            writeable.flush();
            Ok(())
        }

        /// Parse a PPK key file from a string.
        pub fn parse(ppk: &str) -> Result<Box<PuttyPpk>, Box<PickyError>> {
            let ppk: picky::putty::Ppk = ppk.parse()?;
            Ok(Box::new(PuttyPpk(ppk)))
        }

        /// Convert an OpenSSH private key to a PPK key file.
        pub fn from_openssh_private_key(key: &SshPrivateKey) -> Result<Box<PuttyPpk>, Box<PickyError>> {
            let ppk = picky::putty::Ppk::from_openssh_private_key(&key.0)?;
            Ok(Box::new(PuttyPpk(ppk)))
        }

        /// Convert a PPK key file to an OpenSSH private key.
        pub fn to_openssh_private_key(&self, passphrase: &str) -> Result<Box<SshPrivateKey>, Box<PickyError>> {
            let passphrase = if passphrase.is_empty() { None } else { Some(passphrase) };
            let key: picky::ssh::SshPrivateKey = self.0.to_openssh_private_key(passphrase)?;
            Ok(Box::new(SshPrivateKey(key)))
        }

        /// Get the public key from the PPK key file.
        pub fn public_key(&self) -> Result<Box<PublicKey>, Box<PickyError>> {
            let key = self.0.public_key()?;
            Ok(Box::new(PublicKey(key)))
        }

        /// Get the private key from the PPK key file.
        pub fn private_key(&self) -> Result<Box<PrivateKey>, Box<PickyError>> {
            let key = self.0.private_key()?;
            Ok(Box::new(PrivateKey(key)))
        }

        /// Extract the public key file (PuTTY format) from the PPK key file.
        pub fn extract_putty_public_key(&self) -> Result<Box<PuttyPublicKey>, Box<PickyError>> {
            let key = self.0.extract_putty_public_key()?;
            Ok(Box::new(PuttyPublicKey(key)))
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
        pub fn comment(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            writeable.write_str(self.0.comment())?;
            writeable.flush();
            Ok(())
        }

        /// Convert the PPK key file to a different version.
        pub fn to_version(&self, version: PuttyPpkVersion) -> Result<Box<PuttyPpk>, Box<PickyError>> {
            let ppk = self.0.to_version(version.into())?;
            Ok(Box::new(PuttyPpk(ppk)))
        }

        /// Check if the PPK key file is encrypted.
        pub fn is_encrypted(&self) -> bool {
            self.0.is_encrypted()
        }

        /// Get the Argon2 key derivation function parameters (if the key is encrypted).
        pub fn argon2_params(&self) -> Option<Box<PuttyArgon2Params>> {
            self.0
                .argon2_params()
                .map(|params| Box::new(PuttyArgon2Params(params.clone())))
        }

        /// Decrypt the PPK key file and return as a new instance.
        pub fn decrypt(&self, passphrase: &str) -> Result<Box<PuttyPpk>, Box<PickyError>> {
            let ppk = self.0.decrypt(passphrase)?;
            Ok(Box::new(PuttyPpk(ppk)))
        }

        /// Encrypt the PPK key file and return as a new instance.
        pub fn encrypt(
            &self,
            passphrase: &str,
            config: &PuttyPpkEncryptionConfig,
        ) -> Result<Box<PuttyPpk>, Box<PickyError>> {
            let ppk = self.0.encrypt(passphrase, config.0.clone())?;
            Ok(Box::new(PuttyPpk(ppk)))
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
    #[diplomat::opaque]
    pub struct PuttyPublicKey(picky::putty::PuttyPublicKey);

    impl PuttyPublicKey {
        /// Converts an OpenSSH public key to a PuTTY public key.
        pub fn from_openssh(key: &SshPublicKey) -> Result<Box<PuttyPublicKey>, Box<PickyError>> {
            let key = picky::putty::PuttyPublicKey::from_openssh(&key.0)?;
            Ok(Box::new(PuttyPublicKey(key)))
        }

        /// Converts the key to an OpenSSH public key.
        pub fn to_openssh(&self) -> Result<Box<SshPublicKey>, Box<PickyError>> {
            let key = self.0.to_openssh()?;
            Ok(Box::new(crate::ssh::ffi::SshPublicKey(key)))
        }

        /// Get the comment of the public key.
        pub fn comment(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            writeable.write_str(self.0.comment())?;
            writeable.flush();
            Ok(())
        }

        /// Converts the public key to a string (PuTTY format).
        pub fn to_string(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            writeable.write_str(&self.0.to_string())?;
            writeable.flush();
            Ok(())
        }

        /// Parses and returns the inner key as standard picky key type.
        pub fn to_inner_key(&self) -> Result<Box<PublicKey>, Box<PickyError>> {
            let key = self.0.to_inner_key()?;
            Ok(Box::new(PublicKey(key)))
        }
    }

    /// Argon2 key derivation function parameters.
    #[diplomat::opaque]
    pub struct PuttyArgon2Params(picky::putty::Argon2Params);

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

        pub fn salt(&self) -> Box<VecU8> {
            Box::new(VecU8(self.0.salt.to_vec()))
        }
    }

    /// PPK encryption configuration.
    ///
    /// Could be either constructed via `PuttyPpkEncryptionConfig::default()` or `PuttyPpkEncryptionConfig::builder()`
    ///
    /// Defaults are the same as in PuTTY.
    #[diplomat::opaque]
    pub struct PuttyPpkEncryptionConfig(picky::putty::PpkEncryptionConfig);

    impl PuttyPpkEncryptionConfig {
        pub fn default() -> Box<Self> {
            Box::new(PuttyPpkEncryptionConfig(picky::putty::PpkEncryptionConfig::default()))
        }

        pub fn builder() -> Box<PuttyPpkEncryptionConfigBuilder> {
            Box::new(PuttyPpkEncryptionConfigBuilder(
                picky::putty::PpkEncryptionConfig::builder(),
            ))
        }
    }

    /// PPK encryption configuration builder.
    ///
    /// Could be constructed via `PuttyPpkEncryptionConfig::builder()`.
    #[diplomat::opaque]
    pub struct PuttyPpkEncryptionConfigBuilder(picky::putty::PpkEncryptionConfigBuilder);

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

        pub fn build(&self) -> Box<PuttyPpkEncryptionConfig> {
            Box::new(PuttyPpkEncryptionConfig(self.0.clone().build()))
        }
    }
}
