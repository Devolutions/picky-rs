use picky::ssh;

impl From<ffi::SshCertKeyType> for ssh::SshCertKeyType {
    fn from(ty: ffi::SshCertKeyType) -> Self {
        match ty {
            ffi::SshCertKeyType::SshRsaV01 => ssh::SshCertKeyType::SshRsaV01,
            ffi::SshCertKeyType::SshDssV01 => ssh::SshCertKeyType::SshDssV01,
            ffi::SshCertKeyType::RsaSha2_256V01 => ssh::SshCertKeyType::RsaSha2_256V01,
            ffi::SshCertKeyType::RsaSha2_512v01 => ssh::SshCertKeyType::RsaSha2_512v01,
            ffi::SshCertKeyType::EcdsaSha2Nistp256V01 => ssh::SshCertKeyType::EcdsaSha2Nistp256V01,
            ffi::SshCertKeyType::EcdsaSha2Nistp384V01 => ssh::SshCertKeyType::EcdsaSha2Nistp384V01,
            ffi::SshCertKeyType::EcdsaSha2Nistp521V01 => ssh::SshCertKeyType::EcdsaSha2Nistp521V01,
            ffi::SshCertKeyType::SshEd25519V01 => ssh::SshCertKeyType::SshEd25519V01,
        }
    }
}

impl From<ssh::SshCertKeyType> for ffi::SshCertKeyType {
    fn from(ty: ssh::SshCertKeyType) -> Self {
        match ty {
            ssh::SshCertKeyType::SshRsaV01 => ffi::SshCertKeyType::SshRsaV01,
            ssh::SshCertKeyType::SshDssV01 => ffi::SshCertKeyType::SshDssV01,
            ssh::SshCertKeyType::RsaSha2_256V01 => ffi::SshCertKeyType::RsaSha2_256V01,
            ssh::SshCertKeyType::RsaSha2_512v01 => ffi::SshCertKeyType::RsaSha2_512v01,
            ssh::SshCertKeyType::EcdsaSha2Nistp256V01 => ffi::SshCertKeyType::EcdsaSha2Nistp256V01,
            ssh::SshCertKeyType::EcdsaSha2Nistp384V01 => ffi::SshCertKeyType::EcdsaSha2Nistp384V01,
            ssh::SshCertKeyType::EcdsaSha2Nistp521V01 => ffi::SshCertKeyType::EcdsaSha2Nistp521V01,
            ssh::SshCertKeyType::SshEd25519V01 => ffi::SshCertKeyType::SshEd25519V01,
        }
    }
}

impl From<ffi::SshCertType> for ssh::SshCertType {
    fn from(ty: ffi::SshCertType) -> Self {
        match ty {
            ffi::SshCertType::Client => ssh::SshCertType::Client,
            ffi::SshCertType::Host => ssh::SshCertType::Host,
        }
    }
}

impl From<ssh::SshCertType> for ffi::SshCertType {
    fn from(ty: ssh::SshCertType) -> Self {
        match ty {
            ssh::SshCertType::Client => ffi::SshCertType::Client,
            ssh::SshCertType::Host => ffi::SshCertType::Host,
        }
    }
}

#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use crate::key::ffi::{EcCurve, PrivateKey};
    use crate::pem::ffi::Pem;
    use crate::signature::ffi::SignatureAlgorithm;
    use diplomat_runtime::DiplomatWriteable;
    use picky::ssh;
    use std::borrow::ToOwned;
    use std::fmt::Write as _;
    use std::str::FromStr;

    /// SSH Public Key.
    #[diplomat::opaque]
    pub struct SshPublicKey(pub ssh::SshPublicKey);

    impl SshPublicKey {
        /// Parses string representation of a SSH Public Key.
        pub fn parse(repr: &str) -> Result<Box<SshPublicKey>, Box<PickyError>> {
            let key = ssh::SshPublicKey::from_str(repr)?;
            Ok(Box::new(SshPublicKey(key)))
        }

        /// Returns the SSH Public Key string representation.
        ///
        /// It is generally represented as:
        /// "(algorithm) (der for the key) (comment)"
        /// where (comment) is usually an email address.
        pub fn to_repr(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let repr = self.0.to_string()?;
            writeable.write_str(&repr)?;
            writeable.flush();
            Ok(())
        }

        pub fn get_comment(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            writeable.write_str(&self.0.comment)?;
            writeable.flush();
            Ok(())
        }
    }

    /// SSH Private Key.
    #[diplomat::opaque]
    pub struct SshPrivateKey(pub ssh::SshPrivateKey);

    impl SshPrivateKey {
        /// Generates a new SSH RSA Private Key.
        ///
        /// No passphrase is set if `passphrase` is empty.
        ///
        /// No comment is set if `comment` is empty.
        ///
        /// This is slow in debug builds.
        pub fn generate_rsa(
            bits: usize,
            passphrase: &str,
            comment: &str,
        ) -> Result<Box<SshPrivateKey>, Box<PickyError>> {
            let passphrase = if passphrase.is_empty() {
                None
            } else {
                Some(passphrase.to_owned())
            };

            let comment = if comment.is_empty() {
                None
            } else {
                Some(comment.to_owned())
            };

            let key = ssh::SshPrivateKey::generate_rsa(bits, passphrase, comment)?;
            Ok(Box::new(SshPrivateKey(key)))
        }

        /// Generates a new SSH EC Private Key.
        ///
        /// No passphrase is set if `passphrase` is empty.
        ///
        /// No comment is set if `comment` is empty.
        pub fn generate_ec(
            curve: EcCurve,
            passphrase: &str,
            comment: &str,
        ) -> Result<Box<SshPrivateKey>, Box<PickyError>> {
            let passphrase = if passphrase.is_empty() {
                None
            } else {
                Some(passphrase.to_owned())
            };

            let comment = if comment.is_empty() {
                None
            } else {
                Some(comment.to_owned())
            };

            let key = ssh::SshPrivateKey::generate_ec(curve.into(), passphrase, comment)?;
            Ok(Box::new(SshPrivateKey(key)))
        }

        /// Extracts SSH Private Key from PEM object.
        ///
        /// No passphrase is set if `passphrase` is empty.
        pub fn from_pem(pem: &Pem, passphrase: &str) -> Result<Box<SshPrivateKey>, Box<PickyError>> {
            let passphrase = if passphrase.is_empty() {
                None
            } else {
                Some(passphrase.to_owned())
            };

            let key = ssh::SshPrivateKey::from_pem(&pem.0, passphrase)?;
            Ok(Box::new(SshPrivateKey(key)))
        }

        pub fn from_private_key(key: &PrivateKey) -> Result<Box<SshPrivateKey>, Box<PickyError>> {
            let key = ssh::SshPrivateKey::try_from(key.0.clone())?;
            Ok(Box::new(SshPrivateKey(key)))
        }

        /// Exports the SSH Private Key into a PEM object
        pub fn to_pem(&self) -> Result<Box<Pem>, Box<PickyError>> {
            let pem = self.0.to_pem()?;
            Ok(Box::new(Pem(pem)))
        }

        /// Returns the SSH Private Key string representation.
        pub fn to_repr(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let repr = self.0.to_string()?;
            writeable.write_str(&repr)?;
            writeable.flush();
            Ok(())
        }

        pub fn get_cipher_name(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            writeable.write_str(&self.0.cipher_name)?;
            writeable.flush();
            Ok(())
        }

        pub fn get_comment(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            writeable.write_str(&self.0.comment)?;
            writeable.flush();
            Ok(())
        }

        /// Extracts the public part of this private key
        pub fn to_public_key(&self) -> Box<SshPublicKey> {
            Box::new(SshPublicKey(self.0.public_key().clone()))
        }
    }

    /// SSH key type.
    pub enum SshCertKeyType {
        SshRsaV01,
        SshDssV01,
        RsaSha2_256V01,
        RsaSha2_512v01,
        EcdsaSha2Nistp256V01,
        EcdsaSha2Nistp384V01,
        EcdsaSha2Nistp521V01,
        SshEd25519V01,
    }

    /// SSH certificate type.
    pub enum SshCertType {
        Client,
        Host,
    }

    /// SSH Certificate Builder.
    #[diplomat::opaque]
    pub struct SshCertBuilder(pub ssh::SshCertificateBuilder);

    impl SshCertBuilder {
        pub fn init() -> Box<SshCertBuilder> {
            Box::new(Self(ssh::SshCertificateBuilder::init()))
        }

        /// Required
        pub fn set_cert_key_type(&self, key_type: SshCertKeyType) {
            self.0.cert_key_type(key_type.into());
        }

        /// Required
        pub fn set_key(&self, key: &SshPublicKey) {
            self.0.key(key.0.clone());
        }

        /// Optional (set to 0 by default)
        pub fn set_serial(&self, serial: u64) {
            self.0.serial(serial);
        }

        /// Required
        pub fn set_cert_type(&self, cert_type: SshCertType) {
            self.0.cert_type(cert_type.into());
        }

        /// Optional
        pub fn set_key_id(&self, key_id: &str) {
            self.0.key_id(key_id.to_owned());
        }

        /// Required
        pub fn set_valid_before(&self, valid_before: u64) {
            self.0.valid_before(valid_before);
        }

        /// Required
        pub fn set_valid_after(&self, valid_after: u64) {
            self.0.valid_after(valid_after);
        }

        /// Required
        pub fn set_signature_key(&self, signature_key: &SshPrivateKey) {
            self.0.signature_key(signature_key.0.clone());
        }

        /// Optional. RsaPkcs1v15 with SHA256 is used by default.
        pub fn set_signature_algo(&self, signature_algo: &SignatureAlgorithm) {
            self.0.signature_algo(signature_algo.0);
        }

        /// Optional
        pub fn set_comment(&self, comment: &str) {
            self.0.comment(comment.to_owned());
        }

        pub fn build(&self) -> Result<Box<SshCert>, Box<PickyError>> {
            let cert = self.0.build()?;
            Ok(Box::new(SshCert(cert)))
        }
    }

    #[diplomat::opaque]
    pub struct SshCert(pub ssh::SshCertificate);

    impl SshCert {
        pub fn builder() -> Box<SshCertBuilder> {
            SshCertBuilder::init()
        }

        /// Parses string representation of a SSH Certificate.
        pub fn parse(repr: &str) -> Result<Box<SshCert>, Box<PickyError>> {
            let cert = ssh::SshCertificate::from_str(repr)?;
            Ok(Box::new(SshCert(cert)))
        }

        /// Returns the SSH Certificate string representation.
        pub fn to_repr(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let repr = self.0.to_string()?;
            writeable.write_str(&repr)?;
            writeable.flush();
            Ok(())
        }

        pub fn get_public_key(&self) -> Box<SshPublicKey> {
            Box::new(SshPublicKey(self.0.public_key.clone()))
        }

        pub fn get_ssh_key_type(&self) -> SshCertKeyType {
            self.0.cert_key_type.into()
        }

        pub fn get_cert_type(&self) -> SshCertType {
            self.0.cert_type.into()
        }

        pub fn get_valid_after(&self) -> u64 {
            self.0.valid_after.0
        }

        pub fn get_valid_before(&self) -> u64 {
            self.0.valid_before.0
        }

        pub fn get_signature_key(&self) -> Box<SshPublicKey> {
            Box::new(SshPublicKey(self.0.signature_key.clone()))
        }

        pub fn get_key_id(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            writeable.write_str(&self.0.key_id)?;
            writeable.flush();
            Ok(())
        }

        pub fn get_comment(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            writeable.write_str(&self.0.comment)?;
            writeable.flush();
            Ok(())
        }
    }
}
