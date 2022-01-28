use picky::ssh::certificate::{SshCertKeyType, SshCertType};

impl From<ffi::PickySshCertKeyType> for SshCertKeyType {
    fn from(ty: ffi::PickySshCertKeyType) -> Self {
        match ty {
            ffi::PickySshCertKeyType::SshRsaV01 => SshCertKeyType::SshRsaV01,
            ffi::PickySshCertKeyType::SshDssV01 => SshCertKeyType::SshDssV01,
            ffi::PickySshCertKeyType::RsaSha2_256V01 => SshCertKeyType::RsaSha2_256V01,
            ffi::PickySshCertKeyType::RsaSha2_512v01 => SshCertKeyType::RsaSha2_512v01,
            ffi::PickySshCertKeyType::EcdsaSha2Nistp256V01 => SshCertKeyType::EcdsaSha2Nistp256V01,
            ffi::PickySshCertKeyType::EcdsaSha2Nistp384V01 => SshCertKeyType::EcdsaSha2Nistp384V01,
            ffi::PickySshCertKeyType::EcdsaSha2Nistp521V01 => SshCertKeyType::EcdsaSha2Nistp521V01,
            ffi::PickySshCertKeyType::SshEd25519V01 => SshCertKeyType::SshEd25519V01,
        }
    }
}

impl From<SshCertKeyType> for ffi::PickySshCertKeyType {
    fn from(ty: SshCertKeyType) -> Self {
        match ty {
            SshCertKeyType::SshRsaV01 => ffi::PickySshCertKeyType::SshRsaV01,
            SshCertKeyType::SshDssV01 => ffi::PickySshCertKeyType::SshDssV01,
            SshCertKeyType::RsaSha2_256V01 => ffi::PickySshCertKeyType::RsaSha2_256V01,
            SshCertKeyType::RsaSha2_512v01 => ffi::PickySshCertKeyType::RsaSha2_512v01,
            SshCertKeyType::EcdsaSha2Nistp256V01 => ffi::PickySshCertKeyType::EcdsaSha2Nistp256V01,
            SshCertKeyType::EcdsaSha2Nistp384V01 => ffi::PickySshCertKeyType::EcdsaSha2Nistp384V01,
            SshCertKeyType::EcdsaSha2Nistp521V01 => ffi::PickySshCertKeyType::EcdsaSha2Nistp521V01,
            SshCertKeyType::SshEd25519V01 => ffi::PickySshCertKeyType::SshEd25519V01,
        }
    }
}

impl From<ffi::PickySshCertType> for SshCertType {
    fn from(ty: ffi::PickySshCertType) -> Self {
        match ty {
            ffi::PickySshCertType::Client => SshCertType::Client,
            ffi::PickySshCertType::Host => SshCertType::Host,
        }
    }
}

impl From<SshCertType> for ffi::PickySshCertType {
    fn from(ty: SshCertType) -> Self {
        match ty {
            SshCertType::Client => ffi::PickySshCertType::Client,
            SshCertType::Host => ffi::PickySshCertType::Host,
        }
    }
}

#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use crate::key::ffi::PickyPrivateKey;
    use crate::pem::ffi::PickyPem;
    use crate::signature::ffi::PickySignatureAlgorithm;
    use diplomat_runtime::{DiplomatResult, DiplomatWriteable};
    use picky::ssh::certificate::{SshCertificate, SshCertificateBuilder};
    use picky::ssh::private_key::SshPrivateKey;
    use picky::ssh::public_key::SshPublicKey;
    use picky::ssh::sshtime::SshTime;
    use std::borrow::ToOwned;
    use std::fmt::Write as _;
    use std::str::FromStr;

    /// SSH Public Key.
    #[diplomat::opaque]
    pub struct PickySshPublicKey(pub SshPublicKey);

    impl PickySshPublicKey {
        /// Parses string representation of a SSH Public Key.
        pub fn parse(repr: &str) -> DiplomatResult<Box<PickySshPublicKey>, Box<PickyError>> {
            let key = err_check!(SshPublicKey::from_str(repr));
            Ok(Box::new(PickySshPublicKey(key))).into()
        }

        /// Returns the SSH Public Key string representation.
        ///
        /// It is generally represented as:
        /// "<algorithm> <der for the key> <comment>"
        /// where <comment> is usually an email address.
        pub fn to_repr(&self, writeable: &mut DiplomatWriteable) -> DiplomatResult<(), Box<PickyError>> {
            let repr = err_check!(self.0.to_string());
            err_check!(writeable.write_str(&repr));
            writeable.flush();
            Ok(()).into()
        }

        pub fn get_comment(&self, writeable: &mut DiplomatWriteable) -> DiplomatResult<(), Box<PickyError>> {
            err_check!(writeable.write_str(&self.0.comment));
            writeable.flush();
            Ok(()).into()
        }
    }

    /// SSH Private Key.
    #[diplomat::opaque]
    pub struct PickySshPrivateKey(pub SshPrivateKey);

    impl PickySshPrivateKey {
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
        ) -> DiplomatResult<Box<PickySshPrivateKey>, Box<PickyError>> {
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

            let key = err_check!(SshPrivateKey::generate_rsa(bits, passphrase, comment));
            Ok(Box::new(PickySshPrivateKey(key))).into()
        }

        /// Extracts SSH Private Key from PEM object.
        ///
        /// No passphrase is set if `passphrase` is empty.
        pub fn from_pem(pem: &PickyPem, passphrase: &str) -> DiplomatResult<Box<PickySshPrivateKey>, Box<PickyError>> {
            let passphrase = if passphrase.is_empty() {
                None
            } else {
                Some(passphrase.to_owned())
            };

            let key = err_check!(SshPrivateKey::from_pem(&pem.0, passphrase));
            Ok(Box::new(PickySshPrivateKey(key))).into()
        }

        pub fn from_private_key(key: &PickyPrivateKey) -> Box<PickySshPrivateKey> {
            let key = SshPrivateKey::from(key.0.clone());
            Box::new(PickySshPrivateKey(key))
        }

        /// Exports the SSH Private Key into a PEM object
        pub fn to_pem(&self) -> DiplomatResult<Box<PickyPem>, Box<PickyError>> {
            let pem = err_check!(self.0.to_pem());
            Ok(Box::new(PickyPem(pem))).into()
        }

        /// Returns the SSH Private Key string representation.
        pub fn to_repr(&self, writeable: &mut DiplomatWriteable) -> DiplomatResult<(), Box<PickyError>> {
            let repr = err_check!(self.0.to_string());
            err_check!(writeable.write_str(&repr));
            writeable.flush();
            Ok(()).into()
        }

        pub fn get_cipher_name(&self, writeable: &mut DiplomatWriteable) -> DiplomatResult<(), Box<PickyError>> {
            err_check!(writeable.write_str(&self.0.cipher_name));
            writeable.flush();
            Ok(()).into()
        }

        pub fn get_comment(&self, writeable: &mut DiplomatWriteable) -> DiplomatResult<(), Box<PickyError>> {
            err_check!(writeable.write_str(&self.0.comment));
            writeable.flush();
            Ok(()).into()
        }

        /// Extracts the public part of this private key
        pub fn to_public_key(&self) -> Box<PickySshPublicKey> {
            Box::new(PickySshPublicKey(self.0.public_key().clone()))
        }
    }

    /// SSH key type.
    pub enum PickySshCertKeyType {
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
    pub enum PickySshCertType {
        Client,
        Host,
    }

    /// SSH datetime.
    #[diplomat::opaque]
    pub struct PickySshTime(pub SshTime);

    impl PickySshTime {
        pub fn now() -> Box<PickySshTime> {
            Box::new(Self(SshTime::now()))
        }

        pub fn from_timestamp(timestamp: u64) -> Box<PickySshTime> {
            Box::new(Self(SshTime::from_timestamp(timestamp)))
        }

        pub fn get_timestamp(&self) -> u64 {
            self.0.timestamp()
        }

        pub fn get_month(&self) -> u8 {
            self.0.month()
        }

        pub fn get_day(&self) -> u8 {
            self.0.day()
        }

        pub fn get_hour(&self) -> u8 {
            self.0.hour()
        }

        pub fn get_minute(&self) -> u8 {
            self.0.minute()
        }

        pub fn get_second(&self) -> u8 {
            self.0.second()
        }

        pub fn get_year(&self) -> u16 {
            self.0.year()
        }
    }

    /// SSH Certificate Builder.
    #[diplomat::opaque]
    pub struct PickySshCertBuilder(pub SshCertificateBuilder);

    impl PickySshCertBuilder {
        pub fn init() -> Box<PickySshCertBuilder> {
            Box::new(Self(SshCertificateBuilder::init()))
        }

        /// Required
        pub fn set_cert_key_type(&self, key_type: PickySshCertKeyType) {
            self.0.cert_key_type(key_type.into());
        }

        /// Required
        pub fn set_key(&self, key: &PickySshPublicKey) {
            self.0.key(key.0.clone());
        }

        /// Optional (set to 0 by default)
        pub fn set_serial(&self, serial: u64) {
            self.0.serial(serial);
        }

        /// Required
        pub fn set_cert_type(&self, cert_type: PickySshCertType) {
            self.0.cert_type(cert_type.into());
        }

        /// Optional
        pub fn set_key_id(&self, key_id: &str) {
            self.0.key_id(key_id.to_owned());
        }

        /// Required
        pub fn set_valid_before(&self, valid_before: &PickySshTime) {
            self.0.valid_before(valid_before.0);
        }

        /// Required
        pub fn set_valid_after(&self, valid_after: &PickySshTime) {
            self.0.valid_after(valid_after.0);
        }

        /// Required
        pub fn set_signature_key(&self, signature_key: &PickySshPrivateKey) {
            self.0.signature_key(signature_key.0.clone());
        }

        /// Optional. RsaPkcs1v15 with SHA256 is used by default.
        pub fn set_signature_algo(&self, signature_algo: &PickySignatureAlgorithm) {
            self.0.signature_algo(signature_algo.0);
        }

        /// Optional
        pub fn set_comment(&self, comment: &str) {
            self.0.comment(comment.to_owned());
        }

        pub fn build(&self) -> DiplomatResult<Box<PickySshCert>, Box<PickyError>> {
            let cert = err_check!(self.0.build());
            Ok(Box::new(PickySshCert(cert))).into()
        }
    }

    #[diplomat::opaque]
    pub struct PickySshCert(pub SshCertificate);

    impl PickySshCert {
        pub fn builder() -> Box<PickySshCertBuilder> {
            PickySshCertBuilder::init()
        }

        /// Parses string representation of a SSH Certificate.
        pub fn parse(repr: &str) -> DiplomatResult<Box<PickySshCert>, Box<PickyError>> {
            let cert = err_check!(SshCertificate::from_str(repr));
            Ok(Box::new(PickySshCert(cert))).into()
        }

        /// Returns the SSH Certificate string representation.
        pub fn to_repr(&self, writeable: &mut DiplomatWriteable) -> DiplomatResult<(), Box<PickyError>> {
            let repr = err_check!(self.0.to_string());
            err_check!(writeable.write_str(&repr));
            writeable.flush();
            Ok(()).into()
        }

        pub fn get_public_key(&self) -> Box<PickySshPublicKey> {
            Box::new(PickySshPublicKey(self.0.public_key.clone()))
        }

        pub fn get_ssh_key_type(&self) -> PickySshCertKeyType {
            self.0.cert_key_type.into()
        }

        pub fn get_cert_type(&self) -> PickySshCertType {
            self.0.cert_type.into()
        }

        pub fn get_valid_after(&self) -> Box<PickySshTime> {
            Box::new(PickySshTime(self.0.valid_after))
        }

        pub fn get_valid_before(&self) -> Box<PickySshTime> {
            Box::new(PickySshTime(self.0.valid_before))
        }

        pub fn get_signature_key(&self) -> Box<PickySshPublicKey> {
            Box::new(PickySshPublicKey(self.0.signature_key.clone()))
        }

        pub fn get_key_id(&self, writeable: &mut DiplomatWriteable) -> DiplomatResult<(), Box<PickyError>> {
            err_check!(writeable.write_str(&self.0.key_id));
            writeable.flush();
            Ok(()).into()
        }

        pub fn get_comment(&self, writeable: &mut DiplomatWriteable) -> DiplomatResult<(), Box<PickyError>> {
            err_check!(writeable.write_str(&self.0.comment));
            writeable.flush();
            Ok(()).into()
        }
    }
}
