use crate::hash::HashAlgorithm;
use crate::key::KeyError;
#[cfg(feature = "fips")]
use crate::key::ec::EcdsaPublicKey;
#[cfg(feature = "fips")]
use crate::key::ed::EdPublicKey;
use crate::signature::{SignatureAlgorithm, SignatureError};
use crate::ssh::decode::SshComplexTypeDecode;
use crate::ssh::encode::SshComplexTypeEncode;
use crate::ssh::private_key::{SshBasePrivateKey, SshPrivateKey, SshPrivateKeyError};
use crate::ssh::public_key::{SshBasePublicKey, SshPublicKey, SshPublicKeyError};

use serde::Deserialize;
use std::cell::RefCell;
use std::convert::TryFrom;
use std::io;
use std::ops::DerefMut;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshCertificateError {
    #[error("Can not process the certificate: {0:?}")]
    CertificateProcessingError(#[from] std::io::Error),
    #[error("Unsupported certificate type: {0}")]
    UnsupportedCertificateType(String),
    #[error(transparent)]
    SshCriticalOptionError(#[from] SshCriticalOptionError),
    #[error(transparent)]
    SshExtensionError(#[from] SshExtensionError),
    #[error("invalid UTF-8")]
    InvalidUtf8,
    #[error("Invalid base64 string: {0:?}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error(transparent)]
    InvalidCertificateType(#[from] SshCertTypeError),
    #[error("Invalid certificate key type: {0}")]
    InvalidCertificateKeyType(String),
    #[error("Certificate had invalid public key: {0:?}")]
    InvalidPublicKey(#[from] SshPublicKeyError),
    #[cfg(feature = "rustcrypto")]
    #[error(transparent)]
    RsaError(#[from] rsa::errors::Error),
    #[error(transparent)]
    KeyError(#[from] KeyError),
    #[error(transparent)]
    SshSignatureError(#[from] SshSignatureError),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
}

impl From<core::str::Utf8Error> for SshCertificateError {
    fn from(_: core::str::Utf8Error) -> Self {
        Self::InvalidUtf8
    }
}

impl From<std::string::FromUtf8Error> for SshCertificateError {
    fn from(_: std::string::FromUtf8Error) -> Self {
        Self::InvalidUtf8
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
pub enum SshCertType {
    Client,
    Host,
}

#[derive(Error, Debug)]
pub enum SshCertTypeError {
    #[error("Invalid certificate type. Expected 1(Client) or 2(Host) but got: {0}")]
    InvalidCertificateType(u32),
    #[error(transparent)]
    IoError(#[from] io::Error),
}

impl TryFrom<u32> for SshCertType {
    type Error = SshCertTypeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SshCertType::Client),
            2 => Ok(SshCertType::Host),
            x => Err(SshCertTypeError::InvalidCertificateType(x)),
        }
    }
}

impl From<SshCertType> for u32 {
    fn from(val: SshCertType) -> u32 {
        match val {
            SshCertType::Client => 1,
            SshCertType::Host => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SshCertKeyType {
    SshRsaV01,
    SshDssV01,
    RsaSha2_256V01,
    RsaSha2_512v01,
    EcdsaSha2Nistp256V01,
    EcdsaSha2Nistp384V01,
    EcdsaSha2Nistp521V01,
    SshEd25519V01,
    SkSshSha2Nistp256V01,
    SkSshEd25519V01,
}

impl SshCertKeyType {
    pub(crate) fn subject_key_type(&self) -> Result<&'static str, SshCertificateError> {
        use crate::ssh::key_type;
        #[cfg(feature = "fips")]
        if matches!(
            self,
            Self::SshDssV01 | Self::SkSshSha2Nistp256V01 | Self::SkSshEd25519V01
        ) {
            return Err(SshCertificateError::UnsupportedCertificateType(
                self.as_str().to_owned(),
            ));
        }
        Ok(match self {
            Self::SshRsaV01 | Self::RsaSha2_256V01 | Self::RsaSha2_512v01 => key_type::RSA,
            Self::EcdsaSha2Nistp256V01 => key_type::ECDSA_SHA2_NIST_P256,
            Self::EcdsaSha2Nistp384V01 => key_type::ECDSA_SHA2_NIST_P384,
            Self::EcdsaSha2Nistp521V01 => key_type::ECDSA_SHA2_NIST_P521,
            Self::SshEd25519V01 => key_type::ED25519,
            Self::SkSshSha2Nistp256V01 => key_type::SK_ECDSA_SHA2_NIST_P256,
            Self::SkSshEd25519V01 => key_type::SK_ED25519,
            Self::SshDssV01 => {
                return Err(SshCertificateError::UnsupportedCertificateType(
                    self.as_str().to_owned(),
                ));
            }
        })
    }

    pub fn as_str(&self) -> &str {
        match self {
            SshCertKeyType::SshRsaV01 => "ssh-rsa-cert-v01@openssh.com",
            SshCertKeyType::SshDssV01 => "ssh-dss-cert-v01@openssh.com",
            SshCertKeyType::RsaSha2_256V01 => "rsa-sha2-256-cert-v01@openssh.com",
            SshCertKeyType::RsaSha2_512v01 => "rsa-sha2-512-cert-v01@openssh.com",
            SshCertKeyType::EcdsaSha2Nistp256V01 => "ecdsa-sha2-nistp256-cert-v01@openssh.com",
            SshCertKeyType::EcdsaSha2Nistp384V01 => "ecdsa-sha2-nistp384-cert-v01@openssh.com",
            SshCertKeyType::EcdsaSha2Nistp521V01 => "ecdsa-sha2-nistp521-cert-v01@openssh.com",
            SshCertKeyType::SshEd25519V01 => "ssh-ed25519-cert-v01@openssh.com",
            SshCertKeyType::SkSshSha2Nistp256V01 => "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
            SshCertKeyType::SkSshEd25519V01 => "sk-ssh-ed25519-cert-v01@openssh.com",
        }
    }
}

impl TryFrom<String> for SshCertKeyType {
    type Error = SshCertificateError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let key_type = match value.as_str() {
            "ssh-rsa-cert-v01@openssh.com" => Ok(SshCertKeyType::SshRsaV01),
            "ssh-dss-cert-v01@openssh.com" => Ok(SshCertKeyType::SshDssV01),
            "rsa-sha2-256-cert-v01@openssh.com" => Ok(SshCertKeyType::RsaSha2_256V01),
            "rsa-sha2-512-cert-v01@openssh.com" => Ok(SshCertKeyType::RsaSha2_512v01),
            "ecdsa-sha2-nistp256-cert-v01@openssh.com" => Ok(SshCertKeyType::EcdsaSha2Nistp256V01),
            "ecdsa-sha2-nistp384-cert-v01@openssh.com" => Ok(SshCertKeyType::EcdsaSha2Nistp384V01),
            "ecdsa-sha2-nistp521-cert-v01@openssh.com" => Ok(SshCertKeyType::EcdsaSha2Nistp521V01),
            "ssh-ed25519-cert-v01@openssh.com" => Ok(SshCertKeyType::SshEd25519V01),
            "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" => Ok(SshCertKeyType::SkSshSha2Nistp256V01),
            "sk-ssh-ed25519-cert-v01@openssh.com" => Ok(SshCertKeyType::SkSshEd25519V01),
            _ => Err(SshCertificateError::InvalidCertificateKeyType(value)),
        }?;
        #[cfg(feature = "fips")]
        key_type.subject_key_type()?;
        Ok(key_type)
    }
}

impl TryFrom<&str> for SshCertKeyType {
    type Error = SshCertificateError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

#[derive(Error, Debug)]
pub enum SshCriticalOptionError {
    #[error("Unsupported critical option type: {0}")]
    UnsupportedCriticalOptionType(String),
    #[error(transparent)]
    IoError(#[from] io::Error),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum SshCriticalOptionType {
    ForceCommand,
    SourceAddress,
    VerifyRequired,
}

impl SshCriticalOptionType {
    pub fn as_str(&self) -> &str {
        match self {
            SshCriticalOptionType::ForceCommand => "force-command",
            SshCriticalOptionType::SourceAddress => "source-address",
            SshCriticalOptionType::VerifyRequired => "verify-required",
        }
    }
}

impl TryFrom<String> for SshCriticalOptionType {
    type Error = SshCriticalOptionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "force-command" => Ok(SshCriticalOptionType::ForceCommand),
            "source-address" => Ok(SshCriticalOptionType::SourceAddress),
            "verify-required" => Ok(SshCriticalOptionType::VerifyRequired),
            _ => Err(SshCriticalOptionError::UnsupportedCriticalOptionType(value)),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SshCriticalOption {
    pub option_type: SshCriticalOptionType,
    pub data: String,
}

impl TryFrom<&str> for SshCriticalOptionType {
    type Error = SshCriticalOptionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

#[derive(Error, Debug)]
pub enum SshExtensionError {
    #[error("Unsupported extension type: {0}")]
    UnsupportedExtensionType(String),
    #[error(transparent)]
    IoError(#[from] io::Error),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SshExtensionType {
    NoTouchRequired,
    PermitX11Forwarding,
    PermitAgentForwarding,
    PermitPortForwarding,
    PermitPty,
    PermitUserPc,
}

impl SshExtensionType {
    pub fn as_str(&self) -> &str {
        match self {
            SshExtensionType::NoTouchRequired => "no-touch-required",
            SshExtensionType::PermitUserPc => "permit-user-rc",
            SshExtensionType::PermitPty => "permit-pty",
            SshExtensionType::PermitAgentForwarding => "permit-agent-forwarding",
            SshExtensionType::PermitPortForwarding => "permit-port-forwarding",
            SshExtensionType::PermitX11Forwarding => "permit-X11-forwarding",
        }
    }
}

impl TryFrom<String> for SshExtensionType {
    type Error = SshExtensionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "no-touch-required" => Ok(SshExtensionType::NoTouchRequired),
            "permit-X11-forwarding" => Ok(SshExtensionType::PermitX11Forwarding),
            "permit-agent-forwarding" => Ok(SshExtensionType::PermitAgentForwarding),
            "permit-port-forwarding" => Ok(SshExtensionType::PermitPortForwarding),
            "permit-pty" => Ok(SshExtensionType::PermitPty),
            "permit-user-rc" => Ok(SshExtensionType::PermitUserPc),
            _ => Err(SshExtensionError::UnsupportedExtensionType(value)),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SshExtension {
    pub extension_type: SshExtensionType,
    pub data: String,
}

impl TryFrom<&str> for SshExtensionType {
    type Error = SshExtensionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

impl SshExtension {
    pub fn new(extension_type: SshExtensionType, data: String) -> Self {
        Self { extension_type, data }
    }
}

#[derive(Error, Debug)]
pub enum SshSignatureError {
    #[error("unsupported signature format {0}")]
    UnsupportedSignatureFormat(String),
    #[error(transparent)]
    IoError(#[from] io::Error),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SshSignatureFormat {
    SshRsa,
    RsaSha256,
    RsaSha512,
    EcdsaSha2Nistp256,
    EcdsaSha2Nistp384,
    EcdsaSha2Nistp521,
    SshEd25519,
    SkEcdsaSha2NistP256,
    SkEd25519,
}

impl SshSignatureFormat {
    pub fn new<T: AsRef<str>>(format: T) -> Result<SshSignatureFormat, SshSignatureError> {
        #[cfg(feature = "fips")]
        if matches!(
            format.as_ref(),
            "ssh-rsa" | "sk-ecdsa-sha2-nistp256@openssh.com" | "sk-ssh-ed25519@openssh.com"
        ) {
            return Err(SshSignatureError::UnsupportedSignatureFormat(
                format.as_ref().to_owned(),
            ));
        }
        match format.as_ref() {
            "ssh-rsa" => Ok(SshSignatureFormat::SshRsa),
            "rsa-sha2-256" => Ok(SshSignatureFormat::RsaSha256),
            "rsa-sha2-512" => Ok(SshSignatureFormat::RsaSha512),
            "ecdsa-sha2-nistp256" => Ok(SshSignatureFormat::EcdsaSha2Nistp256),
            "ecdsa-sha2-nistp384" => Ok(SshSignatureFormat::EcdsaSha2Nistp384),
            "ecdsa-sha2-nistp521" => Ok(SshSignatureFormat::EcdsaSha2Nistp521),
            "ssh-ed25519" => Ok(SshSignatureFormat::SshEd25519),
            "sk-ecdsa-sha2-nistp256@openssh.com" => Ok(SshSignatureFormat::SkEcdsaSha2NistP256),
            "sk-ssh-ed25519@openssh.com" => Ok(SshSignatureFormat::SkEd25519),
            _ => Err(SshSignatureError::UnsupportedSignatureFormat(
                format.as_ref().to_owned(),
            )),
        }
    }

    pub fn as_str(&self) -> &str {
        match &self {
            SshSignatureFormat::SshRsa => "ssh-rsa",
            SshSignatureFormat::RsaSha256 => "rsa-sha2-256",
            SshSignatureFormat::RsaSha512 => "rsa-sha2-512",
            SshSignatureFormat::EcdsaSha2Nistp256 => "ecdsa-sha2-nistp256",
            SshSignatureFormat::EcdsaSha2Nistp384 => "ecdsa-sha2-nistp384",
            SshSignatureFormat::EcdsaSha2Nistp521 => "ecdsa-sha2-nistp521",
            SshSignatureFormat::SshEd25519 => "ssh-ed25519",
            SshSignatureFormat::SkEcdsaSha2NistP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
            SshSignatureFormat::SkEd25519 => "sk-ssh-ed25519@openssh.com",
        }
    }

    fn algorithm(&self) -> Result<SignatureAlgorithm, SshSignatureError> {
        Self::new(self.as_str())?;
        Ok(match self {
            Self::SshRsa => SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA1),
            Self::RsaSha256 => SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256),
            Self::RsaSha512 => SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_512),
            Self::EcdsaSha2Nistp256 => SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_256),
            Self::EcdsaSha2Nistp384 => SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_384),
            Self::EcdsaSha2Nistp521 => SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_512),
            Self::SshEd25519 => SignatureAlgorithm::Ed25519,
            _ => return Err(SshSignatureError::UnsupportedSignatureFormat(self.as_str().to_owned())),
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SshSignatureBlob {
    Standard(Vec<u8>),
    Sk { data: Vec<u8>, flags: u8, counter: u32 },
}

impl SshSignatureBlob {
    pub fn size(&self) -> usize {
        match self {
            SshSignatureBlob::Standard(data) => data.len(),
            SshSignatureBlob::Sk { data, .. } => data.len() + 5,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SshSignature {
    pub format: SshSignatureFormat,
    pub blob: SshSignatureBlob,
}

/// Elapsed seconds since UNIX epoch
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub fn secs(self) -> u64 {
        self.0
    }
}

impl From<u64> for Timestamp {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCertificate {
    pub cert_key_type: SshCertKeyType,
    pub public_key: SshPublicKey,
    pub nonce: Vec<u8>,
    pub serial: u64,
    pub cert_type: SshCertType,
    pub key_id: String,
    pub valid_principals: Vec<String>,
    pub valid_after: Timestamp,
    pub valid_before: Timestamp,
    pub critical_options: Vec<SshCriticalOption>,
    pub extensions: Vec<SshExtension>,
    pub signature_key: SshPublicKey,
    pub signature: SshSignature,
    pub comment: String,
}

impl SshCertificate {
    pub fn to_string(&self) -> Result<String, SshCertificateError> {
        let mut buffer = Vec::with_capacity(2048);
        self.encode(&mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }

    pub fn builder(&self) -> SshCertificateBuilder {
        SshCertificateBuilder::init()
    }

    /// Verify the certificate signature with its embedded signing key.
    ///
    /// Parsing does not authenticate a certificate; callers must also establish trust
    /// in the signing key and check the certificate's validity and constraints.
    pub fn verify_signature(&self) -> Result<(), SshCertificateError> {
        let mut signed = Vec::new();
        self.encode_signed(&mut signed)?;
        let SshSignatureBlob::Standard(signature) = &self.signature.blob else {
            return Err(
                SshSignatureError::UnsupportedSignatureFormat(self.signature.format.as_str().to_owned()).into(),
            );
        };
        let algorithm = self.signature.format.algorithm()?;
        let signature = if matches!(algorithm, SignatureAlgorithm::Ecdsa(_)) {
            ssh_ecdsa_to_der(signature)?
        } else {
            signature.clone()
        };
        algorithm.verify(self.signature_key.inner_key(), &signed, &signature)?;
        Ok(())
    }
}

impl FromStr for SshCertificate {
    type Err = SshCertificateError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let line = s.strip_suffix("\r\n").or_else(|| s.strip_suffix('\n')).unwrap_or(s);
        if line.contains(['\r', '\n']) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "multiple SSH certificate lines").into());
        }
        SshComplexTypeDecode::decode(s.as_bytes())
    }
}

#[derive(Debug, Error)]
pub enum SshCertificateGenerationError {
    #[error("Unsupported certificate key type: {0}")]
    UnsupportedCertificateKeyType(String),
    #[error("{0}")]
    IncorrectSignatureAlgorithm(String),
    #[error("Missing Public key")]
    MissingPublicKey,
    #[error("Missing certificate type")]
    MissingCertificateType,
    #[error("Invalid time")]
    InvalidTime,
    #[error("Missing signature key")]
    MissingSignatureKey,
    #[error("No extensions are defined for host certificates at present")]
    HostCertificateExtensions,
    #[error("No critical options are defined for host certificates at present")]
    HostCertificateCriticalOptions,
    #[error("Key type is required, but it's missing")]
    NoKeyType,
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    SshPublicKeyError(#[from] SshPublicKeyError),
    #[error(transparent)]
    SshPrivateKeyError(#[from] SshPrivateKeyError),
    #[error(transparent)]
    InvalidCertificateKeyType(#[from] SshCertTypeError),
    #[error(transparent)]
    SshCriticalOptionError(#[from] SshCriticalOptionError),
    #[error(transparent)]
    SshExtensionError(#[from] SshExtensionError),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    CertificateError(#[from] SshCertificateError),
    #[error(transparent)]
    KeyError(#[from] KeyError),
}

#[derive(Debug, Clone, PartialEq, Default)]
struct SshCertificateBuilderInner {
    cert_key_type: Option<SshCertKeyType>,
    public_key: Option<SshPublicKey>,
    serial: Option<u64>,
    cert_type: Option<SshCertType>,
    key_id: Option<String>,
    valid_principals: Option<Vec<String>>,
    valid_after: Option<Timestamp>,
    valid_before: Option<Timestamp>,
    critical_options: Option<Vec<SshCriticalOption>>,
    extensions: Option<Vec<SshExtension>>,
    signature_algo: Option<SignatureAlgorithm>,
    signature_key: Option<SshPrivateKey>,
    comment: Option<String>,
}

pub struct SshCertificateBuilder {
    inner: RefCell<SshCertificateBuilderInner>,
}

impl SshCertificateBuilder {
    pub fn init() -> Self {
        Self {
            inner: RefCell::new(SshCertificateBuilderInner::default()),
        }
    }

    /// Required
    pub fn cert_key_type(&self, key_type: SshCertKeyType) -> &Self {
        self.inner.borrow_mut().cert_key_type = Some(key_type);
        self
    }

    /// Required
    pub fn key(&self, key: SshPublicKey) -> &Self {
        self.inner.borrow_mut().public_key = Some(key);
        self
    }

    /// Optional (set to 0 by default)
    pub fn serial(&self, serial: u64) -> &Self {
        self.inner.borrow_mut().serial = Some(serial);
        self
    }

    /// Required
    pub fn cert_type(&self, cert_type: SshCertType) -> &Self {
        self.inner.borrow_mut().cert_type = Some(cert_type);
        self
    }

    /// Optional
    pub fn key_id(&self, key_id: String) -> &Self {
        self.inner.borrow_mut().key_id = Some(key_id);
        self
    }

    /// Optional. Zero by default means the certificate is valid for any principal of the specified type.
    pub fn principals(&self, principals: Vec<String>) -> &Self {
        self.inner.borrow_mut().valid_principals = Some(principals);
        self
    }

    /// Required
    pub fn valid_before(&self, valid_before: impl Into<Timestamp>) -> &Self {
        self.inner.borrow_mut().valid_before = Some(valid_before.into());
        self
    }

    /// Required
    pub fn valid_after(&self, valid_after: impl Into<Timestamp>) -> &Self {
        self.inner.borrow_mut().valid_after = Some(valid_after.into());
        self
    }

    /// Optional
    pub fn critical_options(&self, critical_options: Vec<SshCriticalOption>) -> &Self {
        self.inner.borrow_mut().critical_options = Some(critical_options);
        self
    }

    /// Optional
    pub fn extensions(&self, extensions: Vec<SshExtension>) -> &Self {
        self.inner.borrow_mut().extensions = Some(extensions);
        self
    }

    /// Required
    pub fn signature_key(&self, signature_key: SshPrivateKey) -> &Self {
        self.inner.borrow_mut().signature_key = Some(signature_key);
        self
    }

    /// Optional. Defaults to SHA-256 RSA PKCS#1 v1.5, the ECDSA curve's hash,
    /// or Ed25519 according to the signing key.
    pub fn signature_algo(&self, signature_algo: SignatureAlgorithm) -> &Self {
        self.inner.borrow_mut().signature_algo = Some(signature_algo);
        self
    }

    /// Optional
    pub fn comment(&self, comment: String) -> &Self {
        self.inner.borrow_mut().comment = Some(comment);
        self
    }

    pub fn build(&self) -> Result<SshCertificate, SshCertificateGenerationError> {
        let mut inner = self.inner.borrow_mut();

        let SshCertificateBuilderInner {
            cert_key_type,
            public_key,
            serial,
            cert_type,
            key_id,
            valid_principals,
            valid_after,
            valid_before,
            critical_options,
            extensions,
            signature_algo,
            signature_key,
            comment,
        } = inner.deref_mut();

        let cert_key_type = cert_key_type.ok_or(SshCertificateGenerationError::NoKeyType)?;
        match cert_key_type {
            SshCertKeyType::SshRsaV01
            | SshCertKeyType::RsaSha2_256V01
            | SshCertKeyType::RsaSha2_512v01
            | SshCertKeyType::EcdsaSha2Nistp256V01
            | SshCertKeyType::EcdsaSha2Nistp384V01
            | SshCertKeyType::EcdsaSha2Nistp521V01
            | SshCertKeyType::SshEd25519V01
            | SshCertKeyType::SkSshSha2Nistp256V01
            | SshCertKeyType::SkSshEd25519V01 => {}

            SshCertKeyType::SshDssV01 => {
                return Err(SshCertificateGenerationError::UnsupportedCertificateKeyType(
                    cert_key_type.as_str().to_owned(),
                ));
            }
        }

        let public_key = public_key
            .take()
            .ok_or(SshCertificateGenerationError::MissingPublicKey)?;
        if cert_key_type.subject_key_type().ok() != Some(public_key.inner_key.key_type()?) {
            return Err(SshCertificateGenerationError::UnsupportedCertificateKeyType(
                cert_key_type.as_str().to_owned(),
            ));
        }
        let serial = serial.take().unwrap_or(0);
        let cert_type = cert_type
            .take()
            .ok_or(SshCertificateGenerationError::MissingCertificateType)?;
        let key_id = key_id.take().unwrap_or_default();

        let mut nonce = vec![0; 32];
        super::private_key::fill_random(&mut nonce)?;

        let valid_after = valid_after.take().ok_or(SshCertificateGenerationError::InvalidTime)?;
        let valid_before = valid_before.take().ok_or(SshCertificateGenerationError::InvalidTime)?;

        if valid_after.secs() > valid_before.secs() {
            return Err(SshCertificateGenerationError::InvalidTime);
        }

        let valid_principals = valid_principals.take().unwrap_or_default();

        let mut critical_options = critical_options.take().unwrap_or_default();
        let mut extensions = extensions.take().unwrap_or_default();

        if cert_type == SshCertType::Host {
            if !extensions.is_empty() {
                return Err(SshCertificateGenerationError::HostCertificateExtensions);
            }
            if !critical_options.is_empty() {
                return Err(SshCertificateGenerationError::HostCertificateCriticalOptions);
            }
        }

        if cert_type == SshCertType::Client && extensions.is_empty() {
            // set default extensions for user certificate as ssh-keygen does
            extensions.extend_from_slice(&[
                SshExtension {
                    extension_type: SshExtensionType::PermitX11Forwarding,
                    data: String::new(),
                },
                SshExtension {
                    extension_type: SshExtensionType::PermitAgentForwarding,
                    data: String::new(),
                },
                SshExtension {
                    extension_type: SshExtensionType::PermitPortForwarding,
                    data: String::new(),
                },
                SshExtension {
                    extension_type: SshExtensionType::PermitPty,
                    data: String::new(),
                },
                SshExtension {
                    extension_type: SshExtensionType::PermitUserPc,
                    data: String::new(),
                },
            ])
        }

        // Options and extensions must be lexically ordered by "name" if they appear in the sequence
        critical_options
            .sort_by(|lhs, rhs| lexical_sort::lexical_cmp(lhs.option_type.as_str(), rhs.option_type.as_str()));
        extensions
            .sort_by(|lhs, rhs| lexical_sort::lexical_cmp(lhs.extension_type.as_str(), rhs.extension_type.as_str()));

        let signature_key = signature_key
            .take()
            .ok_or(SshCertificateGenerationError::MissingSignatureKey)?;
        let default_algorithm = default_signature_algorithm(signature_key.base_key())?;
        let signature_algo = signature_algo.take().unwrap_or(default_algorithm);
        if matches!(signature_algo, SignatureAlgorithm::RsaPss(_)) {
            return Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(
                "RSA-PSS signatures are not defined for OpenSSH certificates".to_owned(),
            ));
        }
        if matches!(
            signature_key.base_key(),
            SshBasePrivateKey::Ec(_) | SshBasePrivateKey::Ed(_)
        ) && signature_algo != default_algorithm
        {
            return Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(
                "signature algorithm does not match the OpenSSH signing key".to_owned(),
            ));
        }
        let comment = comment.take().unwrap_or_default();

        let mut certificate = SshCertificate {
            cert_key_type,
            public_key,
            nonce,
            serial,
            cert_type,
            key_id,
            valid_principals,
            valid_after,
            valid_before,
            critical_options,
            extensions,
            signature_key: signature_key.public_key().clone(),
            signature: SshSignature {
                format: SshSignatureFormat::RsaSha256,
                blob: SshSignatureBlob::Standard(Vec::new()),
            },
            comment,
        };
        let mut raw_signature = Vec::new();
        certificate.encode_signed(&mut raw_signature)?;

        let (signature_blob, signature_format) = match signature_key.base_key() {
            SshBasePrivateKey::Rsa(rsa) => {
                let signature_format = match signature_algo {
                    SignatureAlgorithm::RsaPkcs1v15(hash_algo) => match hash_algo {
                        HashAlgorithm::SHA1 => SshSignatureFormat::SshRsa,
                        HashAlgorithm::SHA2_256 => SshSignatureFormat::RsaSha256,
                        HashAlgorithm::SHA2_512 => SshSignatureFormat::RsaSha512,
                        _ => {
                            return Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(format!(
                                "Invalid signature format hash algorithm. Only sha1, sha2-256 and ssh2-521 are in use in OpenSSH for RSA keys, but got {hash_algo:?} hash"
                            )));
                        }
                    },
                    SignatureAlgorithm::RsaPss(_) => {
                        return Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(
                            "RSA-PSS signatures are not defined for OpenSSH certificates".to_owned(),
                        ));
                    }
                    SignatureAlgorithm::Ecdsa(_) => {
                        return Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(
                            "ECDSA signature algorithm can't be used with RSA keys".to_owned(),
                        ));
                    }
                    SignatureAlgorithm::Ed25519 => {
                        return Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(
                            "Ed25519 signature algorithm can't be used with RSA keys".to_owned(),
                        ));
                    }
                };

                let signature = signature_algo.sign(&raw_signature, rsa)?;
                (SshSignatureBlob::Standard(signature), signature_format)
            }
            SshBasePrivateKey::Ec(ec) => {
                let signature_format = match signature_algo {
                    SignatureAlgorithm::Ecdsa(hash_algo) => match hash_algo {
                        HashAlgorithm::SHA2_256 => SshSignatureFormat::EcdsaSha2Nistp256,
                        HashAlgorithm::SHA2_384 => SshSignatureFormat::EcdsaSha2Nistp384,
                        HashAlgorithm::SHA2_512 => SshSignatureFormat::EcdsaSha2Nistp521,
                        _ => {
                            return Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(format!(
                                "Invalid signature format hash algorithm. Only sha2-256, sha2-384 and ssh2-521 are in use in OpenSSH for ECDSA keys, but got {hash_algo:?} hash"
                            )));
                        }
                    },
                    SignatureAlgorithm::RsaPkcs1v15(_) | SignatureAlgorithm::RsaPss(_) => {
                        return Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(
                            "RSA signature algorithm can't be used with ECDSA keys".to_owned(),
                        ));
                    }
                    SignatureAlgorithm::Ed25519 => {
                        return Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(
                            "Ed25519 signature algorithm can't be used with ECDSA keys".to_owned(),
                        ));
                    }
                };

                let signature = der_ecdsa_to_ssh(&signature_algo.sign(&raw_signature, ec)?)?;
                (SshSignatureBlob::Standard(signature), signature_format)
            }
            SshBasePrivateKey::Ed(ed) => {
                let signature_format = SshSignatureFormat::SshEd25519;

                let signature = signature_algo.sign(&raw_signature, ed)?;
                (SshSignatureBlob::Standard(signature), signature_format)
            }
            SshBasePrivateKey::SkEd25519 { .. } => {
                return Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(
                    "Signing with sk-ed25519 keys is not supported".to_owned(),
                ));
            }
            SshBasePrivateKey::SkEcdsaSha2NistP256 { .. } => {
                return Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(
                    "Signing with sk-ecdsa keys is not supported".to_owned(),
                ));
            }
        };

        certificate.signature = SshSignature {
            format: signature_format,
            blob: signature_blob,
        };

        certificate.verify_signature()?;
        Ok(certificate)
    }
}

fn default_signature_algorithm(key: &SshBasePrivateKey) -> Result<SignatureAlgorithm, SshCertificateGenerationError> {
    use crate::key::EcCurve;
    use crate::key::ec::NamedEcCurve;
    Ok(match key {
        SshBasePrivateKey::Rsa(_) => SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256),
        SshBasePrivateKey::Ec(key) => {
            let key = crate::key::ec::EcdsaKeypair::try_from(key).map_err(SshPublicKeyError::from)?;
            match key.curve() {
                NamedEcCurve::Known(EcCurve::NistP256) => SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_256),
                NamedEcCurve::Known(EcCurve::NistP384) => SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_384),
                NamedEcCurve::Known(EcCurve::NistP521) => SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_512),
                _ => {
                    return Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(
                        "unsupported ECDSA signing key".to_owned(),
                    ));
                }
            }
        }
        SshBasePrivateKey::Ed(_) => SignatureAlgorithm::Ed25519,
        SshBasePrivateKey::SkEd25519 { .. } | SshBasePrivateKey::SkEcdsaSha2NistP256 { .. } => {
            return Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(
                "signing with security keys is not supported".to_owned(),
            ));
        }
    })
}

pub(crate) fn validate_public_key(key: &SshBasePublicKey) -> Result<(), SshCertificateError> {
    #[cfg(feature = "rustcrypto")]
    let _ = key;
    #[cfg(feature = "fips")]
    {
        use crate::key::ec::NamedEcCurve;
        use crate::key::ed::NamedEdAlgorithm;
        use crate::key::{EcCurve, EdAlgorithm};
        use aws_lc_rs::signature::{self, ParsedPublicKey};
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid SSH public key");
        let (algorithm, bytes): (&'static dyn signature::VerificationAlgorithm, Vec<u8>) = match key {
            SshBasePublicKey::Rsa(key) => {
                let picky_asn1_x509::PublicKey::Rsa(rsa) = &key.as_inner().subject_public_key else {
                    return Err(invalid().into());
                };
                let modulus = rsa.modulus.as_unsigned_bytes_be();
                let exponent = rsa.public_exponent.as_unsigned_bytes_be();
                if !matches!(modulus.len(), 256 | 384 | 512 | 1024) || exponent.is_empty() || exponent.len() > 5 {
                    return Err(invalid().into());
                }
                (&signature::RSA_PKCS1_2048_8192_SHA256, key.to_pkcs1()?)
            }
            SshBasePublicKey::Ec(key) => {
                let key = EcdsaPublicKey::try_from(key)?;
                let algorithm: &'static dyn signature::VerificationAlgorithm = match key.curve() {
                    NamedEcCurve::Known(EcCurve::NistP256) => &signature::ECDSA_P256_SHA256_ASN1,
                    NamedEcCurve::Known(EcCurve::NistP384) => &signature::ECDSA_P384_SHA384_ASN1,
                    NamedEcCurve::Known(EcCurve::NistP521) => &signature::ECDSA_P521_SHA512_ASN1,
                    _ => return Err(invalid().into()),
                };
                (algorithm, key.encoded_point().to_vec())
            }
            SshBasePublicKey::Ed(key) => {
                let key = EdPublicKey::try_from(key)?;
                if key.algorithm() != &NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) || key.data().len() != 32 {
                    return Err(invalid().into());
                }
                (&signature::ED25519, key.data().to_vec())
            }
            _ => return Err(invalid().into()),
        };
        ParsedPublicKey::new(algorithm, bytes).map_err(|_| invalid())?;
    }
    Ok(())
}

fn der_ecdsa_to_ssh(der: &[u8]) -> Result<Vec<u8>, SshCertificateError> {
    use crate::ssh::encode::SshWriteExt as _;
    let signature: picky_asn1_x509::signature::EcdsaSignatureValue =
        picky_asn1_der::from_bytes(der).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut output = Vec::new();
    output.write_ssh_mpint_bytes(signature.r.as_unsigned_bytes_be())?;
    output.write_ssh_mpint_bytes(signature.s.as_unsigned_bytes_be())?;
    Ok(output)
}

fn ssh_ecdsa_to_der(mut ssh: &[u8]) -> Result<Vec<u8>, SshCertificateError> {
    use crate::ssh::decode::SshReadExt as _;
    use picky_asn1::wrapper::IntegerAsn1;
    let signature = picky_asn1_x509::signature::EcdsaSignatureValue {
        r: IntegerAsn1::from_bytes_be_unsigned(ssh.read_ssh_mpint_bytes()?),
        s: IntegerAsn1::from_bytes_be_unsigned(ssh.read_ssh_mpint_bytes()?),
    };
    if !ssh.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "trailing SSH ECDSA signature data").into());
    }
    picky_asn1_der::to_vec(&signature).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error).into())
}

#[cfg(all(test, feature = "rustcrypto"))]
pub mod tests {
    use super::*;
    use crate::ssh::private_key::SshPrivateKey;
    use rstest::rstest;
    use std::time::{SystemTime, UNIX_EPOCH};

    const PRIVATE_KEY_PEM: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
                                   b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdz\n\
                                   c2gtcnNhAAAAAwEAAQAAAgEA21AiuHR9Z+HThQb/7I3zJmuKuanu0mePY9hjgxiq\n\
                                   /A7nmTFmC03JOtblDDJVQU918l+pnul+FrAaIo80Fr4MKSwhk6pYUE57ZuRaYVxx\n\
                                   5CsRb4zIT8wpxzUvi9Hm83sHHnLGOa7YMPugYRcHWRoRQX4n9f+rPau8u/vBnt4V\n\
                                   CBKi3YjAw88XOusyGltuo2cTuATB7iqe15Z9iXg47ER789LwTQHXTn5L7afoDO9j\n\
                                   h+LZvcEv1fG1TmevKFNKLPA7ohBp8AOUZ4zo2hXR1rdZg/Afp0SDcSPM2MkHKqd7\n\
                                   eKeedj9Ba4b44IsYuu0cmsdA1DbszdjKUNDkVIEZH8v8VryJlLHj/wX6rzYlpBQF\n\
                                   hzQw0rHOdFpq/oNCYnBtoKMBy2D8SkYyyGzqviYMR6xOE3WgNjSaHlKaSYFlOMrh\n\
                                   peX8dRvgXHa9AvpbDI9eB6fmhmoxDi0OzKtx81hKMfRtSoDeK9uujKH3fE+L64xe\n\
                                   iWvRPqadKV4BL9nL7WCSz9Knax1mn295VrD+ISVp7/zWlz+mQMYhHh7IoK2PfJJo\n\
                                   GWx5v+gJogSe2ykP0vz3pWI95ky9GmJBhe/albQM0pe8iPclch7Je3beY3ZqeviK\n\
                                   H7hLTX5wHH6Gki7tDo6LafVQTL4peqI0nGyTSwS/LRjePrqyHLDVL1YwDp8HN56L\n\
                                   YSsAAAdIA4ihRQOIoUUAAAAHc3NoLXJzYQAAAgEA21AiuHR9Z+HThQb/7I3zJmuK\n\
                                   uanu0mePY9hjgxiq/A7nmTFmC03JOtblDDJVQU918l+pnul+FrAaIo80Fr4MKSwh\n\
                                   k6pYUE57ZuRaYVxx5CsRb4zIT8wpxzUvi9Hm83sHHnLGOa7YMPugYRcHWRoRQX4n\n\
                                   9f+rPau8u/vBnt4VCBKi3YjAw88XOusyGltuo2cTuATB7iqe15Z9iXg47ER789Lw\n\
                                   TQHXTn5L7afoDO9jh+LZvcEv1fG1TmevKFNKLPA7ohBp8AOUZ4zo2hXR1rdZg/Af\n\
                                   p0SDcSPM2MkHKqd7eKeedj9Ba4b44IsYuu0cmsdA1DbszdjKUNDkVIEZH8v8VryJ\n\
                                   lLHj/wX6rzYlpBQFhzQw0rHOdFpq/oNCYnBtoKMBy2D8SkYyyGzqviYMR6xOE3Wg\n\
                                   NjSaHlKaSYFlOMrhpeX8dRvgXHa9AvpbDI9eB6fmhmoxDi0OzKtx81hKMfRtSoDe\n\
                                   K9uujKH3fE+L64xeiWvRPqadKV4BL9nL7WCSz9Knax1mn295VrD+ISVp7/zWlz+m\n\
                                   QMYhHh7IoK2PfJJoGWx5v+gJogSe2ykP0vz3pWI95ky9GmJBhe/albQM0pe8iPcl\n\
                                   ch7Je3beY3ZqeviKH7hLTX5wHH6Gki7tDo6LafVQTL4peqI0nGyTSwS/LRjePrqy\n\
                                   HLDVL1YwDp8HN56LYSsAAAADAQABAAACAC7OXIqnefhIzx7uDoLLDODfRN05Mlo/\n\
                                   de/mR967zgo7mBwu2cuBz3e6U2oV9/IXZmHTHt1mkd1/uiQ0Efbkmq3S2FuumGiT\n\
                                   R2z/QXbUBw6eTntTPZEiTqxQYpRhuPuv/yX1cu7urP9PRLxT8OKIWLR0m0y6Qy7H\n\
                                   T2GDaqBgX3a4m3/SZumjch7GAYx0hRlkr2Wvxj/xYrM6UBKd0PBD8XxpQZX91ZjQ\n\
                                   BZ50HmdcVA61UKlZ6L6tdneEU3K0y/jpUKDXBfUOnoa3IR8iVwWPXhB1mBvX2IG2\n\
                                   FUsTJG9rDUQD6iLsfybWyJkLtrx2TIuQCPsBuep44Tz8SC7s2pLZs0HeihnrM5Ym\n\
                                   qprMggvZ1TkVFoR3bq/42XO6ULy5k8QPuP6t91UN5iVljgr8H/6Jo9MuCeRA45ZP\n\
                                   ZN94Cn1mKJWYamrqRuCqDR5za3A0oHPKYUAfzzD90BLL6Yaib75VpiEDTkOiBuW3\n\
                                   MJUcJsqZipDDl/6eas2Qyloplw60dx42FzcRIDXkXzRNn8hBSy7xmQ5MOKGBszCe\n\
                                   V/eTBtRITQN38yDVMerb8xDlwOsTtjo3PHCg4HEqqSzjv/B0op9aP7RJ8zp9xLOG\n\
                                   lxRZ9YhAlHctUOO6ATsv4uCFwCniZbVOdcUEYwNebYQ0x3IRGUF6RpqjOudUwgLl\n\
                                   o0Lq1KV05fM5AAABAC7fkAB4l5YMAseu+lcj+CwHySzcI+baRFCrMIKldNjEPvvZ\n\
                                   cCSOU/n5pgp2bw0ulw8c4mFQv0GsG//qQCBX1IrIWO0/nRBjEUTPIe2BUswoxm3+\n\
                                   F7pirphdIpABKMzV7ZvENn53p2ByrW9+uiwwXLo/z4tH18JW41Jyp5mXH2+1iWIY\n\
                                   zq5d4gVgMKLGnqWG3DisViHBGg/ExxQCayeXAhlcXVaWZiaVYsgyreaQg58S2RRU\n\
                                   IveWP+ZAeb8+ZJ72ZjIYLc0GIbP673GpcNWkRlCykTJXF9x+Ts0trffqvSxF+2YJ\n\
                                   naacLSWJmWFU1BsxUO2pIM4SI8VeHYBdEoAVqcQAAAEBAPUodhyNIr8dtcJona8L\n\
                                   kn+3BxLdvYAV1bnlWnUcG9m0RQ2L95kH6folOG00aWhRgJHFDoXcCaHND8Mg3PkA\n\
                                   XYUKCucipiIITyd8YeYnF0ckau5GmUEzwc6s4HcGyFilX1yBoyLE7hFMzOJ4+Rcq\n\
                                   +zpD2TfaWcuoo+njDWEHeTbzvGIDQoBYsPnGOtw57q9IA5oWYAG3LtwygazmNF2x\n\
                                   eEnMEtYPyPu7+W0teO0QIJiHWEuK/yLPOb+RHBfA6YJ1f9Jcgc614DxyW6qnB5Yu\n\
                                   zQBovLzgp/7j9J4Z9F8n8f9PAwYScf7IG8icVVhl5NwNgfNOpcjdg6+YB8Z0AXa4\n\
                                   dYcAAAEBAOUDEl6yS1nwZ0QsJwfHE232dpsOqxxqfV4ei4R8/obq+b5YPHiUgbt2\n\
                                   PlHyHtgfQr639BwMmIaAMSR9CLti44Mw6Z3k2DEz3Ef4+XilPeScNiZmWfYanWmV\n\
                                   wFEtb2c+YT3QweUH3DUAViHL+UdU7xp+zhkrd04daVPpYc9NNN9b9Gwmj6Pm0RP0\n\
                                   5UJxsG1ipvN1rGpaCsJiLfS9IoSsKh0Vzdzdty1YvFhEErTl0WBVGGK6xaA5lfMt\n\
                                   aclWi2mGGNXfWflyQzkz87eYlPe2RhM7jW1Lo9h1BBYE6R+jKt3q0mHwRehj+upd\n\
                                   AAXJx0RWF7EDQVJtlTfSrUCm+SSFoD0AAAAOdGVzdEBwaWNreS5jb20BAgMEBQ==\n\
                                   -----END OPENSSH PRIVATE KEY-----";

    #[test]
    fn decode_host_cert() {
        let cert = "ssh-rsa-cert-v01@openssh.com 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 with a trailing space \n";
        let cert = SshCertificate::from_str(cert).unwrap();

        assert_eq!(SshCertType::Host, cert.cert_type);
        assert_eq!("picky".to_owned(), cert.key_id);
        assert_eq!(
            vec!["first.example.com".to_owned(), "second.example.com".to_owned()],
            cert.valid_principals
        );
        assert_eq!("with a trailing space", cert.comment);
        assert!(cert.critical_options.is_empty());
        assert!(cert.extensions.is_empty());
    }

    #[test]
    fn decode_client_cert() {
        let cert = "ssh-rsa-cert-v01@openssh.com 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 sasha@kubuntu \n";
        let cert = SshCertificate::from_str(cert).unwrap();

        assert_eq!(SshCertType::Client, cert.cert_type);
        assert_eq!("picky@example.com".to_owned(), cert.key_id);
        assert_eq!(vec!["test-user".to_owned(), "guest".to_owned()], cert.valid_principals);
        assert_eq!("sasha@kubuntu", cert.comment);
        assert!(cert.critical_options.is_empty());
        assert_eq!(
            vec![
                SshExtension::new(SshExtensionType::PermitX11Forwarding, "".to_owned()),
                SshExtension::new(SshExtensionType::PermitAgentForwarding, "".to_owned()),
                SshExtension::new(SshExtensionType::PermitPortForwarding, "".to_owned()),
                SshExtension::new(SshExtensionType::PermitPty, "".to_owned()),
                SshExtension::new(SshExtensionType::PermitUserPc, "".to_owned()),
            ],
            cert.extensions
        );
    }

    #[test]
    fn encode_host_cert() {
        let cert_before = "ssh-rsa-cert-v01@openssh.com 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 sasha@kubuntu\r\n";
        let cert: SshCertificate = SshCertificate::from_str(cert_before).unwrap();

        let cert_after = cert.to_string().unwrap();

        pretty_assertions::assert_eq!(cert_after, cert_before);
    }

    #[test]
    fn encode_client_cert() {
        let cert_before = "ssh-rsa-cert-v01@openssh.com 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 sasha@kubuntu\r\n";
        let cert: SshCertificate = SshCertificate::from_str(cert_before).unwrap();

        let cert_after = cert.to_string().unwrap();

        pretty_assertions::assert_eq!(cert_before, cert_after);
    }

    #[rstest]
    #[case(picky_test_data::SSH_CERT_EC_P256)]
    #[case(picky_test_data::SSH_CERT_EC_P384)]
    fn ecdsa_roundtrip(#[case] cert_before: &str) {
        let cert: SshCertificate = SshCertificate::from_str(cert_before).unwrap();
        let cert_after = cert.to_string().unwrap();
        pretty_assertions::assert_eq!(cert_before, cert_after);
    }

    #[test]
    fn ed25519_roundtrip() {
        let cert: SshCertificate = SshCertificate::from_str(picky_test_data::SSH_CERT_ED25519).unwrap();
        let cert_after = cert.to_string().unwrap();
        pretty_assertions::assert_eq!(picky_test_data::SSH_CERT_ED25519, cert_after);
    }

    #[test]
    fn sk_ed25519_signed_roundtrip() {
        let cert: SshCertificate = SshCertificate::from_str(picky_test_data::SSH_CERT_SK_ED25519).unwrap();
        let cert_after = cert.to_string().unwrap();
        pretty_assertions::assert_eq!(picky_test_data::SSH_CERT_SK_ED25519, cert_after);
    }

    #[test]
    fn sk_ecdsa_signed_roundtrip() {
        let cert: SshCertificate = SshCertificate::from_str(picky_test_data::SSH_CERT_SK_ECDSA).unwrap();
        let cert_after = cert.to_string().unwrap();
        pretty_assertions::assert_eq!(picky_test_data::SSH_CERT_SK_ECDSA, cert_after);
    }

    #[test]
    fn sk_ed25519_cert_roundtrip() {
        let cert: SshCertificate = SshCertificate::from_str(picky_test_data::SSH_CERT_SK_ED25519_SIG_EC).unwrap();
        let cert_after = cert.to_string().unwrap();
        pretty_assertions::assert_eq!(picky_test_data::SSH_CERT_SK_ED25519_SIG_EC, cert_after);
    }

    #[test]
    fn sk_ecdsa_cert_roundtrip() {
        let cert: SshCertificate = SshCertificate::from_str(picky_test_data::SSH_CERT_SK_ECDSA_SIG_EC).unwrap();
        let cert_after = cert.to_string().unwrap();
        pretty_assertions::assert_eq!(picky_test_data::SSH_CERT_SK_ECDSA_SIG_EC, cert_after);
    }

    #[rstest]
    #[case(SshCertKeyType::EcdsaSha2Nistp256V01, picky_test_data::SSH_PRIVATE_KEY_EC_P256)]
    #[case(SshCertKeyType::RsaSha2_256V01, PRIVATE_KEY_PEM)]
    #[case(SshCertKeyType::SshEd25519V01, picky_test_data::SSH_PRIVATE_KEY_ED25519)]
    fn test_certificate_generation(#[case] key_type: SshCertKeyType, #[case] ssh_key_pem: &str) {
        let certificate_builder = SshCertificateBuilder::init();
        certificate_builder.cert_key_type(key_type);
        let private_key: SshPrivateKey = SshPrivateKey::from_pem_str(ssh_key_pem, None).unwrap();
        certificate_builder.key(private_key.public_key().clone());
        certificate_builder.cert_type(SshCertType::Host);
        let now_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        certificate_builder.valid_after(now_timestamp);
        // 10 minutes = 600 seconds
        let valid_before = now_timestamp + 600;
        certificate_builder.valid_before(valid_before);
        certificate_builder.signature_key(private_key);
        let cert = certificate_builder.build().unwrap();
        // Check that we could parse this certificate after building it
        let serialized = cert.to_string().unwrap();
        SshCertificate::from_str(&serialized).unwrap();
    }

    #[test]
    fn test_time_validation_in_certificate_builder() {
        let certificate_builder = SshCertificateBuilder::init();

        certificate_builder.cert_key_type(SshCertKeyType::RsaSha2_256V01);

        let private_key: SshPrivateKey = SshPrivateKey::from_pem_str(PRIVATE_KEY_PEM, None).unwrap();
        certificate_builder.key(private_key.public_key().clone());

        certificate_builder.cert_type(SshCertType::Host);

        let now_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        // 10 minutes = 600 seconds
        let after = now_timestamp + 600;
        let before = now_timestamp - 600;

        certificate_builder.valid_after(after);

        certificate_builder.valid_before(before);

        certificate_builder.signature_key(private_key);

        let cert = certificate_builder.build();
        assert!(matches!(cert.unwrap_err(), SshCertificateGenerationError::InvalidTime));
    }

    #[test]
    fn test_host_certificate_generation() {
        let certificate_builder = SshCertificateBuilder::init();

        certificate_builder.cert_key_type(SshCertKeyType::RsaSha2_256V01);

        let private_key: SshPrivateKey = SshPrivateKey::from_pem_str(PRIVATE_KEY_PEM, None).unwrap();
        certificate_builder.key(private_key.public_key().clone());

        certificate_builder.cert_type(SshCertType::Host);

        let now_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        certificate_builder.valid_after(now_timestamp);

        // 10 minutes = 600 seconds
        let valid_before = now_timestamp + 600;
        certificate_builder.valid_before(valid_before);

        certificate_builder.signature_key(private_key);

        certificate_builder.principals(vec!["example".to_owned()]);

        certificate_builder.extensions(vec![SshExtension::new(
            SshExtensionType::NoTouchRequired,
            "".to_owned(),
        )]);

        let cert = certificate_builder.build();
        assert!(matches!(
            cert.unwrap_err(),
            SshCertificateGenerationError::HostCertificateExtensions
        ));
    }
}
