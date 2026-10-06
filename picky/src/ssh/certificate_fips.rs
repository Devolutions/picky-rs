use crate::hash::HashAlgorithm;
use crate::key::ec::{EcdsaPublicKey, NamedEcCurve};
use crate::key::ed::{EdPublicKey, NamedEdAlgorithm};
use crate::key::{EcCurve, EdAlgorithm, KeyError, PublicKey};
use crate::signature::{SignatureAlgorithm, SignatureError};
use crate::ssh::private_key::{SshBasePrivateKey, SshPrivateKey, SshPrivateKeyError};
use crate::ssh::public_key::{SshBasePublicKey, SshPublicKey, SshPublicKeyError};
use crate::ssh::wire_fips::{Reader, invalid_data, write_bytes, write_mpint, write_string, write_u32, write_u64};
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use aws_lc_rs::signature::{self, ParsedPublicKey};
use base64::Engine as _;
use serde::Deserialize;
use std::cell::RefCell;
use std::io;
use std::ops::DerefMut;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshCertificateError {
    #[error("Can not process the certificate: {0:?}")]
    CertificateProcessingError(#[from] io::Error),
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
    #[error(transparent)]
    KeyError(#[from] KeyError),
    #[error(transparent)]
    SshSignatureError(#[from] SshSignatureError),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
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
            1 => Ok(Self::Client),
            2 => Ok(Self::Host),
            value => Err(SshCertTypeError::InvalidCertificateType(value)),
        }
    }
}

impl From<SshCertType> for u32 {
    fn from(value: SshCertType) -> Self {
        match value {
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
    pub fn as_str(&self) -> &str {
        match self {
            Self::SshRsaV01 => "ssh-rsa-cert-v01@openssh.com",
            Self::SshDssV01 => "ssh-dss-cert-v01@openssh.com",
            Self::RsaSha2_256V01 => "rsa-sha2-256-cert-v01@openssh.com",
            Self::RsaSha2_512v01 => "rsa-sha2-512-cert-v01@openssh.com",
            Self::EcdsaSha2Nistp256V01 => "ecdsa-sha2-nistp256-cert-v01@openssh.com",
            Self::EcdsaSha2Nistp384V01 => "ecdsa-sha2-nistp384-cert-v01@openssh.com",
            Self::EcdsaSha2Nistp521V01 => "ecdsa-sha2-nistp521-cert-v01@openssh.com",
            Self::SshEd25519V01 => "ssh-ed25519-cert-v01@openssh.com",
            Self::SkSshSha2Nistp256V01 => "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
            Self::SkSshEd25519V01 => "sk-ssh-ed25519-cert-v01@openssh.com",
        }
    }

    fn approved(self) -> bool {
        matches!(
            self,
            Self::RsaSha2_256V01
                | Self::RsaSha2_512v01
                | Self::EcdsaSha2Nistp256V01
                | Self::EcdsaSha2Nistp384V01
                | Self::EcdsaSha2Nistp521V01
                | Self::SshEd25519V01
        )
    }
}

impl TryFrom<&str> for SshCertKeyType {
    type Error = SshCertificateError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let key_type = match value {
            "ssh-rsa-cert-v01@openssh.com" => Self::SshRsaV01,
            "ssh-dss-cert-v01@openssh.com" => Self::SshDssV01,
            "rsa-sha2-256-cert-v01@openssh.com" => Self::RsaSha2_256V01,
            "rsa-sha2-512-cert-v01@openssh.com" => Self::RsaSha2_512v01,
            "ecdsa-sha2-nistp256-cert-v01@openssh.com" => Self::EcdsaSha2Nistp256V01,
            "ecdsa-sha2-nistp384-cert-v01@openssh.com" => Self::EcdsaSha2Nistp384V01,
            "ecdsa-sha2-nistp521-cert-v01@openssh.com" => Self::EcdsaSha2Nistp521V01,
            "ssh-ed25519-cert-v01@openssh.com" => Self::SshEd25519V01,
            "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" => Self::SkSshSha2Nistp256V01,
            "sk-ssh-ed25519-cert-v01@openssh.com" => Self::SkSshEd25519V01,
            _ => return Err(SshCertificateError::InvalidCertificateKeyType(value.to_owned())),
        };
        if key_type.approved() {
            Ok(key_type)
        } else {
            Err(SshCertificateError::UnsupportedCertificateType(value.to_owned()))
        }
    }
}

impl TryFrom<String> for SshCertKeyType {
    type Error = SshCertificateError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
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
            Self::ForceCommand => "force-command",
            Self::SourceAddress => "source-address",
            Self::VerifyRequired => "verify-required",
        }
    }
}

impl TryFrom<&str> for SshCriticalOptionType {
    type Error = SshCriticalOptionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "force-command" => Ok(Self::ForceCommand),
            "source-address" => Ok(Self::SourceAddress),
            "verify-required" => Ok(Self::VerifyRequired),
            _ => Err(SshCriticalOptionError::UnsupportedCriticalOptionType(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SshCriticalOption {
    pub option_type: SshCriticalOptionType,
    pub data: String,
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
            Self::NoTouchRequired => "no-touch-required",
            Self::PermitX11Forwarding => "permit-X11-forwarding",
            Self::PermitAgentForwarding => "permit-agent-forwarding",
            Self::PermitPortForwarding => "permit-port-forwarding",
            Self::PermitPty => "permit-pty",
            Self::PermitUserPc => "permit-user-rc",
        }
    }
}

impl TryFrom<&str> for SshExtensionType {
    type Error = SshExtensionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "no-touch-required" => Ok(Self::NoTouchRequired),
            "permit-X11-forwarding" => Ok(Self::PermitX11Forwarding),
            "permit-agent-forwarding" => Ok(Self::PermitAgentForwarding),
            "permit-port-forwarding" => Ok(Self::PermitPortForwarding),
            "permit-pty" => Ok(Self::PermitPty),
            "permit-user-rc" => Ok(Self::PermitUserPc),
            _ => Err(SshExtensionError::UnsupportedExtensionType(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SshExtension {
    pub extension_type: SshExtensionType,
    pub data: String,
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
    pub fn new<T: AsRef<str>>(format: T) -> Result<Self, SshSignatureError> {
        match format.as_ref() {
            "rsa-sha2-256" => Ok(Self::RsaSha256),
            "rsa-sha2-512" => Ok(Self::RsaSha512),
            "ecdsa-sha2-nistp256" => Ok(Self::EcdsaSha2Nistp256),
            "ecdsa-sha2-nistp384" => Ok(Self::EcdsaSha2Nistp384),
            "ecdsa-sha2-nistp521" => Ok(Self::EcdsaSha2Nistp521),
            "ssh-ed25519" => Ok(Self::SshEd25519),
            unsupported => Err(SshSignatureError::UnsupportedSignatureFormat(unsupported.to_owned())),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::SshRsa => "ssh-rsa",
            Self::RsaSha256 => "rsa-sha2-256",
            Self::RsaSha512 => "rsa-sha2-512",
            Self::EcdsaSha2Nistp256 => "ecdsa-sha2-nistp256",
            Self::EcdsaSha2Nistp384 => "ecdsa-sha2-nistp384",
            Self::EcdsaSha2Nistp521 => "ecdsa-sha2-nistp521",
            Self::SshEd25519 => "ssh-ed25519",
            Self::SkEcdsaSha2NistP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
            Self::SkEd25519 => "sk-ssh-ed25519@openssh.com",
        }
    }

    fn algorithm(&self) -> Result<SignatureAlgorithm, SshCertificateError> {
        Ok(match self {
            Self::RsaSha256 => SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256),
            Self::RsaSha512 => SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_512),
            Self::EcdsaSha2Nistp256 => SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_256),
            Self::EcdsaSha2Nistp384 => SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_384),
            Self::EcdsaSha2Nistp521 => SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_512),
            Self::SshEd25519 => SignatureAlgorithm::Ed25519,
            unsupported => {
                return Err(SshCertificateError::SshSignatureError(
                    SshSignatureError::UnsupportedSignatureFormat(unsupported.as_str().to_owned()),
                ));
            }
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
            Self::Standard(data) => data.len(),
            Self::Sk { data, .. } => data.len() + 5,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SshSignature {
    pub format: SshSignatureFormat,
    pub blob: SshSignatureBlob,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub fn secs(self) -> u64 {
        self.0
    }
}

impl From<u64> for Timestamp {
    fn from(value: u64) -> Self {
        Self(value)
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
        let blob = self.encode_blob(true)?;
        Ok(format!(
            "{} {} {}\r\n",
            self.cert_key_type.as_str(),
            base64::engine::general_purpose::STANDARD.encode(blob),
            self.comment
        ))
    }

    pub fn builder(&self) -> SshCertificateBuilder {
        SshCertificateBuilder::init()
    }

    pub fn verify_signature(&self) -> Result<(), SshCertificateError> {
        let signed = self.encode_blob(false)?;
        let SshSignatureBlob::Standard(signature) = &self.signature.blob else {
            return Err(
                SshSignatureError::UnsupportedSignatureFormat(self.signature.format.as_str().to_owned()).into(),
            );
        };
        let algorithm = self.signature.format.algorithm()?;
        let signature = if matches!(
            self.signature.format,
            SshSignatureFormat::EcdsaSha2Nistp256
                | SshSignatureFormat::EcdsaSha2Nistp384
                | SshSignatureFormat::EcdsaSha2Nistp521
        ) {
            ssh_ecdsa_to_der(signature)?
        } else {
            signature.clone()
        };
        algorithm.verify(self.signature_key.inner_key(), &signed, &signature)?;
        Ok(())
    }

    fn encode_blob(&self, include_signature: bool) -> Result<Vec<u8>, SshCertificateError> {
        if !self.cert_key_type.approved() {
            return Err(SshCertificateError::UnsupportedCertificateType(
                self.cert_key_type.as_str().to_owned(),
            ));
        }
        let mut output = Vec::new();
        write_string(&mut output, self.cert_key_type.as_str())?;
        write_bytes(&mut output, &self.nonce)?;
        encode_certificate_public_key(self.cert_key_type, &self.public_key.inner_key, &mut output)?;
        write_u64(&mut output, self.serial);
        write_u32(&mut output, self.cert_type.into());
        write_string(&mut output, &self.key_id)?;
        encode_strings(&self.valid_principals, &mut output)?;
        write_u64(&mut output, self.valid_after.0);
        write_u64(&mut output, self.valid_before.0);
        encode_critical_options(&self.critical_options, &mut output)?;
        encode_extensions(&self.extensions, &mut output)?;
        write_bytes(&mut output, &[])?;
        let (_, signature_key) = self.signature_key.encode_blob()?;
        write_bytes(&mut output, &signature_key)?;
        if include_signature {
            let mut signature = Vec::new();
            write_string(&mut signature, self.signature.format.as_str())?;
            match &self.signature.blob {
                SshSignatureBlob::Standard(data) => write_bytes(&mut signature, data)?,
                SshSignatureBlob::Sk { .. } => {
                    return Err(SshSignatureError::UnsupportedSignatureFormat(
                        self.signature.format.as_str().to_owned(),
                    )
                    .into());
                }
            }
            write_bytes(&mut output, &signature)?;
        }
        Ok(output)
    }
}

impl FromStr for SshCertificate {
    type Err = SshCertificateError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input
            .strip_suffix("\r\n")
            .or_else(|| input.strip_suffix('\n'))
            .unwrap_or(input);
        if input.contains(['\r', '\n']) {
            return Err(invalid_data().into());
        }
        let mut fields = input.splitn(3, ' ');
        let outer_type = fields.next().ok_or_else(invalid_data)?;
        let encoded = fields.next().ok_or_else(invalid_data)?;
        let comment = fields.next().unwrap_or_default().to_owned();
        let outer_type = SshCertKeyType::try_from(outer_type)?;
        let blob = base64::engine::general_purpose::STANDARD.decode(encoded)?;
        let mut reader = Reader::new(&blob);
        let cert_key_type = SshCertKeyType::try_from(reader.read_string()?)?;
        if outer_type != cert_key_type {
            return Err(invalid_data().into());
        }
        let nonce = reader.read_bytes()?.to_vec();
        let public_key = SshPublicKey {
            inner_key: decode_certificate_public_key(cert_key_type, &mut reader)?,
            comment: String::new(),
        };
        let serial = reader.read_u64()?;
        let cert_type = SshCertType::try_from(reader.read_u32()?)?;
        let key_id = reader.read_string()?.to_owned();
        let valid_principals = decode_strings(&mut reader)?;
        let valid_after = Timestamp(reader.read_u64()?);
        let valid_before = Timestamp(reader.read_u64()?);
        let critical_options = decode_critical_options(&mut reader)?;
        let extensions = decode_extensions(&mut reader)?;
        if !reader.read_bytes()?.is_empty() {
            return Err(invalid_data().into());
        }
        let signature_key_blob = reader.read_bytes()?;
        let signature_key = decode_public_blob(signature_key_blob)?;
        let signature_outer = reader.read_bytes()?;
        if !reader.is_empty() {
            return Err(invalid_data().into());
        }
        let mut signature_reader = Reader::new(signature_outer);
        let format = SshSignatureFormat::new(signature_reader.read_string()?)?;
        let signature_data = signature_reader.read_bytes()?.to_vec();
        if !signature_reader.is_empty() {
            return Err(invalid_data().into());
        }
        Ok(Self {
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
            signature_key,
            signature: SshSignature {
                format,
                blob: SshSignatureBlob::Standard(signature_data),
            },
            comment,
        })
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
    KeyError(#[from] KeyError),
    #[error(transparent)]
    CertificateError(#[from] SshCertificateError),
}

#[derive(Debug, Clone, PartialEq, Default)]
struct BuilderInner {
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
    inner: RefCell<BuilderInner>,
}

impl SshCertificateBuilder {
    pub fn init() -> Self {
        Self {
            inner: RefCell::new(BuilderInner::default()),
        }
    }

    pub fn cert_key_type(&self, value: SshCertKeyType) -> &Self {
        self.inner.borrow_mut().cert_key_type = Some(value);
        self
    }
    pub fn key(&self, value: SshPublicKey) -> &Self {
        self.inner.borrow_mut().public_key = Some(value);
        self
    }
    pub fn serial(&self, value: u64) -> &Self {
        self.inner.borrow_mut().serial = Some(value);
        self
    }
    pub fn cert_type(&self, value: SshCertType) -> &Self {
        self.inner.borrow_mut().cert_type = Some(value);
        self
    }
    pub fn key_id(&self, value: String) -> &Self {
        self.inner.borrow_mut().key_id = Some(value);
        self
    }
    pub fn principals(&self, value: Vec<String>) -> &Self {
        self.inner.borrow_mut().valid_principals = Some(value);
        self
    }
    pub fn valid_before(&self, value: impl Into<Timestamp>) -> &Self {
        self.inner.borrow_mut().valid_before = Some(value.into());
        self
    }
    pub fn valid_after(&self, value: impl Into<Timestamp>) -> &Self {
        self.inner.borrow_mut().valid_after = Some(value.into());
        self
    }
    pub fn critical_options(&self, value: Vec<SshCriticalOption>) -> &Self {
        self.inner.borrow_mut().critical_options = Some(value);
        self
    }
    pub fn extensions(&self, value: Vec<SshExtension>) -> &Self {
        self.inner.borrow_mut().extensions = Some(value);
        self
    }
    pub fn signature_key(&self, value: SshPrivateKey) -> &Self {
        self.inner.borrow_mut().signature_key = Some(value);
        self
    }
    pub fn signature_algo(&self, value: SignatureAlgorithm) -> &Self {
        self.inner.borrow_mut().signature_algo = Some(value);
        self
    }
    pub fn comment(&self, value: String) -> &Self {
        self.inner.borrow_mut().comment = Some(value);
        self
    }

    pub fn build(&self) -> Result<SshCertificate, SshCertificateGenerationError> {
        let mut inner = self.inner.borrow_mut();
        let inner = inner.deref_mut();
        let cert_key_type = inner.cert_key_type.ok_or(SshCertificateGenerationError::NoKeyType)?;
        if !cert_key_type.approved() {
            return Err(SshCertificateGenerationError::UnsupportedCertificateKeyType(
                cert_key_type.as_str().to_owned(),
            ));
        }
        let public_key = inner
            .public_key
            .take()
            .ok_or(SshCertificateGenerationError::MissingPublicKey)?;
        validate_cert_key_pair(cert_key_type, &public_key.inner_key)?;
        let cert_type = inner
            .cert_type
            .take()
            .ok_or(SshCertificateGenerationError::MissingCertificateType)?;
        let valid_after = inner
            .valid_after
            .take()
            .ok_or(SshCertificateGenerationError::InvalidTime)?;
        let valid_before = inner
            .valid_before
            .take()
            .ok_or(SshCertificateGenerationError::InvalidTime)?;
        if valid_after > valid_before {
            return Err(SshCertificateGenerationError::InvalidTime);
        }
        let mut critical_options = inner.critical_options.take().unwrap_or_default();
        let mut extensions = inner.extensions.take().unwrap_or_default();
        if cert_type == SshCertType::Host && !extensions.is_empty() {
            return Err(SshCertificateGenerationError::HostCertificateExtensions);
        }
        if cert_type == SshCertType::Host && !critical_options.is_empty() {
            return Err(SshCertificateGenerationError::HostCertificateCriticalOptions);
        }
        if cert_type == SshCertType::Client && extensions.is_empty() {
            extensions = [
                SshExtensionType::PermitX11Forwarding,
                SshExtensionType::PermitAgentForwarding,
                SshExtensionType::PermitPortForwarding,
                SshExtensionType::PermitPty,
                SshExtensionType::PermitUserPc,
            ]
            .into_iter()
            .map(|extension_type| SshExtension::new(extension_type, String::new()))
            .collect();
        }
        critical_options.sort_by(|left, right| left.option_type.as_str().cmp(right.option_type.as_str()));
        extensions.sort_by(|left, right| left.extension_type.as_str().cmp(right.extension_type.as_str()));

        let signature_key = inner
            .signature_key
            .take()
            .ok_or(SshCertificateGenerationError::MissingSignatureKey)?;
        let (default_algorithm, format) = signature_details(signature_key.base_key())?;
        let algorithm = inner.signature_algo.take().unwrap_or(default_algorithm);
        if matches!(algorithm, SignatureAlgorithm::RsaPss(_)) {
            return Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(
                "RSA-PSS signatures are not defined for OpenSSH certificates".to_owned(),
            ));
        }
        if algorithm != default_algorithm {
            let expected = match signature_key.base_key() {
                SshBasePrivateKey::Rsa(_) => matches!(
                    algorithm,
                    SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256 | HashAlgorithm::SHA2_512)
                ),
                SshBasePrivateKey::Ec(_) | SshBasePrivateKey::Ed(_) => false,
            };
            if !expected {
                if let SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA1) = algorithm {
                    algorithm.sign(b"", signature_key.inner_key().unwrap())?;
                }
                return Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(
                    "signature algorithm does not match the OpenSSH signing key".to_owned(),
                ));
            }
        }
        let format = match algorithm {
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256) => SshSignatureFormat::RsaSha256,
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_512) => SshSignatureFormat::RsaSha512,
            _ => format,
        };
        let mut nonce = vec![0; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| io::Error::other("AWS-LC random generation failed"))?;
        let mut certificate = SshCertificate {
            cert_key_type,
            public_key,
            nonce,
            serial: inner.serial.take().unwrap_or(0),
            cert_type,
            key_id: inner.key_id.take().unwrap_or_default(),
            valid_principals: inner.valid_principals.take().unwrap_or_default(),
            valid_after,
            valid_before,
            critical_options,
            extensions,
            signature_key: signature_key.public_key().clone(),
            signature: SshSignature {
                format,
                blob: SshSignatureBlob::Standard(Vec::new()),
            },
            comment: inner.comment.take().unwrap_or_default(),
        };
        let signed = certificate.encode_blob(false)?;
        let raw_signature = algorithm.sign(&signed, signature_key.inner_key().unwrap())?;
        let encoded_signature = if matches!(algorithm, SignatureAlgorithm::Ecdsa(_)) {
            der_ecdsa_to_ssh(&raw_signature)?
        } else {
            raw_signature
        };
        certificate.signature.blob = SshSignatureBlob::Standard(encoded_signature);
        certificate.verify_signature()?;
        Ok(certificate)
    }
}

fn signature_details(
    key: &SshBasePrivateKey,
) -> Result<(SignatureAlgorithm, SshSignatureFormat), SshCertificateGenerationError> {
    Ok(match key {
        SshBasePrivateKey::Rsa(_) => (
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256),
            SshSignatureFormat::RsaSha256,
        ),
        SshBasePrivateKey::Ec(key) => {
            let key = crate::key::ec::EcdsaKeypair::try_from(key)?;
            match key.curve() {
                NamedEcCurve::Known(EcCurve::NistP256) => (
                    SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_256),
                    SshSignatureFormat::EcdsaSha2Nistp256,
                ),
                NamedEcCurve::Known(EcCurve::NistP384) => (
                    SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_384),
                    SshSignatureFormat::EcdsaSha2Nistp384,
                ),
                NamedEcCurve::Known(EcCurve::NistP521) => (
                    SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_512),
                    SshSignatureFormat::EcdsaSha2Nistp521,
                ),
                _ => {
                    return Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(
                        "unsupported ECDSA signing key".to_owned(),
                    ));
                }
            }
        }
        SshBasePrivateKey::Ed(_) => (SignatureAlgorithm::Ed25519, SshSignatureFormat::SshEd25519),
    })
}

fn validate_cert_key_pair(
    key_type: SshCertKeyType,
    key: &SshBasePublicKey,
) -> Result<(), SshCertificateGenerationError> {
    let valid = match (key_type, key) {
        (SshCertKeyType::RsaSha2_256V01 | SshCertKeyType::RsaSha2_512v01, SshBasePublicKey::Rsa(_)) => true,
        (
            SshCertKeyType::EcdsaSha2Nistp256V01
            | SshCertKeyType::EcdsaSha2Nistp384V01
            | SshCertKeyType::EcdsaSha2Nistp521V01,
            SshBasePublicKey::Ec(key),
        ) => {
            let curve = EcdsaPublicKey::try_from(key)?.curve().clone();
            matches!(
                (key_type, curve),
                (
                    SshCertKeyType::EcdsaSha2Nistp256V01,
                    NamedEcCurve::Known(EcCurve::NistP256)
                ) | (
                    SshCertKeyType::EcdsaSha2Nistp384V01,
                    NamedEcCurve::Known(EcCurve::NistP384)
                ) | (
                    SshCertKeyType::EcdsaSha2Nistp521V01,
                    NamedEcCurve::Known(EcCurve::NistP521)
                )
            )
        }
        (SshCertKeyType::SshEd25519V01, SshBasePublicKey::Ed(key)) => {
            EdPublicKey::try_from(key)?.algorithm() == &NamedEdAlgorithm::Known(EdAlgorithm::Ed25519)
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(SshCertificateGenerationError::UnsupportedCertificateKeyType(
            key_type.as_str().to_owned(),
        ))
    }
}

fn encode_certificate_public_key(
    key_type: SshCertKeyType,
    key: &SshBasePublicKey,
    output: &mut Vec<u8>,
) -> Result<(), SshCertificateError> {
    match key {
        SshBasePublicKey::Rsa(key) => {
            let picky_asn1_x509::PublicKey::Rsa(key) = &key.as_inner().subject_public_key else {
                return Err(invalid_data().into());
            };
            write_mpint(output, key.public_exponent.as_unsigned_bytes_be())?;
            write_mpint(output, key.modulus.as_unsigned_bytes_be())?;
        }
        SshBasePublicKey::Ec(key) => {
            let key = EcdsaPublicKey::try_from(key)?;
            let expected = match key_type {
                SshCertKeyType::EcdsaSha2Nistp256V01 => "nistp256",
                SshCertKeyType::EcdsaSha2Nistp384V01 => "nistp384",
                SshCertKeyType::EcdsaSha2Nistp521V01 => "nistp521",
                _ => return Err(invalid_data().into()),
            };
            write_string(output, expected)?;
            write_bytes(output, key.encoded_point())?;
        }
        SshBasePublicKey::Ed(key) => {
            let key = EdPublicKey::try_from(key)?;
            write_bytes(output, key.data())?;
        }
    }
    Ok(())
}

fn decode_certificate_public_key(
    key_type: SshCertKeyType,
    reader: &mut Reader<'_>,
) -> Result<SshBasePublicKey, SshCertificateError> {
    Ok(match key_type {
        SshCertKeyType::RsaSha2_256V01 | SshCertKeyType::RsaSha2_512v01 => {
            let exponent = reader.read_mpint()?;
            let modulus = reader.read_mpint()?;
            let key = PublicKey::from_rsa_encoded_components(modulus, exponent);
            validate_public_key(&SshBasePublicKey::Rsa(key.clone()))?;
            SshBasePublicKey::Rsa(key)
        }
        SshCertKeyType::EcdsaSha2Nistp256V01
        | SshCertKeyType::EcdsaSha2Nistp384V01
        | SshCertKeyType::EcdsaSha2Nistp521V01 => {
            let (identifier, curve) = match key_type {
                SshCertKeyType::EcdsaSha2Nistp256V01 => ("nistp256", EcCurve::NistP256),
                SshCertKeyType::EcdsaSha2Nistp384V01 => ("nistp384", EcCurve::NistP384),
                _ => ("nistp521", EcCurve::NistP521),
            };
            if reader.read_string()? != identifier {
                return Err(invalid_data().into());
            }
            let key = PublicKey::from_ec_encoded_components(&NamedEcCurve::Known(curve).into(), reader.read_bytes()?);
            validate_public_key(&SshBasePublicKey::Ec(key.clone()))?;
            SshBasePublicKey::Ec(key)
        }
        SshCertKeyType::SshEd25519V01 => {
            let public = reader.read_bytes()?;
            if public.len() != 32 {
                return Err(invalid_data().into());
            }
            let key =
                PublicKey::from_ed_encoded_components(&NamedEdAlgorithm::Known(EdAlgorithm::Ed25519).into(), public);
            validate_public_key(&SshBasePublicKey::Ed(key.clone()))?;
            SshBasePublicKey::Ed(key)
        }
        unsupported => {
            return Err(SshCertificateError::UnsupportedCertificateType(
                unsupported.as_str().to_owned(),
            ));
        }
    })
}

fn decode_public_blob(blob: &[u8]) -> Result<SshPublicKey, SshCertificateError> {
    let mut reader = Reader::new(blob);
    let inner_key = match reader.read_string()? {
        "ssh-rsa" => {
            let exponent = reader.read_mpint()?;
            let modulus = reader.read_mpint()?;
            SshBasePublicKey::Rsa(PublicKey::from_rsa_encoded_components(modulus, exponent))
        }
        key_type @ ("ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521") => {
            let (identifier, curve) = match key_type {
                "ecdsa-sha2-nistp256" => ("nistp256", EcCurve::NistP256),
                "ecdsa-sha2-nistp384" => ("nistp384", EcCurve::NistP384),
                _ => ("nistp521", EcCurve::NistP521),
            };
            if reader.read_string()? != identifier {
                return Err(invalid_data().into());
            }
            SshBasePublicKey::Ec(PublicKey::from_ec_encoded_components(
                &NamedEcCurve::Known(curve).into(),
                reader.read_bytes()?,
            ))
        }
        "ssh-ed25519" => {
            let public = reader.read_bytes()?;
            if public.len() != 32 {
                return Err(invalid_data().into());
            }
            SshBasePublicKey::Ed(PublicKey::from_ed_encoded_components(
                &NamedEdAlgorithm::Known(EdAlgorithm::Ed25519).into(),
                public,
            ))
        }
        unsupported => {
            return Err(SshCertificateError::InvalidPublicKey(
                SshPublicKeyError::UnsupportedKeyType(unsupported.to_owned()),
            ));
        }
    };
    if !reader.is_empty() {
        return Err(invalid_data().into());
    }
    validate_public_key(&inner_key)?;
    Ok(SshPublicKey {
        inner_key,
        comment: String::new(),
    })
}

fn validate_public_key(key: &SshBasePublicKey) -> Result<(), SshCertificateError> {
    let (algorithm, bytes): (&'static dyn signature::VerificationAlgorithm, Vec<u8>) = match key {
        SshBasePublicKey::Rsa(key) => {
            let picky_asn1_x509::PublicKey::Rsa(rsa) = &key.as_inner().subject_public_key else {
                return Err(invalid_data().into());
            };
            let modulus = rsa.modulus.as_unsigned_bytes_be();
            let exponent = rsa.public_exponent.as_unsigned_bytes_be();
            if !matches!(modulus.len(), 256 | 384 | 512 | 1024) || exponent.is_empty() || exponent.len() > 5 {
                return Err(invalid_data().into());
            }
            (&signature::RSA_PKCS1_2048_8192_SHA256, key.to_pkcs1()?)
        }
        SshBasePublicKey::Ec(key) => {
            let key = EcdsaPublicKey::try_from(key)?;
            let algorithm: &'static dyn signature::VerificationAlgorithm = match key.curve() {
                NamedEcCurve::Known(EcCurve::NistP256) => &signature::ECDSA_P256_SHA256_ASN1,
                NamedEcCurve::Known(EcCurve::NistP384) => &signature::ECDSA_P384_SHA384_ASN1,
                NamedEcCurve::Known(EcCurve::NistP521) => &signature::ECDSA_P521_SHA512_ASN1,
                _ => return Err(invalid_data().into()),
            };
            (algorithm, key.encoded_point().to_vec())
        }
        SshBasePublicKey::Ed(key) => {
            let key = EdPublicKey::try_from(key)?;
            if key.algorithm() != &NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) || key.data().len() != 32 {
                return Err(invalid_data().into());
            }
            (&signature::ED25519, key.data().to_vec())
        }
    };
    ParsedPublicKey::new(algorithm, bytes).map_err(|_| invalid_data())?;
    Ok(())
}

fn encode_strings(values: &[String], output: &mut Vec<u8>) -> io::Result<()> {
    let mut inner = Vec::new();
    for value in values {
        write_string(&mut inner, value)?;
    }
    write_bytes(output, &inner)
}

fn decode_strings(reader: &mut Reader<'_>) -> io::Result<Vec<String>> {
    let mut inner = Reader::new(reader.read_bytes()?);
    let mut values = Vec::new();
    while !inner.is_empty() {
        values.push(inner.read_string()?.to_owned());
    }
    Ok(values)
}

fn encode_critical_options(values: &[SshCriticalOption], output: &mut Vec<u8>) -> io::Result<()> {
    let mut inner = Vec::new();
    for value in values {
        write_string(&mut inner, value.option_type.as_str())?;
        write_string(&mut inner, &value.data)?;
    }
    write_bytes(output, &inner)
}

fn decode_critical_options(reader: &mut Reader<'_>) -> Result<Vec<SshCriticalOption>, SshCertificateError> {
    let mut inner = Reader::new(reader.read_bytes()?);
    let mut values = Vec::new();
    while !inner.is_empty() {
        let option_type = SshCriticalOptionType::try_from(inner.read_string()?)?;
        let data = inner.read_string()?.to_owned();
        values.push(SshCriticalOption { option_type, data });
    }
    Ok(values)
}

fn encode_extensions(values: &[SshExtension], output: &mut Vec<u8>) -> io::Result<()> {
    let mut inner = Vec::new();
    for value in values {
        write_string(&mut inner, value.extension_type.as_str())?;
        write_string(&mut inner, &value.data)?;
    }
    write_bytes(output, &inner)
}

fn decode_extensions(reader: &mut Reader<'_>) -> Result<Vec<SshExtension>, SshCertificateError> {
    let mut inner = Reader::new(reader.read_bytes()?);
    let mut values = Vec::new();
    while !inner.is_empty() {
        let extension_type = SshExtensionType::try_from(inner.read_string()?)?;
        let data = inner.read_string()?.to_owned();
        values.push(SshExtension { extension_type, data });
    }
    Ok(values)
}

fn der_ecdsa_to_ssh(der: &[u8]) -> Result<Vec<u8>, SshCertificateError> {
    let mut reader = DerReader::new(der);
    let sequence = reader.read_element(0x30)?;
    if !reader.is_empty() {
        return Err(invalid_data().into());
    }
    let mut sequence = DerReader::new(sequence);
    let r = sequence.read_element(0x02)?;
    let s = sequence.read_element(0x02)?;
    if !sequence.is_empty() {
        return Err(invalid_data().into());
    }
    let mut output = Vec::new();
    write_mpint(&mut output, r)?;
    write_mpint(&mut output, s)?;
    Ok(output)
}

fn ssh_ecdsa_to_der(ssh: &[u8]) -> Result<Vec<u8>, SshCertificateError> {
    let mut reader = Reader::new(ssh);
    let r = reader.read_mpint()?;
    let s = reader.read_mpint()?;
    if !reader.is_empty() {
        return Err(invalid_data().into());
    }
    let mut sequence = Vec::new();
    write_der_integer(&mut sequence, r)?;
    write_der_integer(&mut sequence, s)?;
    let mut output = vec![0x30];
    write_der_len(&mut output, sequence.len())?;
    output.extend_from_slice(&sequence);
    Ok(output)
}

fn write_der_integer(output: &mut Vec<u8>, value: &[u8]) -> io::Result<()> {
    output.push(0x02);
    let needs_zero = value.first().is_some_and(|byte| byte & 0x80 != 0);
    write_der_len(output, value.len() + usize::from(needs_zero))?;
    if needs_zero {
        output.push(0);
    }
    output.extend_from_slice(value);
    Ok(())
}

fn write_der_len(output: &mut Vec<u8>, len: usize) -> io::Result<()> {
    if len < 128 {
        output.push(len as u8);
        return Ok(());
    }
    let bytes = len.to_be_bytes();
    let bytes = &bytes[bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len() - 1)..];
    output.push(0x80 | u8::try_from(bytes.len()).map_err(|_| invalid_data())?);
    output.extend_from_slice(bytes);
    Ok(())
}

struct DerReader<'a>(Reader<'a>);

impl<'a> DerReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self(Reader::new(input))
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    fn read_element(&mut self, tag: u8) -> io::Result<&'a [u8]> {
        if self.0.read_u8()? != tag {
            return Err(invalid_data());
        }
        let first = self.0.read_u8()?;
        let len = if first & 0x80 == 0 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > std::mem::size_of::<usize>() {
                return Err(invalid_data());
            }
            let mut len = 0usize;
            for byte in self.0.take(count)? {
                len = len
                    .checked_mul(256)
                    .and_then(|len| len.checked_add(*byte as usize))
                    .ok_or_else(invalid_data)?;
            }
            len
        };
        self.0.take(len)
    }
}
