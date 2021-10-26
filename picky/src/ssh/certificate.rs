use crate::key::{KeyError, PublicKey};
use crate::signature::{SignatureAlgorithm, SignatureError};
use crate::ssh::private_key::{SshBasePrivateKey, SshPrivateKey, SshPrivateKeyError};
use crate::ssh::public_key::{SshBasePublicKey, SshPublicKey, SshPublicKeyError};
use crate::ssh::{read_to_buffer_till_whitespace, ByteArray, Mpint, SshParser, SshString, SshTime};
use crate::AlgorithmIdentifier;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::{DateTime, Utc};
use rand::Rng;
use rsa::{BigUint, PublicKeyParts, RsaPublicKey};
use std::cell::RefCell;
use std::convert::TryFrom;
use std::io::{self, Cursor, Read, Write};
use std::ops::DerefMut;
use std::string;
use std::time::SystemTime;
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
    #[error("Can not parse. Expected UTF-8 valid text: {0:?}")]
    FromUtf8Error(#[from] string::FromUtf8Error),
    #[error("Invalid base64 string: {0:?}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error(transparent)]
    InvalidCertificateType(#[from] SshCertTypeError),
    #[error("Invalid certificate key type: {0}")]
    InvalidCertificateKeyType(String),
    #[error("Certificate had invalid public key: {0:?}")]
    InvalidPublicKey(#[from] SshPublicKeyError),
    #[error(transparent)]
    RsaError(#[from] rsa::errors::Error),
    #[error(transparent)]
    KeyError(#[from] KeyError),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

impl SshParser for SshCertType {
    type Error = SshCertTypeError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        SshCertType::try_from(stream.read_u32::<BigEndian>()?)
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_u32::<BigEndian>((*self).into())?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SshCertificateKeyType {
    SshRsaV01,
    SshDssV01,
    RsaSha2_256V01,
    RsaSha2_512v01,
    EcdsaSha2Nistp256V01,
    EcdsaSha2Nistp384V01,
    EcdsaSha2Nistp521V01,
    SshEd25519V01,
}

impl SshCertificateKeyType {
    fn as_str(&self) -> &str {
        match self {
            SshCertificateKeyType::SshRsaV01 => "ssh-rsa-cert-v01@openssh.com",
            SshCertificateKeyType::SshDssV01 => "ssh-dss-cert-v01@openssh.com",
            SshCertificateKeyType::RsaSha2_256V01 => "rsa-sha2-256-cert-v01@openssh.com",
            SshCertificateKeyType::RsaSha2_512v01 => "rsa-sha2-512-cert-v01@openssh.com",
            SshCertificateKeyType::EcdsaSha2Nistp256V01 => "ecdsa-sha2-nistp256-cert-v01@openssh.com",
            SshCertificateKeyType::EcdsaSha2Nistp384V01 => "ecdsa-sha2-nistp384-cert-v01@openssh.com",
            SshCertificateKeyType::EcdsaSha2Nistp521V01 => "ecdsa-sha2-nistp521-cert-v01@openssh.com",
            SshCertificateKeyType::SshEd25519V01 => "ssh-ed25519-cert-v01@openssh.com",
        }
    }
}

impl TryFrom<String> for SshCertificateKeyType {
    type Error = SshCertificateError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "ssh-rsa-cert-v01@openssh.com" => Ok(SshCertificateKeyType::SshRsaV01),
            _ => Err(SshCertificateError::InvalidCertificateKeyType(value)),
        }
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
    option_type: SshCriticalOptionType,
    data: String,
}

impl SshParser for SshCriticalOption {
    type Error = SshCriticalOptionError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let option_type: SshString = SshParser::decode(&mut stream)?;
        let data: SshString = SshParser::decode(&mut stream)?;
        Ok(SshCriticalOption {
            option_type: SshCriticalOptionType::try_from(option_type.0)?,
            data: data.0,
        })
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        SshString(self.option_type.as_str().to_owned()).encode(&mut stream)?;
        SshString(self.data.clone()).encode(&mut stream)?;
        Ok(())
    }
}

impl SshParser for Vec<SshCriticalOption> {
    type Error = SshCriticalOptionError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let data: ByteArray = SshParser::decode(&mut stream)?;
        let len = data.0.len();
        let mut cursor = Cursor::new(data.0);
        let mut res = Vec::with_capacity(len);
        while cursor.position() < len as u64 {
            res.push(SshParser::decode(&mut cursor)?);
        }
        Ok(res)
    }

    fn encode(&self, stream: impl Write) -> Result<(), Self::Error> {
        let mut data = Vec::new();
        for critical_option in self.iter() {
            critical_option.encode(&mut data)?;
        }
        ByteArray(data).encode(stream)?;
        Ok(())
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
    extension_type: SshExtensionType,
    data: String,
}

impl SshExtension {
    pub fn new(extension_type: SshExtensionType, data: String) -> Self {
        Self { extension_type, data }
    }
}

impl SshParser for SshExtension {
    type Error = SshExtensionError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let extension_type: SshString = SshParser::decode(&mut stream)?;
        let data: SshString = SshParser::decode(&mut stream)?;
        Ok(SshExtension {
            extension_type: SshExtensionType::try_from(extension_type.0)?,
            data: data.0,
        })
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        SshString(self.extension_type.as_str().to_owned()).encode(&mut stream)?;
        SshString(self.data.clone()).encode(&mut stream)?;
        Ok(())
    }
}

impl SshParser for Vec<SshExtension> {
    type Error = SshExtensionError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let data: ByteArray = SshParser::decode(&mut stream)?;
        let len = data.0.len();
        let mut cursor = Cursor::new(data.0);
        let mut res = Vec::with_capacity(len);
        while cursor.position() < len as u64 {
            res.push(SshParser::decode(&mut cursor)?);
        }
        Ok(res)
    }

    fn encode(&self, stream: impl Write) -> Result<(), Self::Error> {
        let mut data = Vec::new();
        for critical_option in self.iter() {
            critical_option.encode(&mut data)?;
        }
        ByteArray(data).encode(stream)?;
        Ok(())
    }
}

impl SshParser for Vec<String> {
    type Error = io::Error;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let data: ByteArray = SshParser::decode(&mut stream)?;
        let len = data.0.len();
        let mut cursor = Cursor::new(data.0);
        let mut res = Vec::with_capacity(len);
        while cursor.position() < len as u64 {
            res.push(SshString::decode(&mut cursor)?.0);
        }
        Ok(res)
    }

    fn encode(&self, stream: impl Write) -> Result<(), Self::Error> {
        let mut data = Vec::new();
        for s in self.iter() {
            SshString(s.clone()).encode(&mut data)?;
        }
        ByteArray(data).encode(stream)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SshCertificate {
    key_type: SshCertificateKeyType,
    public_key: SshPublicKey,
    nonce: Vec<u8>,
    serial: u64,
    cert_type: SshCertType,
    key_id: String,
    valid_principals: Vec<String>,
    valid_after: SshTime,
    valid_before: SshTime,
    critical_options: Vec<SshCriticalOption>,
    extensions: Vec<SshExtension>,
    signature_key: SshPublicKey,
    signature: Vec<u8>,
    comment: String,
}

impl SshCertificate {
    pub fn from_pem_str(pem: &str) -> Result<Self, SshCertificateError> {
        SshParser::decode(pem.as_bytes())
    }

    pub fn from_raw<R: ?Sized + AsRef<[u8]>>(raw: &R) -> Result<Self, SshCertificateError> {
        let mut slice = raw.as_ref();
        SshParser::decode(&mut slice)
    }

    pub fn to_pem(&self) -> Result<String, SshCertificateError> {
        let buffer = self.to_raw()?;
        Ok(String::from_utf8(buffer)?)
    }

    pub fn to_raw(&self) -> Result<Vec<u8>, SshCertificateError> {
        let mut cursor = Cursor::new(Vec::with_capacity(1024));
        self.encode(&mut cursor)?;
        Ok(cursor.into_inner())
    }

    pub fn builder(&self) -> SshCertificateBuilder {
        SshCertificateBuilder::init()
    }
}

impl SshParser for SshCertificate {
    type Error = SshCertificateError;

    fn decode(mut stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let mut cert_type = Vec::new();
        read_to_buffer_till_whitespace(&mut stream, &mut cert_type)?;

        let _ = SshCertificateKeyType::try_from(String::from_utf8(cert_type)?)?;

        let mut cert_data = Vec::new();
        read_to_buffer_till_whitespace(&mut stream, &mut cert_data)?;

        let cert_data = base64::decode(cert_data)?;
        let mut cursor = Cursor::new(cert_data);

        let cert_key_type: SshString = SshParser::decode(&mut cursor)?;
        let cert_key_type = SshCertificateKeyType::try_from(cert_key_type.0)?;

        let nonce: ByteArray = SshParser::decode(&mut cursor)?;

        let inner_public_key = match &cert_key_type {
            SshCertificateKeyType::SshRsaV01
            | SshCertificateKeyType::RsaSha2_256V01
            | SshCertificateKeyType::RsaSha2_512v01 => {
                let e: Mpint = SshParser::decode(&mut cursor)?;
                let n: Mpint = SshParser::decode(&mut cursor)?;
                SshBasePublicKey::Rsa(PublicKey::from_components(
                    &BigUint::from_bytes_be(&n.0),
                    &BigUint::from_bytes_be(&e.0),
                ))
            }
            SshCertificateKeyType::EcdsaSha2Nistp256V01
            | SshCertificateKeyType::SshDssV01
            | SshCertificateKeyType::EcdsaSha2Nistp384V01
            | SshCertificateKeyType::EcdsaSha2Nistp521V01
            | SshCertificateKeyType::SshEd25519V01 => {
                return Err(SshCertificateError::UnsupportedCertificateType(
                    cert_key_type.as_str().to_owned(),
                ))
            }
        };

        let serial = cursor.read_u64::<BigEndian>()?;
        let cert_type: SshCertType = SshParser::decode(&mut cursor)?;

        let key_id: SshString = SshParser::decode(&mut cursor)?;

        let valid_principals: Vec<String> = SshParser::decode(&mut cursor)?;

        let valid_after: SshTime = SshParser::decode(&mut cursor)?;
        let valid_before: SshTime = SshParser::decode(&mut cursor)?;

        let critical_options: Vec<SshCriticalOption> = SshParser::decode(&mut cursor)?;

        let extensions: Vec<SshExtension> = SshParser::decode(&mut cursor)?;

        let _: ByteArray = SshParser::decode(&mut cursor)?;

        // here is public key
        let signature_key: ByteArray = SshParser::decode(&mut cursor)?;
        let signature_public_key: SshBasePublicKey = SshParser::decode(signature_key.0.as_slice())?;

        let signature: ByteArray = SshParser::decode(&mut cursor)?;

        let mut comment = Vec::new();
        read_to_buffer_till_whitespace(&mut stream, &mut comment)?;

        Ok(SshCertificate {
            key_type: cert_key_type,
            public_key: SshPublicKey::from_inner(inner_public_key),
            nonce: nonce.0,
            serial,
            cert_type,
            key_id: key_id.0,
            valid_principals,
            valid_after,
            valid_before,
            critical_options,
            extensions,
            signature_key: SshPublicKey::from_inner(signature_public_key),
            signature: signature.0,
            comment: String::from_utf8(comment)?,
        })
    }

    fn encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_all(self.key_type.as_str().as_bytes())?;
        stream.write_u8(b' ')?;

        let mut cert_data = Vec::new();
        SshString(self.key_type.as_str().to_owned()).encode(&mut cert_data)?;
        ByteArray(self.nonce.clone()).encode(&mut cert_data)?;

        match &self.public_key.inner_key {
            SshBasePublicKey::Rsa(rsa) => {
                let rsa = RsaPublicKey::try_from(rsa)?;
                Mpint(rsa.e().to_bytes_be()).encode(&mut cert_data)?;
                Mpint(rsa.n().to_bytes_be()).encode(&mut cert_data)?;
            }
        };

        cert_data.write_u64::<BigEndian>(self.serial)?;

        self.cert_type.encode(&mut cert_data)?;

        SshString(self.key_id.clone()).encode(&mut cert_data)?;

        self.valid_principals.encode(&mut cert_data)?;
        self.valid_after.encode(&mut cert_data)?;
        self.valid_before.encode(&mut cert_data)?;
        self.critical_options.encode(&mut cert_data)?;
        self.extensions.encode(&mut cert_data)?;

        ByteArray(Vec::new()).encode(&mut cert_data)?;

        let mut rsa_key = ByteArray(Vec::new());
        self.signature_key.inner_key.encode(&mut rsa_key.0)?;

        rsa_key.encode(&mut cert_data)?;
        ByteArray(self.signature.clone()).encode(&mut cert_data)?;

        stream.write_all(base64::encode(cert_data).as_bytes())?;
        stream.write_u8(b' ')?;

        stream.write_all(self.comment.as_bytes())?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum SshCertificateGenerationError {
    #[error("Unsupported certificate key type: {0}")]
    UnsupportedCertificateKeyType(String),
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
}

#[derive(Debug, Clone, PartialEq)]
struct SshCertificateBuilderInner<'a> {
    key_type: Option<SshCertificateKeyType>,
    public_key: Option<&'a SshPublicKey>,
    serial: Option<u64>,
    cert_type: Option<SshCertType>,
    key_id: Option<String>,
    valid_principals: Option<Vec<String>>,
    valid_after: Option<SshTime>,
    valid_before: Option<SshTime>,
    critical_options: Option<Vec<SshCriticalOption>>,
    extensions: Option<Vec<SshExtension>>,
    signature_key: Option<&'a SshPrivateKey>,
    comment: Option<String>,
}

impl<'a> Default for SshCertificateBuilderInner<'a> {
    fn default() -> Self {
        SshCertificateBuilderInner {
            key_type: None,
            public_key: None,
            serial: None,
            cert_type: None,
            key_id: None,
            valid_principals: None,
            valid_after: None,
            valid_before: None,
            critical_options: None,
            extensions: None,
            signature_key: None,
            comment: None,
        }
    }
}

pub struct SshCertificateBuilder<'a> {
    inner: RefCell<SshCertificateBuilderInner<'a>>,
}

impl<'a> SshCertificateBuilder<'a> {
    pub fn init() -> Self {
        Self {
            inner: RefCell::new(SshCertificateBuilderInner::default()),
        }
    }

    /// Required
    pub fn key_type(&self, key_type: SshCertificateKeyType) -> &Self {
        self.inner.borrow_mut().key_type = Some(key_type);
        self
    }

    /// Required
    pub fn key(&self, key: &'a SshPublicKey) -> &Self {
        self.inner.borrow_mut().public_key = Some(key);
        self
    }

    /// Optional(set to 0 by default)
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
    pub fn valid_before(&self, valid_before: SshTime) -> &Self {
        self.inner.borrow_mut().valid_before = Some(valid_before);
        self
    }

    /// Required
    pub fn valid_after(&self, valid_after: SshTime) -> &Self {
        self.inner.borrow_mut().valid_after = Some(valid_after);
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
    pub fn signature_key(&self, signature_key: &'a SshPrivateKey) -> &Self {
        self.inner.borrow_mut().signature_key = Some(signature_key);
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
            key_type,
            public_key,
            serial,
            cert_type,
            key_id,
            valid_principals,
            valid_after,
            valid_before,
            critical_options,
            extensions,
            signature_key,
            comment,
        } = inner.deref_mut();

        let key_type = key_type.take().ok_or(SshCertificateGenerationError::NoKeyType)?;
        match key_type {
            SshCertificateKeyType::SshRsaV01
            | SshCertificateKeyType::RsaSha2_256V01
            | SshCertificateKeyType::RsaSha2_512v01 => {}
            SshCertificateKeyType::EcdsaSha2Nistp256V01
            | SshCertificateKeyType::SshDssV01
            | SshCertificateKeyType::EcdsaSha2Nistp384V01
            | SshCertificateKeyType::EcdsaSha2Nistp521V01
            | SshCertificateKeyType::SshEd25519V01 => {
                return Err(SshCertificateGenerationError::UnsupportedCertificateKeyType(
                    key_type.as_str().to_owned(),
                ))
            }
        }

        let public_key = public_key
            .take()
            .ok_or(SshCertificateGenerationError::MissingPublicKey)?;
        let serial = serial.take().unwrap_or(0);
        let cert_type = cert_type
            .take()
            .ok_or(SshCertificateGenerationError::MissingCertificateType)?;
        let key_id = key_id.take().unwrap_or_default();

        let mut nonce = Vec::new();
        let mut rnd = rand::thread_rng();
        for _ in 0..32 {
            nonce.push(rnd.gen::<u8>());
        }

        let cur_date = DateTime::<Utc>::from(SystemTime::now());
        let valid_after = valid_after.take().ok_or(SshCertificateGenerationError::InvalidTime)?;
        let valid_before = valid_before.take().ok_or(SshCertificateGenerationError::InvalidTime)?;
        if valid_after.0.timestamp() > cur_date.timestamp() || cur_date.timestamp() >= valid_before.0.timestamp() {
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

        let compute_raw_signature = || -> Result<Vec<u8>, SshCertificateGenerationError> {
            let mut buff = Vec::with_capacity(1024);
            SshString(key_type.as_str().to_owned())
                .encode(&mut buff)
                .map_err(SshCertificateGenerationError::IoError)?;

            public_key
                .encode(&mut buff)
                .map_err(SshCertificateGenerationError::SshPublicKeyError)?;

            ByteArray(nonce.clone())
                .encode(&mut buff)
                .map_err(SshCertificateGenerationError::IoError)?;

            buff.write_u64::<BigEndian>(serial)
                .map_err(SshCertificateGenerationError::IoError)?;

            cert_type.encode(&mut buff)?;

            SshString(key_id.clone()).encode(&mut buff)?;
            valid_principals.encode(&mut buff)?;

            valid_after.encode(&mut buff)?;
            valid_before.encode(&mut buff)?;

            critical_options.encode(&mut buff)?;
            extensions.encode(&mut buff)?;

            signature_key.public_key().encode(&mut buff)?;

            Ok(buff)
        };

        let raw_signature = compute_raw_signature()?;
        let signature = match signature_key.base_key() {
            SshBasePrivateKey::Rsa(rsa) => {
                let algo_ident = match key_type {
                    SshCertificateKeyType::SshRsaV01 => AlgorithmIdentifier::new_sha1_with_rsa_encryption(),
                    SshCertificateKeyType::RsaSha2_256V01 => AlgorithmIdentifier::new_sha256_with_rsa_encryption(),
                    SshCertificateKeyType::RsaSha2_512v01 => AlgorithmIdentifier::new_sha512_with_rsa_encryption(),
                    SshCertificateKeyType::EcdsaSha2Nistp256V01
                    | SshCertificateKeyType::SshDssV01
                    | SshCertificateKeyType::EcdsaSha2Nistp384V01
                    | SshCertificateKeyType::EcdsaSha2Nistp521V01
                    | SshCertificateKeyType::SshEd25519V01 => {
                        return Err(SshCertificateGenerationError::UnsupportedCertificateKeyType(
                            key_type.as_str().to_owned(),
                        ))
                    }
                };

                let signature_algo = SignatureAlgorithm::from_algorithm_identifier(&algo_ident)
                    .expect("Should not panic on a supported algorithm");
                signature_algo.sign(&raw_signature, rsa)?
            }
        };

        Ok(SshCertificate {
            key_type,
            public_key: public_key.clone(),
            nonce,
            serial,
            cert_type,
            key_id,
            valid_principals,
            valid_after,
            valid_before,
            critical_options,
            extensions,
            signature_key: public_key.clone(),
            signature,
            comment: comment.take().unwrap_or_default(),
        })
    }
}

#[cfg(test)]
pub mod tests {
    use crate::ssh::certificate::{SshCertType, SshCertificate, SshCriticalOption, SshExtension, SshExtensionType};
    use crate::ssh::SshParser;

    #[test]
    fn decode_host_cert() {
        let cert = b"ssh-rsa-cert-v01@openssh.com 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 sasha@kubuntu";
        let cert: SshCertificate = SshParser::decode(cert.to_vec().as_slice()).unwrap();

        assert_eq!(SshCertType::Host, cert.cert_type);
        assert_eq!("picky".to_owned(), cert.key_id);
        assert_eq!(
            vec!["first.example.com".to_owned(), "second.example.com".to_owned()],
            cert.valid_principals
        );
        assert_eq!("sasha@kubuntu", cert.comment);
        assert_eq!(Vec::<SshCriticalOption>::new(), cert.critical_options);
        assert_eq!(Vec::<SshExtension>::new(), cert.extensions);
    }

    #[test]
    fn decode_client_cert() {
        let cert = b"ssh-rsa-cert-v01@openssh.com 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 sasha@kubuntu";
        let cert: SshCertificate = SshParser::decode(cert.to_vec().as_slice()).unwrap();

        assert_eq!(SshCertType::Client, cert.cert_type);
        assert_eq!("picky@example.com".to_owned(), cert.key_id);
        assert_eq!(vec!["test-user".to_owned(), "guest".to_owned()], cert.valid_principals);
        assert_eq!("sasha@kubuntu", cert.comment);
        assert_eq!(Vec::<SshCriticalOption>::new(), cert.critical_options);
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
        let cert_before = b"ssh-rsa-cert-v01@openssh.com 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 sasha@kubuntu";
        let cert: SshCertificate = SshParser::decode(cert_before.to_vec().as_slice()).unwrap();
        //println!("{:#?}", cert);
        let mut cert_after = Vec::new();
        cert.encode(&mut cert_after).unwrap();

        pretty_assertions::assert_eq!(cert_before.to_vec(), cert_after);
        assert_eq!(cert_before.to_vec(), cert_after);
    }

    #[test]
    fn encode_client_cert() {
        let cert_before = b"ssh-rsa-cert-v01@openssh.com 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 sasha@kubuntu";
        let cert: SshCertificate = SshParser::decode(cert_before.to_vec().as_slice()).unwrap();

        let mut cert_after = Vec::new();
        cert.encode(&mut cert_after).unwrap();

        //pretty_assertions::assert_eq!(cert_before.to_vec(), cert_after);
        assert_eq!(cert_before.to_vec(), cert_after);
    }
}
