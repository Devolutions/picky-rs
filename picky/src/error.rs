use crate::pem::PemError;
use err_derive::Error;
use serde_asn1_der::SerdeAsn1DerError;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(display = "invalid pem: {}", _0)]
    Pem(PemError),
    #[error(display = "asn1 (de)serialization error: {}", _0)]
    Asn1(SerdeAsn1DerError),
    #[error(display = "couldn't generate certificate")]
    CertGeneration,
    #[error(display = "RSA error")]
    Rsa,
    #[error(display = "invalid signature")]
    BadSignature,
    #[error(display = "invalid certificate")]
    BadCertificate,
    #[error(display = "extension not found")]
    ExtensionNotFound,
    #[error(display = "missing required builder argument `{}`", _0)]
    MissingBuilderArgument(&'static str),
    #[error(display = "unsupported algorithm")]
    UnsupportedAlgorithm,
}

impl From<PemError> for Error {
    fn from(e: PemError) -> Self {
        Self::Pem(e)
    }
}

impl From<SerdeAsn1DerError> for Error {
    fn from(e: SerdeAsn1DerError) -> Self {
        Self::Asn1(e)
    }
}
