use crate::{models::date::UTCDate, pem::PemError};
use err_derive::Error;
use serde_asn1_der::SerdeAsn1DerError;

pub type Result<T> = std::result::Result<T, Error>;

type BoxedError = Box<dyn std::error::Error + Send + Sync>;
type ContextError<T> = err_ctx::Context<T>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(display = "{}", _0)]
    Boxed(BoxedError),
    #[error(display = "invalid pem: {}", _0)]
    Pem(#[error(source)] PemError),
    #[error(display = "asn1 (de)serialization error: {}", _0)]
    Asn1(#[error(source)] SerdeAsn1DerError),
    #[error(display = "couldn't generate certificate")]
    CertGeneration,
    #[error(display = "RSA error")]
    Rsa,
    #[error(display = "invalid signature")]
    BadSignature,
    #[error(display = "CA chain depth does't satisfy basic constraints extension")]
    CAChainTooDeep,
    #[error(display = "CA chain is missing a root certificate")]
    CAChainNoRoot,
    #[error(display = "authority key id doesn't match (expected: {:?}, got: {:?})", expected, actual)]
    AuthorityKeyIdMismatch { expected: Vec<u8>, actual: Vec<u8> },
    #[error(display = "extension not found: {}", _0)]
    ExtensionNotFound(&'static str),
    #[error(display = "missing required builder argument `{}`", _0)]
    MissingBuilderArgument(&'static str),
    #[error(display = "unsupported algorithm: {}", _0)]
    UnsupportedAlgorithm(&'static str),
    #[error(
        display = "certificate is not yet valid (not before: {}, now: {})",
        not_before,
        now
    )]
    CertificateNotYetValid { not_before: UTCDate, now: UTCDate },
    #[error(
        display = "certificate expired (not after: {}, now: {})",
        not_after,
        now
    )]
    CertificateExpired { not_after: UTCDate, now: UTCDate },
}

impl From<BoxedError> for Error {
    fn from(e: BoxedError) -> Self {
        Self::Boxed(e)
    }
}

impl<T: 'static + Send + Sync + std::fmt::Debug + std::fmt::Display> From<ContextError<T>>
    for Error
{
    fn from(e: ContextError<T>) -> Self {
        Self::Boxed(Box::new(e))
    }
}
