use crate::models::date::UTCDate;
use rsa::errors::Error as RSAError;
use serde_asn1_der::{restricted_string::CharSetError, SerdeAsn1DerError};
use snafu::Snafu;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Snafu)]
pub enum Error {
    /// couldn't generate certificate
    #[snafu(display("couldn't generate certificate: {}", source))]
    #[snafu(visibility = "pub(crate)")]
    CertGeneration {
        #[snafu(source(from(Error, Box::new)))]
        source: Box<Error>,
    },

    /// invalid certificate
    #[snafu(display("invalid certificate '{}': {}", id, source))]
    #[snafu(visibility = "pub(crate)")]
    InvalidCertificate {
        id: String,
        #[snafu(source(from(Error, Box::new)))]
        source: Box<Error>,
    },

    /// asn1 serialization error
    #[snafu(display("(asn1) couldn't serialize {}: {}", element, source))]
    #[snafu(visibility = "pub(crate)")]
    Asn1Serialization {
        element: &'static str,
        source: SerdeAsn1DerError,
    },

    /// asn1 deserialization error
    #[snafu(display("(asn1) couldn't deserialize {}: {}", element, source))]
    #[snafu(visibility = "pub(crate)")]
    Asn1Deserialization {
        element: &'static str,
        source: SerdeAsn1DerError,
    },

    /// RSA error
    #[snafu(display("RSA error: {}", context))]
    Rsa { context: String },

    /// no secure randomness available
    NoSecureRandomness,

    /// invalid signature
    BadSignature,

    /// CA chain depth does't satisfy basic constraints extension
    #[snafu(display(
        "CA chain depth doesn't satisfy basic constraints extension: certificate '{}' has pathlen of {}",
        cert_id,
        pathlen
    ))]
    CAChainTooDeep { cert_id: String, pathlen: u8 },

    /// CA chain is missing a root certificate
    CAChainNoRoot,

    /// issuer certificate is not a CA
    #[snafu(display("issuer certificate '{}' is not a CA", issuer_id))]
    IssuerIsNotCA { issuer_id: String },

    /// authority key id doesn't match
    #[snafu(display(
        "authority key id doesn't match (expected: {:?}, got: {:?})",
        expected,
        actual
    ))]
    AuthorityKeyIdMismatch { expected: Vec<u8>, actual: Vec<u8> },

    /// extension not found
    #[snafu(display("extension not found: {}", name))]
    ExtensionNotFound { name: &'static str },

    /// missing required builder argument
    #[snafu(display("missing required builder argument `{}`", arg))]
    MissingBuilderArgument { arg: &'static str },

    /// unsupported algorithm
    #[snafu(display("unsupported algorithm: {}", algorithm))]
    UnsupportedAlgorithm { algorithm: String },

    /// certificate is not yet valid
    #[snafu(display(
        "certificate is not yet valid (not before: {}, now: {})",
        not_before,
        now
    ))]
    CertificateNotYetValid { not_before: UTCDate, now: UTCDate },

    /// certificate expired
    #[snafu(display("certificate expired (not after: {}, now: {})", not_after, now))]
    CertificateExpired { not_after: UTCDate, now: UTCDate },

    /// input has invalid charset
    #[snafu(display("input has invalid charset: {}", input))]
    InvalidCharSet { input: String, source: CharSetError },
}

impl From<RSAError> for Error {
    fn from(e: RSAError) -> Self {
        Error::Rsa {
            context: e.to_string(),
        }
    }
}
