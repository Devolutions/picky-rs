use std::fmt;

use picky::jose::jwe::JweError;
use picky::jose::jws::JwsError;
use picky::jose::jwt::JwtError;
use picky::key::KeyError;
use picky::pem::PemError;
use picky::pkcs12::Pkcs12Error;
use picky::pkcs12::Pkcs12MacError;
use picky::signature::SignatureError;
use picky::ssh::certificate::SshCertificateError;
use picky::ssh::certificate::SshCertificateGenerationError;
use picky::ssh::private_key::SshPrivateKeyError;
use picky::ssh::public_key::SshPublicKeyError;
use picky::x509::certificate::CertError;

use self::ffi::{PickyError, PickyErrorKind};

impl From<String> for PickyErrorKind {
    fn from(_: String) -> Self {
        Self::Generic
    }
}

impl From<&str> for PickyErrorKind {
    fn from(_: &str) -> Self {
        Self::Generic
    }
}

impl From<fmt::Error> for PickyErrorKind {
    fn from(_: fmt::Error) -> Self {
        Self::Generic
    }
}

impl From<PemError> for PickyErrorKind {
    fn from(_: PemError) -> Self {
        Self::Generic
    }
}

impl From<SshCertificateError> for PickyErrorKind {
    fn from(_: SshCertificateError) -> Self {
        Self::Generic
    }
}

impl From<SshPrivateKeyError> for PickyErrorKind {
    fn from(_: SshPrivateKeyError) -> Self {
        Self::Generic
    }
}

impl From<SshPublicKeyError> for PickyErrorKind {
    fn from(_: SshPublicKeyError) -> Self {
        Self::Generic
    }
}

impl From<std::io::Error> for PickyErrorKind {
    fn from(_: std::io::Error) -> Self {
        Self::Generic
    }
}

impl From<KeyError> for PickyErrorKind {
    fn from(_: KeyError) -> Self {
        Self::Generic
    }
}

impl From<serde_json::Error> for PickyErrorKind {
    fn from(_: serde_json::Error) -> Self {
        Self::Generic
    }
}

impl From<SshCertificateGenerationError> for PickyErrorKind {
    fn from(_: SshCertificateGenerationError) -> Self {
        Self::Generic
    }
}

impl From<picky_asn1::restricted_string::CharSetError> for PickyErrorKind {
    fn from(_: picky_asn1::restricted_string::CharSetError) -> Self {
        Self::Generic
    }
}

impl From<Pkcs12Error> for PickyErrorKind {
    fn from(value: Pkcs12Error) -> Self {
        match value {
            Pkcs12Error::Mac(Pkcs12MacError::MacValidation) => Self::Pkcs12MacValidation,
            _ => Self::Generic,
        }
    }
}

impl From<time::error::ComponentRange> for PickyErrorKind {
    fn from(_: time::error::ComponentRange) -> Self {
        Self::Generic
    }
}

impl From<SignatureError> for PickyErrorKind {
    fn from(value: SignatureError) -> Self {
        match value {
            SignatureError::BadSignature => Self::BadSignature,
            _ => Self::Generic,
        }
    }
}

impl From<JweError> for PickyErrorKind {
    fn from(_: JweError) -> Self {
        Self::Generic
    }
}

impl From<JwsError> for PickyErrorKind {
    fn from(value: JwsError) -> Self {
        match value {
            JwsError::Signature { source } => Self::from(source),
            _ => Self::Generic,
        }
    }
}

impl From<JwtError> for PickyErrorKind {
    fn from(value: JwtError) -> Self {
        match value {
            JwtError::NotYetValid { .. } => Self::NotYetValid,
            JwtError::Expired { .. } => Self::Expired,
            JwtError::Jwe { source } => Self::from(source),
            JwtError::Jws { source } => Self::from(source),
            _ => Self::Generic,
        }
    }
}

impl From<CertError> for PickyErrorKind {
    fn from(value: CertError) -> Self {
        match value {
            CertError::CertificateNotYetValid { .. } => Self::NotYetValid,
            CertError::CertificateExpired { .. } => Self::Expired,
            CertError::Signature { source } => Self::from(source),
            _ => Self::Generic,
        }
    }
}

impl<T> From<T> for Box<PickyError>
where
    T: Into<PickyErrorKind> + ToString,
{
    fn from(value: T) -> Self {
        let repr = value.to_string();
        let kind = value.into();
        Box::new(PickyError(PickyErrorInner { repr, kind }))
    }
}

struct PickyErrorInner {
    pub repr: String,
    pub kind: PickyErrorKind,
}

#[diplomat::bridge]
pub mod ffi {
    use diplomat_runtime::DiplomatWriteable;
    use std::fmt::Write as _;

    /// Kind associated to a Picky Error
    #[derive(Clone, Copy)]
    pub enum PickyErrorKind {
        /// Generic Picky error
        Generic,
        /// Token or certificate not yet valid
        NotYetValid,
        /// Token or certificate expired
        Expired,
        /// Bad signature for token or certificate
        BadSignature,
        /// MAC validation failed (wrong password or corrupted data)
        Pkcs12MacValidation,
    }

    /// Stringified Picky error along with an error kind.
    #[diplomat::opaque]
    pub struct PickyError(pub(super) super::PickyErrorInner);

    impl PickyError {
        /// Returns the error as a string.
        pub fn to_display(&self, writeable: &mut DiplomatWriteable) {
            let _ = write!(writeable, "{}", self.0.repr);
            writeable.flush();
        }

        /// Prints the error string.
        pub fn print(&self) {
            println!("{}", self.0.repr);
        }

        /// Returns the error kind.
        pub fn get_kind(&self) -> PickyErrorKind {
            self.0.kind
        }
    }
}
