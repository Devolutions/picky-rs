use picky::jose::jwe::JweError;
use picky::jose::jws::JwsError;
use picky::jose::jwt::JwtError;
use picky::signature::SignatureError;
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

impl<T> From<T> for PickyError
where
    T: Into<PickyErrorKind> + ToString,
{
    fn from(value: T) -> Self {
        let repr = value.to_string();
        let kind = value.into();
        Self(PickyErrorInner { repr, kind })
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
    }

    /// Stringified Picky error along an error kind
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
