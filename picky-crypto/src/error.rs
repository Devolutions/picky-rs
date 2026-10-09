use crate::Algorithm;
use std::fmt;

/// Closed, backend-independent operation errors.
/// See CONTRACT.md section 4.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Unavailable or refused algorithm, operation, size or parameter.
    /// See CONTRACT.md section 4.
    Unsupported(Algorithm),
    /// Malformed, incorrectly typed or rejected key material.
    /// See CONTRACT.md section 4.
    InvalidKey,
    /// Malformed or out-of-range non-key input.
    /// See CONTRACT.md section 4.
    InvalidInput,
    /// Failed signature, tag, unwrap integrity or decryption check.
    /// See CONTRACT.md section 4.
    VerificationFailed,
    /// Backend failure unrelated to the inputs.
    /// See CONTRACT.md section 4.
    ProviderFailure,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(algorithm) => write!(f, "unsupported: {algorithm:?}"),
            Self::InvalidKey => f.write_str("invalid key"),
            Self::InvalidInput => f.write_str("invalid input"),
            Self::VerificationFailed => f.write_str("verification failed"),
            Self::ProviderFailure => f.write_str("provider failure"),
        }
    }
}
impl std::error::Error for Error {}

/// Provider construction errors.
/// See CONTRACT.md sections 4 and 8.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// Two entries implement the same algorithm.
    /// See CONTRACT.md section 8.
    Duplicate(Algorithm),
    /// An entry reports an algorithm its variant cannot implement.
    /// See CONTRACT.md section 8.
    Mismatched(Algorithm),
    /// A directional entry supports neither protection.
    /// See CONTRACT.md sections 4 and 8.
    NoProtection(Algorithm),
}
impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate(algorithm) => write!(f, "duplicate algorithm: {algorithm:?}"),
            Self::Mismatched(algorithm) => write!(f, "mismatched algorithm: {algorithm:?}"),
            Self::NoProtection(algorithm) => write!(f, "no protection: {algorithm:?}"),
        }
    }
}
impl std::error::Error for BuildError {}
