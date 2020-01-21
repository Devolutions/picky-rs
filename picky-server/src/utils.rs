use base64::DecodeError;
use picky::{
    pem::PemError,
    x509::{certificate::CertError, csr::CsrError},
};
use std::{
    error::Error,
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn unix_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("duration since unix epoch")
        .as_secs()
}

// === Greedy Error === //

/// I eat and format any error I can
#[derive(Debug)]
pub struct GreedyError(pub String);

impl Error for GreedyError {}

impl fmt::Display for GreedyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for GreedyError {
    fn from(e: String) -> Self {
        Self(e)
    }
}

impl From<PemError> for GreedyError {
    fn from(e: PemError) -> Self {
        Self(format!("pem: {}", e))
    }
}

impl From<CertError> for GreedyError {
    fn from(e: CertError) -> Self {
        Self(format!("cert: {}", e))
    }
}

impl From<CsrError> for GreedyError {
    fn from(e: CsrError) -> Self {
        Self(format!("csr: {}", e))
    }
}

impl From<serde_json::Error> for GreedyError {
    fn from(e: serde_json::Error) -> Self {
        Self(format!("json: {}", e))
    }
}

impl From<DecodeError> for GreedyError {
    fn from(e: DecodeError) -> Self {
        Self(format!("base64 decode: {}", e))
    }
}
