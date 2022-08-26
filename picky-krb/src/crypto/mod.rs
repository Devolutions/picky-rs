mod aes;
pub(crate) mod nfold;
pub(crate) mod utils;

use crypto::symmetriccipher::SymmetricCipherError;
use thiserror::Error;

use crate::constants::etypes::{AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96, DES3_CBC_SHA1_KD};

/// https://www.rfc-editor.org/rfc/rfc3962.html#section-4
/// the 8-octet ASCII string "kerberos"
pub const KERBEROS: &[u8; 8] = b"kerberos";

#[derive(Error, Debug)]
pub enum KerberosCryptoError {
    #[error("Invalid key length: {0}. Expected: {1}")]
    KeyLength(usize, usize),
    #[error("Invalid cipher length: {0}. Expected at least: {1}")]
    CipherLength(usize, usize),
    #[error("Invalid algorithm identifier: {0}")]
    AlgorithmIdentifier(usize),
    #[error("Bad integrity: calculates hmac is different than provided")]
    IntegrityCheck,
    #[error("cipher error: {0}")]
    CipherError(String),
}

impl From<SymmetricCipherError> for KerberosCryptoError {
    fn from(error: SymmetricCipherError) -> Self {
        Self::CipherError(format!("{:?}", error))
    }
}

pub type KerberosCryptoResult<T> = Result<T, KerberosCryptoError>;

pub trait Cipher {
    fn key_size(&self) -> usize;
    fn cipher_type(&self) -> CipherSuites;
    fn confounder_byte_size(&self) -> usize;
    fn encrypt(&self, key: &[u8], key_usage: i32, payload: &[u8]) -> KerberosCryptoResult<Vec<u8>>;
    fn decrypt(&self, key: &[u8], key_usage: i32, cipher_data: &[u8]) -> KerberosCryptoResult<Vec<u8>>;
    fn checksum(&self, key: &[u8], key_usage: i32, payload: &[u8]) -> KerberosCryptoResult<Vec<u8>>;
}

#[derive(Debug, Clone, PartialEq)]
pub enum CipherSuites {
    Aes128CtsHmacSha196,
    Aes256CtsHmacSha196,
    Des3CbcSha1Kd,
}

impl TryFrom<usize> for CipherSuites {
    type Error = KerberosCryptoError;

    fn try_from(identifier: usize) -> Result<Self, Self::Error> {
        match identifier {
            AES256_CTS_HMAC_SHA1_96 => Ok(Self::Aes256CtsHmacSha196),
            AES128_CTS_HMAC_SHA1_96 => Ok(Self::Aes128CtsHmacSha196),
            DES3_CBC_SHA1_KD => Ok(Self::Des3CbcSha1Kd),
            _ => Err(KerberosCryptoError::AlgorithmIdentifier(identifier)),
        }
    }
}

impl From<CipherSuites> for usize {
    fn from(cipher: CipherSuites) -> Self {
        match cipher {
            CipherSuites::Aes256CtsHmacSha196 => AES256_CTS_HMAC_SHA1_96,
            CipherSuites::Aes128CtsHmacSha196 => AES128_CTS_HMAC_SHA1_96,
            CipherSuites::Des3CbcSha1Kd => DES3_CBC_SHA1_KD,
        }
    }
}
