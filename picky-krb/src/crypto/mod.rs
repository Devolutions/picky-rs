pub mod aes;
pub(crate) mod common;
pub mod des;
pub(crate) mod nfold;
pub(crate) mod utils;

use ::aes::cipher::block_padding::UnpadError;
use ::aes::cipher::inout::PadError;
use thiserror::Error;

use crate::constants::etypes::{AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96, DES3_CBC_SHA1_KD};

use self::aes::aes128_cts_hmac_sha1_96::Aes128CtsHmacSha196;
use self::aes::aes256_cts_hmac_sha1_96::Aes256CtsHmacSha196;
use self::des::des3_cbc_sha1_kd::Des3CbcSha1Kd;

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
    #[error("Padding error: {0:?}")]
    CipherUnpad(UnpadError),
    #[error("Padding error: {0:?}")]
    CipherPad(PadError),
}

impl From<UnpadError> for KerberosCryptoError {
    fn from(err: UnpadError) -> Self {
        Self::CipherUnpad(err)
    }
}

impl From<PadError> for KerberosCryptoError {
    fn from(err: PadError) -> Self {
        Self::CipherPad(err)
    }
}

pub type KerberosCryptoResult<T> = Result<T, KerberosCryptoError>;

pub trait Cipher {
    fn key_size(&self) -> usize;
    fn cipher_type(&self) -> CipherSuite;
    fn encrypt(&self, key: &[u8], key_usage: i32, payload: &[u8]) -> KerberosCryptoResult<Vec<u8>>;
    fn decrypt(&self, key: &[u8], key_usage: i32, cipher_data: &[u8]) -> KerberosCryptoResult<Vec<u8>>;
    fn generate_key_from_password(&self, password: &[u8], salt: &[u8]) -> KerberosCryptoResult<Vec<u8>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherSuite {
    Aes128CtsHmacSha196,
    Aes256CtsHmacSha196,
    Des3CbcSha1Kd,
}

impl CipherSuite {
    pub fn cipher(&self) -> Box<dyn Cipher> {
        match self {
            CipherSuite::Aes256CtsHmacSha196 => Box::new(Aes256CtsHmacSha196::new()),
            CipherSuite::Aes128CtsHmacSha196 => Box::new(Aes128CtsHmacSha196::new()),
            CipherSuite::Des3CbcSha1Kd => Box::new(Des3CbcSha1Kd::new()),
        }
    }
}

impl TryFrom<usize> for CipherSuite {
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

impl From<CipherSuite> for usize {
    fn from(cipher: CipherSuite) -> Self {
        match cipher {
            CipherSuite::Aes256CtsHmacSha196 => AES256_CTS_HMAC_SHA1_96,
            CipherSuite::Aes128CtsHmacSha196 => AES128_CTS_HMAC_SHA1_96,
            CipherSuite::Des3CbcSha1Kd => DES3_CBC_SHA1_KD,
        }
    }
}

impl From<CipherSuite> for u8 {
    fn from(cipher: CipherSuite) -> Self {
        match cipher {
            CipherSuite::Aes256CtsHmacSha196 => AES256_CTS_HMAC_SHA1_96 as u8,
            CipherSuite::Aes128CtsHmacSha196 => AES128_CTS_HMAC_SHA1_96 as u8,
            CipherSuite::Des3CbcSha1Kd => DES3_CBC_SHA1_KD as u8,
        }
    }
}

impl From<&CipherSuite> for u8 {
    fn from(cipher: &CipherSuite) -> Self {
        match cipher {
            CipherSuite::Aes256CtsHmacSha196 => AES256_CTS_HMAC_SHA1_96 as u8,
            CipherSuite::Aes128CtsHmacSha196 => AES128_CTS_HMAC_SHA1_96 as u8,
            CipherSuite::Des3CbcSha1Kd => DES3_CBC_SHA1_KD as u8,
        }
    }
}
