//! Hash algorithms supported by picky

use digest::Digest;
use picky_asn1_x509::ShaVariant;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::error::Error;
use std::fmt;

/// unsupported algorithm
#[derive(Debug)]
pub struct UnsupportedHashAlgorithmError {
    pub algorithm: String,
}

impl fmt::Display for UnsupportedHashAlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported algorithm:  {}", self.algorithm)
    }
}

impl Error for UnsupportedHashAlgorithmError {}

/// Supported hash algorithms
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashAlgorithm {
    SHA1,
    SHA2_224,
    SHA2_256,
    SHA2_384,
    SHA2_512,
    SHA3_384,
    SHA3_512,
}

impl From<HashAlgorithm> for rsa::Hash {
    fn from(v: HashAlgorithm) -> rsa::Hash {
        match v {
            HashAlgorithm::SHA1 => rsa::Hash::SHA1,
            HashAlgorithm::SHA2_224 => rsa::Hash::SHA2_224,
            HashAlgorithm::SHA2_256 => rsa::Hash::SHA2_256,
            HashAlgorithm::SHA2_384 => rsa::Hash::SHA2_384,
            HashAlgorithm::SHA2_512 => rsa::Hash::SHA2_512,
            HashAlgorithm::SHA3_384 => rsa::Hash::SHA3_384,
            HashAlgorithm::SHA3_512 => rsa::Hash::SHA3_512,
        }
    }
}

impl TryFrom<HashAlgorithm> for ShaVariant {
    type Error = UnsupportedHashAlgorithmError;

    fn try_from(v: HashAlgorithm) -> Result<ShaVariant, UnsupportedHashAlgorithmError> {
        match v {
            HashAlgorithm::SHA2_256 => Ok(ShaVariant::SHA2_256),
            HashAlgorithm::SHA2_384 => Ok(ShaVariant::SHA2_384),
            HashAlgorithm::SHA2_512 => Ok(ShaVariant::SHA2_512),
            HashAlgorithm::SHA3_384 => Ok(ShaVariant::SHA3_384),
            HashAlgorithm::SHA3_512 => Ok(ShaVariant::SHA3_512),
            _ => Err(UnsupportedHashAlgorithmError {
                algorithm: format!("{:?}", v),
            }),
        }
    }
}

impl TryFrom<ShaVariant> for HashAlgorithm {
    type Error = UnsupportedHashAlgorithmError;

    fn try_from(v: ShaVariant) -> Result<HashAlgorithm, UnsupportedHashAlgorithmError> {
        match v {
            ShaVariant::SHA2_256 => Ok(HashAlgorithm::SHA2_256),
            ShaVariant::SHA2_384 => Ok(HashAlgorithm::SHA2_384),
            ShaVariant::SHA2_512 => Ok(HashAlgorithm::SHA2_512),
            ShaVariant::SHA3_384 => Ok(HashAlgorithm::SHA3_384),
            ShaVariant::SHA3_512 => Ok(HashAlgorithm::SHA3_512),
            _ => Err(UnsupportedHashAlgorithmError {
                algorithm: format!("{:?}", v),
            }),
        }
    }
}

impl HashAlgorithm {
    pub fn digest(self, msg: &[u8]) -> Vec<u8> {
        match self {
            Self::SHA1 => sha1::Sha1::digest(msg).as_slice().to_vec(),
            Self::SHA2_224 => sha2::Sha224::digest(msg).as_slice().to_vec(),
            Self::SHA2_256 => sha2::Sha256::digest(msg).as_slice().to_vec(),
            Self::SHA2_384 => sha2::Sha384::digest(msg).as_slice().to_vec(),
            Self::SHA2_512 => sha2::Sha512::digest(msg).as_slice().to_vec(),
            Self::SHA3_384 => sha3::Sha3_384::digest(msg).as_slice().to_vec(),
            Self::SHA3_512 => sha3::Sha3_512::digest(msg).as_slice().to_vec(),
        }
    }
}
