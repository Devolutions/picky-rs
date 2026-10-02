//! Hash algorithms supported by picky

#[cfg(feature = "rustcrypto")]
use digest::Digest;
use picky_asn1_x509::ShaVariant;
use serde::{Deserialize, Serialize};
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
    MD5,
    SHA1,
    SHA2_224,
    SHA2_256,
    SHA2_384,
    SHA2_512,
    SHA3_384,
    SHA3_512,
}

impl TryFrom<HashAlgorithm> for ShaVariant {
    type Error = UnsupportedHashAlgorithmError;

    fn try_from(v: HashAlgorithm) -> Result<ShaVariant, UnsupportedHashAlgorithmError> {
        match v {
            HashAlgorithm::MD5 => Ok(ShaVariant::MD5),
            HashAlgorithm::SHA1 => Ok(ShaVariant::SHA1),
            HashAlgorithm::SHA2_256 => Ok(ShaVariant::SHA2_256),
            HashAlgorithm::SHA2_384 => Ok(ShaVariant::SHA2_384),
            HashAlgorithm::SHA2_512 => Ok(ShaVariant::SHA2_512),
            HashAlgorithm::SHA3_384 => Ok(ShaVariant::SHA3_384),
            HashAlgorithm::SHA3_512 => Ok(ShaVariant::SHA3_512),
            _ => Err(UnsupportedHashAlgorithmError {
                algorithm: format!("{v:?}"),
            }),
        }
    }
}

impl TryFrom<ShaVariant> for HashAlgorithm {
    type Error = UnsupportedHashAlgorithmError;

    fn try_from(v: ShaVariant) -> Result<HashAlgorithm, UnsupportedHashAlgorithmError> {
        match v {
            ShaVariant::MD5 => Ok(HashAlgorithm::MD5),
            ShaVariant::SHA1 => Ok(HashAlgorithm::SHA1),
            ShaVariant::SHA2_256 => Ok(HashAlgorithm::SHA2_256),
            ShaVariant::SHA2_384 => Ok(HashAlgorithm::SHA2_384),
            ShaVariant::SHA2_512 => Ok(HashAlgorithm::SHA2_512),
            ShaVariant::SHA3_384 => Ok(HashAlgorithm::SHA3_384),
            ShaVariant::SHA3_512 => Ok(HashAlgorithm::SHA3_512),
            _ => Err(UnsupportedHashAlgorithmError {
                algorithm: format!("{v:?}"),
            }),
        }
    }
}

impl HashAlgorithm {
    pub fn digest(self, msg: &[u8]) -> Vec<u8> {
        #[cfg(feature = "fips-aws-lc")]
        {
            crate::crypto::require_hash(self).unwrap_or_else(|error| panic!("{error}"));
            let algorithm = match self {
                Self::SHA2_256 => &aws_lc_rs::digest::SHA256,
                Self::SHA2_384 => &aws_lc_rs::digest::SHA384,
                Self::SHA2_512 => &aws_lc_rs::digest::SHA512,
                _ => unreachable!("policy checked above"),
            };
            aws_lc_rs::digest::digest(algorithm, msg).as_ref().to_vec()
        }

        #[cfg(not(feature = "fips-aws-lc"))]
        match self {
            Self::MD5 => md5::Md5::digest(msg).as_slice().to_vec(),
            Self::SHA1 => sha1::Sha1::digest(msg).as_slice().to_vec(),
            Self::SHA2_224 => sha2::Sha224::digest(msg).as_slice().to_vec(),
            Self::SHA2_256 => sha2::Sha256::digest(msg).as_slice().to_vec(),
            Self::SHA2_384 => sha2::Sha384::digest(msg).as_slice().to_vec(),
            Self::SHA2_512 => sha2::Sha512::digest(msg).as_slice().to_vec(),
            Self::SHA3_384 => sha3::Sha3_384::digest(msg).as_slice().to_vec(),
            Self::SHA3_512 => sha3::Sha3_512::digest(msg).as_slice().to_vec(),
        }
    }

    pub fn output_size(self) -> usize {
        #[cfg(feature = "fips-aws-lc")]
        {
            crate::crypto::require_hash(self).unwrap_or_else(|error| panic!("{error}"));
        }

        match self {
            Self::MD5 => 16,
            Self::SHA1 => 20,
            Self::SHA2_224 => 28,
            Self::SHA2_256 => 32,
            Self::SHA2_384 => 48,
            Self::SHA2_512 => 64,
            Self::SHA3_384 => 48,
            Self::SHA3_512 => 64,
        }
    }
}
