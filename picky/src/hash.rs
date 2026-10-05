//! Hash algorithms supported by picky

#[cfg(feature = "rustcrypto")]
use digest::Digest;
use picky_asn1_x509::ShaVariant;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use thiserror::Error as ThisError;

use crate::crypto::CryptoPolicyError;

#[derive(Debug, ThisError, PartialEq, Eq)]
pub enum HashError {
    #[error(transparent)]
    Policy(#[from] CryptoPolicyError),

    #[error("{provider} {operation} failed with error code {code}")]
    Provider {
        provider: &'static str,
        operation: &'static str,
        code: i32,
    },
}

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
    /// Hashes `msg` when this algorithm is allowed by the active cryptographic policy.
    pub fn digest(self, msg: &[u8]) -> Result<Vec<u8>, HashError> {
        #[cfg(feature = "fips-aws-lc")]
        {
            crate::crypto::require_hash(self)?;
            let algorithm = match self {
                Self::SHA2_224 => &aws_lc_rs::digest::SHA224,
                Self::SHA2_256 => &aws_lc_rs::digest::SHA256,
                Self::SHA2_384 => &aws_lc_rs::digest::SHA384,
                Self::SHA2_512 => &aws_lc_rs::digest::SHA512,
                Self::SHA3_384 => &aws_lc_rs::digest::SHA3_384,
                Self::SHA3_512 => &aws_lc_rs::digest::SHA3_512,
                _ => unreachable!("policy checked above"),
            };
            Ok(aws_lc_rs::digest::digest(algorithm, msg).as_ref().to_vec())
        }

        #[cfg(feature = "rustcrypto")]
        Ok(match self {
            Self::MD5 => md5::Md5::digest(msg).as_slice().to_vec(),
            Self::SHA1 => sha1::Sha1::digest(msg).as_slice().to_vec(),
            Self::SHA2_224 => sha2::Sha224::digest(msg).as_slice().to_vec(),
            Self::SHA2_256 => sha2::Sha256::digest(msg).as_slice().to_vec(),
            Self::SHA2_384 => sha2::Sha384::digest(msg).as_slice().to_vec(),
            Self::SHA2_512 => sha2::Sha512::digest(msg).as_slice().to_vec(),
            Self::SHA3_384 => sha3::Sha3_384::digest(msg).as_slice().to_vec(),
            Self::SHA3_512 => sha3::Sha3_512::digest(msg).as_slice().to_vec(),
        })
    }

    /// Returns the digest size when this algorithm is allowed by the active cryptographic policy.
    pub fn output_size(self) -> Result<usize, crate::crypto::CryptoPolicyError> {
        #[cfg(feature = "fips")]
        {
            crate::crypto::require_hash(self)?;
        }

        Ok(match self {
            Self::MD5 => 16,
            Self::SHA1 => 20,
            Self::SHA2_224 => 28,
            Self::SHA2_256 => 32,
            Self::SHA2_384 => 48,
            Self::SHA2_512 => 64,
            Self::SHA3_384 => 48,
            Self::SHA3_512 => 64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approved_digests_and_output_sizes_are_available() {
        for (algorithm, expected_hex, expected_size) in [
            (
                HashAlgorithm::SHA2_224,
                "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
                28,
            ),
            (
                HashAlgorithm::SHA2_256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                32,
            ),
            (
                HashAlgorithm::SHA2_384,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
                 8086072ba1e7cc2358baeca134c825a7",
                48,
            ),
            (
                HashAlgorithm::SHA2_512,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                64,
            ),
            (
                HashAlgorithm::SHA3_384,
                "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b\
                 298d88cea927ac7f539f1edf228376d25",
                48,
            ),
            (
                HashAlgorithm::SHA3_512,
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712\
                 e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
                64,
            ),
        ] {
            assert_eq!(algorithm.digest(b"abc").unwrap(), hex::decode(expected_hex).unwrap());
            assert_eq!(algorithm.output_size().unwrap(), expected_size);
        }
    }

    #[cfg(feature = "fips")]
    #[test]
    fn fips_rejects_unapproved_hashing_without_panicking() {
        for algorithm in [HashAlgorithm::MD5, HashAlgorithm::SHA1] {
            let digest_error = algorithm.digest(b"attacker-controlled input").unwrap_err();
            assert!(matches!(
                digest_error,
                HashError::Policy(ref policy_error) if policy_error.algorithm == format!("{algorithm:?}")
            ));
            assert_eq!(
                digest_error.to_string(),
                format!("algorithm disabled by the active cryptographic policy: {algorithm:?}")
            );

            let size_error = algorithm.output_size().unwrap_err();
            assert_eq!(size_error.algorithm, format!("{algorithm:?}"));
            assert_eq!(
                size_error.to_string(),
                format!("algorithm disabled by the active cryptographic policy: {algorithm:?}")
            );
        }
    }

    #[cfg(feature = "rustcrypto")]
    #[test]
    fn rustcrypto_keeps_legacy_hashes_available() {
        assert_eq!(
            HashAlgorithm::SHA1.digest(b"abc").unwrap(),
            hex::decode("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap()
        );
        assert_eq!(
            HashAlgorithm::MD5.digest(b"abc").unwrap(),
            hex::decode("900150983cd24fb0d6963f7d28e17f72").unwrap()
        );
    }
}
