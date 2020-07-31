//! Hash algorithms supported by picky

use digest::Digest;
use serde::{Deserialize, Serialize};

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
