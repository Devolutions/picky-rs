//! Signature algorithms supported by picky

use crate::hash::HashAlgorithm;
use crate::key::{KeyError, PrivateKey, PublicKey};
use picky_asn1_x509::{oids, AlgorithmIdentifier};
use rsa::{PublicKey as _, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SignatureError {
    /// Key error
    #[error("Key error: {source}")]
    Key { source: KeyError },

    /// RSA error
    #[error("RSA error: {context}")]
    Rsa { context: String },

    /// invalid signature
    #[error("invalid signature")]
    BadSignature,

    /// unsupported algorithm
    #[error("unsupported algorithm: {algorithm}")]
    UnsupportedAlgorithm { algorithm: String },
}

impl From<rsa::errors::Error> for SignatureError {
    fn from(e: rsa::errors::Error) -> Self {
        SignatureError::Rsa { context: e.to_string() }
    }
}

impl From<KeyError> for SignatureError {
    fn from(e: KeyError) -> Self {
        SignatureError::Key { source: e }
    }
}

/// Supported signature algorithms
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    RsaPkcs1v15(HashAlgorithm),
}

impl TryFrom<&'_ AlgorithmIdentifier> for SignatureAlgorithm {
    type Error = SignatureError;

    fn try_from(v: &AlgorithmIdentifier) -> Result<Self, Self::Error> {
        let oid_string: String = v.oid().into();
        match oid_string.as_str() {
            oids::MD5_WITH_RSA_ENCRYPTHION => Ok(Self::RsaPkcs1v15(HashAlgorithm::MD5)),
            oids::SHA1_WITH_RSA_ENCRYPTION => Ok(Self::RsaPkcs1v15(HashAlgorithm::SHA1)),
            oids::SHA224_WITH_RSA_ENCRYPTION => Ok(Self::RsaPkcs1v15(HashAlgorithm::SHA2_224)),
            oids::SHA256_WITH_RSA_ENCRYPTION => Ok(Self::RsaPkcs1v15(HashAlgorithm::SHA2_256)),
            oids::SHA384_WITH_RSA_ENCRYPTION => Ok(Self::RsaPkcs1v15(HashAlgorithm::SHA2_384)),
            oids::SHA512_WITH_RSA_ENCRYPTION => Ok(Self::RsaPkcs1v15(HashAlgorithm::SHA2_512)),
            oids::ID_RSASSA_PKCS1_V1_5_WITH_SHA3_384 => Ok(Self::RsaPkcs1v15(HashAlgorithm::SHA3_384)),
            oids::ID_RSASSA_PKCS1_V1_5_WITH_SHA3_512 => Ok(Self::RsaPkcs1v15(HashAlgorithm::SHA3_512)),
            _ => Err(SignatureError::UnsupportedAlgorithm { algorithm: oid_string }),
        }
    }
}

impl From<SignatureAlgorithm> for AlgorithmIdentifier {
    fn from(ty: SignatureAlgorithm) -> Self {
        match ty {
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::MD5) => AlgorithmIdentifier::new_md5_with_rsa_encryption(),
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA1) => AlgorithmIdentifier::new_sha1_with_rsa_encryption(),
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_224) => {
                AlgorithmIdentifier::new_sha224_with_rsa_encryption()
            }
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256) => {
                AlgorithmIdentifier::new_sha256_with_rsa_encryption()
            }
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_384) => {
                AlgorithmIdentifier::new_sha384_with_rsa_encryption()
            }
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_512) => {
                AlgorithmIdentifier::new_sha512_with_rsa_encryption()
            }
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA3_384) => {
                AlgorithmIdentifier::new_sha3_384_with_rsa_encryption()
            }
            SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA3_512) => {
                AlgorithmIdentifier::new_sha3_512_with_rsa_encryption()
            }
        }
    }
}

impl SignatureAlgorithm {
    pub fn from_algorithm_identifier(algorithm_identifier: &AlgorithmIdentifier) -> Result<Self, SignatureError> {
        Self::try_from(algorithm_identifier)
    }

    pub fn sign(self, msg: &[u8], private_key: &PrivateKey) -> Result<Vec<u8>, SignatureError> {
        let signature = match self {
            SignatureAlgorithm::RsaPkcs1v15(picky_hash_algo) => {
                let rsa_private_key = RsaPrivateKey::try_from(private_key)?;
                let digest = picky_hash_algo.digest(msg);
                let rsa_hash_algo = rsa::Hash::from(picky_hash_algo);
                let padding_scheme = rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa_hash_algo));
                rsa_private_key.sign_blinded(&mut rand::rngs::OsRng, padding_scheme, &digest)?
            }
        };

        Ok(signature)
    }

    pub fn verify(self, public_key: &PublicKey, msg: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
        match self {
            SignatureAlgorithm::RsaPkcs1v15(picky_hash_algo) => {
                let rsa_public_key = RsaPublicKey::try_from(public_key)?;
                let digest = picky_hash_algo.digest(msg);
                let rsa_hash_algo = rsa::Hash::from(picky_hash_algo);
                let padding_scheme = rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa_hash_algo));
                rsa_public_key
                    .verify(padding_scheme, &digest, signature)
                    .map_err(|_| SignatureError::BadSignature)?;
            }
        }

        Ok(())
    }

    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match &self {
            SignatureAlgorithm::RsaPkcs1v15(hash_algo) => *hash_algo,
        }
    }
}
