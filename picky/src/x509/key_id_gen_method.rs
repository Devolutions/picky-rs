use crate::hash::HashAlgorithm;
use crate::key::{KeyError, PublicKey};
use der::asn1::BitString;
use der::Error as Asn1DerError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyIdGenError {
    /// asn1 serialization error
    #[error("(asn1) couldn't serialize {element}: {source}")]
    Asn1Serialization {
        element: &'static str,
        source: Asn1DerError,
    },

    /// invalid key
    #[error("invalid key: {source}")]
    InvalidKey { source: KeyError },

    /// public key parsing error
    #[error("public key parsing error: {source}")]
    PublicKeyParsing { source: picky_asn1_x509::PublicKeyError },
}

/// Describes which method to use to generate key identifiers.
///
/// See [RFC5280 #4](https://tools.ietf.org/html/rfc5280#section-4.2.1.2) and
/// [RFC7093 #2](https://tools.ietf.org/html/rfc7093#section-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyIdGenMethod {
    /// Hash the leftmost 160-bits of the
    /// SHA-256 hash of the value of the BIT STRING subjectPublicKey
    /// (excluding the tag, length, and number of unused bits).
    SPKValueHashedLeftmost160(HashAlgorithm),
    /// Hash the DER encoding of the SubjectPublicKeyInfo value.
    SPKFullDER(HashAlgorithm),
}

impl KeyIdGenMethod {
    pub fn generate_from(self, public_key: &PublicKey) -> Result<Vec<u8>, KeyIdGenError> {
        use picky_asn1_x509::PublicKey as InnerPublicKey;

        match self {
            KeyIdGenMethod::SPKValueHashedLeftmost160(hash_algo) => {
                let spki = public_key.as_inner().map_err(|e| KeyIdGenError::InvalidKey {
                    source: e,
                })?;
                
                match picky_asn1_x509::parse_subject_public_key_info(&spki).map_err(|e| KeyIdGenError::PublicKeyParsing {
                    source: e,
                })? {
                    InnerPublicKey::Rsa(rsa_pk) => {
                        use der::Encode;
                        let der = rsa_pk.to_der().map_err(|e| KeyIdGenError::Asn1Serialization {
                            source: e,
                            element: "RSA public key",
                        })?;
                        Ok(hash_algo.digest(&der)[..20].to_vec())
                    }
                    InnerPublicKey::Ec(bitstring) => {
                        let der = bitstring.raw_bytes();
                        Ok(hash_algo.digest(der)[..20].to_vec())
                    }
                    InnerPublicKey::Ed(bitstring) => {
                        let der = bitstring.raw_bytes();
                        Ok(hash_algo.digest(der)[..20].to_vec())
                    }
                }
            }
            KeyIdGenMethod::SPKFullDER(hash_algo) => {
                let der = public_key
                    .to_der()
                    .map_err(|e| KeyIdGenError::InvalidKey { source: e })?;
                Ok(hash_algo.digest(&der))
            }
        }
    }
}
