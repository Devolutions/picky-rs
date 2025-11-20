//! Algorithm Identifier types using der crate

use crate::oids;
use const_oid::ObjectIdentifier;
use der::asn1::{AnyRef, Null};

// Re-export the standard AlgorithmIdentifier from spki
pub use spki::AlgorithmIdentifier;

/// Create AlgorithmIdentifier for MD5 with RSA encryption
pub fn md5_with_rsa_encryption() -> AlgorithmIdentifier<AnyRef<'static>> {
    AlgorithmIdentifier {
        oid: oids::MD5_WITH_RSA_ENCRYPTION,
        parameters: Some(AnyRef::from(Null)),
    }
}

/// Create AlgorithmIdentifier for SHA-1 with RSA encryption
pub fn sha1_with_rsa_encryption() -> AlgorithmIdentifier<AnyRef<'static>> {
    AlgorithmIdentifier {
        oid: oids::SHA1_WITH_RSA_ENCRYPTION,
        parameters: Some(AnyRef::from(Null)),
    }
}

/// Create AlgorithmIdentifier for SHA-1
pub fn sha1() -> AlgorithmIdentifier<AnyRef<'static>> {
    AlgorithmIdentifier {
        oid: oids::SHA1,
        parameters: Some(AnyRef::from(Null)),
    }
}

/// Create AlgorithmIdentifier for SHA-224 with RSA encryption
pub fn sha224_with_rsa_encryption() -> AlgorithmIdentifier<AnyRef<'static>> {
    AlgorithmIdentifier {
        oid: oids::SHA224_WITH_RSA_ENCRYPTION,
        parameters: Some(AnyRef::from(Null)),
    }
}

/// Create AlgorithmIdentifier for SHA-256 with RSA encryption
pub fn sha256_with_rsa_encryption() -> AlgorithmIdentifier<AnyRef<'static>> {
    AlgorithmIdentifier {
        oid: oids::SHA256_WITH_RSA_ENCRYPTION,
        parameters: Some(AnyRef::from(Null)),
    }
}

/// Create AlgorithmIdentifier for SHA-384 with RSA encryption
pub fn sha384_with_rsa_encryption() -> AlgorithmIdentifier<AnyRef<'static>> {
    AlgorithmIdentifier {
        oid: oids::SHA384_WITH_RSA_ENCRYPTION,
        parameters: Some(AnyRef::from(Null)),
    }
}

/// Create AlgorithmIdentifier for SHA-512 with RSA encryption
pub fn sha512_with_rsa_encryption() -> AlgorithmIdentifier<AnyRef<'static>> {
    AlgorithmIdentifier {
        oid: oids::SHA512_WITH_RSA_ENCRYPTION,
        parameters: Some(AnyRef::from(Null)),
    }
}

/// Create AlgorithmIdentifier for RSA encryption (PKCS#1 v1.5)
pub fn rsa_encryption() -> AlgorithmIdentifier<AnyRef<'static>> {
    AlgorithmIdentifier {
        oid: oids::RSA_ENCRYPTION,
        parameters: Some(AnyRef::from(Null)),
    }
}

/// Create AlgorithmIdentifier for ECDSA with SHA-256
pub fn ecdsa_with_sha256() -> AlgorithmIdentifier<AnyRef<'static>> {
    AlgorithmIdentifier {
        oid: oids::ECDSA_WITH_SHA256,
        parameters: None,
    }
}

/// Create AlgorithmIdentifier for ECDSA with SHA-384
pub fn ecdsa_with_sha384() -> AlgorithmIdentifier<AnyRef<'static>> {
    AlgorithmIdentifier {
        oid: oids::ECDSA_WITH_SHA384,
        parameters: None,
    }
}

/// Create AlgorithmIdentifier for ECDSA with SHA-512
pub fn ecdsa_with_sha512() -> AlgorithmIdentifier<AnyRef<'static>> {
    AlgorithmIdentifier {
        oid: oids::ECDSA_WITH_SHA512,
        parameters: None,
    }
}

/// Create AlgorithmIdentifier for Ed25519
pub fn ed25519() -> AlgorithmIdentifier<AnyRef<'static>> {
    AlgorithmIdentifier {
        oid: oids::ED25519,
        parameters: None,
    }
}

/// Create AlgorithmIdentifier for Ed448
pub fn ed448() -> AlgorithmIdentifier<AnyRef<'static>> {
    AlgorithmIdentifier {
        oid: oids::ED448,
        parameters: None,
    }
}

/// Create AlgorithmIdentifier for SHA3-256 with RSA encryption
pub fn sha3_256_with_rsa_encryption() -> AlgorithmIdentifier<AnyRef<'static>> {
    AlgorithmIdentifier {
        oid: oids::ID_RSASSA_PKCS1_V1_5_WITH_SHA3_256,
        parameters: Some(AnyRef::from(Null)),
    }
}

/// Create AlgorithmIdentifier for SHA3-384 with RSA encryption
pub fn sha3_384_with_rsa_encryption() -> AlgorithmIdentifier<AnyRef<'static>> {
    AlgorithmIdentifier {
        oid: oids::ID_RSASSA_PKCS1_V1_5_WITH_SHA3_384,
        parameters: Some(AnyRef::from(Null)),
    }
}

/// Create AlgorithmIdentifier for SHA3-512 with RSA encryption
pub fn sha3_512_with_rsa_encryption() -> AlgorithmIdentifier<AnyRef<'static>> {
    AlgorithmIdentifier {
        oid: oids::ID_RSASSA_PKCS1_V1_5_WITH_SHA3_512,
        parameters: Some(AnyRef::from(Null)),
    }
}

/// Decode AlgorithmIdentifier from DER bytes
pub fn from_der_bytes(bytes: &[u8]) -> der::Result<AlgorithmIdentifier<AnyRef>> {
    use der::Decode;
    AlgorithmIdentifier::from_der(bytes)
}

/// Encode AlgorithmIdentifier to DER bytes
pub fn to_der_bytes<T>(alg_id: &AlgorithmIdentifier<T>) -> der::Result<Vec<u8>>
where
    AlgorithmIdentifier<T>: der::Encode,
{
    use der::Encode;
    alg_id.to_der()
}

/// Extension trait for AlgorithmIdentifier
pub trait AlgorithmIdentifierExt {
    /// Check if this algorithm matches the given OID
    fn is_a(&self, algorithm: ObjectIdentifier) -> bool;

    /// Check if this algorithm matches any of the given OIDs  
    fn is_one_of(&self, algorithms: impl IntoIterator<Item = ObjectIdentifier>) -> bool;
}

impl<T> AlgorithmIdentifierExt for AlgorithmIdentifier<T> {
    fn is_a(&self, algorithm: ObjectIdentifier) -> bool {
        algorithm == self.oid
    }

    fn is_one_of(&self, algorithms: impl IntoIterator<Item = ObjectIdentifier>) -> bool {
        algorithms.into_iter().any(|oid| self.is_a(oid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    
    #[test]
    fn helper_functions_roundtrip() {
        let alg_id = sha256_with_rsa_encryption();
        
        let der_bytes = to_der_bytes(&alg_id).expect("Failed to encode AlgorithmIdentifier");
        let decoded = from_der_bytes(&der_bytes).expect("Failed to decode AlgorithmIdentifier");
        
        assert_eq!(alg_id.oid, decoded.oid);
        assert_eq!(alg_id.parameters.is_some(), decoded.parameters.is_some());
    }
    
    #[test] 
    fn helper_functions_with_different_algorithms() {
        let algorithms = vec![
            sha256_with_rsa_encryption(),
            ecdsa_with_sha256(),
            ed25519(),
            rsa_encryption(),
            sha3_256_with_rsa_encryption(),
            sha3_384_with_rsa_encryption(),
            sha3_512_with_rsa_encryption(),
        ];
        
        for alg in algorithms {
            let encoded = to_der_bytes(&alg).expect("Encode should work");
            let decoded = from_der_bytes(&encoded).expect("Decode should work");
            
            assert_eq!(alg.oid, decoded.oid);
            // Parameters handling differs between algorithms
            match alg.oid {
                oids::ECDSA_WITH_SHA256 | oids::ED25519 => {
                    assert!(decoded.parameters.is_none());
                }
                _ => {
                    assert!(decoded.parameters.is_some());
                }
            }
        }
    }
    
    #[test]
    fn algorithm_identifier_ext_trait() {
        let sha256_rsa = sha256_with_rsa_encryption();
        let ecdsa_sha256 = ecdsa_with_sha256();
        
        assert!(sha256_rsa.is_a(oids::SHA256_WITH_RSA_ENCRYPTION));
        assert!(!sha256_rsa.is_a(oids::ECDSA_WITH_SHA256));
        
        assert!(ecdsa_sha256.is_one_of([oids::ECDSA_WITH_SHA256, oids::ECDSA_WITH_SHA384]));
        assert!(!ecdsa_sha256.is_one_of([oids::SHA256_WITH_RSA_ENCRYPTION, oids::RSA_ENCRYPTION]));
    }
}
