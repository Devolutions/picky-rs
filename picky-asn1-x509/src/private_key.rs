//! Private key helper types and methods for PKCS#8 handling
//!
//! This module provides convenient access to different private key types
//! from PrivateKeyInfo, similar to the PublicKey helper.

use crate::oids;
use der::Decode;
use der::asn1::OctetStringRef;
use pkcs1::RsaPrivateKey;
use pkcs8::PrivateKeyInfo;
use sec1::EcPrivateKey;

/// Enum representing different private key types that can be contained in a PrivateKeyInfo
#[derive(Clone, Debug)]
pub enum PrivateKey<'a> {
    /// RSA private key - parsed PKCS#1 RSA private key structure
    Rsa(RsaPrivateKey<'a>),
    /// Elliptic Curve private key - parsed SEC1 EC private key structure
    Ec(EcPrivateKey<'a>),
    /// Edwards Curve private key - raw private key bytes (Ed25519/Ed448)
    Ed(OctetStringRef<'a>),
}

/// Error type for private key parsing
#[derive(Debug, thiserror::Error)]
pub enum PrivateKeyError {
    #[error("Unsupported algorithm: {oid}")]
    UnsupportedAlgorithm { oid: const_oid::ObjectIdentifier },
    #[error("Failed to parse private key: {0}")]
    ParseError(#[from] der::Error),
    #[error("Invalid key data")]
    InvalidKeyData,
}

/// Extension trait for PrivateKeyInfo to provide convenient key type access
pub trait PrivateKeyInfoExt {
    /// Parse the private key into a specific key type enum
    fn parse(&self) -> Result<PrivateKey<'_>, PrivateKeyError>;

    /// Check if this is an RSA key
    fn is_rsa_key(&self) -> bool;

    /// Check if this is an EC key  
    fn is_ec_key(&self) -> bool;

    /// Check if this is an Ed25519/Ed448 key
    fn is_ed_key(&self) -> bool;
}

/// Decode PrivateKeyInfo from DER bytes
pub fn from_der_bytes(bytes: &[u8]) -> der::Result<pkcs8::PrivateKeyInfo<'_>> {
    use der::Decode;
    pkcs8::PrivateKeyInfo::from_der(bytes)
}

/// Encode PrivateKeyInfo to DER bytes
pub fn to_der_bytes(pki: &pkcs8::PrivateKeyInfo<'_>) -> der::Result<Vec<u8>> {
    use der::Encode;
    pki.to_der()
}

// Note: Constructor helpers like new_rsa_key(), new_ec_key(), etc. can be created
// but are simple enough that users can construct PrivateKeyInfo directly:
//
// Example:
//   let pki = pkcs8::PrivateKeyInfo {
//       algorithm: crate::algorithm_identifier::rsa_encryption(),
//       private_key: rsa_key_der,
//       public_key: None,
//   };

impl PrivateKeyInfoExt for PrivateKeyInfo<'_> {
    fn parse(&self) -> Result<PrivateKey<'_>, PrivateKeyError> {
        match self.algorithm.oid {
            oids::RSA_ENCRYPTION => {
                // Parse the private key bytes as PKCS#1 RSA private key
                let key_bytes = self.private_key;
                let rsa_key = RsaPrivateKey::from_der(key_bytes)?;
                Ok(PrivateKey::Rsa(rsa_key))
            }
            oids::EC_PUBLIC_KEY => {
                // Parse the private key bytes as SEC1 EC private key
                let key_bytes = self.private_key;
                let ec_key = EcPrivateKey::from_der(key_bytes)?;
                Ok(PrivateKey::Ec(ec_key))
            }
            oids::ED25519 | oids::ED448 => {
                // For Edwards curves, the private key is raw bytes
                Ok(PrivateKey::Ed(OctetStringRef::new(self.private_key)?))
            }
            oid => Err(PrivateKeyError::UnsupportedAlgorithm { oid }),
        }
    }

    fn is_rsa_key(&self) -> bool {
        self.algorithm.oid == oids::RSA_ENCRYPTION
    }

    fn is_ec_key(&self) -> bool {
        self.algorithm.oid == oids::EC_PUBLIC_KEY
    }

    fn is_ed_key(&self) -> bool {
        matches!(self.algorithm.oid, oids::ED25519 | oids::ED448)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;
    use der::asn1::{AnyRef, Null, OctetString};
    use pkcs8::PrivateKeyInfo;

    #[test]
    fn rsa_private_key_parsing() {
        // Create a minimal RSA private key (PKCS#1)
        let rsa_key = pkcs1::RsaPrivateKey {
            modulus: der::asn1::UintRef::new(&[0x00, 0xC5]).unwrap(),
            public_exponent: der::asn1::UintRef::new(&[0x01, 0x00, 0x01]).unwrap(),
            private_exponent: der::asn1::UintRef::new(&[0x42]).unwrap(),
            prime1: der::asn1::UintRef::new(&[0x0B]).unwrap(),
            prime2: der::asn1::UintRef::new(&[0x11]).unwrap(),
            exponent1: der::asn1::UintRef::new(&[0x05]).unwrap(),
            exponent2: der::asn1::UintRef::new(&[0x07]).unwrap(),
            coefficient: der::asn1::UintRef::new(&[0x03]).unwrap(),
            other_prime_infos: None,
        };

        let rsa_key_der = rsa_key.to_der().unwrap();

        let pki = PrivateKeyInfo {
            algorithm: crate::AlgorithmIdentifier {
                oid: oids::RSA_ENCRYPTION,
                parameters: Some(AnyRef::from(Null)),
            },
            private_key: &rsa_key_der,
            public_key: None,
        };

        // Test parsing
        let parsed = pki.parse().unwrap();
        match parsed {
            PrivateKey::Rsa(parsed_rsa) => {
                // Check that we got an RSA key with correct structure
                assert!(parsed_rsa.modulus.as_bytes().len() > 0);
                assert!(parsed_rsa.public_exponent.as_bytes().len() > 0);
                assert!(parsed_rsa.private_exponent.as_bytes().len() > 0);
            }
            _ => panic!("Expected RSA key"),
        }

        // Test key type detection
        assert!(pki.is_rsa_key());
        assert!(!pki.is_ec_key());
        assert!(!pki.is_ed_key());
    }

    #[test]
    fn ec_private_key_parsing() {
        // Create a minimal EC private key (SEC1)
        let ec_key = sec1::EcPrivateKey {
            private_key: &[
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xaa,
                0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            ],
            parameters: None,
            public_key: None,
        };

        let ec_key_der = ec_key.to_der().unwrap();

        let pki = PrivateKeyInfo {
            algorithm: crate::AlgorithmIdentifier {
                oid: oids::EC_PUBLIC_KEY,
                parameters: Some(AnyRef::from(Null)),
            },
            private_key: &ec_key_der,
            public_key: None,
        };

        // Test parsing
        let parsed = pki.parse().unwrap();
        match parsed {
            PrivateKey::Ec(parsed_ec) => {
                assert_eq!(
                    parsed_ec.private_key,
                    &[
                        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                    ]
                );
            }
            _ => panic!("Expected EC key"),
        }

        // Test key type detection
        assert!(!pki.is_rsa_key());
        assert!(pki.is_ec_key());
        assert!(!pki.is_ed_key());
    }

    #[test]
    fn ed25519_private_key_parsing() {
        // Ed25519 private key is 32 bytes
        let ed25519_key_data = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49,
            0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
        ];

        let private_key_octet = OctetString::new(&ed25519_key_data).unwrap();
        let ed25519_pkcs8_der = private_key_octet.to_der().unwrap();

        let pki = PrivateKeyInfo {
            algorithm: crate::AlgorithmIdentifier {
                oid: oids::ED25519,
                parameters: None, // Ed25519 has no parameters
            },
            private_key: &ed25519_pkcs8_der,
            public_key: None,
        };

        // Test parsing
        let parsed = pki.parse().unwrap();
        match parsed {
            PrivateKey::Ed(ed_bytes) => {
                // For Ed25519, the private key is wrapped in an OCTET STRING
                assert_eq!(ed_bytes.as_bytes(), &ed25519_pkcs8_der);
            }
            _ => panic!("Expected Ed25519 key"),
        }

        // Test key type detection
        assert!(!pki.is_rsa_key());
        assert!(!pki.is_ec_key());
        assert!(pki.is_ed_key());
    }

    #[test]
    fn unsupported_algorithm() {
        let pki = PrivateKeyInfo {
            algorithm: crate::AlgorithmIdentifier {
                oid: const_oid::ObjectIdentifier::new_unwrap("1.2.3.4.5"), // Fake OID
                parameters: None,
            },
            private_key: &[0x00],
            public_key: None,
        };

        let result = pki.parse();
        assert!(result.is_err());
        match result.unwrap_err() {
            PrivateKeyError::UnsupportedAlgorithm { oid } => {
                assert_eq!(oid, const_oid::ObjectIdentifier::new_unwrap("1.2.3.4.5"));
            }
            _ => panic!("Expected UnsupportedAlgorithm error"),
        }
    }
}
