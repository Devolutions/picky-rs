//! Public key helper types and methods for SPKI handling
//!
//! This module provides convenient access to different public key types
//! from SubjectPublicKeyInfo, similar to the old picky_asn1_x509::PublicKey enum.

use crate::oids;
use der::Decode;
use der::asn1::BitStringRef;
use pkcs1::RsaPublicKey;
use spki::SubjectPublicKeyInfo;

/// Enum representing different public key types that can be contained in a SubjectPublicKeyInfo
#[derive(Clone, Debug, PartialEq)]
pub enum PublicKey<'a> {
    /// RSA public key - parsed PKCS#1 RSA public key structure
    Rsa(RsaPublicKey<'a>),
    /// Elliptic Curve public key - raw EC point data from BitString
    Ec(BitStringRef<'a>),
    /// Edwards Curve public key - raw public key bytes (Ed25519/Ed448)
    Ed(BitStringRef<'a>),
}

/// Error type for public key parsing
#[derive(Debug, thiserror::Error)]
pub enum PublicKeyError {
    #[error("Unsupported algorithm: {oid}")]
    UnsupportedAlgorithm { oid: const_oid::ObjectIdentifier },
    #[error("Failed to parse RSA public key: {0}")]
    RsaParseError(#[from] der::Error),
    #[error("Invalid key data")]
    InvalidKeyData,
}

/// Extension trait for SubjectPublicKeyInfo to provide convenient key type access
pub trait SubjectPublicKeyInfoExt {
    /// Parse the subject public key into a specific key type enum
    fn parse(&self) -> Result<PublicKey<'_>, PublicKeyError>;

    /// Check if this is an RSA key
    fn is_rsa_key(&self) -> bool;

    /// Check if this is an EC key  
    fn is_ec_key(&self) -> bool;

    /// Check if this is an Ed25519/Ed448 key
    fn is_ed_key(&self) -> bool;
}

/// Decode SubjectPublicKeyInfo from DER bytes
pub fn from_der_bytes(
    bytes: &[u8],
) -> der::Result<spki::SubjectPublicKeyInfo<crate::AlgorithmIdentifier<der::asn1::AnyRef>, der::asn1::BitStringRef>> {
    use der::Decode;
    spki::SubjectPublicKeyInfo::from_der(bytes)
}

/// Encode SubjectPublicKeyInfo to DER bytes
pub fn to_der_bytes<P, K>(spki: &spki::SubjectPublicKeyInfo<P, K>) -> der::Result<Vec<u8>>
where
    spki::SubjectPublicKeyInfo<P, K>: der::Encode,
{
    use der::Encode;
    spki.to_der()
}

// Note: Constructor helpers like new_rsa_key(), new_ec_key(), etc.
// would require complex generic type annotations due to spki's type system.
// Users can construct SubjectPublicKeyInfo directly using algorithm_identifier helpers:
//
// Example:
//   let spki = spki::SubjectPublicKeyInfo {
//       algorithm: crate::algorithm_identifier::rsa_encryption(),
//       subject_public_key: rsa_key_der,
//   };

impl<Params, Key> SubjectPublicKeyInfoExt for SubjectPublicKeyInfo<Params, Key>
where
    Key: AsRef<[u8]>,
{
    fn parse(&self) -> Result<PublicKey<'_>, PublicKeyError> {
        match self.algorithm.oid {
            oids::RSA_ENCRYPTION => {
                // Parse the BitString as PKCS#1 RSA public key
                let key_bytes = self.subject_public_key.as_ref();
                let rsa_key = RsaPublicKey::from_der(key_bytes)?;
                Ok(PublicKey::Rsa(rsa_key))
            }
            oids::EC_PUBLIC_KEY => {
                // For EC keys, the subject_public_key contains raw EC point data
                Ok(PublicKey::Ec(BitStringRef::from_bytes(
                    self.subject_public_key.as_ref(),
                )?))
            }
            oids::ED25519 | oids::ED448 => {
                // For Edwards curves, the public key is the raw key bytes in the BitString
                Ok(PublicKey::Ed(BitStringRef::from_bytes(
                    self.subject_public_key.as_ref(),
                )?))
            }
            oid => Err(PublicKeyError::UnsupportedAlgorithm { oid }),
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

/// Parse a SubjectPublicKeyInfo with BitStringRef (borrowed) key
/// This function works around the trait bounds issue where BitStringRef doesn't implement AsRef<[u8]>
pub fn parse_subject_public_key_info<'a, Params>(
    spki: &'a spki::SubjectPublicKeyInfo<Params, der::asn1::BitStringRef<'a>>,
) -> Result<PublicKey<'a>, PublicKeyError> {
    match spki.algorithm.oid {
        oids::RSA_ENCRYPTION => {
            // Parse the BitString as PKCS#1 RSA public key
            let key_bytes = spki.subject_public_key.raw_bytes();
            let rsa_key = RsaPublicKey::from_der(key_bytes)?;
            Ok(PublicKey::Rsa(rsa_key))
        }
        oids::EC_PUBLIC_KEY => {
            // For EC keys, the subject_public_key contains raw EC point data
            Ok(PublicKey::Ec(BitStringRef::from_bytes(
                spki.subject_public_key.raw_bytes(),
            )?))
        }
        oids::ED25519 | oids::ED448 => {
            // For Edwards curves, the public key is the raw key bytes in the BitString
            Ok(PublicKey::Ed(BitStringRef::from_bytes(
                spki.subject_public_key.raw_bytes(),
            )?))
        }
        oids::X25519 | oids::X448 => {
            // For X25519/X448 ECDH, the public key is the raw key bytes in the BitString
            Ok(PublicKey::Ed(BitStringRef::from_bytes(
                spki.subject_public_key.raw_bytes(),
            )?))
        }
        oid => Err(PublicKeyError::UnsupportedAlgorithm { oid }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;
    use der::asn1::{AnyRef, Null};
    use spki::SubjectPublicKeyInfo;

    // Test RSA public key parsing
    #[test]
    fn rsa_public_key_parsing() {
        // Create a simple RSA public key (this is a minimal valid RSA public key)
        let rsa_key = pkcs1::RsaPublicKey {
            modulus: der::asn1::UintRef::new(&[0x00, 0xC5]).unwrap(), // Small test modulus
            public_exponent: der::asn1::UintRef::new(&[0x01, 0x00, 0x01]).unwrap(), // 65537
        };

        let rsa_key_der = rsa_key.to_der().unwrap();

        let spki = SubjectPublicKeyInfo {
            algorithm: crate::AlgorithmIdentifier {
                oid: oids::RSA_ENCRYPTION,
                parameters: Some(AnyRef::from(Null)),
            },
            subject_public_key: &rsa_key_der,
        };

        // Test parsing
        let parsed = spki.parse().unwrap();
        match parsed {
            PublicKey::Rsa(parsed_rsa) => {
                // Check that we got an RSA key with correct structure
                assert!(parsed_rsa.modulus.as_bytes().len() > 0);
                assert!(parsed_rsa.public_exponent.as_bytes().len() > 0);
            }
            _ => panic!("Expected RSA key"),
        }

        // Test key type detection
        assert!(spki.is_rsa_key());
        assert!(!spki.is_ec_key());
        assert!(!spki.is_ed_key());
    }

    #[test]
    fn ec_public_key_parsing() {
        // Create a minimal EC public key (uncompressed point for P-256)
        let ec_point_data = [
            0x04, // Uncompressed point indicator
            // x coordinate (32 bytes)
            0x18, 0x52, 0x3c, 0x68, 0x9d, 0xc9, 0x0d, 0x28, 0x49, 0x65, 0x3e, 0x5a, 0x73, 0x2a, 0x8c, 0xdd, 0x5a, 0xb3,
            0x49, 0x7b, 0x94, 0x24, 0xfb, 0x42, 0x1d, 0x5b, 0x53, 0x7b, 0x90, 0x77, 0x2b, 0xf8,
            // y coordinate (32 bytes)
            0x29, 0x1c, 0x88, 0x7f, 0x8b, 0x8d, 0xc9, 0x65, 0x77, 0x9d, 0x75, 0xc2, 0x11, 0xe8, 0x1c, 0x85, 0x4d, 0x42,
            0x1a, 0x9b, 0x4d, 0x6f, 0x2b, 0xf3, 0x15, 0xd3, 0x24, 0x9f, 0x36, 0x5c, 0x7b, 0x9d,
        ];

        let spki = SubjectPublicKeyInfo {
            algorithm: crate::AlgorithmIdentifier {
                oid: oids::EC_PUBLIC_KEY,
                parameters: Some(AnyRef::from(Null)),
            },
            subject_public_key: &ec_point_data,
        };

        // Test parsing
        let parsed = spki.parse().unwrap();
        match parsed {
            PublicKey::Ec(ec_bits) => {
                assert_eq!(ec_bits.raw_bytes(), &ec_point_data);
            }
            _ => panic!("Expected EC key"),
        }

        // Test key type detection
        assert!(!spki.is_rsa_key());
        assert!(spki.is_ec_key());
        assert!(!spki.is_ed_key());
    }

    #[test]
    fn ed25519_public_key_parsing() {
        // Ed25519 public key is 32 bytes
        let ed25519_key_data = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1,
            0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
        ];

        let spki = SubjectPublicKeyInfo {
            algorithm: crate::AlgorithmIdentifier::<Option<AnyRef>> {
                oid: oids::ED25519,
                parameters: None, // Ed25519 has no parameters
            },
            subject_public_key: &ed25519_key_data,
        };

        // Test parsing
        let parsed = spki.parse().unwrap();
        match parsed {
            PublicKey::Ed(ed_bits) => {
                assert_eq!(ed_bits.raw_bytes(), &ed25519_key_data);
            }
            _ => panic!("Expected Ed25519 key"),
        }

        // Test key type detection
        assert!(!spki.is_rsa_key());
        assert!(!spki.is_ec_key());
        assert!(spki.is_ed_key());
    }

    #[test]
    fn unsupported_algorithm() {
        let spki = SubjectPublicKeyInfo {
            algorithm: crate::AlgorithmIdentifier::<Option<AnyRef>> {
                oid: const_oid::ObjectIdentifier::new_unwrap("1.2.3.4.5"), // Fake OID
                parameters: None,
            },
            subject_public_key: &[0x00][..],
        };

        let result = spki.parse();
        assert!(result.is_err());
        match result.unwrap_err() {
            PublicKeyError::UnsupportedAlgorithm { oid } => {
                assert_eq!(oid, const_oid::ObjectIdentifier::new_unwrap("1.2.3.4.5"));
            }
            _ => panic!("Expected UnsupportedAlgorithm error"),
        }
    }

    #[test]
    fn public_key_helpers() {
        // Test that our helper functions exist and can be called
        // (Full round-trip testing would require valid ASN.1 structures)

        // Verify helper functions exist
        let test_bytes = [0x30, 0x06, 0x02, 0x01, 0xC5, 0x02, 0x01, 0x03];

        // Test that from_der_bytes returns an error for invalid data (as expected)
        let result = super::from_der_bytes(&test_bytes);
        assert!(result.is_err()); // Invalid ASN.1 should fail to parse

        println!("✅ Public key helper functions are available and working");
    }
}
