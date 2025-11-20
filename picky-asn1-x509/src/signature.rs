//! Signature-related ASN.1 types and utilities
//!
//! This module provides types for handling signature values and signature algorithms,
//! particularly ECDSA signature values that are commonly used in X.509 certificates.

use der::asn1::UintRef;
use der::Sequence;

/// ECDSA signature value as defined in RFC 3279
/// 
/// ```text
/// Ecdsa-Sig-Value ::= SEQUENCE {
///     r     INTEGER,
///     s     INTEGER
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EcdsaSignatureValue<'a> {
    /// The r value of the ECDSA signature
    pub r: UintRef<'a>,
    /// The s value of the ECDSA signature  
    pub s: UintRef<'a>,
}

impl<'a> EcdsaSignatureValue<'a> {
    /// Create a new ECDSA signature value from r and s components
    pub fn new(r: &'a [u8], s: &'a [u8]) -> Result<Self, der::Error> {
        Ok(Self {
            r: UintRef::new(r)?,
            s: UintRef::new(s)?,
        })
    }
    
    /// Get the r component as bytes
    pub fn r_bytes(&self) -> &[u8] {
        self.r.as_bytes()
    }
    
    /// Get the s component as bytes
    pub fn s_bytes(&self) -> &[u8] {
        self.s.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Decode, Encode};

    #[test]
    fn test_ecdsa_signature_value_roundtrip() {
        // Create test r and s values
        let r_bytes = &[0x01, 0x23, 0x45, 0x67];
        let s_bytes = &[0x89, 0xab, 0xcd, 0xef];
        
        let sig_value = EcdsaSignatureValue::new(r_bytes, s_bytes).unwrap();
        
        // Test encoding
        let encoded = sig_value.to_der().unwrap();
        
        // Test decoding
        let decoded = EcdsaSignatureValue::from_der(&encoded).unwrap();
        
        assert_eq!(decoded.r_bytes(), r_bytes);
        assert_eq!(decoded.s_bytes(), s_bytes);
    }
}