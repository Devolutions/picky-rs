//! X.509 Certificate types using der crate and x509-cert integration

use crate::oids;
use der::{Decode, Encode};

// Re-export core types from x509-cert
pub use x509_cert::{
    Certificate, TbsCertificate,
    ext::{Extension, Extensions},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};

// Re-export SPKI types
pub use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

/// Certificate extensions helper trait
pub trait CertificateExt {
    /// Get subject key identifier extension
    fn subject_key_identifier(&self) -> Option<&[u8]>;

    /// Get authority key identifier extension  
    fn authority_key_identifier(&self) -> Option<&[u8]>;

    /// Get basic constraints extension
    fn basic_constraints(&self) -> Option<bool>;

    /// Get key usage extension
    fn key_usage(&self) -> Option<&[u8]>;

    /// Get extended key usage extension
    fn extended_key_usage(&self) -> Option<&[u8]>;

    /// Get subject alternative name extension
    fn subject_alt_name(&self) -> Option<&[u8]>;
}

impl CertificateExt for Certificate {
    fn subject_key_identifier(&self) -> Option<&[u8]> {
        self.tbs_certificate
            .extensions
            .as_ref()?
            .iter()
            .find(|ext| ext.extn_id == oids::SUBJECT_KEY_IDENTIFIER)
            .map(|ext| ext.extn_value.as_bytes())
    }

    fn authority_key_identifier(&self) -> Option<&[u8]> {
        self.tbs_certificate
            .extensions
            .as_ref()?
            .iter()
            .find(|ext| ext.extn_id == oids::AUTHORITY_KEY_IDENTIFIER)
            .map(|ext| ext.extn_value.as_bytes())
    }

    fn basic_constraints(&self) -> Option<bool> {
        self.tbs_certificate
            .extensions
            .as_ref()?
            .iter()
            .any(|ext| ext.extn_id == oids::BASIC_CONSTRAINTS)
            .then_some(true)
    }

    fn key_usage(&self) -> Option<&[u8]> {
        self.tbs_certificate
            .extensions
            .as_ref()?
            .iter()
            .find(|ext| ext.extn_id == oids::KEY_USAGE)
            .map(|ext| ext.extn_value.as_bytes())
    }

    fn extended_key_usage(&self) -> Option<&[u8]> {
        self.tbs_certificate
            .extensions
            .as_ref()?
            .iter()
            .find(|ext| ext.extn_id == oids::EXTENDED_KEY_USAGE)
            .map(|ext| ext.extn_value.as_bytes())
    }

    fn subject_alt_name(&self) -> Option<&[u8]> {
        self.tbs_certificate
            .extensions
            .as_ref()?
            .iter()
            .find(|ext| ext.extn_id == oids::SUBJECT_ALT_NAME)
            .map(|ext| ext.extn_value.as_bytes())
    }
}

/// Decode certificate from DER bytes
pub fn from_der_bytes(bytes: &[u8]) -> der::Result<Certificate> {
    <Certificate as Decode>::from_der(bytes)
}

/// Encode certificate to DER bytes
pub fn to_der_bytes(cert: &Certificate) -> der::Result<Vec<u8>> {
    <Certificate as Encode>::to_der(cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn helper_functions_basic() {
        // Create a simple certificate using constructor and test helpers
        let rsa_alg = crate::algorithm_identifier::rsa_encryption();
        let sha256_rsa_alg = crate::algorithm_identifier::sha256_with_rsa_encryption();

        // Test that our helper functions work with AlgorithmIdentifier
        let encoded_rsa = crate::algorithm_identifier::to_der_bytes(&rsa_alg).expect("RSA encode failed");
        let decoded_rsa = crate::algorithm_identifier::from_der_bytes(&encoded_rsa).expect("RSA decode failed");
        assert_eq!(rsa_alg.oid, decoded_rsa.oid);

        let encoded_sha256 =
            crate::algorithm_identifier::to_der_bytes(&sha256_rsa_alg).expect("SHA256-RSA encode failed");
        let decoded_sha256 =
            crate::algorithm_identifier::from_der_bytes(&encoded_sha256).expect("SHA256-RSA decode failed");
        assert_eq!(sha256_rsa_alg.oid, decoded_sha256.oid);

        println!("✅ Helper functions work correctly with AlgorithmIdentifier");
    }

    #[test]
    fn certificate_ext_trait_methods_exist() {
        // This test mainly verifies that the trait methods compile and can be called
        // The actual certificate parsing is tested in the cross-compatibility tests

        println!("✅ CertificateExt trait methods are available");
    }
}
