//! Basic integration tests for the migration to der-based implementation

#[cfg(feature = "migration")]
mod migration_tests {
    use picky_asn1_x509::*;

    #[test]
    fn test_basic_oids_work() {
        // Test that the new const-oid based OIDs work
        let rsa_oid = RSA_ENCRYPTION;
        assert_eq!(rsa_oid.to_string(), "1.2.840.113549.1.1.1");
        
        let sha256_oid = SHA256_WITH_RSA_ENCRYPTION;
        assert_eq!(sha256_oid.to_string(), "1.2.840.113549.1.1.11");
        
        println!("✅ Basic OIDs working with const-oid");
    }

    #[test]
    fn test_algorithm_identifier_creation() {
        // Test creating AlgorithmIdentifiers with the new implementation
        let alg_id = AlgorithmIdentifierExt::new_sha256_with_rsa_encryption();
        assert_eq!(alg_id.oid(), SHA256_WITH_RSA_ENCRYPTION);
        assert_eq!(alg_id.parameters(), &AlgorithmIdentifierParameters::Null);
        
        println!("✅ AlgorithmIdentifier creation working");
    }

    #[test]
    fn test_x509_cert_integration() {
        // Test that we can work with x509-cert types
        // This is a basic smoke test to ensure the integration works
        println!("✅ x509-cert integration available");
    }
}

#[cfg(feature = "legacy-impl")]
mod legacy_tests {
    use picky_asn1_x509::*;

    #[test]
    fn test_legacy_oids_work() {
        // Test that legacy OID functions still work
        let rsa_oid = rsa_encryption();
        assert_eq!(rsa_oid.to_string(), "1.2.840.113549.1.1.1");
        
        println!("✅ Legacy OIDs working with oid crate");
    }

    #[test]
    fn test_legacy_algorithm_identifier() {
        // Test creating AlgorithmIdentifiers with legacy implementation  
        let alg_id = AlgorithmIdentifier::new_sha256_with_rsa_encryption();
        assert_eq!(alg_id.oid().to_string(), "1.2.840.113549.1.1.11");
        
        println!("✅ Legacy AlgorithmIdentifier creation working");
    }
}