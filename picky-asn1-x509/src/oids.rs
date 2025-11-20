//! OIDs commonly used with X.509 certificates
//!
//! This replaces the old oid-based implementation with const-oid.

use const_oid::ObjectIdentifier;

// x9-57
pub const DSA_WITH_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10040.4.3");

// x9-42
pub const DIFFIE_HELLMAN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10046.2.1");

// ANSI-X962
pub const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
pub const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
pub const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
pub const ECDSA_WITH_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
pub const SECP192R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.1");
pub const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

// RSADSI
pub const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
pub const MD5_WITH_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.4");
pub const SHA1_WITH_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
pub const SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
pub const SHA384_WITH_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
pub const SHA512_WITH_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
pub const SHA224_WITH_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.14");
pub const RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
pub const EMAIL_ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1"); // deprecated
pub const EXTENSION_REQ: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");


// NIST
pub const DSA_WITH_SHA224: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.1");
pub const DSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.2");
pub const DSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.3");
pub const DSA_WITH_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.4");
pub const ID_ECDSA_WITH_SHA3_224: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.9");
pub const ID_ECDSA_WITH_SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.10");
pub const ID_ECDSA_WITH_SHA3_384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.11");
pub const ID_ECDSA_WITH_SHA3_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.12");
pub const ID_RSASSA_PKCS1_V1_5_WITH_SHA3_224: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.13");
pub const ID_RSASSA_PKCS1_V1_5_WITH_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.14");
pub const ID_RSASSA_PKCS1_V1_5_WITH_SHA3_384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.15");
pub const ID_RSASSA_PKCS1_V1_5_WITH_SHA3_512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.16");

// Certicom Object Identifiers
pub const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
pub const SECT163K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.1");
pub const SECT163R2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.15");
pub const SECP224R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.33");
pub const SECT233K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.26");
pub const SECT233R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.27");
pub const SECT283K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.16");
pub const SECT283R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.17");
pub const SECT409K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.36");
pub const SECT409R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.37");
pub const SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
pub const SECT571K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.38");
pub const SECT571R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.39");

// RFC 8410 - EdDSA
pub const X25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");
pub const X448: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.111");
pub const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
pub const ED448: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.113");

// Hash functions
pub const SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
pub const SHA224: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.4");
pub const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
pub const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
pub const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
pub const SHA3_224: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.7");
pub const SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8");
pub const SHA3_384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.9");
pub const SHA3_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.10");

// X.509 certificate extensions
pub const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
pub const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
pub const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
pub const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
pub const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
pub const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

// Distinguished name attributes
pub const COUNTRY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
pub const ORGANIZATION_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
pub const ORGANIZATIONAL_UNIT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
pub const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
pub const LOCALITY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.7");
pub const STATE_OR_PROVINCE_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.8");
pub const TITLE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.12");
pub const GIVEN_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.42");
pub const SURNAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.4");
