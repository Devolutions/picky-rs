//! ASN.1 types for X.509 certificates and related standards
//!
//! This crate provides ASN.1 types defined by X.509 related RFCs, now using the `der` crate
//! for proper ASN.1 DER encoding instead of the old serde-based approach.
//!
//! # Key Changes from Legacy Implementation
//!
//! - Uses `der` crate for proper ASN.1 DER encoding/decoding
//! - Uses `const-oid` for compile-time OID constants
//! - Integrates with RustCrypto ecosystem (`x509-cert`, `spki`, `pkcs1`, etc.)
//! - Eliminates serde impedance mismatch issues
//! - Provides correct ASN.1 encoding for interoperability

pub mod algorithm_identifier;
pub mod certificate;
pub mod extension;
pub mod name;
pub mod oids;
pub mod private_key;
pub mod public_key;
pub mod signature;

// Re-export der::DateTime for compatibility
pub use der::DateTime;

// Re-exports for convenience
pub use algorithm_identifier::{AlgorithmIdentifier, AlgorithmIdentifierExt};
pub use certificate::{Certificate, CertificateExt, TbsCertificate};
pub use extension::ExtensionExt;
pub use name::{NameExt, IntoDirectoryString};
pub use private_key::{PrivateKey, PrivateKeyError, PrivateKeyInfoExt};
pub use public_key::{parse_subject_public_key_info, PublicKey, PublicKeyError, SubjectPublicKeyInfoExt};
pub use signature::EcdsaSignatureValue;
pub use const_oid::ObjectIdentifier;

// Re-exports from x509-cert for compatibility  
pub use x509_cert::ext::pkix::name::DirectoryString;
pub use x509_cert::ext::{Extension, Extensions};

// Type aliases for legacy compatibility
pub use der::asn1::{Ia5String as Ia5StringAsn1, UintRef as IntegerAsn1};
pub use x509_cert::Version;

// Legacy type placeholders - these would need proper implementation
// For now, we'll create basic type aliases to get compilation working
pub type ShaVariant = &'static str; // Placeholder - needs proper implementation
pub type AttributeValues = x509_cert::attr::Attributes; // Using RustCrypto equivalent

// Re-export core dependencies
pub use der;
