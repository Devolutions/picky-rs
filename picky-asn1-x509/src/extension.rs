//! Extension helper methods for x509-cert crate types
//!
//! This module provides convenience methods for creating X.509 certificate extensions
//! using the types from the `x509-cert` crate.

use der::asn1::OctetString;
use x509_cert::ext::pkix::name::GeneralNames;
use x509_cert::ext::{Extension, pkix::*};
use x509_cert::serial_number::SerialNumber;

/// Extension helper trait to provide convenience constructors
pub trait ExtensionExt {
    /// Create a new BasicConstraints extension
    fn new_basic_constraints(ca: bool, pathlen: Option<u8>) -> Extension;

    /// Create a new KeyUsage extension  
    fn new_key_usage(key_usage: KeyUsage) -> Extension;

    /// Create a new ExtendedKeyUsage extension
    fn new_extended_key_usage(extended_key_usage: ExtendedKeyUsage) -> Extension;

    /// Create a new SubjectAltName extension
    fn new_subject_alt_name(san: Vec<x509_cert::ext::pkix::name::GeneralName>) -> Extension;

    /// Create a new IssuerAltName extension
    fn new_issuer_alt_name(ian: Vec<x509_cert::ext::pkix::name::GeneralName>) -> Extension;

    /// Create a new SubjectKeyIdentifier extension
    fn new_subject_key_identifier(ski: OctetString) -> Extension;

    /// Create a new AuthorityKeyIdentifier extension
    fn new_authority_key_identifier(
        key_identifier: Option<OctetString>,
        authority_cert_issuer: Option<GeneralNames>,
        authority_cert_serial_number: Option<SerialNumber>,
    ) -> Extension;

    /// Set the critical flag of the extension
    fn critical(self, critical: bool) -> Extension;
}

impl ExtensionExt for Extension {
    fn new_basic_constraints(ca: bool, pathlen: Option<u8>) -> Extension {
        let basic_constraints = BasicConstraints {
            ca,
            path_len_constraint: pathlen,
        };

        Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS,
            critical: false,
            extn_value: OctetString::new(der::Encode::to_der(&basic_constraints).unwrap()).unwrap(),
        }
    }

    fn new_key_usage(key_usage: KeyUsage) -> Extension {
        Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_KEY_USAGE,
            critical: false,
            extn_value: OctetString::new(der::Encode::to_der(&key_usage).unwrap()).unwrap(),
        }
    }

    fn new_extended_key_usage(extended_key_usage: ExtendedKeyUsage) -> Extension {
        Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE,
            critical: false,
            extn_value: OctetString::new(der::Encode::to_der(&extended_key_usage).unwrap()).unwrap(),
        }
    }

    fn new_subject_alt_name(san: Vec<x509_cert::ext::pkix::name::GeneralName>) -> Extension {
        use x509_cert::ext::pkix::SubjectAltName;
        let san_ext = SubjectAltName(san);
        Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME,
            critical: false,
            extn_value: OctetString::new(der::Encode::to_der(&san_ext).unwrap()).unwrap(),
        }
    }

    fn new_issuer_alt_name(ian: Vec<x509_cert::ext::pkix::name::GeneralName>) -> Extension {
        use x509_cert::ext::pkix::IssuerAltName;
        let ian_ext = IssuerAltName(ian);
        Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_ISSUER_ALT_NAME,
            critical: false,
            extn_value: OctetString::new(der::Encode::to_der(&ian_ext).unwrap()).unwrap(),
        }
    }

    fn new_subject_key_identifier(ski: OctetString) -> Extension {
        Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER,
            critical: false,
            extn_value: OctetString::new(der::Encode::to_der(&ski).unwrap()).unwrap(),
        }
    }

    fn new_authority_key_identifier(
        key_identifier: Option<OctetString>,
        authority_cert_issuer: Option<GeneralNames>,
        authority_cert_serial_number: Option<SerialNumber>,
    ) -> Extension {
        let authority_key_identifier = AuthorityKeyIdentifier {
            key_identifier,
            authority_cert_issuer,
            authority_cert_serial_number,
        };

        Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER,
            critical: false,
            extn_value: OctetString::new(der::Encode::to_der(&authority_key_identifier).unwrap()).unwrap(),
        }
    }

    fn critical(mut self, critical: bool) -> Extension {
        self.critical = critical;
        self
    }
}
