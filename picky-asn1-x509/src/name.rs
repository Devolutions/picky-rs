//! Name extension methods for x509-cert crate types
//!
//! This module provides convenient extension methods for X.509 names
//! using the types from the `x509-cert` crate, similar to the DirectoryName type
//! but directly on the RustCrypto Name type.

use const_oid::ObjectIdentifier;
use der::asn1::{Ia5String, PrintableString, SetOfVec, TeletexString};
use der::{Decode, Encode};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::pkix::name::DirectoryString;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};

/// Trait for converting types into DirectoryString
pub trait IntoDirectoryString {
    /// Convert into a DirectoryString
    fn into_directory_string(self) -> DirectoryString;
}

impl IntoDirectoryString for String {
    fn into_directory_string(self) -> DirectoryString {
        DirectoryString::Utf8String(self)
    }
}

impl IntoDirectoryString for &str {
    fn into_directory_string(self) -> DirectoryString {
        DirectoryString::Utf8String(self.to_owned())
    }
}

impl IntoDirectoryString for PrintableString {
    fn into_directory_string(self) -> DirectoryString {
        DirectoryString::PrintableString(self)
    }
}

impl IntoDirectoryString for TeletexString {
    fn into_directory_string(self) -> DirectoryString {
        DirectoryString::TeletexString(self)
    }
}

impl IntoDirectoryString for DirectoryString {
    fn into_directory_string(self) -> DirectoryString {
        self
    }
}

/// Extension trait providing convenient methods for Name
pub trait NameExt {
    /// Find the first common name attribute
    fn find_common_name(&self) -> Option<DirectoryString>;

    /// Find the first organization attribute
    fn find_organization(&self) -> Option<DirectoryString>;

    /// Find the first organizational unit attribute
    fn find_organizational_unit(&self) -> Option<DirectoryString>;

    /// Find the first country attribute
    fn find_country(&self) -> Option<DirectoryString>;

    /// Find the first state or province attribute
    fn find_state_or_province(&self) -> Option<DirectoryString>;

    /// Find the first locality attribute
    fn find_locality(&self) -> Option<DirectoryString>;

    /// Find email address attribute (Note: per RFC 5280, email should be in SAN instead)
    fn find_email(&self) -> Option<Ia5String>;

    /// Check if the name contains a specific attribute
    fn has_attribute(&self, oid: ObjectIdentifier) -> bool;

    /// Get all values for a specific attribute OID
    fn get_attribute_values(&self, oid: ObjectIdentifier) -> Vec<DirectoryString>;

    /// Create a new Name with a common name attribute
    fn new_common_name<S: IntoDirectoryString>(name: S) -> Name;

    /// Create a new Name with an organization attribute
    fn new_organization<S: IntoDirectoryString>(name: S) -> Name;

    /// Create a new Name with an organizational unit attribute
    fn new_organizational_unit<S: IntoDirectoryString>(name: S) -> Name;

    /// Create a new Name with a country attribute
    fn new_country<S: IntoDirectoryString>(name: S) -> Name;

    /// Create a new Name with a state or province attribute
    fn new_state_or_province<S: IntoDirectoryString>(name: S) -> Name;

    /// Create a new Name with a locality attribute
    fn new_locality<S: IntoDirectoryString>(name: S) -> Name;

    /// Create a new Name with an email address attribute
    /// Note: per RFC 5280, email should be placed in SAN instead
    fn new_email<S: Into<String>>(email: S) -> Name;

    /// Add a common name attribute to this Name
    fn add_common_name<S: IntoDirectoryString>(&mut self, name: S);

    /// Add an organization attribute to this Name
    fn add_organization<S: IntoDirectoryString>(&mut self, name: S);

    /// Add an organizational unit attribute to this Name
    fn add_organizational_unit<S: IntoDirectoryString>(&mut self, name: S);

    /// Add a country attribute to this Name
    fn add_country<S: IntoDirectoryString>(&mut self, name: S);

    /// Add a state or province attribute to this Name
    fn add_state_or_province<S: IntoDirectoryString>(&mut self, name: S);

    /// Add a locality attribute to this Name
    fn add_locality<S: IntoDirectoryString>(&mut self, name: S);

    /// Add an email address attribute to this Name
    /// Note: per RFC 5280, email should be placed in SAN instead
    fn add_email<S: Into<String>>(&mut self, email: S);
}

impl NameExt for Name {
    fn find_common_name(&self) -> Option<DirectoryString> {
        find_first_attribute_value(self, const_oid::db::rfc4519::CN)
    }

    fn find_organization(&self) -> Option<DirectoryString> {
        find_first_attribute_value(self, const_oid::db::rfc4519::O)
    }

    fn find_organizational_unit(&self) -> Option<DirectoryString> {
        find_first_attribute_value(self, const_oid::db::rfc4519::OU)
    }

    fn find_country(&self) -> Option<DirectoryString> {
        find_first_attribute_value(self, const_oid::db::rfc4519::C)
    }

    fn find_state_or_province(&self) -> Option<DirectoryString> {
        find_first_attribute_value(self, const_oid::db::rfc4519::ST)
    }

    fn find_locality(&self) -> Option<DirectoryString> {
        find_first_attribute_value(self, const_oid::db::rfc4519::L)
    }

    fn find_email(&self) -> Option<Ia5String> {
        // Email address OID from PKCS#9
        const EMAIL_ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");

        for rdn in &self.0 {
            for attr in rdn.0.as_ref() {
                if attr.oid == EMAIL_ADDRESS {
                    // Decode the complete DER bytes (tag + value) as an Ia5String
                    if let Ok(full_der_bytes) = attr.value.to_der() {
                        if let Ok(ia5_string) = Ia5String::from_der(&full_der_bytes) {
                            return Some(ia5_string);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_attribute(&self, oid: ObjectIdentifier) -> bool {
        for rdn in &self.0 {
            for attr in rdn.0.as_ref() {
                if attr.oid == oid {
                    return true;
                }
            }
        }
        false
    }

    fn get_attribute_values(&self, oid: ObjectIdentifier) -> Vec<DirectoryString> {
        let mut values = Vec::new();
        for rdn in &self.0 {
            for attr in rdn.0.as_ref() {
                if attr.oid == oid {
                    if let Ok(directory_string) = DirectoryString::from_der(attr.value.value()) {
                        values.push(directory_string);
                    }
                }
            }
        }
        values
    }

    fn new_common_name<S: IntoDirectoryString>(name: S) -> Name {
        create_single_attribute_name(const_oid::db::rfc4519::CN, name.into_directory_string())
    }

    fn new_organization<S: IntoDirectoryString>(name: S) -> Name {
        create_single_attribute_name(const_oid::db::rfc4519::O, name.into_directory_string())
    }

    fn new_organizational_unit<S: IntoDirectoryString>(name: S) -> Name {
        create_single_attribute_name(const_oid::db::rfc4519::OU, name.into_directory_string())
    }

    fn new_country<S: IntoDirectoryString>(name: S) -> Name {
        create_single_attribute_name(const_oid::db::rfc4519::C, name.into_directory_string())
    }

    fn new_state_or_province<S: IntoDirectoryString>(name: S) -> Name {
        create_single_attribute_name(const_oid::db::rfc4519::ST, name.into_directory_string())
    }

    fn new_locality<S: IntoDirectoryString>(name: S) -> Name {
        create_single_attribute_name(const_oid::db::rfc4519::L, name.into_directory_string())
    }

    fn new_email<S: Into<String>>(email: S) -> Name {
        create_single_email_attribute_name(email.into())
    }

    fn add_common_name<S: IntoDirectoryString>(&mut self, name: S) {
        add_attribute_to_name(self, const_oid::db::rfc4519::CN, name.into_directory_string());
    }

    fn add_organization<S: IntoDirectoryString>(&mut self, name: S) {
        add_attribute_to_name(self, const_oid::db::rfc4519::O, name.into_directory_string());
    }

    fn add_organizational_unit<S: IntoDirectoryString>(&mut self, name: S) {
        add_attribute_to_name(self, const_oid::db::rfc4519::OU, name.into_directory_string());
    }

    fn add_country<S: IntoDirectoryString>(&mut self, name: S) {
        add_attribute_to_name(self, const_oid::db::rfc4519::C, name.into_directory_string());
    }

    fn add_state_or_province<S: IntoDirectoryString>(&mut self, name: S) {
        add_attribute_to_name(self, const_oid::db::rfc4519::ST, name.into_directory_string());
    }

    fn add_locality<S: IntoDirectoryString>(&mut self, name: S) {
        add_attribute_to_name(self, const_oid::db::rfc4519::L, name.into_directory_string());
    }

    fn add_email<S: Into<String>>(&mut self, email: S) {
        add_email_attribute_to_name(self, email.into());
    }
}

/// Helper function to find the first attribute value for a given OID
fn find_first_attribute_value(name: &Name, oid: ObjectIdentifier) -> Option<DirectoryString> {
    for rdn in &name.0 {
        for attr in rdn.0.as_ref() {
            if attr.oid == oid {
                // Decode the complete DER bytes (tag + value) as a DirectoryString
                if let Ok(full_der_bytes) = attr.value.to_der() {
                    if let Ok(directory_string) = DirectoryString::from_der(&full_der_bytes) {
                        return Some(directory_string);
                    }
                }
            }
        }
    }
    None
}

/// Helper function to create a Name with a single attribute
fn create_single_attribute_name(oid: ObjectIdentifier, value: DirectoryString) -> Name {
    let attribute = AttributeTypeAndValue {
        oid,
        value: der::Any::encode_from(&value).unwrap(),
    };

    let rdn = RelativeDistinguishedName(SetOfVec::try_from(vec![attribute]).unwrap());

    RdnSequence(vec![rdn])
}

/// Helper function to add a new attribute to an existing Name
fn add_attribute_to_name(name: &mut Name, oid: ObjectIdentifier, value: DirectoryString) {
    let attribute = AttributeTypeAndValue {
        oid,
        value: der::Any::encode_from(&value).unwrap(),
    };

    let rdn = RelativeDistinguishedName(SetOfVec::try_from(vec![attribute]).unwrap());

    // Add the new RDN to the existing Name
    name.0.push(rdn);
}

/// Helper function to create a Name with a single email attribute
fn create_single_email_attribute_name(email: String) -> Name {
    // Email address OID from PKCS#9
    const EMAIL_ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");

    let ia5_string = Ia5String::new(&email).unwrap();
    let attribute = AttributeTypeAndValue {
        oid: EMAIL_ADDRESS,
        value: der::Any::encode_from(&ia5_string).unwrap(),
    };

    let rdn = RelativeDistinguishedName(SetOfVec::try_from(vec![attribute]).unwrap());

    RdnSequence(vec![rdn])
}

/// Helper function to add an email attribute to an existing Name
fn add_email_attribute_to_name(name: &mut Name, email: String) {
    // Email address OID from PKCS#9
    const EMAIL_ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");

    let ia5_string = Ia5String::new(&email).unwrap();
    let attribute = AttributeTypeAndValue {
        oid: EMAIL_ADDRESS,
        value: der::Any::encode_from(&ia5_string).unwrap(),
    };

    let rdn = RelativeDistinguishedName(SetOfVec::try_from(vec![attribute]).unwrap());

    // Add the new RDN to the existing Name
    name.0.push(rdn);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_extension_methods() {
        let name = Name::new_common_name("CommonName");
        assert!(matches!(
            name.find_common_name(),
            Some(DirectoryString::Utf8String(ref s)) if s == "CommonName"
        ));
        assert!(name.has_attribute(const_oid::db::rfc4519::CN));
    }

    #[test]
    fn constructor_functions() {
        let mut name = Name::new_common_name("Test CN");
        name.add_organization("Test Org");
        name.add_country("US");

        assert!(matches!(
            name.find_common_name(),
            Some(DirectoryString::Utf8String(ref s)) if s == "Test CN"
        ));
        assert!(matches!(
            name.find_organization(),
            Some(DirectoryString::Utf8String(ref s)) if s == "Test Org"
        ));
        assert!(matches!(
            name.find_country(),
            Some(DirectoryString::Utf8String(ref s)) if s == "US"
        ));
    }

    #[test]
    fn add_methods_ergonomics() {
        // Test building up a complex Name using add_* methods.
        let mut name = Name::new_common_name("John Doe");
        name.add_organization("Example Corp");
        name.add_organizational_unit("Engineering");
        name.add_country("US");
        name.add_state_or_province("California");
        name.add_locality("San Francisco");

        // Verify all attributes were added correctly.
        assert!(matches!(
            name.find_common_name(),
            Some(DirectoryString::Utf8String(ref s)) if s == "John Doe"
        ));
        assert!(matches!(
            name.find_organization(),
            Some(DirectoryString::Utf8String(ref s)) if s == "Example Corp"
        ));
        assert!(matches!(
            name.find_organizational_unit(),
            Some(DirectoryString::Utf8String(ref s)) if s == "Engineering"
        ));
        assert!(matches!(
            name.find_country(),
            Some(DirectoryString::Utf8String(ref s)) if s == "US"
        ));
        assert!(matches!(
            name.find_state_or_province(),
            Some(DirectoryString::Utf8String(ref s)) if s == "California"
        ));
        assert!(matches!(
            name.find_locality(),
            Some(DirectoryString::Utf8String(ref s)) if s == "San Francisco"
        ));

        // Verify that all attributes are present.
        assert!(name.has_attribute(const_oid::db::rfc4519::CN));
        assert!(name.has_attribute(const_oid::db::rfc4519::O));
        assert!(name.has_attribute(const_oid::db::rfc4519::OU));
        assert!(name.has_attribute(const_oid::db::rfc4519::C));
        assert!(name.has_attribute(const_oid::db::rfc4519::ST));
        assert!(name.has_attribute(const_oid::db::rfc4519::L));
    }

    #[test]
    fn email_methods() {
        let name = Name::new_email("test@example.com");
        assert_eq!(
            name.find_email().map(|email| email.to_string()),
            Some("test@example.com".to_string())
        );
    }
}
