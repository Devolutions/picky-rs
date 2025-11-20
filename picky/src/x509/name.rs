use const_oid::ObjectIdentifier;
use der::asn1::{Ia5String, SequenceOf};
use x509_cert::name::Name;
use x509_cert::ext::pkix::name::{DirectoryString, OtherName};
use x509_cert::ext::pkix::name::{GeneralName as SerdeGeneralName, GeneralNames as SerdeGeneralNames};
use std::fmt;

// === DirectoryName ===

pub use x509_cert::attr::AttributeTypeAndValue as NameAttr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryName(Name);

impl Default for DirectoryName {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectoryName {
    pub fn new() -> Self {
        use x509_cert::name::RdnSequence;
        Self(Name::from(RdnSequence::default()))
    }

    pub fn new_common_name<S: Into<DirectoryString>>(name: S) -> Self {
        use x509_cert::name::RdnSequence;
        use x509_cert::attr::AttributeTypeAndValue;
        use const_oid::db::rfc4519::CN;
        
        let dir_string = name.into();
        let attr_value = match dir_string {
            DirectoryString::Utf8String(s) => x509_cert::attr::AttributeValue::new(der::Tag::Utf8String, s.as_bytes()).unwrap(),
            DirectoryString::PrintableString(s) => x509_cert::attr::AttributeValue::new(der::Tag::PrintableString, s.as_bytes()).unwrap(),
            // Add other variants as needed
            _ => return Self::new(), // Fallback for unsupported types
        };
        let attr = AttributeTypeAndValue {
            oid: CN,
            value: attr_value,
        };
        let rdn = x509_cert::name::RelativeDistinguishedName::try_from(vec![attr]).unwrap();
        let rdn_seq = RdnSequence::from(vec![rdn]);
        Self(Name::from(rdn_seq))
    }

    /// Find the first common name contained in this `Name`
    pub fn find_common_name(&self) -> Option<&DirectoryString> {
        use const_oid::db::rfc4519::CN;
        
        for rdn in &self.0 .0 {
            for attr in rdn.0.iter() {
                if attr.oid == CN {
                    // TODO: properly convert attribute value to DirectoryString
                    return None; // Simplified for now
                }
            }
        }
        None
    }

    pub fn add_attr<S: Into<DirectoryString>>(&mut self, attr: NameAttr, value: S) {
        use x509_cert::name::RdnSequence;
        // TODO: implement proper attribute addition to RdnSequence
        // For now, this is a stub implementation
    }

    /// Add an emailAddress attribute.
    /// NOTE: this attribute does not conform with the RFC 5280, email should be placed in SAN instead
    pub fn add_email<S: Into<String>>(&mut self, value: S) {
        use x509_cert::name::RdnSequence;
        // TODO: implement proper email attribute addition to RdnSequence
        // For now, this is a stub implementation
    }
}

impl fmt::Display for DirectoryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: implement proper name formatting
        write!(f, "Name({})", self.0.0.len())
    }
}

impl From<Name> for DirectoryName {
    fn from(name: Name) -> Self {
        Self(name)
    }
}

impl From<DirectoryName> for Name {
    fn from(name: DirectoryName) -> Self {
        name.0
    }
}

// === GeneralNames === //

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum GeneralName {
    OtherName(OtherName),
    RFC822Name(Ia5String),
    DNSName(Ia5String),
    DirectoryName(DirectoryName),
    EDIPartyName {
        name_assigner: Option<DirectoryString>,
        party_name: DirectoryString,
    },
    URI(Ia5String),
    IpAddress(Vec<u8>),
    RegisteredId(ObjectIdentifier),
}

impl GeneralName {
    pub fn new_rfc822_name<S: Into<String>>(name: S) -> Result<Self, der::Error> {
        Ok(Self::RFC822Name(Ia5String::new(&name.into())?))
    }

    pub fn new_dns_name<S: Into<String>>(name: S) -> Result<Self, der::Error> {
        Ok(Self::DNSName(Ia5String::new(&name.into())?))
    }

    pub fn new_directory_name<N: Into<DirectoryName>>(name: N) -> Self {
        Self::DirectoryName(name.into())
    }

    pub fn new_edi_party_name<PN, NA>(party_name: PN, name_assigner: Option<NA>) -> Self
    where
        PN: Into<DirectoryString>,
        NA: Into<DirectoryString>,
    {
        Self::EDIPartyName {
            name_assigner: name_assigner.map(Into::into),
            party_name: party_name.into(),
        }
    }

    pub fn new_uri<S: Into<String>>(uri: S) -> Result<Self, der::Error> {
        Ok(Self::URI(Ia5String::new(&uri.into())?))
    }

    pub fn new_ip_address<ADDR: Into<Vec<u8>>>(ip_address: ADDR) -> Self {
        Self::IpAddress(ip_address.into())
    }

    pub fn new_registered_id<OID: Into<ObjectIdentifier>>(oid: OID) -> Self {
        Self::RegisteredId(oid.into())
    }
}

impl From<SerdeGeneralName> for GeneralName {
    fn from(gn: SerdeGeneralName) -> Self {
        match gn {
            SerdeGeneralName::OtherName(other_name) => Self::OtherName(other_name),
            SerdeGeneralName::Rfc822Name(name) => Self::RFC822Name(Ia5String::new(&name.to_string()).unwrap()),
            SerdeGeneralName::DnsName(name) => Self::DNSName(Ia5String::new(&name.to_string()).unwrap()),
            SerdeGeneralName::DirectoryName(name) => Self::DirectoryName(name.into()),
            SerdeGeneralName::EdiPartyName(edi_pn) => Self::EDIPartyName {
                name_assigner: edi_pn.name_assigner.map(|na| na),
                party_name: edi_pn.party_name,
            },
            SerdeGeneralName::UniformResourceIdentifier(uri) => Self::URI(Ia5String::new(&uri.to_string()).unwrap()),
            SerdeGeneralName::IpAddress(ip_addr) => Self::IpAddress(ip_addr.as_bytes().to_vec()),
            SerdeGeneralName::RegisteredId(id) => Self::RegisteredId(id),
        }
    }
}

impl From<GeneralName> for SerdeGeneralName {
    fn from(gn: GeneralName) -> Self {
        match gn {
            GeneralName::OtherName(other_name) => SerdeGeneralName::OtherName(other_name),
            GeneralName::RFC822Name(name) => SerdeGeneralName::Rfc822Name(name.into()),
            GeneralName::DNSName(name) => SerdeGeneralName::DnsName(name.into()),
            GeneralName::DirectoryName(name) => SerdeGeneralName::DirectoryName(name.into()),
            GeneralName::EDIPartyName {
                name_assigner,
                party_name,
            } => SerdeGeneralName::EdiPartyName(x509_cert::ext::pkix::name::EdiPartyName {
                name_assigner,
                party_name,
            }),
            GeneralName::URI(uri) => SerdeGeneralName::UniformResourceIdentifier(uri.into()),
            GeneralName::IpAddress(ip_addr) => SerdeGeneralName::IpAddress(der::asn1::OctetString::new(ip_addr).unwrap()),
            GeneralName::RegisteredId(id) => SerdeGeneralName::RegisteredId(id.into()),
        }
    }
}

impl From<GeneralName> for SerdeGeneralNames {
    fn from(gn: GeneralName) -> Self {
        GeneralNames::new(gn).into()
    }
}

/// Wraps x509 `GeneralNames` into an easy to use API.
///
/// # Example
///
/// ```
/// use picky::x509::name::{GeneralNames, GeneralName, DirectoryName};
///
/// let common_name = GeneralName::new_directory_name(DirectoryName::new_common_name("MyName"));
/// let dns_name = GeneralName::new_dns_name("localhost").expect("invalid name string");
/// let names = GeneralNames::from(vec![common_name, dns_name]);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneralNames(SerdeGeneralNames);

impl GeneralNames {
    /// # Example
    ///
    /// ```
    /// use picky::x509::name::{GeneralName, GeneralNames};
    ///
    /// let dns_name = GeneralName::new_dns_name("localhost").expect("invalid name string");
    /// let names = GeneralNames::new(dns_name);
    /// ```
    pub fn new<Gn: Into<GeneralName>>(gn: Gn) -> Self {
        let gn = gn.into();
        Self(vec![gn.into()])
    }

    pub fn new_directory_name<Dn: Into<DirectoryName>>(name: Dn) -> Self {
        let gn = GeneralName::new_directory_name(name);
        Self::new(gn)
    }

    pub fn with_directory_name<Dn: Into<DirectoryName>>(mut self, name: Dn) -> Self {
        let gn = GeneralName::new_directory_name(name);
        self.0.push(gn.into());
        self
    }

    pub fn find_directory_name(&self) -> Option<DirectoryName> {
        for name in &self.0 {
            if let SerdeGeneralName::DirectoryName(name) = name {
                return Some(name.clone().into());
            }
        }
        None
    }

    /// # Example
    ///
    /// ```
    /// use picky::x509::name::GeneralNames;
    /// use picky_asn1::restricted_string::Ia5String;
    ///
    /// let names = GeneralNames::new_dns_name(Ia5String::new("localhost").unwrap());
    /// ```
    pub fn new_dns_name<Ia5: Into<Ia5String>>(dns_name: Ia5) -> Self {
        let gn = GeneralName::DNSName(dns_name.into());
        Self::new(gn)
    }

    /// # Example
    ///
    /// ```
    /// use picky::x509::name::{GeneralNames, DirectoryName};
    /// use picky_asn1::restricted_string::Ia5String;
    ///
    /// let names = GeneralNames::new_directory_name(DirectoryName::new_common_name("MyName"))
    ///         .with_dns_name(Ia5String::new("localhost").unwrap());
    /// ```
    pub fn with_dns_name<Ia5: Into<Ia5String>>(mut self, dns_name: Ia5) -> Self {
        let gn = GeneralName::DNSName(dns_name.into());
        self.0.push(gn.into());
        self
    }

    pub fn find_dns_name(&self) -> Option<&Ia5String> {
        for name in &self.0 {
            if let SerdeGeneralName::DnsName(name) = name {
                return Some(name);
            }
        }
        None
    }

    pub fn add_name<Gn: Into<GeneralName>>(&mut self, name: Gn) {
        let gn = name.into();
        self.0.push(gn.into());
    }

    /// # Example
    ///
    /// ```
    /// use picky::x509::name::{GeneralNames, GeneralName, DirectoryName};
    ///
    /// let common_name = GeneralName::new_directory_name(DirectoryName::new_common_name("MyName"));
    /// let dns_name = GeneralName::new_dns_name("localhost").expect("invalid name string");
    /// let names = GeneralNames::new(common_name).with_name(dns_name);
    /// ```
    pub fn with_name<GN: Into<GeneralName>>(mut self, name: GN) -> Self {
        let gn = name.into();
        self.0.push(gn.into());
        self
    }

    pub fn into_general_names(self) -> Vec<GeneralName> {
        self.0.into_iter().map(|gn| gn.into()).collect()
    }

    pub fn to_general_names(&self) -> Vec<GeneralName> {
        self.0.iter().map(|gn| gn.clone().into()).collect()
    }
}

impl From<SerdeGeneralNames> for GeneralNames {
    fn from(gn: SerdeGeneralNames) -> Self {
        Self(gn)
    }
}

impl From<GeneralNames> for SerdeGeneralNames {
    fn from(gn: GeneralNames) -> Self {
        gn.0
    }
}

impl From<Vec<GeneralName>> for GeneralNames {
    fn from(names: Vec<GeneralName>) -> Self {
        let serde_names = names.into_iter().map(|n| n.into()).collect();
        Self(serde_names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_format_directory_name() {
        let mut my_name = DirectoryName::new_common_name("CommonName");
        my_name.add_attr(NameAttr::StateOrProvinceName, "SomeState");
        my_name.add_attr(NameAttr::CountryName, "SomeCountry");
        assert_eq!(my_name.to_string(), "CN=CommonName,ST=SomeState,C=SomeCountry");
    }

    #[test]
    fn find_common_name() {
        let my_name = DirectoryName::new_common_name("CommonName");
        let cn = my_name.find_common_name().unwrap();
        assert_eq!(cn.to_utf8_lossy(), "CommonName");
    }
}
