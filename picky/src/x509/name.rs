use crate::x509::{
    private::{
        attribute_type_and_value::AttributeTypeAndValueParameters,
        name::{
            GeneralName as SerdeGeneralName, GeneralNames as SerdeGeneralNames, NamePrettyFormatter,
        },
        AttributeTypeAndValue, Name,
    },
    DirectoryString,
};
use oid::ObjectIdentifier;
use picky_asn1::{
    restricted_string::{CharSetError, IA5String},
    wrapper::{Asn1SequenceOf, Asn1SetOf},
};
use std::fmt;

// === DirectoryName ===

#[derive(Clone, Debug, PartialEq)]
pub enum NameAttr {
    CommonName,
    Surname,
    SerialNumber,
    CountryName,
    LocalityName,
    StateOrProvinceName,
    StreetName,
    OrganisationName,
    OrganisationalUnitName,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DirectoryName(Name);

impl Default for DirectoryName {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectoryName {
    pub fn new() -> Self {
        Self(Asn1SequenceOf(vec![Asn1SetOf(vec![])]))
    }

    pub fn new_common_name<S: Into<DirectoryString>>(name: S) -> Self {
        let mut dn = Self::default();
        dn.add_attr(NameAttr::CommonName, name);
        dn
    }

    /// Find the first common name contained in this `Name`
    pub fn find_common_name(&self) -> Option<&DirectoryString> {
        for relative_distinguished_name in &((self.0).0) {
            for attr_ty_val in &relative_distinguished_name.0 {
                if let AttributeTypeAndValueParameters::CommonName(dir_string) = &attr_ty_val.value
                {
                    return Some(dir_string);
                }
            }
        }
        None
    }

    pub fn add_attr<S: Into<DirectoryString>>(&mut self, attr: NameAttr, value: S) {
        let ty_val = match attr {
            NameAttr::CommonName => AttributeTypeAndValue::new_common_name(value),
            NameAttr::Surname => AttributeTypeAndValue::new_surname(value),
            NameAttr::SerialNumber => AttributeTypeAndValue::new_serial_number(value),
            NameAttr::CountryName => AttributeTypeAndValue::new_country_name(value),
            NameAttr::LocalityName => AttributeTypeAndValue::new_locality_name(value),
            NameAttr::StateOrProvinceName => {
                AttributeTypeAndValue::new_state_or_province_name(value)
            }
            NameAttr::StreetName => AttributeTypeAndValue::new_street_name(value),
            NameAttr::OrganisationName => AttributeTypeAndValue::new_organisation_name(value),
            NameAttr::OrganisationalUnitName => {
                AttributeTypeAndValue::new_organisational_unit_name(value)
            }
        };
        ((self.0).0)[0].0.push(ty_val);
    }
}

impl fmt::Display for DirectoryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        NamePrettyFormatter(&self.0).fmt(f)
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

#[derive(Debug, PartialEq, Clone)]
pub enum GeneralName {
    RFC822Name(IA5String),
    DNSName(IA5String),
    DirectoryName(DirectoryName),
    EDIPartyName {
        name_assigner: Option<DirectoryString>,
        party_name: DirectoryString,
    },
    URI(IA5String),
    IpAddress(Vec<u8>),
    RegisteredId(ObjectIdentifier),
}

impl GeneralName {
    pub fn new_rfc822_name<S: Into<String>>(name: S) -> Result<Self, CharSetError> {
        Ok(Self::RFC822Name(IA5String::from_string(name.into())?))
    }

    pub fn new_dns_name<S: Into<String>>(name: S) -> Result<Self, CharSetError> {
        Ok(Self::DNSName(IA5String::from_string(name.into())?))
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

    pub fn new_uri<S: Into<String>>(uri: S) -> Result<Self, CharSetError> {
        Ok(Self::URI(IA5String::from_string(uri.into())?))
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
            SerdeGeneralName::RFC822Name(name) => Self::RFC822Name(name.0),
            SerdeGeneralName::DNSName(name) => Self::DNSName(name.0),
            SerdeGeneralName::DirectoryName(name) => Self::DirectoryName(name.into()),
            SerdeGeneralName::EDIPartyName(edi_pn) => Self::EDIPartyName {
                name_assigner: edi_pn.name_assigner.0.map(|na| na.0),
                party_name: edi_pn.party_name.0,
            },
            SerdeGeneralName::URI(uri) => Self::URI(uri.0),
            SerdeGeneralName::IpAddress(ip_addr) => Self::IpAddress(ip_addr.0),
            SerdeGeneralName::RegisteredId(id) => Self::RegisteredId(id.0),
        }
    }
}

impl From<GeneralName> for SerdeGeneralName {
    fn from(gn: GeneralName) -> Self {
        match gn {
            GeneralName::RFC822Name(name) => SerdeGeneralName::RFC822Name(name.into()),
            GeneralName::DNSName(name) => SerdeGeneralName::DNSName(name.into()),
            GeneralName::DirectoryName(name) => SerdeGeneralName::DirectoryName(name.into()),
            GeneralName::EDIPartyName {
                name_assigner,
                party_name,
            } => SerdeGeneralName::new_edi_party_name(party_name, name_assigner),
            GeneralName::URI(uri) => SerdeGeneralName::URI(uri.into()),
            GeneralName::IpAddress(ip_addr) => SerdeGeneralName::IpAddress(ip_addr.into()),
            GeneralName::RegisteredId(id) => SerdeGeneralName::RegisteredId(id.into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GeneralNames(SerdeGeneralNames);

impl GeneralNames {
    pub fn new<GN: Into<GeneralName>>(gn: GN) -> Self {
        let gn = gn.into();
        Self(Asn1SequenceOf(vec![gn.into()]))
    }

    pub fn new_directory_name<DN: Into<DirectoryName>>(name: DN) -> Self {
        let gn = GeneralName::new_directory_name(name);
        Self::new(gn)
    }

    pub fn find_directory_name(&self) -> Option<DirectoryName> {
        for name in &(self.0).0 {
            if let SerdeGeneralName::DirectoryName(name) = name {
                return Some(name.clone().into());
            }
        }
        None
    }

    pub fn new_dns_name<IA5: Into<IA5String>>(dns_name: IA5) -> Self {
        let gn = GeneralName::DNSName(dns_name.into());
        Self::new(gn)
    }

    pub fn find_dns_name(&self) -> Option<&IA5String> {
        for name in &(self.0).0 {
            if let SerdeGeneralName::DNSName(name) = name {
                return Some(&name.0);
            }
        }
        None
    }

    pub fn add_name<GN: Into<GeneralName>>(&mut self, name: GN) {
        let gn = name.into();
        (self.0).0.push(gn.into());
    }

    pub fn into_general_names(self) -> Vec<GeneralName> {
        (self.0).0.into_iter().map(|gn| gn.into()).collect()
    }

    pub fn to_general_names(&self) -> Vec<GeneralName> {
        (self.0).0.iter().map(|gn| gn.clone().into()).collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_format_directory_name() {
        let mut my_name = DirectoryName::new_common_name("CommonName");
        my_name.add_attr(NameAttr::StateOrProvinceName, "SomeState");
        my_name.add_attr(NameAttr::CountryName, "SomeCountry");
        assert_eq!(
            my_name.to_string(),
            "CN=CommonName,ST=SomeState,C=SomeCountry"
        );
    }

    #[test]
    fn find_common_name() {
        let my_name = DirectoryName::new_common_name("CommonName");
        let cn = my_name.find_common_name().unwrap();
        assert_eq!(cn.to_utf8_lossy(), "CommonName");
    }
}
