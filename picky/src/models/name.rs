use crate::serde::{
    attribute_type_and_value::DirectoryString,
    name::{new_common_name, NamePrettyFormatter},
    AttributeTypeAndValue, Name as SerdeName,
    attribute_type_and_value::AttributeTypeAndValueParameters,
};
use serde_asn1_der::asn1_wrapper::{Asn1SequenceOf, Asn1SetOf};
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub enum NameAttr {
    CommonName,
    SerialNumber,
    CountryName,
    LocalityName,
    StateOrProvinceName,
    OrganisationName,
    OrganisationalUnitName,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Name(SerdeName);

impl Default for Name {
    fn default() -> Self {
        Self::new()
    }
}

impl Name {
    pub fn new() -> Self {
        Self(Asn1SequenceOf(vec![Asn1SetOf(vec![])]))
    }

    pub fn new_common_name<S: Into<DirectoryString>>(name: S) -> Self {
        Self(new_common_name(name))
    }

    /// Find the first common name contained in this `Name`
    pub fn find_common_name(&self) -> Option<&DirectoryString> {
        for relative_distinguished_name in &((self.0).0) {
            for attr_ty_val in &relative_distinguished_name.0 {
                if let AttributeTypeAndValueParameters::CommonName(dir_string) = &attr_ty_val.value {
                    return Some(dir_string);
                }
            }
        }
        None
    }

    pub fn add_attr<S: Into<DirectoryString>>(&mut self, attr: NameAttr, value: S) {
        let ty_val = match attr {
            NameAttr::CommonName => AttributeTypeAndValue::new_common_name(value),
            NameAttr::SerialNumber => AttributeTypeAndValue::new_serial_number(value),
            NameAttr::CountryName => AttributeTypeAndValue::new_country_name(value),
            NameAttr::LocalityName => AttributeTypeAndValue::new_locality_name(value),
            NameAttr::StateOrProvinceName => {
                AttributeTypeAndValue::new_state_or_province_name(value)
            }
            NameAttr::OrganisationName => AttributeTypeAndValue::new_organisation_name(value),
            NameAttr::OrganisationalUnitName => {
                AttributeTypeAndValue::new_organisational_unit_name(value)
            }
        };
        ((self.0).0)[0].0.push(ty_val);
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        NamePrettyFormatter(&self.0).fmt(f)
    }
}

impl From<SerdeName> for Name {
    fn from(name: SerdeName) -> Self {
        Self(name)
    }
}

impl From<Name> for SerdeName {
    fn from(name: Name) -> Self {
        name.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_format_name() {
        let mut my_name = Name::new_common_name("CommonName");
        my_name.add_attr(NameAttr::StateOrProvinceName, "SomeState");
        my_name.add_attr(NameAttr::CountryName, "SomeCountry");
        assert_eq!(
            my_name.to_string(),
            "CN=CommonName,ST=SomeState,C=SomeCountry"
        );
    }
}
