use crate::{AttributeTypeAndValue, AttributeTypeAndValueParameters, DirectoryString};
use picky_asn1::{
    tag::{Tag, TagPeeker},
    wrapper::{
        ApplicationTag1, ApplicationTag2, ApplicationTag4, ApplicationTag5, ApplicationTag6, ApplicationTag7,
        ApplicationTag8, Asn1SequenceOf, Asn1SetOf, ContextTag0, ContextTag1, ContextTag2, ContextTag4, ContextTag5,
        ContextTag6, ContextTag7, ContextTag8, IA5StringAsn1, Implicit, ObjectIdentifierAsn1, OctetStringAsn1,
    },
};
use serde::{de, ser, Deserialize, Serialize};
use std::fmt;

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

/// [RFC 5280 #4.1.2.4](https://tools.ietf.org/html/rfc5280#section-4.1.2.4)
///
/// ```not_rust
/// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
/// ```
pub type RDNSequence = Asn1SequenceOf<RelativeDistinguishedName>;

/// [RFC 5280 #4.1.2.4](https://tools.ietf.org/html/rfc5280#section-4.1.2.4)
///
/// ```not_rust
/// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
/// ```
pub type RelativeDistinguishedName = Asn1SetOf<AttributeTypeAndValue>;

/// [RFC 5280 #4.2.1.6](https://tools.ietf.org/html/rfc5280#section-4.2.1.6)
///
/// ```not_rust
/// DirectoryName ::= Name
/// ```
pub type DirectoryName = Name;

/// [RFC 5280 #4.1.2.4](https://tools.ietf.org/html/rfc5280#section-4.1.2.4)
///
/// ```not_rust
/// Name ::= CHOICE { -- only one possibility for now --
///       rdnSequence  RDNSequence }
/// ```
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Name(pub RDNSequence);

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
        let mut dn = Self::default();
        dn.add_attr(NameAttr::CommonName, name);
        dn
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
            NameAttr::Surname => AttributeTypeAndValue::new_surname(value),
            NameAttr::SerialNumber => AttributeTypeAndValue::new_serial_number(value),
            NameAttr::CountryName => AttributeTypeAndValue::new_country_name(value),
            NameAttr::LocalityName => AttributeTypeAndValue::new_locality_name(value),
            NameAttr::StateOrProvinceName => AttributeTypeAndValue::new_state_or_province_name(value),
            NameAttr::StreetName => AttributeTypeAndValue::new_street_name(value),
            NameAttr::OrganisationName => AttributeTypeAndValue::new_organisation_name(value),
            NameAttr::OrganisationalUnitName => AttributeTypeAndValue::new_organisational_unit_name(value),
        };
        ((self.0).0)[0].0.push(ty_val);
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        NamePrettyFormatter(self).fmt(f)
    }
}

pub struct NamePrettyFormatter<'a>(pub &'a Name);

impl fmt::Display for NamePrettyFormatter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for name in &((self.0).0).0 {
            for attr in &name.0 {
                if first {
                    first = false;
                } else {
                    write!(f, ",")?;
                }

                match &attr.value {
                    AttributeTypeAndValueParameters::CommonName(name) => {
                        write!(f, "CN={}", name)?;
                    }
                    AttributeTypeAndValueParameters::Surname(name) => {
                        write!(f, "SURNAME={}", name)?;
                    }
                    AttributeTypeAndValueParameters::SerialNumber(name) => {
                        write!(f, "SN={}", name)?;
                    }
                    AttributeTypeAndValueParameters::CountryName(name) => {
                        write!(f, "C={}", name)?;
                    }
                    AttributeTypeAndValueParameters::LocalityName(name) => {
                        write!(f, "L={}", name)?;
                    }
                    AttributeTypeAndValueParameters::StateOrProvinceName(name) => {
                        write!(f, "ST={}", name)?;
                    }
                    AttributeTypeAndValueParameters::StreetName(name) => {
                        write!(f, "STREET NAME={}", name)?;
                    }
                    AttributeTypeAndValueParameters::OrganisationName(name) => {
                        write!(f, "O={}", name)?;
                    }
                    AttributeTypeAndValueParameters::OrganisationalUnitName(name) => {
                        write!(f, "OU={}", name)?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// [RFC 5280 #4.2.1.6](https://tools.ietf.org/html/rfc5280#section-4.2.1.6)
///
/// ```not_rust
/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
/// ```
pub type GeneralNames = Asn1SequenceOf<GeneralName>;

/// [RFC 5280 #4.2.1.6](https://tools.ietf.org/html/rfc5280#section-4.2.1.6)
///
/// ```not_rust
/// GeneralName ::= CHOICE {
///       otherName                       [0]     OtherName,
///       rfc822Name                      [1]     IA5String,
///       dNSName                         [2]     IA5String,
///       x400Address                     [3]     ORAddress,
///       directoryName                   [4]     Name,
///       ediPartyName                    [5]     EDIPartyName,
///       uniformResourceIdentifier       [6]     IA5String,
///       iPAddress                       [7]     OCTET STRING,
///       registeredID                    [8]     OBJECT IDENTIFIER }
/// ```
#[derive(Debug, PartialEq, Clone)]
pub enum GeneralName {
    //OtherName(OtherName),
    RFC822Name(IA5StringAsn1),
    DNSName(IA5StringAsn1),
    //X400Address(ORAddress),
    DirectoryName(Name),
    EDIPartyName(EDIPartyName),
    URI(IA5StringAsn1),
    IpAddress(OctetStringAsn1),
    RegisteredId(ObjectIdentifierAsn1),
}

impl GeneralName {
    pub fn new_edi_party_name<PN, NA>(party_name: PN, name_assigner: Option<NA>) -> Self
    where
        PN: Into<DirectoryString>,
        NA: Into<DirectoryString>,
    {
        Self::EDIPartyName(EDIPartyName {
            name_assigner: Implicit(name_assigner.map(Into::into).map(ContextTag0)),
            party_name: ContextTag1(party_name.into()),
        })
    }
}

impl From<Name> for GeneralName {
    fn from(name: Name) -> Self {
        Self::DirectoryName(name)
    }
}

impl ser::Serialize for GeneralName {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        match &self {
            GeneralName::RFC822Name(name) => ContextTag1(name).serialize(serializer),
            GeneralName::DNSName(name) => ContextTag2(name).serialize(serializer),
            GeneralName::DirectoryName(name) => ContextTag4(name).serialize(serializer),
            GeneralName::EDIPartyName(name) => ContextTag5(name).serialize(serializer),
            GeneralName::URI(name) => ContextTag6(name).serialize(serializer),
            GeneralName::IpAddress(name) => ContextTag7(name).serialize(serializer),
            GeneralName::RegisteredId(name) => ContextTag8(name).serialize(serializer),
        }
    }
}

impl<'de> de::Deserialize<'de> for GeneralName {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = GeneralName;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded GeneralName")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let tag_peeker: TagPeeker = seq_next_element!(seq, DirectoryString, "choice tag");
                match tag_peeker.next_tag {
                    Tag::CTX_0 | Tag::APP_0 => Err(serde_invalid_value!(
                        GeneralName,
                        "OtherName not supported",
                        "a supported choice"
                    )),
                    Tag::CTX_1 => Ok(GeneralName::RFC822Name(
                        seq_next_element!(seq, ContextTag1<IA5StringAsn1>, GeneralName, "RFC822Name").0,
                    )),
                    Tag::APP_1 => Ok(GeneralName::RFC822Name(
                        seq_next_element!(seq, ApplicationTag1<IA5StringAsn1>, GeneralName, "RFC822Name").0,
                    )),
                    Tag::CTX_2 => Ok(GeneralName::DNSName(
                        seq_next_element!(seq, ContextTag2<IA5StringAsn1>, GeneralName, "DNSName").0,
                    )),
                    Tag::APP_2 => Ok(GeneralName::DNSName(
                        seq_next_element!(seq, ApplicationTag2<IA5StringAsn1>, GeneralName, "DNSName").0,
                    )),
                    Tag::CTX_3 | Tag::APP_3 => Err(serde_invalid_value!(
                        GeneralName,
                        "X400Address not supported",
                        "a supported choice"
                    )),
                    Tag::CTX_4 => Ok(GeneralName::DirectoryName(
                        seq_next_element!(seq, ContextTag4<Name>, GeneralName, "DirectoryName").0,
                    )),
                    Tag::APP_4 => Ok(GeneralName::DirectoryName(
                        seq_next_element!(seq, ApplicationTag4<Name>, GeneralName, "DirectoryName").0,
                    )),
                    Tag::CTX_5 => Ok(GeneralName::EDIPartyName(
                        seq_next_element!(seq, ContextTag5<EDIPartyName>, GeneralName, "EDIPartyName").0,
                    )),
                    Tag::APP_5 => Ok(GeneralName::EDIPartyName(
                        seq_next_element!(seq, ApplicationTag5<EDIPartyName>, GeneralName, "EDIPartyName").0,
                    )),
                    Tag::CTX_6 => Ok(GeneralName::URI(
                        seq_next_element!(seq, ContextTag6<IA5StringAsn1>, GeneralName, "URI").0,
                    )),
                    Tag::APP_6 => Ok(GeneralName::URI(
                        seq_next_element!(seq, ApplicationTag6<IA5StringAsn1>, GeneralName, "URI").0,
                    )),
                    Tag::CTX_7 => Ok(GeneralName::IpAddress(
                        seq_next_element!(seq, ContextTag7<OctetStringAsn1>, GeneralName, "IpAddress").0,
                    )),
                    Tag::APP_7 => Ok(GeneralName::IpAddress(
                        seq_next_element!(seq, ApplicationTag7<OctetStringAsn1>, GeneralName, "IpAddress").0,
                    )),
                    Tag::CTX_8 => Ok(GeneralName::RegisteredId(
                        seq_next_element!(seq, ContextTag8<ObjectIdentifierAsn1>, GeneralName, "RegisteredId").0,
                    )),
                    Tag::APP_8 => Ok(GeneralName::RegisteredId(
                        seq_next_element!(seq, ApplicationTag8<ObjectIdentifierAsn1>, GeneralName, "RegisteredId").0,
                    )),
                    _ => Err(serde_invalid_value!(
                        GeneralName,
                        "unknown choice value",
                        "a supported GeneralName choice"
                    )),
                }
            }
        }

        deserializer.deserialize_enum(
            "GeneralName",
            &[
                "RFC822Name",
                "DNSName",
                "DirectoryName",
                "EDIPartyName",
                "URI",
                "IpAddress",
                "RegisteredId",
            ],
            Visitor,
        )
    }
}

// OtherName ::= SEQUENCE {
//      type-id    OBJECT IDENTIFIER,
//      value      [0] EXPLICIT ANY DEFINED BY type-id }
//pub struct OtherName { ... }

/// [RFC 5280 #4.2.1.6](https://tools.ietf.org/html/rfc5280#section-4.2.1.6)
///
/// ```not_rust
/// EDIPartyName ::= SEQUENCE {
///      nameAssigner            [0]     DirectoryString OPTIONAL,
///      partyName               [1]     DirectoryString }
/// ```
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct EDIPartyName {
    pub name_assigner: Implicit<Option<ContextTag0<DirectoryString>>>,
    pub party_name: ContextTag1<DirectoryString>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use picky_asn1::restricted_string::IA5String;

    #[test]
    fn common_name() {
        #[rustfmt::skip]
        let encoded = [
            0x30, 0x1D, // sequence
                0x31, 0x1B, // set
                    0x30, 0x19, // sequence
                        0x06, 0x03, 0x55, 0x04, 0x03, // oid
                        0x0c, 0x12, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x63, 0x6F, 0x6E, 0x74, 0x6F,
                            0x73, 0x6F, 0x2E, 0x6C, 0x6F, 0x63, 0x61, 0x6C, // utf8 string
        ];
        let expected = Name::new_common_name("test.contoso.local");
        check_serde!(expected: Name in encoded);
    }

    #[test]
    fn general_name_dns() {
        #[rustfmt::skip]
        let encoded = [
            0x82, 0x11,
                0x64, 0x65, 0x76, 0x65, 0x6C, 0x2E, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D,
        ];
        let expected = GeneralName::DNSName(IA5String::from_string("devel.example.com".into()).unwrap().into());
        check_serde!(expected: GeneralName in encoded);
    }
}
