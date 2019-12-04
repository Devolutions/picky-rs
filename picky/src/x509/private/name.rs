use crate::x509::{
    private::attribute_type_and_value::{AttributeTypeAndValue, AttributeTypeAndValueParameters},
    DirectoryString,
};
use picky_asn1::{
    tag::{Tag, TagPeeker},
    wrapper::{
        ApplicationTag1, ApplicationTag2, ApplicationTag4, ApplicationTag5, ApplicationTag6,
        ApplicationTag7, ApplicationTag8, Asn1SequenceOf, Asn1SetOf, ContextTag0, ContextTag1,
        ContextTag2, ContextTag4, ContextTag5, ContextTag6, ContextTag7, ContextTag8,
        IA5StringAsn1, Implicit, ObjectIdentifierAsn1, OctetStringAsn1,
    },
};
use serde::{de, ser, Deserialize, Serialize};
use std::fmt;

// Name ::= CHOICE { -- only one possibility for now --
//       rdnSequence  RDNSequence }
pub(crate) type Name = RDNSequence;
// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
pub(crate) type RDNSequence = Asn1SequenceOf<RelativeDistinguishedName>;
// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
pub(crate) type RelativeDistinguishedName = Asn1SetOf<AttributeTypeAndValue>;

pub(crate) struct NamePrettyFormatter<'a>(pub &'a Name);
impl fmt::Display for NamePrettyFormatter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for name in &(self.0).0 {
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

// https://tools.ietf.org/html/rfc5280#section-4.2.1.6
// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
pub(crate) type GeneralNames = Asn1SequenceOf<GeneralName>;

// GeneralName ::= CHOICE {
//      otherName                       [0]     OtherName,
//      rfc822Name                      [1]     IA5String,
//      dNSName                         [2]     IA5String,
//      x400Address                     [3]     ORAddress,
//      directoryName                   [4]     Name,
//      ediPartyName                    [5]     EDIPartyName,
//      uniformResourceIdentifier       [6]     IA5String,
//      iPAddress                       [7]     OCTET STRING,
//      registeredID                    [8]     OBJECT IDENTIFIER }
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum GeneralName {
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
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
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
                // cannot panic with DER deserializer
                match seq.next_element::<TagPeeker>()?.unwrap().next_tag {
                    Tag::CTX_0 | Tag::APP_0 => Err(de::Error::invalid_value(
                        de::Unexpected::Other("[GeneralName] OtherName not supported"),
                        &"a supported GeneraleName choice",
                    )),
                    Tag::CTX_1 => Ok(GeneralName::RFC822Name(
                        seq.next_element::<ContextTag1<IA5StringAsn1>>()?.unwrap().0,
                    )),
                    Tag::APP_1 => Ok(GeneralName::RFC822Name(
                        seq.next_element::<ApplicationTag1<IA5StringAsn1>>()?
                            .unwrap()
                            .0,
                    )),
                    Tag::CTX_2 => Ok(GeneralName::DNSName(
                        seq.next_element::<ContextTag2<IA5StringAsn1>>()?.unwrap().0,
                    )),
                    Tag::APP_2 => Ok(GeneralName::DNSName(
                        seq.next_element::<ApplicationTag2<IA5StringAsn1>>()?
                            .unwrap()
                            .0,
                    )),
                    Tag::CTX_3 | Tag::APP_3 => Err(de::Error::invalid_value(
                        de::Unexpected::Other("[GeneralName] X400Address not supported"),
                        &"a supported GeneraleName choice",
                    )),
                    Tag::CTX_4 => Ok(GeneralName::DirectoryName(
                        seq.next_element::<ContextTag4<Name>>()?.unwrap().0,
                    )),
                    Tag::APP_4 => Ok(GeneralName::DirectoryName(
                        seq.next_element::<ApplicationTag4<Name>>()?.unwrap().0,
                    )),
                    Tag::CTX_5 => Ok(GeneralName::EDIPartyName(
                        seq.next_element::<ContextTag5<EDIPartyName>>()?.unwrap().0,
                    )),
                    Tag::APP_5 => Ok(GeneralName::EDIPartyName(
                        seq.next_element::<ApplicationTag5<EDIPartyName>>()?
                            .unwrap()
                            .0,
                    )),
                    Tag::CTX_6 => Ok(GeneralName::URI(
                        seq.next_element::<ContextTag6<IA5StringAsn1>>()?.unwrap().0,
                    )),
                    Tag::APP_6 => Ok(GeneralName::URI(
                        seq.next_element::<ApplicationTag6<IA5StringAsn1>>()?
                            .unwrap()
                            .0,
                    )),
                    Tag::CTX_7 => Ok(GeneralName::IpAddress(
                        seq.next_element::<ContextTag7<OctetStringAsn1>>()?
                            .unwrap()
                            .0,
                    )),
                    Tag::APP_7 => Ok(GeneralName::IpAddress(
                        seq.next_element::<ApplicationTag7<OctetStringAsn1>>()?
                            .unwrap()
                            .0,
                    )),
                    Tag::CTX_8 => Ok(GeneralName::RegisteredId(
                        seq.next_element::<ContextTag8<ObjectIdentifierAsn1>>()?
                            .unwrap()
                            .0,
                    )),
                    Tag::APP_8 => Ok(GeneralName::RegisteredId(
                        seq.next_element::<ApplicationTag8<ObjectIdentifierAsn1>>()?
                            .unwrap()
                            .0,
                    )),
                    _ => Err(de::Error::invalid_value(
                        de::Unexpected::Other("[GeneralName] unknown choice value"),
                        &"a supported GeneralName choice",
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
//pub(crate) struct OtherName { ... }

// EDIPartyName ::= SEQUENCE {
//      nameAssigner            [0]     DirectoryString OPTIONAL,
//      partyName               [1]     DirectoryString }
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub(crate) struct EDIPartyName {
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
        let expected = Asn1SequenceOf(vec![Asn1SetOf(vec![
            AttributeTypeAndValue::new_common_name("test.contoso.local"),
        ])]);
        check_serde!(expected: Name in encoded);
    }

    #[test]
    fn general_name_dns() {
        #[rustfmt::skip]
        let encoded = [
            0x82, 0x11,
                0x64, 0x65, 0x76, 0x65, 0x6C, 0x2E, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D,
        ];
        let expected = GeneralName::DNSName(
            IA5String::from_string("devel.example.com".into())
                .unwrap()
                .into(),
        );
        check_serde!(expected: GeneralName in encoded);
    }
}
