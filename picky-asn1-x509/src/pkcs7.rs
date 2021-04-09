use crate::{oids, DigestInfo};
use picky_asn1::restricted_string::BMPString;
use picky_asn1::wrapper::{
    ApplicationTag0, ApplicationTag1, BMPStringAsn1, BitStringAsn1, IA5StringAsn1, Implicit, ObjectIdentifierAsn1,
    OctetStringAsn1,
};
use serde::{de, Deserialize, Serialize};
use std::convert::Into;
use widestring::U16String;

#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct ContentInfo {
    pub content_type: ObjectIdentifierAsn1,
    pub content: SpcIndirectDataContent,
}

impl<'de> de::Deserialize<'de> for ContentInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        use std::fmt;

        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = ContentInfo;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded ContentInfo")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let oid: ObjectIdentifierAsn1 = seq_next_element!(seq, ContentInfo, "type oid");

                let value = match Into::<String>::into(&oid.0).as_str() {
                    oids::SPC_INDIRECT_DATA_OBJID => {
                        seq_next_element!(seq, SpcIndirectDataContent, ContentInfo, "a SpcIndirectDataContent object")
                    }
                    _ => {
                        return Err(serde_invalid_value!(
                            ContentInfo,
                            "unknown oid type",
                            "a SPC_INDIRECT_DATA_OBJID oid"
                        ))
                    }
                };

                Ok(ContentInfo {
                    content_type: oid,
                    content: value,
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SpcIndirectDataContent {
    pub data: SpcAttributeAndOptionalValue,
    pub message_digest: DigestInfo,
}

#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct SpcAttributeAndOptionalValue {
    pub _type: ObjectIdentifierAsn1,
    pub value: ApplicationTag0<SpcPeImageData>,
}

impl<'de> de::Deserialize<'de> for SpcAttributeAndOptionalValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        use std::fmt;

        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = SpcAttributeAndOptionalValue;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded SpcAttributeAndOptionalValue")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let oid: ObjectIdentifierAsn1 = seq_next_element!(seq, SpcAttributeAndOptionalValue, "type oid");

                let value = match Into::<String>::into(&oid.0).as_str() {
                    oids::SPC_PE_IMAGE_DATAOBJ => seq_next_element!(
                        seq,
                        ApplicationTag0<SpcPeImageData>,
                        SpcAttributeAndOptionalValue,
                        "a SpcPeImageData object"
                    ),
                    _ => {
                        return Err(serde_invalid_value!(
                            SpcAttributeAndOptionalValue,
                            "unknown oid type",
                            "a SPC_PE_IMAGE_DATAOBJ oid"
                        ))
                    }
                };

                Ok(SpcAttributeAndOptionalValue { _type: oid, value })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SpcPeImageFlags(pub BitStringAsn1);

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SpcPeImageData {
    pub flags: SpcPeImageFlags,
    pub file: SpcLink,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)] // https://stackoverflow.com/questions/36775864/use-default-trait-for-struct-as-enum-option
pub enum SpcLink {
    Url(Url),
    Moniker(Moniker),
    File(File),
}

impl Default for SpcLink {
    fn default() -> Self {
        SpcLink::File(File::default())
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Url(pub Implicit<ApplicationTag0<IA5StringAsn1>>);

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Moniker(pub Implicit<ApplicationTag0<SpcSerialized>>);

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct File(pub SpcString);

impl Default for File {
    fn default() -> Self {
        let unicode_string = U16String::from_str("<<<Obsolete>>>");

        let buffer_size = unicode_string.len() * 2;
        let mut buffer = Vec::with_capacity(buffer_size);

        for elem in unicode_string.into_vec().into_iter() {
            let bytes = elem.to_be_bytes();
            buffer.push(bytes[0]);
            buffer.push(bytes[1]);
        }

        File(SpcString::Unicode(Implicit(ApplicationTag0(BMPStringAsn1::from(
            BMPString::new(buffer).unwrap(),
        )))))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SpcUuid(pub OctetStringAsn1);

impl Default for SpcUuid {
    fn default() -> Self {
        Self(OctetStringAsn1(vec![
            0xa6, 0xb5, 0x86, 0xd5, 0xb4, 0xa1, 0x24, 0x66, 0xae, 0x05, 0xa2, 0x17, 0xda, 0x8e, 0x60, 0xd6,
        ]))
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct SpcSerialized {
    pub class_id: SpcUuid,
    pub serialized_data: OctetStringAsn1,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum SpcString {
    Unicode(Implicit<ApplicationTag0<BMPStringAsn1>>),
    Ancii(Implicit<ApplicationTag1<IA5StringAsn1>>),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SpcSpOpusInfo {
    pub more_info: SpcLink,
    pub program_name: SpcString,
}
