use std::convert::{Into, TryFrom};

use serde::{de, ser, Deserialize, Serialize};
use widestring::U16String;

use picky_asn1::bit_string::BitString;
use picky_asn1::restricted_string::{BMPString, CharSetError};
use picky_asn1::tag::{Tag, TagPeeker};
use picky_asn1::wrapper::{
    ApplicationTag0, ApplicationTag1, ApplicationTag2, BMPStringAsn1, BitStringAsn1, ContextTag0, ContextTag1,
    IA5StringAsn1, Implicit, ObjectIdentifierAsn1, OctetStringAsn1,
};

use crate::{oids, DigestInfo};

#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct ContentInfo {
    pub content_type: ObjectIdentifierAsn1,
    pub content: Option<SpcIndirectDataContent>,
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
                let oid: ObjectIdentifierAsn1 =
                    seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;

                let value = match Into::<String>::into(&oid.0).as_str() {
                    oids::SPC_INDIRECT_DATA_OBJID => {
                        Some(seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?)
                    }
                    oids::PKCS7 => None,
                    _ => {
                        return Err(serde_invalid_value!(
                            ContentInfo,
                            "unknown oid type",
                            "SPC_INDIRECT_DATA_OBJID or PKCS7 oid"
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

#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct SpcPeImageData {
    pub flags: SpcPeImageFlags,
    pub file: SpcLink,
}

impl<'de> de::Deserialize<'de> for SpcPeImageData {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        use std::fmt;

        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = SpcPeImageData;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded SpcPeImageData")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                Ok(SpcPeImageData {
                    flags: seq.next_element()?.unwrap_or_default(),
                    file: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?,
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SpcPeImageFlags(pub BitStringAsn1);

impl Default for SpcPeImageFlags {
    fn default() -> Self {
        let mut flags = BitString::with_len(3);
        flags.set(0, true); // includeResources
        flags.set(1, false); // includeDebugInfo
        flags.set(2, false); // includeImportAddressTable
        Self(flags.into())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum SpcLink {
    Url(Url),
    Moniker(Moniker),
    File(File),
}

impl Serialize for SpcLink {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        match &self {
            SpcLink::Url(url) => url.serialize(serializer),
            SpcLink::Moniker(moniker) => moniker.serialize(serializer),
            SpcLink::File(file) => file.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for SpcLink {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        use std::fmt;

        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = SpcLink;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded SpcLink")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let tag_peeker: TagPeeker = seq_next_element!(seq, SpcLink, "choice tag");
                let spc_link = match tag_peeker.next_tag {
                    Tag::APP_0 => SpcLink::Url(Url(seq_next_element!(
                        seq,
                        Implicit<ApplicationTag0<IA5StringAsn1>>,
                        SpcLink,
                        "Url"
                    ))),
                    Tag::APP_1 => SpcLink::Moniker(Moniker(seq_next_element!(
                        seq,
                        Implicit<ApplicationTag1<SpcSerialized>>,
                        SpcLink,
                        "Moniker"
                    ))),
                    Tag::APP_2 => SpcLink::File(File(seq_next_element!(
                        seq,
                        ApplicationTag2<SpcString>,
                        SpcLink,
                        "File"
                    ))),
                    _ => {
                        return Err(serde_invalid_value!(
                            SpcString,
                            "unknown choice value",
                            "a supported SpcString choice"
                        ))
                    }
                };

                Ok(spc_link)
            }
        }

        deserializer.deserialize_enum("SpcLink", &["Url", "Moniker", "File"], Visitor)
    }
}

impl Default for SpcLink {
    fn default() -> Self {
        SpcLink::File(File::default())
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Url(pub Implicit<ApplicationTag0<IA5StringAsn1>>);

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Moniker(pub Implicit<ApplicationTag1<SpcSerialized>>);

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct File(pub ApplicationTag2<SpcString>);

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

        File(ApplicationTag2(SpcString::Unicode(Implicit(ContextTag0(
            BMPStringAsn1::from(BMPString::new(buffer).unwrap()),
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

#[derive(Debug, PartialEq, Clone)]
pub enum SpcString {
    Unicode(Implicit<ContextTag0<BMPStringAsn1>>),
    Ancii(Implicit<ContextTag1<IA5StringAsn1>>),
}

impl Serialize for SpcString {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        match &self {
            SpcString::Unicode(unicode) => unicode.serialize(serializer),
            SpcString::Ancii(ancii) => ancii.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for SpcString {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        use std::fmt;

        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = SpcString;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded SpcString")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let tag_peeker: TagPeeker = seq_next_element!(seq, SpcString, "choice tag");

                let spc_string = match tag_peeker.next_tag {
                    Tag::CTX_0 => SpcString::Unicode(seq_next_element!(
                        seq,
                        Implicit<ContextTag0<BMPStringAsn1>>,
                        SpcString,
                        "BMPStringAsn1"
                    )),
                    Tag::CTX_1 => SpcString::Ancii(seq_next_element!(
                        seq,
                        Implicit<ContextTag1<IA5StringAsn1>>,
                        SpcString,
                        "IA5StringAsn1"
                    )),
                    _ => {
                        println!("unknown tag");
                        return Err(serde_invalid_value!(
                            SpcString,
                            "unknown choice value",
                            "a supported SpcString choice"
                        ));
                    }
                };

                Ok(spc_string)
            }
        }

        deserializer.deserialize_enum("SpcString", &["Unicode, Ancii"], Visitor)
    }
}

impl TryFrom<String> for SpcString {
    type Error = CharSetError;

    fn try_from(string: String) -> Result<Self, Self::Error> {
        Ok(SpcString::Unicode(Implicit(ContextTag0(
            BMPString::new(string)?.into(),
        ))))
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SpcSpOpusInfo {
    pub more_info: SpcLink,
    pub program_name: SpcString,
}
