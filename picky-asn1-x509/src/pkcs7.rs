use crate::DigestInfo;
use oid::ObjectIdentifier;
use picky_asn1::{
    restricted_string::BMPString,
    wrapper::{
        ApplicationTag0, ApplicationTag1, BMPStringAsn1, BitStringAsn1, IA5StringAsn1, Implicit, OctetStringAsn1,
    },
};
use serde::{Deserialize, Serialize};
use widestring::U16String;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ContentInfo {
    content_type: ObjectIdentifier,
    content: SpcIndirectDataContent,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SpcIndirectDataContent {
    data: SpcAttributeAndOptionalValue,
    message_digest: DigestInfo,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SpcAttributeAndOptionalValue {
    _type: ObjectIdentifier,
    value: ApplicationTag0<SpcPeImageData>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SpcPeImageFlags(pub BitStringAsn1);

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SpcPeImageData {
    flags: SpcPeImageFlags,
    file: SpcLink,
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
pub struct File(SpcString);

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
    class_id: SpcUuid,
    serialized_data: OctetStringAsn1,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum SpcString {
    Unicode(Implicit<ApplicationTag0<BMPStringAsn1>>),
    Ancii(Implicit<ApplicationTag1<IA5StringAsn1>>),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct SpcSpOpusInfoImpl {
    more_info: SpcLink,
    program_name: SpcString,
}
