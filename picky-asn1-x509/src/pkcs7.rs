use crate::{oids, AlgorithmIdentifier, AttributeValue, Attributes, Certificate, DigestInfo, Name, Version};
use picky_asn1::{
    restricted_string::BMPString,
    wrapper::{
        ApplicationTag0, ApplicationTag1, Asn1SetOf, BMPStringAsn1, BitStringAsn1, IA5StringAsn1, Implicit,
        IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1,
    },
};
use serde::{de, Deserialize, Serialize};
use std::{borrow::Borrow, convert::Into};
use widestring::U16String;

#[derive(Serialize, Debug, PartialEq, Clone)]
struct SignedData {
    pub version: Version,
    pub digest_algorithm: DigestAlgorithmIdentifiers,
    pub content_info: ContentInfo,
    pub certificates: Implicit<ApplicationTag0<ExtendedCertificatesAndCertificates>>,
    pub singers_infos: SingersInfos,
}

impl<'de> Deserialize<'de> for SignedData {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        use std::fmt;

        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = SignedData;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded SignedData")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let version: Version = seq_next_element!(seq, SignedData, "Version");

                if version as u8 != 1 {
                    return Err(serde_invalid_value!(
                        SignedData,
                        "wrong version field",
                        "Version equal to 1"
                    ));
                }

                let digest_algorithm: DigestAlgorithmIdentifiers =
                    seq_next_element!(seq, SignedData, "DigestAlgorithmIdentifiers");

                let content_info: ContentInfo = seq_next_element!(seq, SignedData, "ContentInfo");

                let certificates: Implicit<ApplicationTag0<ExtendedCertificatesAndCertificates>> =
                    seq_next_element!(seq, SignedData, "ExtendedCertificatesAndCertificates");

                let singers_infos: SingersInfos = seq_next_element!(seq, SignedData, "SingesInfos");

                if singers_infos.0 .0.len() != 1 {
                    return Err(serde_invalid_value!(
                        SignedData,
                        "DigestAlgorithmIdentifiers of Signed does not match ",
                        "SignersInfos contains exactly one SignerInfo structure"
                    ));
                }

                if digest_algorithm.0 != singers_infos.0.0.first().unwrap().digest_algorithm {
                    return Err(serde_invalid_value!(
                        SignedData,
                        "the digestAlgorithm of SignedData does not match the DigestAlgorithm in SingerInfo",
                        "the digestAlgorithm of SignedData matches the DigestAlgorithm in SingerInfo"
                    ));
                }

                Ok(SignedData {
                    version,
                    digest_algorithm,
                    content_info,
                    certificates,
                    singers_infos,
                })
            }
        }
        deserializer.deserialize_seq(Visitor)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct DigestAlgorithmIdentifiers(pub AlgorithmIdentifier);

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct ExtendedCertificatesAndCertificates(pub Asn1SetOf<Certificate>);

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SingersInfos(pub Asn1SetOf<SignerInfo>);

#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct SignerInfo {
    pub version: Version,
    pub issuer_and_serial_number: IssuerAndSerialNumber,
    pub digest_algorithm: AlgorithmIdentifier,
    pub authenticode_attributes: Implicit<Attributes>,
    // unauthenticated_attributes
    pub digest_encryption_algorithms: DigestEncryptionAlgorithmIdentifier,
    pub encrypted_digest: EncryptedDigest,
}

impl<'de> de::Deserialize<'de> for SignerInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        use std::fmt;

        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = SignerInfo;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded SignerInfo")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let version: Version = seq_next_element!(seq, SignerInfo, "Version");
                if version as u8 != 1 {
                    return Err(serde_invalid_value!(
                        SignerInfo,
                        "wrong version field",
                        "Version equal to 1"
                    ));
                }

                let issuer_and_serial_number: IssuerAndSerialNumber =
                    seq_next_element!(seq, SignerInfo, "IssuerAndSerialNumber");

                let digest_algorithm: AlgorithmIdentifier = seq_next_element!(seq, SignerInfo, "AlgorithmIdentifier");

                let authenticode_attributes: Implicit<Attributes> =
                    seq_next_element!(seq, SignerInfo, "Set of signed Attributes");

                let attributes = authenticode_attributes.0.borrow();

                if !attributes
                    .0
                    .iter()
                    .any(|attr| matches!(attr.value, AttributeValue::ContentType(_)))
                {
                    return Err(serde_invalid_value!(
                        SignerInfo,
                        "ContentType attribute is missing",
                        "ContentType attribute is present"
                    ));
                }

                if !attributes
                    .0
                    .iter()
                    .any(|attr| matches!(attr.value, AttributeValue::MessageDigest(_)))
                {
                    return Err(serde_invalid_value!(
                        SignerInfo,
                        "MessageDigest attribute is missing",
                        "MessageDigest attribute is present"
                    ));
                }

                if !attributes
                    .0
                    .iter()
                    .any(|attr| matches!(attr.value, AttributeValue::SpcSpOpusInfo(_)))
                {
                    return Err(serde_invalid_value!(
                        SignerInfo,
                        "SpcSpOpusInfo attribute is missing",
                        "SpcSpOpusInfo attribute is present"
                    ));
                }

                let digest_encryption_algorithms: DigestEncryptionAlgorithmIdentifier =
                    seq_next_element!(seq, SignerInfo, "DigestEncryptionAlgorithmIdentifier");

                let encrypted_digest: EncryptedDigest = seq_next_element!(seq, SignerInfo, "EncryptedDigest");

                Ok(SignerInfo {
                    version,
                    issuer_and_serial_number,
                    digest_algorithm,
                    authenticode_attributes,
                    digest_encryption_algorithms,
                    encrypted_digest,
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct DigestEncryptionAlgorithmIdentifier(pub AlgorithmIdentifier);

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct EncryptedDigest(pub OctetStringAsn1);

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct IssuerAndSerialNumber {
    pub issuer: Name,
    pub serial_number: CertificateSerialNumber,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct CertificateSerialNumber(pub IntegerAsn1);

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
                        seq_next_element!(
                            seq,
                            SpcIndirectDataContent,
                            ContentInfo,
                            "a SpcIndirectDataContent object"
                        )
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
    #[serde(skip_serializing_if = "spc_pe_image_flags_is_default")]
    pub flags: SpcPeImageFlags,
    pub file: SpcLink,
}

fn spc_pe_image_flags_is_default(flags: &SpcPeImageFlags) -> bool {
    flags.0.is_set(0) | !flags.0.is_set(1) | !flags.0.is_set(2)
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
