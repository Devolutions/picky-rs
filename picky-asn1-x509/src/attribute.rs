#[cfg(feature = "pkcs7")]
use crate::pkcs7::content_info::SpcSpOpusInfo;
use crate::{oids, Extension, Extensions};
use picky_asn1::tag::Tag;
use picky_asn1::wrapper::{Asn1SetOf, ObjectIdentifierAsn1, OctetStringAsn1};
use serde::{de, ser};

// FIXME: this type is a hack to workaround [this issue](https://github.com/Devolutions/picky-rs/pull/78#issuecomment-789904165).
// Further refactorings are required to clean this up (proper support for IMPLICIT / EXPLICIT tags, etc)
#[derive(Clone, Debug, PartialEq)]
pub struct Attributes(pub Vec<Attribute>);

impl ser::Serialize for Attributes {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        let mut raw_der = picky_asn1_der::to_vec(&self.0).unwrap_or_default();
        raw_der[0] = Tag::APP_0.number();
        picky_asn1_der::Asn1RawDer(raw_der).serialize(serializer)
    }
}

impl<'de> de::Deserialize<'de> for Attributes {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        let mut raw_der = picky_asn1_der::Asn1RawDer::deserialize(deserializer)?.0;
        raw_der[0] = Tag::SEQUENCE.number();
        let vec = picky_asn1_der::from_bytes(&raw_der).unwrap_or_default();
        Ok(Attributes(vec))
    }
}

impl Default for Attributes {
    fn default() -> Self {
        Self(Vec::new())
    }
}

/// [RFC 2985 page 15 and 16](https://tools.ietf.org/html/rfc2985#page-15)
///
/// Accepted attribute types are `challengePassword` (TODO), `extensionRequest`,
/// `contentType`, `messageDigest` and `spcSpOpusInfo`
///
/// `spcSpOpusInfo` is behind the `pkcs7` feature.
///
/// `contentType`, `messageDigest` and `spcSpOpusInfo` are used for [microsoft authenticode]
/// (http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx)
#[derive(Clone, Debug, PartialEq)]
pub enum AttributeValues {
    /// `extensionRequest`
    Extensions(Asn1SetOf<Extensions>), // the set will always have 1 element in this variant
    // TODO: support for challenge password
    // ChallengePassword(Asn1SetOf<ChallengePassword>))
    Custom(picky_asn1_der::Asn1RawDer), // fallback
    ContentType(Asn1SetOf<ObjectIdentifierAsn1>),
    MessageDigest(Asn1SetOf<OctetStringAsn1>),
    #[cfg(feature = "pkcs7")]
    SpcSpOpusInfo(Asn1SetOf<SpcSpOpusInfo>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Attribute {
    pub ty: ObjectIdentifierAsn1,
    pub value: AttributeValues,
}

impl Attribute {
    pub fn new_extension_request(extensions: Vec<Extension>) -> Self {
        Self {
            ty: oids::extension_request().into(),
            value: AttributeValues::Extensions(Asn1SetOf(vec![Extensions(extensions)])),
        }
    }
}

impl ser::Serialize for Attribute {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        use ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.ty)?;
        match &self.value {
            AttributeValues::Extensions(extensions) => seq.serialize_element(extensions)?,
            AttributeValues::Custom(der) => seq.serialize_element(der)?,
            AttributeValues::ContentType(oid) => seq.serialize_element(oid)?,
            AttributeValues::MessageDigest(octet_string) => seq.serialize_element(octet_string)?,
            #[cfg(feature = "pkcs7")]
            AttributeValues::SpcSpOpusInfo(spc_sp_opus_info) => seq.serialize_element(spc_sp_opus_info)?,
        }
        seq.end()
    }
}

impl<'de> de::Deserialize<'de> for Attribute {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        use std::fmt;

        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Attribute;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded attribute")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let ty: ObjectIdentifierAsn1 = seq_next_element!(seq, Attribute, "type oid");

                let value = match Into::<String>::into(&ty.0).as_str() {
                    oids::EXTENSION_REQ => {
                        AttributeValues::Extensions(seq_next_element!(seq, Attribute, "at extension request"))
                    }
                    oids::CONTENT_TYPE => {
                        AttributeValues::ContentType(seq_next_element!(seq, Attribute, "message digest oid"))
                    }
                    oids::MESSAGE_DIGEST => {
                        AttributeValues::MessageDigest(seq_next_element!(seq, Attribute, "an octet string"))
                    }
                    #[cfg(feature = "pkcs7")]
                    oids::SPC_SP_OPUS_INFO_OBJID => {
                        AttributeValues::SpcSpOpusInfo(seq_next_element!(seq, Attribute, "an SpcSpOpusInfo object"))
                    }
                    _ => AttributeValues::Custom(seq_next_element!(seq, Attribute, "at custom value")),
                };

                Ok(Attribute { ty, value })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}
