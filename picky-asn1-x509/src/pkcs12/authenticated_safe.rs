use crate::{oids, pkcs12::SafeContentsContentInfo};
use core::fmt;
use oid::ObjectIdentifier;
use picky_asn1::wrapper::{Asn1SequenceOf, ExplicitContextTag0, ObjectIdentifierAsn1, OctetStringAsn1Container};
use picky_asn1_der::Asn1RawDer;
use serde::{de, ser};

/// Top-level `ContentInfo` type used in context of `AuthenticatedSafe` for PKCS#12 `PFX` structure.
/// Defined in [PKCS #12](https://datatracker.ietf.org/doc/html/rfc7292#section-3.4)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticatedSafeContentInfo {
    Data(Vec<SafeContentsContentInfo>),
    /// Unknown `ContentInfo` type used in context of `AuthenticatedSafe`.
    /// Most likely `SignedData` is used, which is not currently supported by picky.
    Unknown {
        content_type: ObjectIdentifier,
        content: Option<Asn1RawDer>,
    },
}

impl ser::Serialize for AuthenticatedSafeContentInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        use ser::SerializeSeq;

        match self {
            AuthenticatedSafeContentInfo::Data(safe_contents) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                let oid: ObjectIdentifierAsn1 = oids::content_info_type_data().into();
                seq.serialize_element(&oid)?;
                let content: ExplicitContextTag0<OctetStringAsn1Container<Asn1SequenceOf<SafeContentsContentInfo>>> =
                    OctetStringAsn1Container(Asn1SequenceOf(safe_contents.clone())).into();
                seq.serialize_element(&content)?;
                seq.end()
            }
            AuthenticatedSafeContentInfo::Unknown { content_type, content } => {
                let sequence_length = 1 + content.is_some() as usize;
                let mut seq = serializer.serialize_seq(Some(sequence_length))?;
                let oid: ObjectIdentifierAsn1 = content_type.clone().into();
                seq.serialize_element(&oid)?;
                if let Some(content) = content {
                    let content: ExplicitContextTag0<Asn1RawDer> = content.clone().into();
                    seq.serialize_element(&content)?;
                }
                seq.end()
            }
        }
    }
}

impl<'de> de::Deserialize<'de> for AuthenticatedSafeContentInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct AuthenticatedSafeContentInfoVisitor;

        impl<'de> de::Visitor<'de> for AuthenticatedSafeContentInfoVisitor {
            type Value = AuthenticatedSafeContentInfo;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a valid DER-encoded AuthenticatedSafeContentInfo")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let content_type: ObjectIdentifierAsn1 = seq_next_element!(
                    seq,
                    AuthenticatedSafeContentInfo,
                    "ContentInfo<AuthenticatedSafe> content type"
                );
                let oid_str: String = content_type.0.clone().into();

                match oid_str.as_str() {
                    oids::CONTENT_INFO_TYPE_DATA => {
                        let content: ExplicitContextTag0<
                            OctetStringAsn1Container<Asn1SequenceOf<SafeContentsContentInfo>>,
                        > = seq_next_element!(
                            seq,
                            AuthenticatedSafeContentInfo,
                            "ContentInfo<AuthenticatedSafe> content"
                        );
                        Ok(AuthenticatedSafeContentInfo::Data(content.0 .0 .0))
                    }
                    _ => {
                        let content: Option<ExplicitContextTag0<Asn1RawDer>> = seq.next_element()?;
                        Ok(AuthenticatedSafeContentInfo::Unknown {
                            content_type: content_type.0,
                            content: content.map(|c| c.0),
                        })
                    }
                }
            }
        }

        deserializer.deserialize_seq(AuthenticatedSafeContentInfoVisitor)
    }
}
