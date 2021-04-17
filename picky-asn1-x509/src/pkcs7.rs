pub mod content_info;
pub mod crls;
pub mod signed_data;
pub mod singer_info;

use crate::oids;
use signed_data::SignedData;

use picky_asn1::wrapper::{ApplicationTag0, ObjectIdentifierAsn1};
use serde::{de, Serialize};

#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct Pkcs7Certificate {
    pub oid: ObjectIdentifierAsn1,
    pub signed_data: ApplicationTag0<SignedData>,
}

impl<'de> de::Deserialize<'de> for Pkcs7Certificate {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        use std::fmt;

        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Pkcs7Certificate;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded pcks7 certificate")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let oid: ObjectIdentifierAsn1 =
                    seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;

                let signed_data: ApplicationTag0<SignedData> = match Into::<String>::into(&oid.0).as_str() {
                    oids::SIGNED_DATA => seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    _ => {
                        return Err(serde_invalid_value!(
                            Pkcs7Certificate,
                            "unknown oid type",
                            "SignedData oid"
                        ))
                    }
                };

                Ok(Pkcs7Certificate { oid, signed_data })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}
