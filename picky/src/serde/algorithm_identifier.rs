use crate::oids;
use oid::ObjectIdentifier;
use serde::{de, ser};
use serde_asn1_der::{asn1_wrapper::ObjectIdentifierAsn1, tag::Tag, tag_peeker::TagPeeker};
use std::fmt;

#[derive(Debug, PartialEq, Clone)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifierAsn1,
    pub parameters: AlgorithmIdentifierParameters,
}

impl AlgorithmIdentifier {
    pub fn new_sha1_with_rsa_encryption() -> Self {
        Self {
            algorithm: oids::sha1_with_rsa_encryption().into(),
            parameters: AlgorithmIdentifierParameters::Null,
        }
    }

    pub fn new_sha256_with_rsa_encryption() -> Self {
        Self {
            algorithm: oids::sha256_with_rsa_encryption().into(),
            parameters: AlgorithmIdentifierParameters::Null,
        }
    }

    pub fn new_rsa_encryption() -> Self {
        Self {
            algorithm: oids::rsa_encryption().into(),
            parameters: AlgorithmIdentifierParameters::Null,
        }
    }

    pub fn new_ecdsa_with_sha384() -> Self {
        Self {
            algorithm: oids::ecdsa_with_sha384().into(),
            parameters: AlgorithmIdentifierParameters::None,
        }
    }

    pub fn new_ecdsa_with_sha256() -> Self {
        Self {
            algorithm: oids::ecdsa_with_sha256().into(),
            parameters: AlgorithmIdentifierParameters::None,
        }
    }

    pub fn new_elliptic_curve<P: Into<ECParameters>>(ec_params: P) -> Self {
        Self {
            algorithm: oids::ec_public_key().into(),
            parameters: AlgorithmIdentifierParameters::EC(ec_params.into()),
        }
    }
}

impl ser::Serialize for AlgorithmIdentifier {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        use ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.algorithm)?;
        match &self.parameters {
            AlgorithmIdentifierParameters::None => {}
            AlgorithmIdentifierParameters::Null => {
                seq.serialize_element(&())?;
            }
            AlgorithmIdentifierParameters::EC(ec_params) => {
                seq.serialize_element(ec_params)?;
            }
        }
        seq.end()
    }
}

impl<'de> de::Deserialize<'de> for AlgorithmIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = AlgorithmIdentifier;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded algorithm identifier")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let oid: ObjectIdentifierAsn1 = seq.next_element()?.unwrap();

                let args = match Into::<String>::into(&oid.0).as_str() {
                    oids::SHA256_WITH_RSA_ENCRYPTION
                    | oids::RSA_ENCRYPTION
                    | oids::SHA1_WITH_RSA_ENCRYPTION
                    | oids::SHA384_WITH_RSA_ENCRYPTION
                    | oids::SHA512_WITH_RSA_ENCRYPTION => {
                        seq.next_element::<()>()?.unwrap();
                        AlgorithmIdentifierParameters::Null
                    }
                    oids::ECDSA_WITH_SHA384 | oids::ECDSA_WITH_SHA256 => {
                        AlgorithmIdentifierParameters::None
                    }
                    oids::EC_PUBLIC_KEY => AlgorithmIdentifierParameters::EC(
                        seq.next_element::<ECParameters>()?.unwrap(),
                    ),
                    oid => {
                        println!("{}", oid);
                        return Err(de::Error::invalid_value(
                            de::Unexpected::Other(
                                "[AlgorithmIdentifier] unsupported algorithm (unknown oid)",
                            ),
                            &"a supported algorithm",
                        ));
                    }
                };

                Ok(AlgorithmIdentifier {
                    algorithm: oid,
                    parameters: args,
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum AlgorithmIdentifierParameters {
    None,
    Null,
    EC(ECParameters),
}

#[derive(Debug, PartialEq, Clone)]
pub enum ECParameters {
    NamedCurve(ObjectIdentifierAsn1),
    ImplicitCurve,
    //SpecifiedCurve(SpecifiedECDomain) // see [X9.62]
}

impl From<ObjectIdentifierAsn1> for ECParameters {
    fn from(oid: ObjectIdentifierAsn1) -> Self {
        Self::NamedCurve(oid)
    }
}

impl From<ObjectIdentifier> for ECParameters {
    fn from(oid: ObjectIdentifier) -> Self {
        Self::NamedCurve(oid.into())
    }
}

impl From<()> for ECParameters {
    fn from(_: ()) -> Self {
        Self::ImplicitCurve
    }
}

impl ser::Serialize for ECParameters {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        match &self {
            ECParameters::NamedCurve(oid) => oid.serialize(serializer),
            ECParameters::ImplicitCurve => ().serialize(serializer),
        }
    }
}

impl<'de> de::Deserialize<'de> for ECParameters {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = ECParameters;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded DirectoryString")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                // cannot panic with DER deserializer
                match seq.next_element::<TagPeeker>()?.unwrap().next_tag {
                    Tag::OID => Ok(ECParameters::NamedCurve(seq.next_element()?.unwrap())),
                    Tag::NULL => {
                        seq.next_element::<()>()?.unwrap();
                        Ok(ECParameters::ImplicitCurve)
                    }
                    _ => Err(de::Error::invalid_value(
                        de::Unexpected::Other(
                            "[ECParameters] unsupported or unknown elliptic curve parameter",
                        ),
                        &"a supported elliptic curve parameter",
                    )),
                }
            }
        }

        deserializer.deserialize_enum("DirectoryString", &["NamedCurve", "ImplicitCurve"], Visitor)
    }
}
