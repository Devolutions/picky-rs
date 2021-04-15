use crate::{AlgorithmIdentifier, Attributes, Name, Version};
use picky_asn1::wrapper::{Asn1SetOf, Implicit, IntegerAsn1, OctetStringAsn1};
use serde::{de, Deserialize, Serialize};

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

                let version = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
                if version != Version::V2 {
                    return Err(serde_invalid_value!(
                        SignerInfo,
                        "wrong version field",
                        "Version equal to 1"
                    ));
                }

                Ok(SignerInfo {
                    version,
                    issuer_and_serial_number: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    digest_algorithm: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(2, &self))?,
                    authenticode_attributes: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(3, &self))?,
                    digest_encryption_algorithms: seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(4, &self))?,
                    encrypted_digest: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(5, &self))?,
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct IssuerAndSerialNumber {
    pub issuer: Name,
    pub serial_number: CertificateSerialNumber,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct CertificateSerialNumber(pub IntegerAsn1);

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct DigestEncryptionAlgorithmIdentifier(pub AlgorithmIdentifier);

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct EncryptedDigest(pub OctetStringAsn1);
