use serde::{de, ser, Deserialize, Serialize};

use picky_asn1::wrapper::{ContextTag0, Implicit, IntegerAsn1, OctetStringAsn1};

use crate::cmsversion::CMSVersion;
use crate::{AlgorithmIdentifier, Attributes, Name, SubjectKeyIdentifier};
use picky_asn1::tag::{Tag, TagPeeker};

/// [RFC 5652 #5.3](https://datatracker.ietf.org/doc/html/rfc5652#section-5.3)
/// ``` not_rust
/// SignerInfo ::= SEQUENCE {
///         version CMSVersion,
///         sid SignerIdentifier,
///         digestAlgorithm DigestAlgorithmIdentifier,
///         signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///         signatureAlgorithm SignatureAlgorithmIdentifier,
///         signature SignatureValue,
///         unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
///
/// SignerIdentifier ::= CHOICE {
///          issuerAndSerialNumber IssuerAndSerialNumber,
///          subjectKeyIdentifier [0] SubjectKeyIdentifier }
///
/// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
///
/// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
///
/// SignatureValue ::= OCTET STRING
/// ```
#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct SignerInfo {
    pub version: CMSVersion,
    pub sid: SignerIdentifier,
    pub digest_algorithm: DigestAlgorithmIdentifier,
    pub signed_attrs: Implicit<Attributes>,
    pub signature_algorithm: SignatureAlgorithmIdentifier,
    pub signature: SignatureValue,
    // unsigned_attrs
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
                if version != CMSVersion::V1 {
                    return Err(serde_invalid_value!(
                        SignerInfo,
                        "wrong version field",
                        "Version equal to 1"
                    ));
                }

                Ok(SignerInfo {
                    version,
                    sid: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    digest_algorithm: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(2, &self))?,
                    signed_attrs: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(3, &self))?,
                    signature_algorithm: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(4, &self))?,
                    signature: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(5, &self))?,
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum SignerIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    SubjectKeyIdentifier(ContextTag0<SubjectKeyIdentifier>),
}

impl Serialize for SignerIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        match &self {
            SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial_number) => {
                issuer_and_serial_number.serialize(serializer)
            }
            SignerIdentifier::SubjectKeyIdentifier(subject_key_identifier) => {
                subject_key_identifier.serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for SignerIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        use std::fmt;

        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = SignerIdentifier;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded SpcLink")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let tag_peeker: TagPeeker = seq_next_element!(seq, SignerIdentifier, "a choice tag");

                let singer_identifier = match tag_peeker.next_tag {
                    Tag::CTX_0 => SignerIdentifier::SubjectKeyIdentifier(seq_next_element!(
                        seq,
                        ContextTag0<SubjectKeyIdentifier>,
                        SignerIdentifier,
                        "SubjectKeyIdentifier"
                    )),
                    _ => SignerIdentifier::IssuerAndSerialNumber(seq_next_element!(
                        seq,
                        IssuerAndSerialNumber,
                        "IssuerAndSerialNumber"
                    )),
                };

                Ok(singer_identifier)
            }
        }

        deserializer.deserialize_enum(
            "SignerIdentifier",
            &["SubjectKeyIdentifier, IssuerAndSerialNumber"],
            Visitor,
        )
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SignatureValue(pub OctetStringAsn1);

/// [RFC 5652 #10.1.1](https://datatracker.ietf.org/doc/html/rfc5652#section-10.1.1)
/// ``` not_rust
/// DigestAlgorithmIdentifier ::= AlgorithmIdentifier
/// ```
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct DigestAlgorithmIdentifier(pub AlgorithmIdentifier);

/// [RFC 5652 #10.1.2](https://datatracker.ietf.org/doc/html/rfc5652#section-10.1.2)
/// ``` not_rust
/// SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
/// ```
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SignatureAlgorithmIdentifier(pub AlgorithmIdentifier);

/// [RFC 5652 #10.2.4](https://datatracker.ietf.org/doc/html/rfc5652#section-10.2.4)
/// ``` not_rust
/// IssuerAndSerialNumber ::= SEQUENCE {
///      issuer Name,
///      serialNumber CertificateSerialNumber }
///
/// CertificateSerialNumber ::= INTEGER
/// ```
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct IssuerAndSerialNumber {
    pub issuer: Name,
    pub serial_number: CertificateSerialNumber,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct CertificateSerialNumber(pub IntegerAsn1);
