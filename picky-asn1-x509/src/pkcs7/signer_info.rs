use crate::cmsversion::CmsVersion;
use crate::{AlgorithmIdentifier, Attribute, Name, SubjectKeyIdentifier};
use picky_asn1::tag::{Tag, TagClass, TagPeeker};
use picky_asn1::wrapper::{ImplicitContextTag0, IntegerAsn1, OctetStringAsn1, Optional};
use serde::{de, ser, Deserialize, Serialize};

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
/// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
///
/// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct SignerInfo {
    pub version: CmsVersion,
    pub sid: SignerIdentifier,
    pub digest_algorithm: DigestAlgorithmIdentifier,
    pub signed_attrs: Optional<Attributes>,
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
                if version != CmsVersion::V1 {
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

// This is a workaround for constructed encoding as implicit
#[derive(Debug, PartialEq, Clone, Default)]
pub struct Attributes(pub Vec<Attribute>);

impl ser::Serialize for Attributes {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        let mut raw_der = picky_asn1_der::to_vec(&self.0).unwrap_or_else(|_| vec![0]);
        raw_der[0] = Tag::context_specific_constructed(0).inner();
        picky_asn1_der::Asn1RawDer(raw_der).serialize(serializer)
    }
}

impl<'de> de::Deserialize<'de> for Attributes {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        let mut raw_der = picky_asn1_der::Asn1RawDer::deserialize(deserializer)?.0;
        raw_der[0] = Tag::SEQUENCE.inner();
        let vec = picky_asn1_der::from_bytes(&raw_der).unwrap_or_default();
        Ok(Attributes(vec))
    }
}

/// [RFC 5652 #5.3](https://datatracker.ietf.org/doc/html/rfc5652#section-5.3)
/// ``` not_rust
/// SignerIdentifier ::= CHOICE {
///          issuerAndSerialNumber IssuerAndSerialNumber,
///          subjectKeyIdentifier [0] SubjectKeyIdentifier }
/// ```
#[derive(Debug, PartialEq, Clone)]
pub enum SignerIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    SubjectKeyIdentifier(ImplicitContextTag0<SubjectKeyIdentifier>),
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

                let singer_identifier =
                    if tag_peeker.next_tag.class() == TagClass::ContextSpecific && tag_peeker.next_tag.number() == 0 {
                        SignerIdentifier::SubjectKeyIdentifier(seq_next_element!(
                            seq,
                            ImplicitContextTag0<SubjectKeyIdentifier>,
                            SignerIdentifier,
                            "SubjectKeyIdentifier"
                        ))
                    } else {
                        SignerIdentifier::IssuerAndSerialNumber(seq_next_element!(
                            seq,
                            IssuerAndSerialNumber,
                            "IssuerAndSerialNumber"
                        ))
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

/// [RFC 5652 #5.3](https://datatracker.ietf.org/doc/html/rfc5652#section-5.3)
/// ``` not_rust
/// SignatureValue ::= OCTET STRING
/// ```
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
/// ```
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct IssuerAndSerialNumber {
    pub issuer: Name,
    pub serial_number: CertificateSerialNumber,
}

/// [RFC 5652 #10.2.4](https://datatracker.ietf.org/doc/html/rfc5652#section-10.2.4)
/// ``` not_rust
/// CertificateSerialNumber ::= INTEGER
/// ```
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct CertificateSerialNumber(pub IntegerAsn1);

#[cfg(test)]
mod tests {
    use super::*;
    use picky_asn1_der::Asn1DerError;

    #[test]
    fn decode_certificate_trust_list_signer_info() {
        let signer_info = base64::decode(
            "MIICngIBATCBmTCBgTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x\
            EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv\
            bjErMCkGA1UEAxMiTWljcm9zb2Z0IENlcnRpZmljYXRlIExpc3QgQ0EgMjAxMQIT\
            MwAAAFajs3kCOFJzBAAAAAAAVjANBglghkgBZQMEAgEFAKCB2jAYBgkqhkiG9w0B\
            CQMxCwYJKwYBBAGCNwoBMC8GCSqGSIb3DQEJBDEiBCDKbAY82LhZRyLtnnizMz42\
            OJp0yEyTg/jBC9lXDMyatTCBjAYKKwYBBAGCNwIBDDF+MHygVoBUAE0AaQBjAHIA\
            bwBzAG8AZgB0ACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAVAByAHUAcwB0ACAA\
            TABpAHMAdAAgAFAAdQBiAGwAaQBzAGgAZQByoSKAIGh0dHA6Ly93d3cubWljcm9z\
            b2Z0LmNvbS93aW5kb3dzMA0GCSqGSIb3DQEBAQUABIIBAJolH27b3wLNu+E2Gh+B\
            9FFUsp5eiF1AGyUQb6hcjoYJIUjQgqW1shr+P4z9MI0ziTVWc1qVYh8LgXBAcuzN\
            pGu7spEFIckf40eITNeB5KUZFtHWym+MUIQERfs/C+iqCiSgtSiWxUIci7h/VF39\
            vhRTABMyZQddozLldJMsawRIhlceaOCTrp9tLQLLHHkEVDHSMOkbd4S9IOhw/YY9\
            cwcGic2ebDrpSZe0VVEgF9Blqk49W+JRwADVNdWFcDZbiAQv63vSy+VdFzKZer07\
            JAVDdVamvS5pk4MvNkszAG2KHsij6J3M97KcJY0FKuhPsfb9pnR61nmfDaFzoHOY\
            pkw=",
        )
        .unwrap();

        let signer_info: Result<SignerInfo, Asn1DerError> = picky_asn1_der::from_bytes(&signer_info);
        assert!(signer_info.is_ok());
    }
}
