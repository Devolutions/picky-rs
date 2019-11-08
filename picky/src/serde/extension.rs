use crate::{oids, serde::name::GeneralNames};
use serde::{de, ser};
use serde_asn1_der::{
    asn1_wrapper::{
        ApplicationTag1, ApplicationTag4, BitStringAsn1, ContextTag0, ContextTag2, Implicit,
        IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1, OctetStringAsn1Container,
    },
    bit_string::BitString,
};
use std::fmt;

/// https://tools.ietf.org/html/rfc5280#section-4.1.2.9
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Extensions(pub Vec<Extension>);

#[derive(Debug, PartialEq, Clone)]
pub struct Extension {
    pub extn_id: ObjectIdentifierAsn1,
    pub critical: Implicit<bool>,
    pub extn_value: ExtensionValue,
}

impl Extension {
    pub fn new_key_usage(key_usage: KeyUsage) -> Self {
        Self {
            extn_id: oids::key_usage().into(),
            // When present, conforming CAs SHOULD mark this extension as critical
            critical: true.into(),
            extn_value: ExtensionValue::KeyUsage(key_usage.into()),
        }
    }

    pub fn new_subject_key_identifier<V: Into<Vec<u8>>>(ski: V) -> Self {
        Self {
            extn_id: oids::subject_key_identifier().into(),
            // Conforming CAs MUST mark this extension as non-critical
            critical: false.into(),
            extn_value: ExtensionValue::SubjectKeyIdentifier(OctetStringAsn1(ski.into()).into()),
        }
    }

    pub fn new_authority_key_identifier<KI, I, SN>(
        key_identifier: KI,
        authority_cert_issuer: I,
        authority_cert_serial_number: SN,
    ) -> Self
    where
        KI: Into<Option<KeyIdentifier>>,
        I: Into<Option<GeneralNames>>,
        SN: Into<Option<IntegerAsn1>>,
    {
        Self {
            extn_id: oids::authority_key_identifier().into(),
            // Conforming CAs MUST mark this extension as non-critical
            critical: false.into(),
            extn_value: ExtensionValue::AuthorityKeyIdentifier(
                AuthorityKeyIdentifier {
                    key_identifier: key_identifier.into().map(ContextTag0),
                    authority_cert_issuer: authority_cert_issuer
                        .into()
                        .map(ApplicationTag4)
                        .map(ApplicationTag1),
                    authority_cert_serial_number: authority_cert_serial_number
                        .into()
                        .map(ContextTag2),
                }
                .into(),
            ),
        }
    }

    pub fn new_basic_constraints<CA: Into<Option<bool>>, PLC: Into<Option<u8>>>(
        is_critical: bool,
        ca: CA,
        path_len_constraints: PLC,
    ) -> Self {
        Self {
            extn_id: oids::basic_constraints().into(),
            // FIXME: check details here: https://tools.ietf.org/html/rfc5280#section-4.2.1.9
            critical: Implicit(is_critical),
            extn_value: ExtensionValue::BasicConstraints(
                BasicConstraints {
                    ca: Implicit(ca.into()),
                    path_len_constraint: Implicit(path_len_constraints.into()),
                }
                .into(),
            ),
        }
    }
}

impl ser::Serialize for Extension {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        use ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(3))?;
        seq.serialize_element(&self.extn_id)?;

        if self.critical.0 != bool::default() {
            seq.serialize_element(&self.critical)?;
        }

        seq.serialize_element(&self.extn_value)?;

        seq.end()
    }
}

impl<'de> de::Deserialize<'de> for Extension {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Extension;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded algorithm identifier")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let id: ObjectIdentifierAsn1 = seq.next_element()?.unwrap();
                let critical: Implicit<bool> = seq.next_element()?.unwrap();
                let value = match Into::<String>::into(&id.0).as_str() {
                    oids::KEY_USAGE => ExtensionValue::KeyUsage(seq.next_element()?.unwrap()),
                    oids::SUBJECT_KEY_IDENTIFIER => {
                        ExtensionValue::SubjectKeyIdentifier(seq.next_element()?.unwrap())
                    }
                    oids::AUTHORITY_KEY_IDENTIFIER => {
                        ExtensionValue::AuthorityKeyIdentifier(seq.next_element()?.unwrap())
                    }
                    oids::BASIC_CONSTRAINTS => {
                        ExtensionValue::BasicConstraints(seq.next_element()?.unwrap())
                    }
                    _ => ExtensionValue::Generic(seq.next_element()?.unwrap()),
                };

                Ok(Extension {
                    extn_id: id,
                    critical,
                    extn_value: value,
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum ExtensionValue {
    AuthorityKeyIdentifier(OctetStringAsn1Container<AuthorityKeyIdentifier>),
    SubjectKeyIdentifier(OctetStringAsn1Container<SubjectKeyIdentifier>),
    KeyUsage(OctetStringAsn1Container<KeyUsage>),
    //CertificatePolicies(OctetStringAsn1Container<Asn1SequenceOf<PolicyInformation>>),
    //PolicyMappings(OctetStringAsn1Container<Asn1SequenceOfPolicyMapping>>),
    //SubjectAlternativeName(OctetStringAsn1Container<SubjectAltName>), TODO: prefer this extension
    //IssuerAlternativeName(OctetStringAsn1Container<IssuerAltName>),
    //SubjectDirectoryAttributes(OctetStringAsn1Container<Asn1SequenceOf<Attribute>>),
    BasicConstraints(OctetStringAsn1Container<BasicConstraints>),
    //NameConstraints(…),
    //PolicyConstraints(…),
    //ExtendedKeyUsage(…),
    //CRLDistributionPoints(…),
    //InhibitAnyPolicy(…),
    //FreshestCRL(…),
    Generic(OctetStringAsn1),
}

impl ser::Serialize for ExtensionValue {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        match self {
            ExtensionValue::AuthorityKeyIdentifier(aki) => aki.serialize(serializer),
            ExtensionValue::SubjectKeyIdentifier(ski) => ski.serialize(serializer),
            ExtensionValue::KeyUsage(key_usage) => key_usage.serialize(serializer),
            ExtensionValue::BasicConstraints(basic_constraints) => {
                basic_constraints.serialize(serializer)
            }
            ExtensionValue::Generic(octet_string) => octet_string.serialize(serializer),
        }
    }
}

/// https://tools.ietf.org/html/rfc5280#section-4.2.1.1
#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct AuthorityKeyIdentifier {
    pub key_identifier: Option<ContextTag0<KeyIdentifier>>,
    pub authority_cert_issuer: Option<ApplicationTag1<ApplicationTag4<GeneralNames>>>,
    pub authority_cert_serial_number: Option<ContextTag2<IntegerAsn1>>,
}

pub type KeyIdentifier = OctetStringAsn1;

impl<'de> de::Deserialize<'de> for AuthorityKeyIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = AuthorityKeyIdentifier;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded algorithm identifier")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                Ok(AuthorityKeyIdentifier {
                    key_identifier: seq.next_element().unwrap_or(Some(None)).unwrap_or(None),
                    authority_cert_issuer: seq.next_element().unwrap_or(Some(None)).unwrap_or(None),
                    authority_cert_serial_number: seq
                        .next_element()
                        .unwrap_or(Some(None))
                        .unwrap_or(None),
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

/// https://tools.ietf.org/html/rfc5280#section-4.2.1.2
pub type SubjectKeyIdentifier = OctetStringAsn1;

/// https://tools.ietf.org/html/rfc5280#section-4.2.1.3
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct KeyUsage(BitStringAsn1);

impl Default for KeyUsage {
    fn default() -> Self {
        Self::new(9)
    }
}

macro_rules! bit_string_get_set {
    ($getter:ident , $setter:ident , $idx:literal) => {
        pub fn $getter(&self) -> bool {
            self.0.is_set($idx)
        }

        pub fn $setter(&mut self, val: bool) {
            if self.0.get_num_bits() <= $idx {
                self.0.set_num_bits($idx + 1)
            }
            self.0.set($idx, val);
        }
    };
    ( $( $getter:ident , $setter:ident , $idx:literal ; )+ ) => {
        $( bit_string_get_set! { $getter, $setter, $idx } )+
    };
}

impl KeyUsage {
    pub fn new(num_bits: usize) -> Self {
        Self(BitString::with_len(num_bits).into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.payload_view()
    }

    bit_string_get_set! {
        digital_signature, set_digital_signature, 0;
        content_commitment, set_content_commitment, 1;
        key_encipherment, set_key_encipherment, 2;
        data_encipherment, set_data_encipherment, 3;
        key_agreement, set_key_agreement, 4;
        key_cert_sign, set_key_cert_sign, 5;
        crl_sign, set_crl_sign, 6;
        encipher_only, set_encipher_only, 7;
        decipher_only, set_decipher_only, 8;
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.2.1.9
#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct BasicConstraints {
    pub ca: Implicit<Option<bool>>, // default is false
    pub path_len_constraint: Implicit<Option<u8>>,
}

impl<'de> de::Deserialize<'de> for BasicConstraints {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = BasicConstraints;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded basic constraints extension")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                Ok(BasicConstraints {
                    ca: Implicit(seq.next_element().unwrap_or(Some(None)).unwrap_or(None)),
                    path_len_constraint: Implicit(
                        seq.next_element().unwrap_or(Some(None)).unwrap_or(None),
                    ),
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_usage() {
        let encoded: [u8; 4] = [0x03, 0x02, 0x01, 0xA0];
        let mut key_usage = KeyUsage::new(7);
        key_usage.set_digital_signature(true);
        key_usage.set_key_encipherment(true);
        assert_eq!(key_usage.as_bytes(), &[0xA0]);
        check_serde!(key_usage: KeyUsage in encoded);
    }
}
