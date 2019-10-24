use crate::oids;
use serde::{de, ser};
use serde_asn1_der::{
    asn1_wrapper::{
        BitStringAsn1, Implicit, ObjectIdentifierAsn1, OctetStringAsn1, OctetStringAsn1Container,
    },
    bit_string::BitString,
};
use std::fmt;

/// https://tools.ietf.org/html/rfc5280#section-4.1.2.9
#[derive(Serialize, Deserialize, Debug, PartialEq)]
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

        match &self.extn_value {
            ExtensionValue::KeyUsage(key_usage) => {
                seq.serialize_element(key_usage)?;
            }
            ExtensionValue::Generic(octet_string) => {
                seq.serialize_element(octet_string)?;
            }
        }

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
    //AuthorityKeyIdentifier(OctetStringAsn1Container<AuthorityKeyIdentifier>),
    //SubjectKeyIdentifier(OctetStringAsn1Container<SubjectKeyIdentifier>),
    KeyUsage(OctetStringAsn1Container<KeyUsage>),
    //CertificatePolicies(OctetStringAsn1Container<Asn1SequenceOf<PolicyInformation>>),
    //PolicyMappings(OctetStringAsn1Container<Asn1SequenceOfPolicyMapping>>),
    //SubjectAlternativeName(OctetStringAsn1Container<SubjectAltName>),
    //IssuerAlternativeName(OctetStringAsn1Container<IssuerAltName>),
    //SubjectDirectoryAttributes(OctetStringAsn1Container<Asn1SequenceOf<Attribute>>),
    //BasicConstraints(…)
    //NameConstraints(…)
    //PolicyConstraints(…)
    //ExtendedKeyUsage(…)
    //CRLDistributionPoints(…)
    //InhibitAnyPolicy(…)
    //FreshestCRL(…)
    Generic(OctetStringAsn1),
}

/// https://tools.ietf.org/html/rfc5280#section-4.2.1.1
/*#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AuthorityKeyIdentifier {
    key_identifier: Implicit<Option<ApplicationTag0<KeyIdentifier>>>,
    authority_cert_issuer: Implicit<Option<ApplicationTag1<Asn1SequenceOf<GeneralName>>>>,
    authority_cert_serial_number: Implicit<Option<ApplicationTag2<CertificateSerialNumber>>>,
}*/

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
