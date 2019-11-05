use crate::{
    oids,
    serde::{
        AlgorithmIdentifier, AttributeTypeAndValue, AttributeTypeAndValueParameters,
        AuthorityKeyIdentifier, ExtensionValue, Extensions, SubjectPublicKeyInfo, Validity,
        Version,
    },
};
use serde::{
    de,
    export::{fmt::Error, Formatter},
};
use serde_asn1_der::asn1_wrapper::{
    ApplicationTag0, ApplicationTag3, Asn1SequenceOf, Asn1SetOf, BitStringAsn1, IntegerAsn1,
    OctetStringAsn1Container,
};
use std::{convert::TryFrom, fmt};

pub type RelativeDistinguishedName = Asn1SetOf<AttributeTypeAndValue>;
pub type GeneralNames = Asn1SequenceOf<RelativeDistinguishedName>;
pub type Name = GeneralNames;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Certificate {
    pub tbs_certificate: TBSCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: BitStringAsn1,
}

impl Certificate {
    pub fn from_der(der: &[u8]) -> serde_asn1_der::Result<Self> {
        serde_asn1_der::from_bytes(der)
    }

    pub fn to_der(&self) -> serde_asn1_der::Result<Vec<u8>> {
        serde_asn1_der::to_vec(self)
    }

    pub fn get_subject_key_identifier(&self) -> Result<String, String> {
        let key_identifier_oid = oids::subject_key_identifier();
        let ext = (self.tbs_certificate.extensions.0)
            .0
            .iter()
            .find(|ext| ext.extn_id == key_identifier_oid)
            .ok_or_else(|| "subject key identifier extension not found".to_owned())?;

        match &ext.extn_value {
            ExtensionValue::SubjectKeyIdentifier(ski) => Ok(hex::encode(&(ski.0).0)),
            _ => unreachable!("invalid extension (expected subject key identifier)"),
        }
    }

    pub fn get_authority_key_identifier(&self) -> Result<String, String> {
        let key_identifier_oid = oids::authority_key_identifier();
        let ext = (self.tbs_certificate.extensions.0)
            .0
            .iter()
            .find(|ext| ext.extn_id == key_identifier_oid)
            .ok_or_else(|| "authority key identifier extension not found".to_owned())?;

        match &ext.extn_value {
            ExtensionValue::AuthorityKeyIdentifier(OctetStringAsn1Container(
                AuthorityKeyIdentifier {
                    key_identifier: Some(key_identifier),
                    authority_cert_issuer: _,
                    authority_cert_serial_number: _,
                },
            )) => Ok(hex::encode(&(key_identifier.0).0)),
            _ => unreachable!("invalid extension (expected authority key identifier)"),
        }
    }

    pub fn get_subject_name(&self) -> String {
        NamePrettyFormatter(&self.tbs_certificate.subject).to_string()
    }

    pub fn get_issuer_name(&self) -> String {
        NamePrettyFormatter(&self.tbs_certificate.issuer).to_string()
    }
}

impl TryFrom<&[u8]> for Certificate {
    type Error = serde_asn1_der::SerdeAsn1DerError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_der(value)
    }
}

#[derive(Serialize, Debug, PartialEq)]
pub struct TBSCertificate {
    pub version: ApplicationTag0<Version>,
    pub serial_number: IntegerAsn1,
    pub signature: AlgorithmIdentifier,
    pub issuer: Name,
    pub validity: Validity,
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    // issuer_unique_id
    // subject_unique_id
    pub extensions: ApplicationTag3<Extensions>,
}

// Implement Deserialize manually to return an easy to understand error on V1 certificates
// (aka ApplicationTag0 not present).
impl<'de> de::Deserialize<'de> for TBSCertificate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = TBSCertificate;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct TBSCertificate")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: de::SeqAccess<'de>,
            {
                Ok(TBSCertificate {
                    version: seq.next_element().map_err(|_| de::Error::invalid_value(
                            de::Unexpected::Other(
                                "[TBSCertificate] V1 certificates unsupported. Only V3 certificates \
                                are supported",
                            ),
                            &"a supported certificate",
                        ))?.ok_or_else(|| de::Error::invalid_length(0, &self))?,
                    serial_number: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    signature: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(2, &self))?,
                    issuer: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(3, &self))?,
                    validity: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(4, &self))?,
                    subject: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(5, &self))?,
                    subject_public_key_info: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(6, &self))?,
                    extensions: seq.next_element()?.ok_or_else(|| de::Error::invalid_length(7, &self))?,
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

pub struct NamePrettyFormatter<'a>(pub &'a Name);
impl fmt::Display for NamePrettyFormatter<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        let mut first = true;
        for name in &(self.0).0 {
            if first {
                first = false;
            } else {
                write!(f, " ")?;
            }

            match &name.0[0].value {
                AttributeTypeAndValueParameters::CommonName(name) => {
                    write!(f, "{}", name)?;
                }
                AttributeTypeAndValueParameters::SerialNumber(name) => {
                    write!(f, "{}", name)?;
                }
                AttributeTypeAndValueParameters::CountryName(name) => {
                    write!(f, "{}", name)?;
                }
                AttributeTypeAndValueParameters::LocalityName(name) => {
                    write!(f, "{}", name)?;
                }
                AttributeTypeAndValueParameters::StateOrProvinceName(name) => {
                    write!(f, "{}", name)?;
                }
                AttributeTypeAndValueParameters::OrganisationName(name) => {
                    write!(f, "{}", name)?;
                }
                AttributeTypeAndValueParameters::OrganisationalUnitName(name) => {
                    write!(f, "{}", name)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        oids,
        serde::{AttributeTypeAndValue, Extension, ExtensionValue, KeyIdentifier, KeyUsage},
    };
    use num_bigint_dig::{BigInt, Sign};
    use serde_asn1_der::{
        asn1_wrapper::{Asn1SequenceOf, Asn1SetOf},
        bit_string::BitString,
        date::UTCTime,
    };

    #[test]
    fn x509_v3_certificate() {
        let encoded = base64::decode(
            "MIIEGjCCAgKgAwIBAgIEN8NXxDANBgkqhkiG9w0BAQsFADAiMSAwHgYDVQQ\
             DDBdjb250b3NvLmxvY2FsIEF1dGhvcml0eTAeFw0xOTEwMTcxNzQxMjhaFw0yMjEwM\
             TYxNzQxMjhaMB0xGzAZBgNVBAMMEnRlc3QuY29udG9zby5sb2NhbDCCASIwDQYJKoZ\
             IhvcNAQEBBQADggEPADCCAQoCggEBAMptALdk7xKj9JmFSycxlaTV47oLv5Aabir17\
             f1WseAcZ492Mx0wqcJMmT8rVAusyfqvrhodHu4GELGBySo4KChLEuoEOGTNw/wEMtM\
             6j1E9K7kig1iiuH9nf9oow7OUdix4+w7TWQWpwl1NekKdTtvLLtEGSjmG187CUqR6f\
             NHYag+iVMV5Umc5VQadvAgva8qxOsPpDkN/E2df5gST7H5g3igaZtxUa3x7VreN3qJ\
             P0+hYQiyM7KsgmdFAkKpHC6/k36H7SXtpzh0NbH5OJHifYsAP34WL+a6lAd0VM7UiI\
             RMcLWA8HfmKL3p4bC+LFv5I0dvUUy1BTz1wHpRvVz8CAwEAAaNdMFswCQYDVR0TBAI\
             wADAOBgNVHQ8BAf8EBAMCAaAwHQYDVR0OBBYEFCMimIgHf5c00sI9jZzeWoMLsR60M\
             B8GA1UdIwQYMBaAFBbHC24DEnsUFLz/zmqB5cMCHo9OMA0GCSqGSIb3DQEBCwUAA4I\
             CAQA1ehZTTBbes2DgGXwQugoV9PdOGMFEVT4dzrrluo/4exSfqLrNuY2NXVuNBKW4n\
             DA5aD71Q/KUZ8Y8cV9qa8OBJQvQ0dd0qeHmeEYdDsj5YD4ECycKx9U1ZX5fi6tpSIX\
             6DsietpCnrw4aTgbEOvMeQcuYCTP30Vpt+mYEKBlR/E2Vcl2zUD+67gqppSaC1RceL\
             /8Cy6ZXlPqwmS2zqK9UhYVRKlEww8xSh/9CR9MmIDc4pHtCpMawcn6Dmo+A+LcKi5v\
             /NIwvSJTei+h1gvRhvEOPcf4VZJMHXquNrxkMsKpuu7g/AYH7wl2MBaNaxyNlXY5e5\
             OjxslrbRCfDab11YaJEONcBnapl/+Ajr70uVFN09tDXyk0EHYf75NiRztgVKclna26\
             zP5qRb0JSYNQJW2kIIBX6DhU7kt6RcauF2hJ+jLWOF2vsAS8PdEr7vnR1EGOrrcQ3V\
             UgMscNsDqf50YMi2Inu1Kt2t+QSvYs61ON39aVpqR67nskdUWzFCVgWQVezM1ZagoO\
             yNp7WjRYl8hJ0YVZ7TRtP8nJOkZ6s046YHVWxMuGdqZfd/AUFb9xzzXjGRuuZ1JmSf\
             +VBOFEe2MaPMyMQBeIs3Othz6Fcy6Am5F6c3It31WYJwiCa/NdbMIvGy1xvAN5kzR/\
             Y6hkoQljoSr1rVuszJ9dtvuTccA==",
        )
        .expect("invalid base64");

        // Issuer

        let issuer: Name = Asn1SequenceOf(vec![Asn1SetOf(vec![
            AttributeTypeAndValue::new_common_name("contoso.local Authority"),
        ])]);
        check_serde!(issuer: Name in encoded[34..70]);

        // Validity

        let validity = Validity {
            not_before: UTCTime::new(2019, 10, 17, 17, 41, 28).unwrap().into(),
            not_after: UTCTime::new(2022, 10, 16, 17, 41, 28).unwrap().into(),
        };
        check_serde!(validity: Validity in encoded[70..102]);

        // Subject

        let subject: Name = Asn1SequenceOf(vec![Asn1SetOf(vec![
            AttributeTypeAndValue::new_common_name("test.contoso.local"),
        ])]);
        check_serde!(subject: Name in encoded[102..133]);

        // SubjectPublicKeyInfo

        let subject_public_key_info = SubjectPublicKeyInfo::new_rsa_key(
            BigInt::from_bytes_be(Sign::Plus, &encoded[165..422]).into(),
            BigInt::from(65537).into(),
        );
        check_serde!(subject_public_key_info: SubjectPublicKeyInfo in encoded[133..427]);

        // Extensions

        let mut key_usage = KeyUsage::new(7);
        key_usage.set_digital_signature(true);
        key_usage.set_key_encipherment(true);

        let extensions = Extensions(vec![
            Extension {
                extn_id: oids::basic_constraints().into(),
                critical: false.into(),
                extn_value: ExtensionValue::Generic(encoded[440..442].to_vec().into()),
            },
            Extension::new_key_usage(key_usage),
            Extension::new_subject_key_identifier(&encoded[469..489]),
            Extension::new_authority_key_identifier(
                KeyIdentifier::from(encoded[502..522].to_vec()),
                None,
                None,
            ),
        ]);
        check_serde!(extensions: Extensions in encoded[429..522]);

        // SignatureAlgorithm

        let signature_algorithm = AlgorithmIdentifier::new_sha256_with_rsa_encryption();
        check_serde!(signature_algorithm: AlgorithmIdentifier in encoded[522..537]);

        // TBSCertificate

        let tbs_certificate = TBSCertificate {
            version: ApplicationTag0(Version::V3).into(),
            serial_number: BigInt::from(935548868).into(),
            signature: signature_algorithm.clone(),
            issuer,
            validity,
            subject,
            subject_public_key_info,
            extensions: extensions.into(),
        };
        check_serde!(tbs_certificate: TBSCertificate in encoded[4..522]);

        // Full certificate

        let certificate = Certificate {
            tbs_certificate,
            signature_algorithm,
            signature_value: BitString::with_bytes(&encoded[542..1054]).into(),
        };
        check_serde!(certificate: Certificate in encoded);
    }
}
