use crate::{
    oids,
    serde::{
        extension::{AuthorityKeyIdentifier, BasicConstraints, ExtensionValue},
        AlgorithmIdentifier, Extensions, Name, SubjectPublicKeyInfo, Validity, Version,
    },
};
use err_ctx::ResultExt;
use serde::de;
use serde_asn1_der::asn1_wrapper::{
    ApplicationTag0, ApplicationTag3, BitStringAsn1, Implicit, IntegerAsn1,
    OctetStringAsn1Container,
};
use std::{convert::TryFrom, fmt};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Certificate {
    pub tbs_certificate: TBSCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: BitStringAsn1,
}

macro_rules! find_ext {
    ($oid:expr, $self:ident, $error_ctx:literal) => {{
        let key_identifier_oid = $oid;
        ($self.tbs_certificate.extensions.0)
            .0
            .iter()
            .find(|ext| ext.extn_id == key_identifier_oid)
            .ok_or(crate::error::Error::ExtensionNotFound)
            .ctx($error_ctx)
    }};
}

impl Certificate {
    pub fn from_der(der: &[u8]) -> serde_asn1_der::Result<Self> {
        serde_asn1_der::from_bytes(der)
    }

    pub fn to_der(&self) -> serde_asn1_der::Result<Vec<u8>> {
        serde_asn1_der::to_vec(self)
    }

    pub fn subject_key_identifier(&self) -> crate::error::Result<&[u8]> {
        let ext = find_ext!(
            oids::subject_key_identifier(),
            self,
            "couldn't fetch subject key identifier"
        )?;
        match &ext.extn_value {
            ExtensionValue::SubjectKeyIdentifier(ski) => Ok(&(ski.0).0),
            _ => unreachable!("invalid extension (expected subject key identifier)"),
        }
    }

    pub fn authority_key_identifier(&self) -> crate::error::Result<&[u8]> {
        let ext = find_ext!(
            oids::authority_key_identifier(),
            self,
            "couldn't fetch authority key identifier"
        )?;
        match &ext.extn_value {
            ExtensionValue::AuthorityKeyIdentifier(OctetStringAsn1Container(
                AuthorityKeyIdentifier {
                    key_identifier: Some(key_identifier),
                    ..
                },
            )) => Ok(&(key_identifier.0).0),
            _ => unreachable!("invalid extension (expected authority key identifier)"),
        }
    }

    pub fn basic_constraints(&self) -> crate::error::Result<(Option<bool>, Option<u8>)> {
        let ext = find_ext!(
            oids::basic_constraints(),
            self,
            "couldn't fetch basic constraints"
        )?;
        match &ext.extn_value {
            ExtensionValue::BasicConstraints(OctetStringAsn1Container(BasicConstraints {
                ca: Implicit(ca),
                path_len_constraint: Implicit(len),
            })) => Ok((*ca, *len)),
            _ => unreachable!("invalid extension (expected basic constraints)"),
        }
    }
}

impl TryFrom<&[u8]> for Certificate {
    type Error = serde_asn1_der::SerdeAsn1DerError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_der(value)
    }
}

#[derive(Serialize, Clone, Debug, PartialEq)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        pem::parse_pem,
        serde::{
            extension::{KeyIdentifier, KeyUsage},
            name::new_common_name,
            Extension,
        },
    };
    use num_bigint_dig::{BigInt, Sign};
    use serde_asn1_der::{bit_string::BitString, date::UTCTime};

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

        let issuer: Name = new_common_name("contoso.local Authority");
        check_serde!(issuer: Name in encoded[34..70]);

        // Validity

        let validity = Validity {
            not_before: UTCTime::new(2019, 10, 17, 17, 41, 28).unwrap().into(),
            not_after: UTCTime::new(2022, 10, 16, 17, 41, 28).unwrap().into(),
        };
        check_serde!(validity: Validity in encoded[70..102]);

        // Subject

        let subject: Name = new_common_name("test.contoso.local");
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
            Extension::new_basic_constraints(false, None, None),
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

    static PEM: &'static [u8] = include_bytes!("../../test_files/intermediate_ca.crt");

    #[test]
    fn key_id() {
        let intermediate_cert_pem = parse_pem(PEM).unwrap();
        let cert = Certificate::from_der(intermediate_cert_pem.data()).unwrap();
        pretty_assertions::assert_eq!(
            hex::encode(&cert.subject_key_identifier().unwrap()),
            "1f74d63f29c17474453b05122c3da8bd435902a6"
        );
        pretty_assertions::assert_eq!(
            hex::encode(&cert.authority_key_identifier().unwrap()),
            "b45ae4a5b3ded252f6b9d5a6950feb3ebcc7fdff"
        );
    }
}
