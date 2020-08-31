/****************************************************************************
 * https://tools.ietf.org/html/rfc5280#section-4.1
 *
 *  Certificate  ::=  SEQUENCE  {
 *       tbsCertificate       TBSCertificate,
 *       signatureAlgorithm   AlgorithmIdentifier,
 *       signatureValue       BIT STRING  }
 *
 *  TBSCertificate  ::=  SEQUENCE  {
 *       version         [0]  EXPLICIT Version DEFAULT v1,
 *       serialNumber         CertificateSerialNumber,
 *       signature            AlgorithmIdentifier,
 *       issuer               Name,
 *       validity             Validity,
 *       subject              Name,
 *       subjectPublicKeyInfo SubjectPublicKeyInfo,
 *       issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                            -- If present, version MUST be v2 or v3
 *       subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                            -- If present, version MUST be v2 or v3
 *       extensions      [3]  EXPLICIT Extensions OPTIONAL
 *                            -- If present, version MUST be v3
 *       }
 *
 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 *
 *  CertificateSerialNumber  ::=  INTEGER
 *
 *  Validity ::= SEQUENCE {
 *       notBefore      Time,
 *       notAfter       Time }
 *
 *  Time ::= CHOICE {
 *       utcTime        UTCTime,
 *       generalTime    GeneralizedTime }
 *
 *  UniqueIdentifier  ::=  BIT STRING
 *
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *       algorithm            AlgorithmIdentifier,
 *       subjectPublicKey     BIT STRING  }
 *
 *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 *
 *  Extension  ::=  SEQUENCE  {
 *       extnID      OBJECT IDENTIFIER,
 *       critical    BOOLEAN DEFAULT FALSE,
 *       extnValue   OCTET STRING
 *                   -- contains the DER encoding of an ASN.1 value
 *                   -- corresponding to the extension type identified
 *                   -- by extnID
 *       }
 *
 ****************************************************************************/
// https://lapo.it/asn1js/#MIIEGjCCAgKgAwIBAgIEN8NXxDANBgkqhkiG9w0BAQsFADAiMSAwHgYDVQQDDBdjb250b3NvLmxvY2FsIEF1dGhvcml0eTAeFw0xOTEwMTcxNzQxMjhaFw0yMjEwMTYxNzQxMjhaMB0xGzAZBgNVBAMMEnRlc3QuY29udG9zby5sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMptALdk7xKj9JmFSycxlaTV47oLv5Aabir17f1WseAcZ492Mx0wqcJMmT8rVAusyfqvrhodHu4GELGBySo4KChLEuoEOGTNw_wEMtM6j1E9K7kig1iiuH9nf9oow7OUdix4-w7TWQWpwl1NekKdTtvLLtEGSjmG187CUqR6fNHYag-iVMV5Umc5VQadvAgva8qxOsPpDkN_E2df5gST7H5g3igaZtxUa3x7VreN3qJP0-hYQiyM7KsgmdFAkKpHC6_k36H7SXtpzh0NbH5OJHifYsAP34WL-a6lAd0VM7UiIRMcLWA8HfmKL3p4bC-LFv5I0dvUUy1BTz1wHpRvVz8CAwEAAaNdMFswCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCAaAwHQYDVR0OBBYEFCMimIgHf5c00sI9jZzeWoMLsR60MB8GA1UdIwQYMBaAFBbHC24DEnsUFLz_zmqB5cMCHo9OMA0GCSqGSIb3DQEBCwUAA4ICAQA1ehZTTBbes2DgGXwQugoV9PdOGMFEVT4dzrrluo_4exSfqLrNuY2NXVuNBKW4nDA5aD71Q_KUZ8Y8cV9qa8OBJQvQ0dd0qeHmeEYdDsj5YD4ECycKx9U1ZX5fi6tpSIX6DsietpCnrw4aTgbEOvMeQcuYCTP30Vpt-mYEKBlR_E2Vcl2zUD-67gqppSaC1RceL_8Cy6ZXlPqwmS2zqK9UhYVRKlEww8xSh_9CR9MmIDc4pHtCpMawcn6Dmo-A-LcKi5v_NIwvSJTei-h1gvRhvEOPcf4VZJMHXquNrxkMsKpuu7g_AYH7wl2MBaNaxyNlXY5e5OjxslrbRCfDab11YaJEONcBnapl_-Ajr70uVFN09tDXyk0EHYf75NiRztgVKclna26zP5qRb0JSYNQJW2kIIBX6DhU7kt6RcauF2hJ-jLWOF2vsAS8PdEr7vnR1EGOrrcQ3VUgMscNsDqf50YMi2Inu1Kt2t-QSvYs61ON39aVpqR67nskdUWzFCVgWQVezM1ZagoOyNp7WjRYl8hJ0YVZ7TRtP8nJOkZ6s046YHVWxMuGdqZfd_AUFb9xzzXjGRuuZ1JmSf-VBOFEe2MaPMyMQBeIs3Othz6Fcy6Am5F6c3It31WYJwiCa_NdbMIvGy1xvAN5kzR_Y6hkoQljoSr1rVuszJ9dtvuTccA

use crate::pki_tests::{
    ocsp_request::AlgorithmIdentifier,
    rsa_public_key::{RSAPublicKey, SubjectPublicKeyInfoRsa},
    version::{implicit_app0_version_is_default, Version},
};
use num_bigint_dig::BigInt;
use oid::prelude::*;
use picky_asn1::{
    bit_string::BitString,
    date::Date,
    wrapper::{
        ApplicationTag0, ApplicationTag3, Asn1SequenceOf, Asn1SetOf, BitStringAsn1, Implicit, IntegerAsn1,
        ObjectIdentifierAsn1, OctetStringAsn1, UTCTimeAsn1,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Certificate {
    pub tbs_certificate: TBSCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: BitStringAsn1,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct TBSCertificate {
    #[serde(skip_serializing_if = "implicit_app0_version_is_default")]
    pub version: Implicit<ApplicationTag0<Version>>,
    pub serial_number: u128,
    pub signature: AlgorithmIdentifier,
    pub issuer: Name,
    pub validity: Validity,
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfoRsa,
    pub extensions: ApplicationTag3<Extensions>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AttributeTypeAndValue {
    ty: ObjectIdentifierAsn1,
    value: String, // hardcoded for ty = 2.5.4.3 (commonName)
}
pub type RelativeDistinguishedName = Asn1SetOf<AttributeTypeAndValue>;
pub type Name = Asn1SequenceOf<RelativeDistinguishedName>;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Validity {
    not_before: UTCTimeAsn1,
    not_after: UTCTimeAsn1,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Extensions(Vec<Extension>);

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Extension {
    extn_id: ObjectIdentifierAsn1,
    critical: Implicit<Option<bool>>,
    extn_value: OctetStringAsn1,
}

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

    let issuer: Name = Asn1SequenceOf(vec![Asn1SetOf(vec![AttributeTypeAndValue {
        ty: ObjectIdentifier::try_from("2.5.4.3").unwrap().into(),
        value: "contoso.local Authority".into(),
    }])]);
    check!(issuer: Name in encoded[34..70]);

    // Validity

    let validity = Validity {
        not_before: Date::new(2019, 10, 17, 17, 41, 28).unwrap().into(),
        not_after: Date::new(2022, 10, 16, 17, 41, 28).unwrap().into(),
    };
    check!(validity: Validity in encoded[70..102]);

    // Subject

    let subject: Name = Asn1SequenceOf(vec![Asn1SetOf(vec![AttributeTypeAndValue {
        ty: ObjectIdentifier::try_from("2.5.4.3").unwrap().into(),
        value: "test.contoso.local".into(),
    }])]);
    check!(subject: Name in encoded[102..133]);

    // SubjectPublicKeyInfo

    let rsa_encryption = ObjectIdentifier::try_from("1.2.840.113549.1.1.1").unwrap();
    let subject_public_key_info = SubjectPublicKeyInfoRsa {
        algorithm: AlgorithmIdentifier {
            algorithm: rsa_encryption.into(),
            parameters: (),
        },
        subject_public_key: RSAPublicKey {
            modulus: IntegerAsn1::from_bytes_be_signed(encoded[165..422].to_vec()),
            public_exponent: BigInt::from(65537).to_signed_bytes_be().into(),
        }
        .into(),
    };
    check!(subject_public_key_info: SubjectPublicKeyInfoRsa in encoded[133..427]);

    // Extensions

    let basic_constraints = ObjectIdentifier::try_from("2.5.29.19").unwrap();
    let key_usage = ObjectIdentifier::try_from("2.5.29.15").unwrap();
    let subject_key_identifier = ObjectIdentifier::try_from("2.5.29.14").unwrap();
    let authority_key_identifier = ObjectIdentifier::try_from("2.5.29.35").unwrap();
    let extensions = Extensions(vec![
        Extension {
            extn_id: basic_constraints.into(),
            critical: None.into(),
            extn_value: encoded[440..442].to_vec().into(),
        },
        Extension {
            extn_id: key_usage.into(),
            critical: Some(true).into(),
            extn_value: encoded[454..458].to_vec().into(),
        },
        Extension {
            extn_id: subject_key_identifier.into(),
            critical: None.into(),
            extn_value: encoded[467..489].to_vec().into(),
        },
        Extension {
            extn_id: authority_key_identifier.into(),
            critical: None.into(),
            extn_value: encoded[498..522].to_vec().into(),
        },
    ]);
    check!(extensions: Extensions in encoded[429..522]);

    // TBSCertificate

    let tbs_certificate = TBSCertificate {
        version: ApplicationTag0(Version::V3).into(),
        serial_number: 935548868,
        signature: AlgorithmIdentifier {
            algorithm: ObjectIdentifier::try_from("1.2.840.113549.1.1.11").unwrap().into(), // sha256
            parameters: (),
        },
        issuer,
        validity,
        subject,
        subject_public_key_info,
        extensions: ApplicationTag3(extensions),
    };
    check!(tbs_certificate: TBSCertificate in encoded[4..522]);

    // SignatureAlgorithm

    let sha256_oid = ObjectIdentifier::try_from("1.2.840.113549.1.1.11").unwrap();
    let signature_algorithm = AlgorithmIdentifier {
        algorithm: sha256_oid.into(),
        parameters: (),
    };
    check!(signature_algorithm: AlgorithmIdentifier in encoded[522..537]);

    // Full certificate

    let certificate = Certificate {
        tbs_certificate,
        signature_algorithm,
        signature_value: BitString::with_bytes(&encoded[542..1054]).into(),
    };
    check!(certificate: Certificate in encoded);
}
