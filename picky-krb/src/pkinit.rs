use picky_asn1::wrapper::{
    Asn1SequenceOf, Asn1SetOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ImplicitContextTag0, IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use serde::{Deserialize, Serialize};

use crate::data_types::{KerberosTime, PrincipalName, Realm};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Pku2uValueInner<T> {
    pub identifier: ObjectIdentifierAsn1,
    pub value: T,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Pku2uValue<T> {
    pub inner: Asn1SetOf<Pku2uValueInner<T>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Pku2uNegoReqMetadata {
    pub inner: ImplicitContextTag0<OctetStringAsn1>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Pku2uNegoBody {
    pub realm: ExplicitContextTag0<Realm>,
    pub sname: ExplicitContextTag1<PrincipalName>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Pku2uNegoReq {
    pub metadata: ExplicitContextTag0<Asn1SequenceOf<Pku2uNegoReqMetadata>>,
    pub body: ExplicitContextTag1<Pku2uNegoBody>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Pku2uNegoRep {
    pub metadata: ExplicitContextTag0<Asn1SequenceOf<Pku2uNegoReqMetadata>>,
}

/// [Generation of Client Request](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.1)
/// ```not_rust
/// ExternalPrincipalIdentifier ::= SEQUENCE {
///    subjectName             [0] IMPLICIT OCTET STRING OPTIONAL,
///    issuerAndSerialNumber   [1] IMPLICIT OCTET STRING OPTIONAL,
///    subjectKeyIdentifier    [2] IMPLICIT OCTET STRING OPTIONAL,
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct ExternalPrincipalIdentifier {
    #[serde(default)]
    subject_name: Optional<Option<ExplicitContextTag0<OctetStringAsn1>>>,
    #[serde(default)]
    issuer_and_serial_number: Optional<Option<ExplicitContextTag1<OctetStringAsn1>>>,
    #[serde(default)]
    subject_key_identifier: Optional<Option<ExplicitContextTag2<OctetStringAsn1>>>,
}

/// [Generation of Client Request](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.1)
/// ```not_rust
/// PA-PK-AS-REQ ::= SEQUENCE {
///    signedAuthPack          [0] IMPLICIT OCTET STRING,
///    trustedCertifiers       [1] SEQUENCE OF ExternalPrincipalIdentifier OPTIONAL,
///    kdcPkId                 [2] IMPLICIT OCTET STRING OPTIONAL,
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct PaPkAsReq {
    signed_auth_pack: ExplicitContextTag0<OctetStringAsn1>,
    #[serde(default)]
    trusted_certifiers: Optional<Option<ExplicitContextTag1<Asn1SequenceOf<ExternalPrincipalIdentifier>>>>,
    #[serde(default)]
    kdc_pk_id: Optional<Option<ExplicitContextTag2<OctetStringAsn1>>>,
}

/// [Generation of Client Request](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.1)
/// ```not_rust
/// PKAuthenticator ::= SEQUENCE {
///    cusec                   [0] INTEGER (0..999999),
///    ctime                   [1] KerberosTime,
///    nonce                   [2] INTEGER (0..4294967295),
///    paChecksum              [3] OCTET STRING OPTIONAL,
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct PkAuthenticator {
    cusec: ExplicitContextTag0<IntegerAsn1>,
    ctime: ExplicitContextTag1<KerberosTime>,
    nonce: ExplicitContextTag2<IntegerAsn1>,
    #[serde(default)]
    pa_checksum: Optional<Option<ExplicitContextTag3<OctetStringAsn1>>>,
}

/// [Generation of Client Request](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.1)
/// ```not_rust
/// DHNonce ::= OCTET STRING
/// ```
pub type DhNonce = OctetStringAsn1;

/// [Generation of Client Request](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.1)
/// ```not_rust
/// AuthPack ::= SEQUENCE {
///    pkAuthenticator         [0] PKAuthenticator,
///    clientPublicValue       [1] SubjectPublicKeyInfo OPTIONAL,
///    supportedCMSTypes       [2] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
///    clientDHNonce           [3] DHNonce OPTIONAL,
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct AuthPack {
    pk_authenticator: ExplicitContextTag0<PkAuthenticator>,
    #[serde(default)]
    client_public_value: Optional<Option<ExplicitContextTag1<SubjectPublicKeyInfo>>>,
    #[serde(default)]
    supported_cms_types: Optional<Option<ExplicitContextTag2<Asn1SequenceOf<AlgorithmIdentifier>>>>,
    #[serde(default)]
    client_dh_nonce: Optional<Option<ExplicitContextTag3<DhNonce>>>,
}

/// [Generation of KDC Reply](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3)
/// ```not_rust
/// DHRepInfo ::= SEQUENCE {
///    dhSignedData            [0] IMPLICIT OCTET STRING,
///    serverDHNonce           [1] DHNonce OPTIONAL,
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct DhRepInfo {
    dh_signed_data: ExplicitContextTag0<OctetStringAsn1>,
    #[serde(default)]
    server_dh_nonce: Optional<Option<DhNonce>>,
}

/// [Generation of KDC Reply](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3)
/// ```not_rust
/// PA-PK-AS-REP ::= CHOICE {
///    dhInfo                  [0] DHRepInfo,
///    encKeyPack              [1] IMPLICIT OCTET STRING,
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct PaPkAsRep {
    dh_info: ExplicitContextTag0<DhRepInfo>,
    enc_key_pack: ExplicitContextTag1<OctetStringAsn1>,
}

/// [Generation of KDC Reply](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3)
/// ```not_rust
/// KDCDHKeyInfo ::= SEQUENCE {
///    subjectPublicKey        [0] BIT STRING,
///    nonce                   [1] INTEGER (0..4294967295),
///    dhKeyExpiration         [2] KerberosTime OPTIONAL,
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct KdcDhKeyInfo {
    subject_public_key: ExplicitContextTag0<BitStringAsn1>,
    nonce: ExplicitContextTag1<IntegerAsn1>,
    #[serde(default)]
    dh_key_expiration: Optional<Option<ExplicitContextTag2<KerberosTime>>>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use oid::ObjectIdentifier;
    use picky_asn1::restricted_string::{BMPString, IA5String, PrintableString};
    use picky_asn1::tag::Tag;
    use picky_asn1::wrapper::{
        Asn1SequenceOf, Asn1SetOf, BMPStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ImplicitContextTag0,
        IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1, PrintableStringAsn1,
    };

    use crate::data_types::{KerberosStringAsn1, PrincipalName};

    use super::{Pku2uNegoBody, Pku2uNegoRep, Pku2uNegoReq, Pku2uNegoReqMetadata, Pku2uValue, Pku2uValueInner};

    #[test]
    fn pku2u_nego_req_encode() {
        let message = Pku2uNegoReq {
            metadata: ExplicitContextTag0::from(Asn1SequenceOf::from(vec![
                Pku2uNegoReqMetadata {
                    inner: ImplicitContextTag0::from(OctetStringAsn1::from(vec![
                        48, 77, 49, 75, 48, 73, 6, 3, 85, 4, 3, 30, 66, 0, 77, 0, 83, 0, 45, 0, 79, 0, 114, 0, 103, 0,
                        97, 0, 110, 0, 105, 0, 122, 0, 97, 0, 116, 0, 105, 0, 111, 0, 110, 0, 45, 0, 80, 0, 50, 0, 80,
                        0, 45, 0, 65, 0, 99, 0, 99, 0, 101, 0, 115, 0, 115, 0, 32, 0, 91, 0, 50, 0, 48, 0, 50, 0, 49,
                        0, 93,
                    ])),
                },
                Pku2uNegoReqMetadata {
                    inner: ImplicitContextTag0::from(OctetStringAsn1::from(vec![
                        48, 77, 49, 75, 48, 73, 6, 3, 85, 4, 3, 30, 66, 0, 77, 0, 83, 0, 45, 0, 79, 0, 114, 0, 103, 0,
                        97, 0, 110, 0, 105, 0, 122, 0, 97, 0, 116, 0, 105, 0, 111, 0, 110, 0, 45, 0, 80, 0, 50, 0, 80,
                        0, 45, 0, 65, 0, 99, 0, 99, 0, 101, 0, 115, 0, 115, 0, 32, 0, 91, 0, 50, 0, 48, 0, 50, 0, 49,
                        0, 93,
                    ])),
                },
            ])),
            body: ExplicitContextTag1::from(Pku2uNegoBody {
                realm: ExplicitContextTag0::from(KerberosStringAsn1::from(
                    IA5String::from_string("WELLKNOWN:PKU2U".into()).unwrap(),
                )),
                sname: ExplicitContextTag1::from(PrincipalName {
                    name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![2])),
                    name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                        KerberosStringAsn1::from(IA5String::from_string("TERMSRV".into()).unwrap()),
                        KerberosStringAsn1::from(IA5String::from_string("AZRDOWN-W10".into()).unwrap()),
                    ])),
                }),
            }),
        };

        let encoded = picky_asn1_der::to_vec(&message).unwrap();

        assert_eq!(
            &[
                48, 129, 230, 160, 129, 169, 48, 129, 166, 48, 81, 128, 79, 48, 77, 49, 75, 48, 73, 6, 3, 85, 4, 3, 30,
                66, 0, 77, 0, 83, 0, 45, 0, 79, 0, 114, 0, 103, 0, 97, 0, 110, 0, 105, 0, 122, 0, 97, 0, 116, 0, 105,
                0, 111, 0, 110, 0, 45, 0, 80, 0, 50, 0, 80, 0, 45, 0, 65, 0, 99, 0, 99, 0, 101, 0, 115, 0, 115, 0, 32,
                0, 91, 0, 50, 0, 48, 0, 50, 0, 49, 0, 93, 48, 81, 128, 79, 48, 77, 49, 75, 48, 73, 6, 3, 85, 4, 3, 30,
                66, 0, 77, 0, 83, 0, 45, 0, 79, 0, 114, 0, 103, 0, 97, 0, 110, 0, 105, 0, 122, 0, 97, 0, 116, 0, 105,
                0, 111, 0, 110, 0, 45, 0, 80, 0, 50, 0, 80, 0, 45, 0, 65, 0, 99, 0, 99, 0, 101, 0, 115, 0, 115, 0, 32,
                0, 91, 0, 50, 0, 48, 0, 50, 0, 49, 0, 93, 161, 56, 48, 54, 160, 17, 27, 15, 87, 69, 76, 76, 75, 78, 79,
                87, 78, 58, 80, 75, 85, 50, 85, 161, 33, 48, 31, 160, 3, 2, 1, 2, 161, 24, 48, 22, 27, 7, 84, 69, 82,
                77, 83, 82, 86, 27, 11, 65, 90, 82, 68, 79, 87, 78, 45, 87, 49, 48
            ],
            encoded.as_slice()
        );
    }

    #[test]
    fn pku2u_value_decode() {
        let raw_data = [
            48, 35, 49, 33, 48, 31, 6, 3, 85, 4, 3, 19, 24, 84, 111, 107, 101, 110, 32, 83, 105, 103, 110, 105, 110,
            103, 32, 80, 117, 98, 108, 105, 99, 32, 75, 101, 121,
        ];

        let pku2u_value: Pku2uValue<PrintableStringAsn1> = picky_asn1_der::from_bytes(&raw_data).unwrap();

        assert_eq!(
            Pku2uValue {
                inner: Asn1SetOf::from(vec![Pku2uValueInner {
                    identifier: ObjectIdentifierAsn1(ObjectIdentifier::try_from("2.5.4.3").unwrap()),
                    value: PrintableStringAsn1::from(PrintableString::from_str("Token Signing Public Key").unwrap()),
                }])
            },
            pku2u_value
        );
    }

    #[test]
    fn pku2u_value_encode() {
        let value = Pku2uValue {
            inner: Asn1SetOf::from(vec![Pku2uValueInner {
                identifier: ObjectIdentifierAsn1(ObjectIdentifier::try_from("2.5.4.3").unwrap()),
                value: BMPStringAsn1::from(BMPString::from_str("\0M\0S\0-\0O\0r\0g\0a\0n\0i\0z\0a\0t\0i\0o\0n\0-\0P\02\0P\0-\0A\0c\0c\0e\0s\0s\0 \0[\02\00\02\01\0]").unwrap()),
            }]),
        };

        let encoded = picky_asn1_der::to_vec(&value).unwrap();

        assert_eq!(
            &[
                48, 77, 49, 75, 48, 73, 6, 3, 85, 4, 3, 30, 66, 0, 77, 0, 83, 0, 45, 0, 79, 0, 114, 0, 103, 0, 97, 0,
                110, 0, 105, 0, 122, 0, 97, 0, 116, 0, 105, 0, 111, 0, 110, 0, 45, 0, 80, 0, 50, 0, 80, 0, 45, 0, 65,
                0, 99, 0, 99, 0, 101, 0, 115, 0, 115, 0, 32, 0, 91, 0, 50, 0, 48, 0, 50, 0, 49, 0, 93
            ],
            encoded.as_slice()
        );
    }

    #[test]
    fn pku2u_nego_rep_encode() {
        let nego_rep = Pku2uNegoRep {
            metadata: ExplicitContextTag0::from(Asn1SequenceOf::from(vec![
                Pku2uNegoReqMetadata {
                    inner: ImplicitContextTag0::from(OctetStringAsn1::from(vec![
                        48, 77, 49, 75, 48, 73, 6, 3, 85, 4, 3, 30, 66, 0, 77, 0, 83, 0, 45, 0, 79, 0, 114, 0, 103, 0,
                        97, 0, 110, 0, 105, 0, 122, 0, 97, 0, 116, 0, 105, 0, 111, 0, 110, 0, 45, 0, 80, 0, 50, 0, 80,
                        0, 45, 0, 65, 0, 99, 0, 99, 0, 101, 0, 115, 0, 115, 0, 32, 0, 91, 0, 50, 0, 48, 0, 50, 0, 49,
                        0, 93,
                    ])),
                },
                Pku2uNegoReqMetadata {
                    inner: ImplicitContextTag0::from(OctetStringAsn1::from(vec![
                        48, 35, 49, 33, 48, 31, 6, 3, 85, 4, 3, 19, 24, 84, 111, 107, 101, 110, 32, 83, 105, 103, 110,
                        105, 110, 103, 32, 80, 117, 98, 108, 105, 99, 32, 75, 101, 121,
                    ])),
                },
            ])),
        };

        let encoded = picky_asn1_der::to_vec(&nego_rep).unwrap();

        assert_eq!(
            &[
                48, 129, 128, 160, 126, 48, 124, 48, 81, 128, 79, 48, 77, 49, 75, 48, 73, 6, 3, 85, 4, 3, 30, 66, 0,
                77, 0, 83, 0, 45, 0, 79, 0, 114, 0, 103, 0, 97, 0, 110, 0, 105, 0, 122, 0, 97, 0, 116, 0, 105, 0, 111,
                0, 110, 0, 45, 0, 80, 0, 50, 0, 80, 0, 45, 0, 65, 0, 99, 0, 99, 0, 101, 0, 115, 0, 115, 0, 32, 0, 91,
                0, 50, 0, 48, 0, 50, 0, 49, 0, 93, 48, 39, 128, 37, 48, 35, 49, 33, 48, 31, 6, 3, 85, 4, 3, 19, 24, 84,
                111, 107, 101, 110, 32, 83, 105, 103, 110, 105, 110, 103, 32, 80, 117, 98, 108, 105, 99, 32, 75, 101,
                121
            ],
            encoded.as_slice()
        );
    }

    #[test]
    fn pku2u_nego_rep_decode() {
        let raw_data = [
            48, 129, 171, 160, 129, 168, 48, 129, 165, 48, 81, 128, 79, 48, 77, 49, 75, 48, 73, 6, 3, 85, 4, 3, 30, 66,
            0, 77, 0, 83, 0, 45, 0, 79, 0, 114, 0, 103, 0, 97, 0, 110, 0, 105, 0, 122, 0, 97, 0, 116, 0, 105, 0, 111,
            0, 110, 0, 45, 0, 80, 0, 50, 0, 80, 0, 45, 0, 65, 0, 99, 0, 99, 0, 101, 0, 115, 0, 115, 0, 32, 0, 91, 0,
            50, 0, 48, 0, 50, 0, 49, 0, 93, 48, 39, 128, 37, 48, 35, 49, 33, 48, 31, 6, 3, 85, 4, 3, 19, 24, 84, 111,
            107, 101, 110, 32, 83, 105, 103, 110, 105, 110, 103, 32, 80, 117, 98, 108, 105, 99, 32, 75, 101, 121, 48,
            39, 128, 37, 48, 35, 49, 33, 48, 31, 6, 3, 85, 4, 3, 19, 24, 84, 111, 107, 101, 110, 32, 83, 105, 103, 110,
            105, 110, 103, 32, 80, 117, 98, 108, 105, 99, 32, 75, 101, 121,
        ];

        let pku2u_nego_rep: Pku2uNegoRep = picky_asn1_der::from_bytes(&raw_data).unwrap();

        assert_eq!(
            Pku2uNegoRep {
                metadata: ExplicitContextTag0::from(Asn1SequenceOf::from(vec![
                    Pku2uNegoReqMetadata {
                        inner: ImplicitContextTag0::from(OctetStringAsn1::from(vec![
                            48, 77, 49, 75, 48, 73, 6, 3, 85, 4, 3, 30, 66, 0, 77, 0, 83, 0, 45, 0, 79, 0, 114, 0, 103,
                            0, 97, 0, 110, 0, 105, 0, 122, 0, 97, 0, 116, 0, 105, 0, 111, 0, 110, 0, 45, 0, 80, 0, 50,
                            0, 80, 0, 45, 0, 65, 0, 99, 0, 99, 0, 101, 0, 115, 0, 115, 0, 32, 0, 91, 0, 50, 0, 48, 0,
                            50, 0, 49, 0, 93
                        ]))
                    },
                    Pku2uNegoReqMetadata {
                        inner: ImplicitContextTag0::from(OctetStringAsn1::from(vec![
                            48, 35, 49, 33, 48, 31, 6, 3, 85, 4, 3, 19, 24, 84, 111, 107, 101, 110, 32, 83, 105, 103,
                            110, 105, 110, 103, 32, 80, 117, 98, 108, 105, 99, 32, 75, 101, 121
                        ]))
                    },
                    Pku2uNegoReqMetadata {
                        inner: ImplicitContextTag0::from(OctetStringAsn1::from(vec![
                            48, 35, 49, 33, 48, 31, 6, 3, 85, 4, 3, 19, 24, 84, 111, 107, 101, 110, 32, 83, 105, 103,
                            110, 105, 110, 103, 32, 80, 117, 98, 108, 105, 99, 32, 75, 101, 121
                        ]))
                    },
                ]))
            },
            pku2u_nego_rep
        );
    }

    #[test]
    fn test_tag() {
        let tag = Tag::from(0x80);

        println!("{:?}", tag);
        println!("{:?}", Tag::context_specific_constructed(0));
    }
}
