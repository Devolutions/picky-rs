use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use serde::{Deserialize, Serialize};

use crate::data_types::KerberosTime;

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
