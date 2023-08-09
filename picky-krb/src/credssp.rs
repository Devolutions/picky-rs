use picky_asn1::wrapper::{
    ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3, ExplicitContextTag4,
    IntegerAsn1, OctetStringAsn1, Optional,
};
use serde::{Deserialize, Serialize};

/// [2.2.1.2.2.1 TSCspDataDetail](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/34ee27b3-5791-43bb-9201-076054b58123)
///
/// ```not_rust
/// TSCspDataDetail ::= SEQUENCE {
///         keySpec       [0] INTEGER,
///         cardName      [1] OCTET STRING OPTIONAL,
///         readerName    [2] OCTET STRING OPTIONAL,
///         containerName [3] OCTET STRING OPTIONAL,
///         cspName       [4] OCTET STRING OPTIONAL
/// }
/// ```
#[derive(Serialize, Deserialize)]
pub struct TsCspDataDetail {
    pub key_spec: ExplicitContextTag0<IntegerAsn1>,
    pub card_name: Optional<Option<ExplicitContextTag1<OctetStringAsn1>>>,
    pub reader_name: Optional<Option<ExplicitContextTag2<OctetStringAsn1>>>,
    pub container_name: Optional<Option<ExplicitContextTag3<OctetStringAsn1>>>,
    pub csp_name: Optional<Option<ExplicitContextTag4<OctetStringAsn1>>>,
}

/// [2.2.1.2.2.1 TSCspDataDetail](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/34ee27b3-5791-43bb-9201-076054b58123)
///
/// ```not_rust
/// TSPasswordCreds ::= SEQUENCE {
///         domainName  [0] OCTET STRING,
///         userName    [1] OCTET STRING,
///         password    [2] OCTET STRING
/// }
/// ```
#[derive(Serialize, Deserialize)]
pub struct TsPasswordCreds {
    pub domain_name: ExplicitContextTag0<OctetStringAsn1>,
    pub user_name: ExplicitContextTag1<OctetStringAsn1>,
    pub password: ExplicitContextTag2<OctetStringAsn1>,
}

/// [2.2.1.2.2 TSSmartCardCreds](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/4251d165-cf01-4513-a5d8-39ee4a98b7a4)
///
/// ```not_rust
/// TSSmartCardCreds ::= SEQUENCE {
///         pin         [0] OCTET STRING,
///         cspData     [1] TSCspDataDetail,
///         userHint    [2] OCTET STRING OPTIONAL,
///         domainHint  [3] OCTET STRING OPTIONAL
/// }
/// ```
#[derive(Serialize, Deserialize)]
pub struct TsSmartCardCreds {
    pub pin: ExplicitContextTag0<OctetStringAsn1>,
    pub csp_data: ExplicitContextTag1<TsCspDataDetail>,
    pub user_hint: Optional<Option<ExplicitContextTag2<OctetStringAsn1>>>,
    pub domain_hint: Optional<Option<ExplicitContextTag3<OctetStringAsn1>>>,
}

/// [2.2.1.2 TSCredentials](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/94a1ab00-5500-42fd-8d3d-7a84e6c2cf03)
///
/// ```not_rust
/// TSCredentials ::= SEQUENCE {
///         credType    [0] INTEGER,
///         credentials [1] OCTET STRING
/// }
/// ```
#[derive(Serialize, Deserialize)]
pub struct TsCredentials {
    pub cred_type: ExplicitContextTag0<IntegerAsn1>,
    pub credentials: ExplicitContextTag1<OctetStringAsn1>,
}
