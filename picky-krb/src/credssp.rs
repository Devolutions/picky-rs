use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    ExplicitContextTag4, IntegerAsn1, OctetStringAsn1, Optional,
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
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct TsCspDataDetail {
    pub key_spec: ExplicitContextTag0<IntegerAsn1>,
    #[serde(default)]
    pub card_name: Optional<Option<ExplicitContextTag1<OctetStringAsn1>>>,
    #[serde(default)]
    pub reader_name: Optional<Option<ExplicitContextTag2<OctetStringAsn1>>>,
    #[serde(default)]
    pub container_name: Optional<Option<ExplicitContextTag3<OctetStringAsn1>>>,
    #[serde(default)]
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
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
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
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct TsSmartCardCreds {
    pub pin: ExplicitContextTag0<OctetStringAsn1>,
    pub csp_data: ExplicitContextTag1<TsCspDataDetail>,
    #[serde(default)]
    pub user_hint: Optional<Option<ExplicitContextTag2<OctetStringAsn1>>>,
    #[serde(default)]
    pub domain_hint: Optional<Option<ExplicitContextTag3<OctetStringAsn1>>>,
}

/// [2.2.1.2.3.1 TSRemoteGuardPackageCred](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/173eee44-1a2c-463f-b909-c15db01e68d7)
///
/// ```not_rust
/// TSRemoteGuardPackageCred ::= SEQUENCE {
///         packageName [0] OCTET STRING,
///         credBuffer  [1] OCTET STRING
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct TsRemoteGuardPackageCred {
    pub package_name: ExplicitContextTag0<OctetStringAsn1>,
    pub cred_buffer: ExplicitContextTag1<OctetStringAsn1>,
}

/// [2.2.1.2.3 TSRemoteGuardCreds](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/7ef8229c-44ea-4c1b-867f-00369b882b38)
///
/// ```not_rust
/// TSRemoteGuardCreds ::= SEQUENCE {
///         logonCred         [0] TSRemoteGuardPackageCred,
///         supplementalCreds [1] SEQUENCE OF TSRemoteGuardPackageCred OPTIONAL
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct TsRemoteGuardCreds {
    pub logon_cred: ExplicitContextTag0<TsRemoteGuardPackageCred>,
    #[serde(default)]
    pub supplemental_creds: Optional<Option<ExplicitContextTag1<Asn1SequenceOf<TsRemoteGuardPackageCred>>>>,
}

/// [2.2.1.2 TSCredentials](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/94a1ab00-5500-42fd-8d3d-7a84e6c2cf03)
///
/// ```not_rust
/// TSCredentials ::= SEQUENCE {
///         credType    [0] INTEGER,
///         credentials [1] OCTET STRING
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct TsCredentials {
    pub cred_type: ExplicitContextTag0<IntegerAsn1>,
    pub credentials: ExplicitContextTag1<OctetStringAsn1>,
}

#[cfg(test)]
mod tests {
    use picky_asn1::wrapper::{
        Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
        ExplicitContextTag4, IntegerAsn1, OctetStringAsn1, Optional,
    };

    use crate::constants::cred_ssp::{AT_KEYEXCHANGE, TS_PASSWORD_CREDS, TS_REMOTE_GUARD_CREDS, TS_SMART_CARD_CREDS};
    use crate::credssp::{TsCredentials, TsPasswordCreds};

    use super::{TsCspDataDetail, TsRemoteGuardCreds, TsRemoteGuardPackageCred, TsSmartCardCreds};

    #[test]
    fn remote_guard_creds_encoding_matches_ms_cssp_layout() {
        let package = TsRemoteGuardPackageCred {
            package_name: ExplicitContextTag0::from(OctetStringAsn1::from(vec![b'K', 0])),
            cred_buffer: ExplicitContextTag1::from(OctetStringAsn1::from(vec![1, 2, 3])),
        };
        let package_raw = [
            0x30, 0x0d, 0xa0, 0x04, 0x04, 0x02, b'K', 0x00, 0xa1, 0x05, 0x04, 0x03, 0x01, 0x02, 0x03,
        ];
        assert_eq!(picky_asn1_der::to_vec(&package).unwrap(), package_raw);
        assert_eq!(
            picky_asn1_der::from_bytes::<TsRemoteGuardPackageCred>(&package_raw).unwrap(),
            package
        );

        let creds = TsRemoteGuardCreds {
            logon_cred: ExplicitContextTag0::from(package),
            supplemental_creds: Optional::from(None),
        };
        let expected_raw = [
            0x30, 0x11, 0xa0, 0x0f, 0x30, 0x0d, 0xa0, 0x04, 0x04, 0x02, b'K', 0x00, 0xa1, 0x05, 0x04, 0x03, 0x01, 0x02,
            0x03,
        ];
        assert_eq!(picky_asn1_der::to_vec(&creds).unwrap(), expected_raw);
        assert_eq!(
            picky_asn1_der::from_bytes::<TsRemoteGuardCreds>(&expected_raw).unwrap(),
            creds
        );
        assert!(picky_asn1_der::from_bytes::<TsRemoteGuardCreds>(&[0x30, 0x00]).is_err());
        assert!(picky_asn1_der::from_bytes::<TsRemoteGuardCreds>(&expected_raw[..expected_raw.len() - 1]).is_err());

        let with_empty_supplemental = TsRemoteGuardCreds {
            supplemental_creds: Optional::from(Some(ExplicitContextTag1::from(Asn1SequenceOf::from(vec![])))),
            ..creds
        };
        let expected_raw = [
            0x30, 0x15, 0xa0, 0x0f, 0x30, 0x0d, 0xa0, 0x04, 0x04, 0x02, b'K', 0x00, 0xa1, 0x05, 0x04, 0x03, 0x01, 0x02,
            0x03, 0xa1, 0x02, 0x30, 0x00,
        ];
        assert_eq!(picky_asn1_der::to_vec(&with_empty_supplemental).unwrap(), expected_raw);
        assert_eq!(
            picky_asn1_der::from_bytes::<TsRemoteGuardCreds>(&expected_raw).unwrap(),
            with_empty_supplemental
        );
    }

    #[test]
    fn ts_credentials_remote_guard_with_supplemental_creds() {
        let remote_guard = TsRemoteGuardCreds {
            logon_cred: ExplicitContextTag0::from(TsRemoteGuardPackageCred {
                package_name: ExplicitContextTag0::from(OctetStringAsn1::from(vec![b'K', 0])),
                cred_buffer: ExplicitContextTag1::from(OctetStringAsn1::from(vec![1])),
            }),
            supplemental_creds: Optional::from(Some(ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                TsRemoteGuardPackageCred {
                    package_name: ExplicitContextTag0::from(OctetStringAsn1::from(vec![b'N', 0])),
                    cred_buffer: ExplicitContextTag1::from(OctetStringAsn1::from(vec![2])),
                },
                TsRemoteGuardPackageCred {
                    package_name: ExplicitContextTag0::from(OctetStringAsn1::from(vec![b'P', 0])),
                    cred_buffer: ExplicitContextTag1::from(OctetStringAsn1::from(vec![3])),
                },
            ])))),
        };
        let remote_guard_raw = [
            0x30, 0x2d, 0xa0, 0x0d, 0x30, 0x0b, 0xa0, 0x04, 0x04, 0x02, b'K', 0, 0xa1, 0x03, 0x04, 0x01, 1, 0xa1, 0x1c,
            0x30, 0x1a, 0x30, 0x0b, 0xa0, 0x04, 0x04, 0x02, b'N', 0, 0xa1, 0x03, 0x04, 0x01, 2, 0x30, 0x0b, 0xa0, 0x04,
            0x04, 0x02, b'P', 0, 0xa1, 0x03, 0x04, 0x01, 3,
        ];
        assert_eq!(picky_asn1_der::to_vec(&remote_guard).unwrap(), remote_guard_raw);
        assert_eq!(
            picky_asn1_der::from_bytes::<TsRemoteGuardCreds>(&remote_guard_raw).unwrap(),
            remote_guard
        );

        let credentials = TsCredentials {
            cred_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![TS_REMOTE_GUARD_CREDS])),
            credentials: ExplicitContextTag1::from(OctetStringAsn1::from(remote_guard_raw.to_vec())),
        };
        let expected_raw = [
            0x30, 0x38, 0xa0, 0x03, 0x02, 0x01, 0x06, 0xa1, 0x31, 0x04, 0x2f, 0x30, 0x2d, 0xa0, 0x0d, 0x30, 0x0b, 0xa0,
            0x04, 0x04, 0x02, b'K', 0, 0xa1, 0x03, 0x04, 0x01, 1, 0xa1, 0x1c, 0x30, 0x1a, 0x30, 0x0b, 0xa0, 0x04, 0x04,
            0x02, b'N', 0, 0xa1, 0x03, 0x04, 0x01, 2, 0x30, 0x0b, 0xa0, 0x04, 0x04, 0x02, b'P', 0, 0xa1, 0x03, 0x04,
            0x01, 3,
        ];
        assert_eq!(picky_asn1_der::to_vec(&credentials).unwrap(), expected_raw);
        assert_eq!(
            picky_asn1_der::from_bytes::<TsCredentials>(&expected_raw).unwrap(),
            credentials
        );
    }

    #[test]
    fn ts_password_creds() {
        let expected_raw = [
            48, 66, 160, 24, 4, 22, 101, 0, 120, 0, 97, 0, 109, 0, 112, 0, 108, 0, 101, 0, 46, 0, 99, 0, 111, 0, 109,
            0, 161, 10, 4, 8, 112, 0, 119, 0, 49, 0, 51, 0, 162, 26, 4, 24, 113, 0, 113, 0, 113, 0, 81, 0, 81, 0, 81,
            0, 49, 0, 49, 0, 49, 0, 33, 0, 33, 0, 33, 0,
        ];
        let expected = TsPasswordCreds {
            domain_name: ExplicitContextTag0::from(OctetStringAsn1::from(vec![
                101, 0, 120, 0, 97, 0, 109, 0, 112, 0, 108, 0, 101, 0, 46, 0, 99, 0, 111, 0, 109, 0,
            ])),
            user_name: ExplicitContextTag1::from(OctetStringAsn1::from(vec![112, 0, 119, 0, 49, 0, 51, 0])),
            password: ExplicitContextTag2::from(OctetStringAsn1::from(vec![
                113, 0, 113, 0, 113, 0, 81, 0, 81, 0, 81, 0, 49, 0, 49, 0, 49, 0, 33, 0, 33, 0, 33, 0,
            ])),
        };

        let password_creds: TsPasswordCreds = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let password_creds_raw = picky_asn1_der::to_vec(&password_creds).unwrap();

        assert_eq!(password_creds, expected);
        assert_eq!(password_creds_raw, expected_raw);
    }

    #[test]
    fn ts_smart_card_creds() {
        let expected_raw = [
            48, 130, 1, 34, 160, 26, 4, 24, 50, 0, 49, 0, 52, 0, 54, 0, 53, 0, 51, 0, 50, 0, 49, 0, 52, 0, 54, 0, 53,
            0, 51, 0, 161, 130, 1, 2, 48, 129, 255, 160, 3, 2, 1, 1, 161, 16, 4, 14, 86, 0, 83, 0, 67, 0, 116, 0, 101,
            0, 115, 0, 116, 0, 162, 62, 4, 60, 77, 0, 105, 0, 99, 0, 114, 0, 111, 0, 115, 0, 111, 0, 102, 0, 116, 0,
            32, 0, 86, 0, 105, 0, 114, 0, 116, 0, 117, 0, 97, 0, 108, 0, 32, 0, 83, 0, 109, 0, 97, 0, 114, 0, 116, 0,
            32, 0, 67, 0, 97, 0, 114, 0, 100, 0, 32, 0, 48, 0, 163, 80, 4, 78, 116, 0, 101, 0, 45, 0, 82, 0, 68, 0, 80,
            0, 115, 0, 109, 0, 97, 0, 114, 0, 116, 0, 99, 0, 97, 0, 114, 0, 100, 0, 108, 0, 111, 0, 103, 0, 111, 0,
            110, 0, 53, 0, 45, 0, 56, 0, 102, 0, 102, 0, 51, 0, 97, 0, 51, 0, 56, 0, 101, 0, 45, 0, 99, 0, 54, 0, 45,
            0, 53, 0, 48, 0, 57, 0, 56, 0, 55, 0, 164, 84, 4, 82, 77, 0, 105, 0, 99, 0, 114, 0, 111, 0, 115, 0, 111, 0,
            102, 0, 116, 0, 32, 0, 66, 0, 97, 0, 115, 0, 101, 0, 32, 0, 83, 0, 109, 0, 97, 0, 114, 0, 116, 0, 32, 0,
            67, 0, 97, 0, 114, 0, 100, 0, 32, 0, 67, 0, 114, 0, 121, 0, 112, 0, 116, 0, 111, 0, 32, 0, 80, 0, 114, 0,
            111, 0, 118, 0, 105, 0, 100, 0, 101, 0, 114, 0,
        ];
        let expected_smart_card_creds = TsSmartCardCreds {
            pin: ExplicitContextTag0::from(OctetStringAsn1::from(vec![
                50, 0, 49, 0, 52, 0, 54, 0, 53, 0, 51, 0, 50, 0, 49, 0, 52, 0, 54, 0, 53, 0, 51, 0,
            ])),
            csp_data: ExplicitContextTag1::from(TsCspDataDetail {
                key_spec: ExplicitContextTag0::from(IntegerAsn1::from(vec![AT_KEYEXCHANGE])),
                card_name: Optional::from(Some(ExplicitContextTag1::from(OctetStringAsn1::from(vec![
                    86, 0, 83, 0, 67, 0, 116, 0, 101, 0, 115, 0, 116, 0,
                ])))),
                reader_name: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(vec![
                    77, 0, 105, 0, 99, 0, 114, 0, 111, 0, 115, 0, 111, 0, 102, 0, 116, 0, 32, 0, 86, 0, 105, 0, 114, 0,
                    116, 0, 117, 0, 97, 0, 108, 0, 32, 0, 83, 0, 109, 0, 97, 0, 114, 0, 116, 0, 32, 0, 67, 0, 97, 0,
                    114, 0, 100, 0, 32, 0, 48, 0,
                ])))),
                container_name: Optional::from(Some(ExplicitContextTag3::from(OctetStringAsn1::from(vec![
                    116, 0, 101, 0, 45, 0, 82, 0, 68, 0, 80, 0, 115, 0, 109, 0, 97, 0, 114, 0, 116, 0, 99, 0, 97, 0,
                    114, 0, 100, 0, 108, 0, 111, 0, 103, 0, 111, 0, 110, 0, 53, 0, 45, 0, 56, 0, 102, 0, 102, 0, 51, 0,
                    97, 0, 51, 0, 56, 0, 101, 0, 45, 0, 99, 0, 54, 0, 45, 0, 53, 0, 48, 0, 57, 0, 56, 0, 55, 0,
                ])))),
                csp_name: Optional::from(Some(ExplicitContextTag4::from(OctetStringAsn1::from(vec![
                    77, 0, 105, 0, 99, 0, 114, 0, 111, 0, 115, 0, 111, 0, 102, 0, 116, 0, 32, 0, 66, 0, 97, 0, 115, 0,
                    101, 0, 32, 0, 83, 0, 109, 0, 97, 0, 114, 0, 116, 0, 32, 0, 67, 0, 97, 0, 114, 0, 100, 0, 32, 0,
                    67, 0, 114, 0, 121, 0, 112, 0, 116, 0, 111, 0, 32, 0, 80, 0, 114, 0, 111, 0, 118, 0, 105, 0, 100,
                    0, 101, 0, 114, 0,
                ])))),
            }),
            user_hint: Optional::from(None),
            domain_hint: Optional::from(None),
        };

        let smart_card_creds: TsSmartCardCreds = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let smart_card_creds_raw = picky_asn1_der::to_vec(&smart_card_creds).unwrap();

        assert_eq!(smart_card_creds, expected_smart_card_creds);
        assert_eq!(smart_card_creds_raw, expected_raw);
    }

    #[test]
    fn ts_credentials_smart_card() {
        let expected_raw = [
            48, 130, 1, 51, 160, 3, 2, 1, 2, 161, 130, 1, 42, 4, 130, 1, 38, 48, 130, 1, 34, 160, 26, 4, 24, 50, 0, 49,
            0, 52, 0, 54, 0, 53, 0, 51, 0, 50, 0, 49, 0, 52, 0, 54, 0, 53, 0, 51, 0, 161, 130, 1, 2, 48, 129, 255, 160,
            3, 2, 1, 1, 161, 16, 4, 14, 86, 0, 83, 0, 67, 0, 116, 0, 101, 0, 115, 0, 116, 0, 162, 62, 4, 60, 77, 0,
            105, 0, 99, 0, 114, 0, 111, 0, 115, 0, 111, 0, 102, 0, 116, 0, 32, 0, 86, 0, 105, 0, 114, 0, 116, 0, 117,
            0, 97, 0, 108, 0, 32, 0, 83, 0, 109, 0, 97, 0, 114, 0, 116, 0, 32, 0, 67, 0, 97, 0, 114, 0, 100, 0, 32, 0,
            48, 0, 163, 80, 4, 78, 116, 0, 101, 0, 45, 0, 82, 0, 68, 0, 80, 0, 115, 0, 109, 0, 97, 0, 114, 0, 116, 0,
            99, 0, 97, 0, 114, 0, 100, 0, 108, 0, 111, 0, 103, 0, 111, 0, 110, 0, 53, 0, 45, 0, 56, 0, 102, 0, 102, 0,
            51, 0, 97, 0, 51, 0, 56, 0, 101, 0, 45, 0, 99, 0, 54, 0, 45, 0, 53, 0, 48, 0, 57, 0, 56, 0, 55, 0, 164, 84,
            4, 82, 77, 0, 105, 0, 99, 0, 114, 0, 111, 0, 115, 0, 111, 0, 102, 0, 116, 0, 32, 0, 66, 0, 97, 0, 115, 0,
            101, 0, 32, 0, 83, 0, 109, 0, 97, 0, 114, 0, 116, 0, 32, 0, 67, 0, 97, 0, 114, 0, 100, 0, 32, 0, 67, 0,
            114, 0, 121, 0, 112, 0, 116, 0, 111, 0, 32, 0, 80, 0, 114, 0, 111, 0, 118, 0, 105, 0, 100, 0, 101, 0, 114,
            0,
        ];
        let expected_smart_card_creds = TsSmartCardCreds {
            pin: ExplicitContextTag0::from(OctetStringAsn1::from(vec![
                50, 0, 49, 0, 52, 0, 54, 0, 53, 0, 51, 0, 50, 0, 49, 0, 52, 0, 54, 0, 53, 0, 51, 0,
            ])),
            csp_data: ExplicitContextTag1::from(TsCspDataDetail {
                key_spec: ExplicitContextTag0::from(IntegerAsn1::from(vec![AT_KEYEXCHANGE])),
                card_name: Optional::from(Some(ExplicitContextTag1::from(OctetStringAsn1::from(vec![
                    86, 0, 83, 0, 67, 0, 116, 0, 101, 0, 115, 0, 116, 0,
                ])))),
                reader_name: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(vec![
                    77, 0, 105, 0, 99, 0, 114, 0, 111, 0, 115, 0, 111, 0, 102, 0, 116, 0, 32, 0, 86, 0, 105, 0, 114, 0,
                    116, 0, 117, 0, 97, 0, 108, 0, 32, 0, 83, 0, 109, 0, 97, 0, 114, 0, 116, 0, 32, 0, 67, 0, 97, 0,
                    114, 0, 100, 0, 32, 0, 48, 0,
                ])))),
                container_name: Optional::from(Some(ExplicitContextTag3::from(OctetStringAsn1::from(vec![
                    116, 0, 101, 0, 45, 0, 82, 0, 68, 0, 80, 0, 115, 0, 109, 0, 97, 0, 114, 0, 116, 0, 99, 0, 97, 0,
                    114, 0, 100, 0, 108, 0, 111, 0, 103, 0, 111, 0, 110, 0, 53, 0, 45, 0, 56, 0, 102, 0, 102, 0, 51, 0,
                    97, 0, 51, 0, 56, 0, 101, 0, 45, 0, 99, 0, 54, 0, 45, 0, 53, 0, 48, 0, 57, 0, 56, 0, 55, 0,
                ])))),
                csp_name: Optional::from(Some(ExplicitContextTag4::from(OctetStringAsn1::from(vec![
                    77, 0, 105, 0, 99, 0, 114, 0, 111, 0, 115, 0, 111, 0, 102, 0, 116, 0, 32, 0, 66, 0, 97, 0, 115, 0,
                    101, 0, 32, 0, 83, 0, 109, 0, 97, 0, 114, 0, 116, 0, 32, 0, 67, 0, 97, 0, 114, 0, 100, 0, 32, 0,
                    67, 0, 114, 0, 121, 0, 112, 0, 116, 0, 111, 0, 32, 0, 80, 0, 114, 0, 111, 0, 118, 0, 105, 0, 100,
                    0, 101, 0, 114, 0,
                ])))),
            }),
            user_hint: Optional::from(None),
            domain_hint: Optional::from(None),
        };
        let expected = TsCredentials {
            cred_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![TS_SMART_CARD_CREDS])),
            credentials: ExplicitContextTag1::from(OctetStringAsn1::from(
                picky_asn1_der::to_vec(&expected_smart_card_creds).unwrap(),
            )),
        };

        let credentials: TsCredentials = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let credentials_raw = picky_asn1_der::to_vec(&credentials).unwrap();

        assert_eq!(credentials, expected);
        assert_eq!(credentials_raw, expected_raw);
    }

    #[test]
    fn ts_credentials_password() {
        let expected_raw = [
            48, 77, 160, 3, 2, 1, 1, 161, 70, 4, 68, 48, 66, 160, 24, 4, 22, 101, 0, 120, 0, 97, 0, 109, 0, 112, 0,
            108, 0, 101, 0, 46, 0, 99, 0, 111, 0, 109, 0, 161, 10, 4, 8, 112, 0, 119, 0, 49, 0, 51, 0, 162, 26, 4, 24,
            113, 0, 113, 0, 113, 0, 81, 0, 81, 0, 81, 0, 49, 0, 49, 0, 49, 0, 33, 0, 33, 0, 33, 0,
        ];
        let expected_password_creds = TsPasswordCreds {
            domain_name: ExplicitContextTag0::from(OctetStringAsn1::from(vec![
                101, 0, 120, 0, 97, 0, 109, 0, 112, 0, 108, 0, 101, 0, 46, 0, 99, 0, 111, 0, 109, 0,
            ])),
            user_name: ExplicitContextTag1::from(OctetStringAsn1::from(vec![112, 0, 119, 0, 49, 0, 51, 0])),
            password: ExplicitContextTag2::from(OctetStringAsn1::from(vec![
                113, 0, 113, 0, 113, 0, 81, 0, 81, 0, 81, 0, 49, 0, 49, 0, 49, 0, 33, 0, 33, 0, 33, 0,
            ])),
        };
        let expected = TsCredentials {
            cred_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![TS_PASSWORD_CREDS])),
            credentials: ExplicitContextTag1::from(OctetStringAsn1::from(
                picky_asn1_der::to_vec(&expected_password_creds).unwrap(),
            )),
        };

        let credentials: TsCredentials = picky_asn1_der::from_bytes(&expected_raw).unwrap();
        let credentials_raw = picky_asn1_der::to_vec(&credentials).unwrap();

        assert_eq!(credentials, expected);
        assert_eq!(credentials_raw, expected_raw);
    }
}
