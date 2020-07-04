use crate::{AlgorithmIdentifier, Name, SubjectPublicKeyInfo};
use picky_asn1::wrapper::{ApplicationTag0, BitStringAsn1, HeaderOnly, Implicit};
use serde::{Deserialize, Serialize};

/// [RFC 2986 #4](https://tools.ietf.org/html/rfc2986#section-4)
///
/// ```not_rust
/// CertificationRequestInfo ::= SEQUENCE {
///      version       INTEGER { v1(0) } (v1,...),
///      subject       Name,
///      subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
///      attributes    [0] Attributes{{ CRIAttributes }}
/// }
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CertificationRequestInfo {
    pub version: u8,
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    /// Not yet supported
    pub attributes: Implicit<Option<HeaderOnly<ApplicationTag0<()>>>>,
}

impl CertificationRequestInfo {
    pub fn new(subject: Name, subject_public_key_info: SubjectPublicKeyInfo) -> Self {
        // It shall be 0 for this version of the standard.
        Self {
            version: 0,
            subject,
            subject_public_key_info,
            attributes: Implicit(Some(HeaderOnly::<ApplicationTag0<()>>::default())),
        }
    }
}

/// [RFC 2986 #4](https://tools.ietf.org/html/rfc2986#section-4)
///
/// ```not_rust
/// CertificationRequest ::= SEQUENCE {
///      certificationRequestInfo CertificationRequestInfo,
///      signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
///      signature          BIT STRING
/// }
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CertificationRequest {
    pub certification_request_info: CertificationRequestInfo,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: BitStringAsn1,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DirectoryName;
    use picky_asn1::{bit_string::BitString, restricted_string::PrintableString, wrapper::IntegerAsn1};
    use std::str::FromStr;

    #[test]
    fn deserialize_csr() {
        let encoded = base64::decode(
            "MIICYjCCAUoCAQAwHTEbMBkGA1UEAxMSdGVzdC5jb250b3NvLmxvY2FsMIIBIjAN\
            BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAym0At2TvEqP0mYVLJzGVpNXjugu/\
            kBpuKvXt/Vax4Bxnj3YzHTCpwkyZPytUC6zJ+q+uGh0e7gYQsYHJKjgoKEsS6gQ4\
            ZM3D/AQy0zqPUT0ruSKDWKK4f2d/2ijDs5R2LHj7DtNZBanCXU16Qp1O28su0QZK\
            OYbXzsJSpHp80dhqD6JUxXlSZzlVBp28CC9ryrE6w+kOQ38TZ1/mBJPsfmDeKBpm\
            3FRrfHtWt43eok/T6FhCLIzsqyCZ0UCQqkcLr+TfoftJe2nOHQ1sfk4keJ9iwA/f\
            hYv5rqUB3RUztSIhExwtYDwd+YovenhsL4sW/kjR29RTLUFPPXAelG9XPwIDAQAB\
            oAAwDQYJKoZIhvcNAQELBQADggEBAKrCf4sFDBFZQ6CPYdaxe3InMp7KFaueMIB8\
            /YK73rJ+JGB6fQfltCCkToTE1y0Q3UqTlqHmaqdoh0KMWue6jCFvBat4/TUqUG7W\
            tRLDP67eMulolcIzLqwTjR38DVJvnwrd2pey43q3UHBjlStxT/gI4ysQHn4qrzHB\
            6OK9O6ypqTtwXxnm3TJF9dctLwvbh7NZSaamSlxI0/ajKZOP9k1KZEOPtaiiMPe2\
            yr+QvwY2ov66MRG5PPRZELQWBaPZOuFwmCsFOLXJMpvhoAgklBCFZmiQMgApGIC1\
            FIDgjm2ZhQQIRMnTsAV6f7BclRTaUkc0sPl17YB9GfNfOm1oL7o=",
        )
        .expect("invalid base64");

        let certification_request_info = CertificationRequestInfo::new(
            DirectoryName::new_common_name(PrintableString::from_str("test.contoso.local").unwrap()).into(),
            SubjectPublicKeyInfo::new_rsa_key(
                IntegerAsn1::from(encoded[74..331].to_vec()),
                IntegerAsn1::from(encoded[333..336].to_vec()),
            ),
        );

        check_serde!(certification_request_info: CertificationRequestInfo in encoded[4..338]);

        let csr = CertificationRequest {
            certification_request_info,
            signature_algorithm: AlgorithmIdentifier::new_sha256_with_rsa_encryption(),
            signature: BitString::with_bytes(&encoded[358..614]).into(),
        };

        check_serde!(csr: CertificationRequest in encoded);
    }
}
