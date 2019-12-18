use crate::{private::SubjectPublicKeyInfo, x509::private::Name, AlgorithmIdentifier};
use picky_asn1::wrapper::{ApplicationTag0, BitStringAsn1, HeaderOnly, Implicit};
use serde::{Deserialize, Serialize};

/// https://tools.ietf.org/html/rfc2986#section-4
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct CertificationRequestInfo {
    pub version: u8,
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    pub attributes: Implicit<Option<HeaderOnly<ApplicationTag0<()>>>>, // unsupported.
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct CertificationRequest {
    pub certification_request_info: CertificationRequestInfo,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: BitStringAsn1,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pem::Pem, x509::name::DirectoryName};
    use picky_asn1::{bit_string::BitString, restricted_string::PrintableString, wrapper::IntegerAsn1};
    use std::str::FromStr;

    #[test]
    fn deserialize_csr() {
        let pem = crate::test_files::CSR.parse::<Pem>().expect("couldn't parse csr pem");
        let encoded = pem.data();
        assert_eq!(pem.label(), "CERTIFICATE REQUEST");

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
