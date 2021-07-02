use crate::hash::UnsupportedHashAlgorithmError;
use crate::pem::Pem;
use crate::x509::certificate::CertError;
use crate::x509::utils::{from_der, from_pem, from_pem_str, to_der, to_pem};
use picky_asn1::restricted_string::CharSetError;
use picky_asn1_der::Asn1DerError;
use picky_asn1_x509::algorithm_identifier::UnsupportedAlgorithmError;
use picky_asn1_x509::pkcs7::Pkcs7Certificate;

use thiserror::Error;

type Pkcs7Result<T> = Result<T, Pkcs7Error>;

const ELEMENT_NAME: &str = "pkcs7 certificate";

#[derive(Debug, Error)]
pub enum Pkcs7Error {
    #[error(transparent)]
    Cert(#[from] CertError),
    #[error(transparent)]
    Asn1DerError(#[from] Asn1DerError),
    #[error(transparent)]
    SignatureError(#[from] crate::signature::SignatureError),
    #[error("the program name has invalid charset")]
    ProgramNameCharSet(#[from] CharSetError),
    #[error(transparent)]
    UnsupportedHashAlgorithmError(UnsupportedHashAlgorithmError),
    #[error(transparent)]
    UnsupportedAlgorithmError(UnsupportedAlgorithmError),
    #[error("The signing certificate must contain the extended key usage (EKU) value for code signing")]
    NoEKUCodeSigning,
    #[error("Certificates must contain at least Leaf and Intermediate certificates, but got no certificates")]
    NoCertificates,
}

const PKCS7_PEM_LABEL: &str = "PKCS7";

#[derive(Clone, Debug, PartialEq)]
pub struct Pkcs7(pub(crate) Pkcs7Certificate);

impl Pkcs7 {
    pub fn from_der<V: ?Sized + AsRef<[u8]>>(data: &V) -> Pkcs7Result<Self> {
        Ok(from_der(data, ELEMENT_NAME).map(Self)?)
    }

    pub fn from_pem(pem: &Pem) -> Pkcs7Result<Self> {
        Ok(from_pem(pem, PKCS7_PEM_LABEL, ELEMENT_NAME).map(Self)?)
    }

    pub fn from_pem_str(pem_str: &str) -> Pkcs7Result<Self> {
        Ok(from_pem_str(pem_str, PKCS7_PEM_LABEL, ELEMENT_NAME).map(Self)?)
    }

    pub fn to_der(&self) -> Pkcs7Result<Vec<u8>> {
        Ok(to_der(&self.0, ELEMENT_NAME)?)
    }

    pub fn to_pem(&self) -> Pkcs7Result<Pem> {
        Ok(to_pem(&self.0, PKCS7_PEM_LABEL, ELEMENT_NAME)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pem::parse_pem;

    #[test]
    fn read_pem_and_parse_certificate() {
        let pem = parse_pem(crate::test_files::PKCS7.as_bytes()).unwrap();
        let decoded = Pkcs7::from_pem(&pem);
        assert!(decoded.is_ok());
    }

    #[test]
    fn parse_certificate_trust_list_in_der() {
        let pkcs7 = Pkcs7::from_der(crate::test_files::CERTIFICATE_TRUST_LIST);
        assert!(pkcs7.is_ok());
    }
}
