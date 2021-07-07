use crate::pem::Pem;
use crate::x509::certificate::{Cert, CertError, CertType};
use crate::x509::utils::{from_der, from_pem, from_pem_str, to_der, to_pem};
use crate::AlgorithmIdentifier;
use picky_asn1_der::Asn1DerError;
use picky_asn1_x509::content_info::EncapsulatedContentInfo;
use picky_asn1_x509::pkcs7::Pkcs7Certificate;
use picky_asn1_x509::signer_info::SignerInfo;
use std::convert::TryFrom;
use thiserror::Error;

pub mod authenticode;
#[cfg(feature = "ctl")]
pub mod ctl;

type Pkcs7Result<T> = Result<T, Pkcs7Error>;

const ELEMENT_NAME: &str = "pkcs7 certificate";

#[derive(Debug, Error)]
pub enum Pkcs7Error {
    #[error(transparent)]
    Cert(#[from] CertError),
    #[error(transparent)]
    Asn1DerError(#[from] Asn1DerError),
}

const PKCS7_PEM_LABEL: &str = "PKCS7";

#[derive(Clone, Debug, PartialEq)]
pub struct Pkcs7(Pkcs7Certificate);

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

    pub fn digest_algorithms(&self) -> &[AlgorithmIdentifier] {
        self.0.signed_data.digest_algorithms.0 .0.as_slice()
    }

    pub fn singer_infos(&self) -> &[SignerInfo] {
        &self.0.signed_data.signers_infos.0
    }

    pub fn encapsulated_content_info(&self) -> &EncapsulatedContentInfo {
        &self.0.signed_data.0.content_info
    }

    pub fn certificates(&self) -> Vec<Cert> {
        self.0
            .signed_data
            .certificates
            .0
            .iter()
            .cloned()
            .filter_map(|cert| Cert::try_from(cert).ok())
            .collect::<Vec<Cert>>()
    }

    pub fn intermediate_certificate(&self) -> Option<Cert> {
        self.certificates()
            .into_iter()
            .find(|cert| cert.ty() == CertType::Intermediate)
    }

    pub fn root_certificate(&self) -> Option<Cert> {
        self.certificates()
            .into_iter()
            .map(Cert::from)
            .find(|cert| cert.ty() == CertType::Root)
    }
}

impl From<Pkcs7Certificate> for Pkcs7 {
    fn from(pkcs7_certificate: Pkcs7Certificate) -> Self {
        Pkcs7(pkcs7_certificate)
    }
}

impl From<Pkcs7> for Pkcs7Certificate {
    fn from(pkcs7: Pkcs7) -> Self {
        pkcs7.0
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
}
