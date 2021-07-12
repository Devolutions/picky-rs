use picky_asn1_x509::content_info::ContentValue;
use picky_asn1_x509::pkcs7::ctl::CTLEntry;
use std::io::{self, Cursor, Read};

use crate::x509::pkcs7::{Pkcs7, Pkcs7Error};
use thiserror::Error;

pub use picky_asn1_x509::pkcs7::ctl::CTLEntryAttributeValues;

#[derive(Debug, Error)]
pub enum CtlError {
    #[error("Failed to download CTL:  {description}")]
    DownloadError { description: String },
    #[error("{description}")]
    ExtractingError { description: String },
    #[error("Failed to parse CertificateTrustList: {0}")]
    FailedToParseCtl(Pkcs7Error),
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("For CTL we expects CertificateTrustList content in EncapsulatedContentInfo, but something else")]
    IncorrectContentValue,
}

pub struct CertificateTrustList {
    pkcs7: Pkcs7,
}

impl CertificateTrustList {
    pub fn new() -> Result<Self, CtlError> {
        let ctl_url: &str =
            "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab";

        let mut cab = reqwest::blocking::get(ctl_url).map_err(|err| CtlError::DownloadError {
            description: err.to_string(),
        })?;

        if !cab.status().is_success() {
            return Err(CtlError::DownloadError {
                description: format!("Response status code is {}", cab.status()),
            });
        }

        let mut buffer = Vec::new();
        cab.copy_to(&mut buffer).map_err(|err| CtlError::ExtractingError {
            description: format!("Failed to copy Response body to Vec: {}", err),
        })?;

        let mut cabinet = cab::Cabinet::new(Cursor::new(&mut buffer)).map_err(|err| CtlError::ExtractingError {
            description: format!("Failed to parse Cabinet file: {}", err),
        })?;

        let mut authroot = cabinet
            .read_file("authroot.stl")
            .expect("authroot.stl should be present in authrootstl.cab");

        let mut ctl_buffer = Vec::new();
        authroot.read_to_end(&mut ctl_buffer)?;

        let pkcs7: Pkcs7 = Pkcs7::from_der(&ctl_buffer).map_err(CtlError::FailedToParseCtl)?;

        Ok(Self { pkcs7 })
    }

    pub fn ctl_entries(&self) -> Result<Vec<CTLEntry>, CtlError> {
        let content_value = self
            .pkcs7
            .0
            .signed_data
            .content_info
            .content
            .as_ref()
            .expect("CTL Content should be present in EncapsulatedContentInfo");

        let ctl = match &content_value.0 {
            ContentValue::CertificateTrustList(ctl) => ctl,
            _ => return Err(CtlError::IncorrectContentValue),
        };

        Ok(ctl.crl_entries.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::pkcs7::Pkcs7;

    #[test]
    fn parse_certificate_trust_list_in_der() {
        let pkcs7 = Pkcs7::from_der(crate::test_files::CERTIFICATE_TRUST_LIST);
        assert!(pkcs7.is_ok());
    }

    #[test]
    fn create_ctl() {
        let ctl = CertificateTrustList::new();
        assert!(ctl.is_ok());
    }
}
