use base64::DecodeError;
use serde::export::Formatter;
use std::{fmt, str::FromStr};
use std::error::Error;

const PEM_HEADER_START: &str = "-----BEGIN";
const PEM_HEADER_END: &str = "-----END";

#[derive(Debug, Clone)]
pub enum PemError {
    HeaderNotFound,
    InvalidHeader,
    FooterNotFound,
    Base64Decoding(DecodeError),
}

impl Error for PemError {}

impl fmt::Display for PemError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PemError::HeaderNotFound => write!(f, "pem header not found"),
            PemError::InvalidHeader => write!(f, "invalid pem header"),
            PemError::FooterNotFound => write!(f, "pem footer not found"),
            PemError::Base64Decoding(err) => write!(f, "couldn't decode base64: {}", err),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pem {
    pub label: String,
    pub data: Vec<u8>,
}

impl FromStr for Pem {
    type Err = PemError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_pem(s.as_bytes())
    }
}

impl fmt::Display for Pem {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}-----\n{}\n{} {}-----",
            PEM_HEADER_START,
            self.label,
            base64::encode(&self.data),
            PEM_HEADER_END,
            self.label,
        )
    }
}

impl Into<String> for Pem {
    fn into(self) -> String {
        format!("{}", self)
    }
}

/// Read a PEM-encoded structure
///
/// If the input contains line ending characters (`\r`, `\n`), a copy of input
/// is allocated striping these. If you can strip these with minimal data copy
/// you should do it beforehand.
pub fn parse_pem<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<Pem, PemError> {
    __parse_pem_impl(input.as_ref())
}

fn __parse_pem_impl(input: &[u8]) -> Result<Pem, PemError> {
    let header_start_idx =
        __find(input, PEM_HEADER_START.as_bytes()).ok_or(PemError::HeaderNotFound)?;

    let label_start_idx = header_start_idx + PEM_HEADER_START.len();
    let label_end_idx =
        __find(&input[label_start_idx..], b"-").ok_or(PemError::InvalidHeader)? + label_start_idx;
    let label = String::from_utf8_lossy(&input[label_start_idx..label_end_idx])
        .trim()
        .to_owned();

    let header_end_idx =
        __find(&input[label_end_idx..], b"\n").ok_or(PemError::FooterNotFound)? + label_end_idx;

    let footer_start_idx = __find(&input[header_end_idx..], PEM_HEADER_END.as_bytes())
        .ok_or(PemError::FooterNotFound)?
        + header_end_idx;

    let raw_data = &input[header_end_idx + 1..footer_start_idx - 1];

    let data = if __find(raw_data, b"\n").is_some() {
        // Line ending characters should be striped... Sadly, this means we need to copy and allocate.
        let striped_raw_data: Vec<u8> = raw_data
            .iter()
            .copied()
            .filter(|byte| *byte != b'\r' && *byte != b'\n')
            .collect();
        base64::decode(&striped_raw_data).map_err(PemError::Base64Decoding)?
    } else {
        // Can be decoded as is!
        base64::decode(raw_data).map_err(PemError::Base64Decoding)?
    };

    Ok(Pem { label, data })
}

fn __find(buffer: &[u8], value: &[u8]) -> Option<usize> {
    buffer
        .windows(value.len())
        .position(|window| window == value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        oids,
        serde::{AttributeTypeAndValueParameters, Certificate, Version},
    };
    use num_bigint_dig::BigInt;
    use serde_asn1_der::date::UTCTime;

    static PEM_BYTES: &[u8] = include_bytes!("../test_files/intermediate_ca.crt");
    static PEM_STR: &str = include_str!("../test_files/intermediate_ca.crt");

    #[test]
    fn read_pem() {
        let pem_from_bytes = parse_pem(PEM_BYTES).unwrap();
        assert_eq!(pem_from_bytes.label, "CERTIFICATE");

        let pem_from_str = PEM_STR.parse::<Pem>().unwrap();
        assert_eq!(pem_from_bytes, pem_from_str);
    }

    #[test]
    fn to_pem() {
        let pem = PEM_STR.parse::<Pem>().unwrap();
        let reconverted_pem = pem.to_string();
        assert_eq!(reconverted_pem.replace("\n", ""), PEM_STR.replace("\n", ""));
    }

    #[test]
    fn read_pem_and_parse_certificate() {
        let pem = parse_pem(PEM_BYTES).unwrap();
        let cert = Certificate::from_bytes(&pem.data).unwrap();

        assert_eq!(cert.tbs_certificate.version.0, Version::V3);
        assert_eq!(cert.tbs_certificate.serial_number, BigInt::from(1));
        assert_eq!(
            Into::<String>::into(cert.tbs_certificate.signature.algorithm.0).as_str(),
            oids::SHA1_WITH_RSA_ENCRYPTION
        );
        assert_eq!(
            cert.tbs_certificate.validity.not_before,
            UTCTime::new(2011, 2, 12, 14, 44, 6).unwrap().into()
        );
        assert_eq!(
            cert.tbs_certificate.validity.not_after,
            UTCTime::new(2021, 2, 12, 14, 44, 6).unwrap().into()
        );

        for name in cert.tbs_certificate.issuer.0 {
            match &name.0[0].value {
                AttributeTypeAndValueParameters::CommonName(name) => {
                    assert_eq!(name.to_utf8_lossy(), "PolarSSL Test CA");
                }
                AttributeTypeAndValueParameters::CountryName(name) => {
                    assert_eq!(name.to_utf8_lossy(), "NL");
                }
                AttributeTypeAndValueParameters::OrganisationName(name) => {
                    assert_eq!(name.to_utf8_lossy(), "PolarSSL");
                }
                _ => panic!("unexpected branch"),
            }
        }
    }
}
