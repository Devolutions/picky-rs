use base64::DecodeError;
use serde::export::Formatter;
use snafu::{ResultExt, Snafu};
use std::{borrow::Cow, fmt, str::FromStr};

const PEM_HEADER_START: &str = "-----BEGIN";
const PEM_HEADER_END: &str = "-----END";
const PEM_DASHES_BOUNDARIES: &str = "-----";

#[derive(Debug, Clone, Snafu)]
pub enum PemError {
    /// pem header not found
    HeaderNotFound,

    /// invalid pem header
    InvalidHeader,

    /// pem footer not found
    FooterNotFound,

    /// couldn't decode base64
    #[snafu(display("couldn't decode base64: {}", source))]
    Base64Decoding { source: DecodeError },
}

// https://tools.ietf.org/html/rfc7468
#[derive(Debug, Clone, PartialEq)]
pub struct Pem<'a> {
    label: String,
    data: Cow<'a, [u8]>,
}

impl<'a> Pem<'a> {
    pub fn new<S: Into<String>, D: Into<Cow<'a, [u8]>>>(label: S, data: D) -> Self {
        Self {
            label: label.into(),
            data: data.into(),
        }
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_data(self) -> Cow<'a, [u8]> {
        self.data
    }
}

impl FromStr for Pem<'static> {
    type Err = PemError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_pem(s.as_bytes())
    }
}

impl fmt::Display for Pem<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} {}-----", PEM_HEADER_START, self.label)?;

        let encoded = base64::encode(&self.data);
        let bytes = encoded.as_bytes();
        for chunk in bytes.chunks(64) {
            let chunk = std::str::from_utf8(chunk).map_err(|_| fmt::Error)?;
            writeln!(f, "{}", chunk)?;
        }

        write!(f, "{} {}-----", PEM_HEADER_END, self.label)?;

        Ok(())
    }
}

impl Into<String> for Pem<'_> {
    fn into(self) -> String {
        self.to_string()
    }
}

/// Read a PEM-encoded structure
///
/// If the input contains line ending characters (`\r`, `\n`), a copy of input
/// is allocated striping these. If you can strip these with minimal data copy
/// you should do it beforehand.
pub fn parse_pem<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<Pem<'static>, PemError> {
    __parse_pem_impl(input.as_ref())
}

fn __parse_pem_impl(input: &[u8]) -> Result<Pem<'static>, PemError> {
    let header_start_idx =
        __find(input, PEM_HEADER_START.as_bytes()).ok_or(PemError::HeaderNotFound)?;

    let label_start_idx = header_start_idx + PEM_HEADER_START.as_bytes().len();
    let label_end_idx =
        __find(&input[label_start_idx..], b"-").ok_or(PemError::InvalidHeader)? + label_start_idx;
    let label = String::from_utf8_lossy(&input[label_start_idx..label_end_idx])
        .trim()
        .to_owned();

    let header_end_idx = __find(&input[label_end_idx..], PEM_DASHES_BOUNDARIES.as_bytes())
        .ok_or(PemError::InvalidHeader)?
        + label_end_idx
        + PEM_DASHES_BOUNDARIES.as_bytes().len();

    let footer_start_idx = __find(&input[header_end_idx..], PEM_HEADER_END.as_bytes())
        .ok_or(PemError::FooterNotFound)?
        + header_end_idx;

    let raw_data = &input[header_end_idx..footer_start_idx];

    let data = if __find(raw_data, b"\n").is_some() {
        // Line ending characters should be striped... Sadly, this means we need to copy and allocate.
        let striped_raw_data: Vec<u8> = raw_data
            .iter()
            .copied()
            .filter(|byte| *byte != b'\r' && *byte != b'\n')
            .collect();
        base64::decode(&striped_raw_data).context(Base64Decoding)?
    } else {
        // Can be decoded as is!
        base64::decode(raw_data).context(Base64Decoding)?
    };

    Ok(Pem {
        label,
        data: Cow::Owned(data),
    })
}

fn __find(buffer: &[u8], value: &[u8]) -> Option<usize> {
    buffer
        .windows(value.len())
        .position(|window| window == value)
}

/// Build a PEM-encoded structure into a String.
pub fn to_pem<S, T>(label: S, data: &T) -> String
where
    S: Into<String>,
    T: ?Sized + AsRef<[u8]>,
{
    Pem::new(label, data.as_ref()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        oids,
        serde::{name::NamePrettyFormatter, Certificate, Version},
    };
    use num_bigint_dig::BigInt;
    use serde_asn1_der::date::UTCTime;

    const PEM_BYTES: &[u8] = crate::test_files::INTERMEDIATE_CA.as_bytes();
    const PEM_STR: &str = crate::test_files::INTERMEDIATE_CA;
    const FLATTENED_PEM: &str = "-----BEGIN GARBAGE-----GARBAGE-----END GARBAGE-----";

    #[test]
    fn read_pem() {
        let pem_from_bytes = parse_pem(PEM_BYTES).unwrap();
        assert_eq!(pem_from_bytes.label, "CERTIFICATE");

        let pem_from_str = PEM_STR.parse::<Pem>().unwrap();
        pretty_assertions::assert_eq!(pem_from_bytes, pem_from_str);
    }

    #[test]
    fn to_pem() {
        let pem = PEM_STR.parse::<Pem>().unwrap();
        let reconverted_pem = pem.to_string();
        pretty_assertions::assert_eq!(reconverted_pem, PEM_STR);
    }

    #[test]
    fn flattened_pem() {
        FLATTENED_PEM.parse::<Pem>().unwrap();
    }

    #[test]
    fn read_pem_and_parse_certificate() {
        let pem = parse_pem(PEM_BYTES).unwrap();
        let cert = Certificate::from_der(&pem.data).unwrap();

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

        assert_eq!(
            NamePrettyFormatter(&cert.tbs_certificate.issuer).to_string(),
            "C=NL,O=PolarSSL,CN=PolarSSL Test CA"
        );
    }
}
