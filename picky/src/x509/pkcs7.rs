#![allow(non_camel_case_types)]

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::io::{self, BufReader, BufWriter};
use std::{error, mem};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WinCertificateError {
    #[error("Revision value is wrong(expected any of {expected}, but {got} got)")]
    WrongRevisionValue { expected: String, got: u16 },
    #[error("Certificate type is wrong(expected any of {expected}, but {got} got)")]
    WrongCertificateType { expected: String, got: u16 },
    #[error("Length is wrong({minimum} at least, but {got} got)")]
    WrongLength { minimum: usize, got: usize },
    #[error("Certificate data is empty")]
    CertificateDataIsEmpty,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Other(#[from] Box<dyn error::Error>),
}

pub struct Pkcs7 {}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(align(8))]
pub struct WinCertificate {
    length: u32,
    revision: RevisionType,
    certificate_type: CertificateType,
    certificate: Vec<u8>,
}

impl WinCertificate {
    pub fn decode<V: ?Sized + AsRef<[u8]>>(data: &V) -> Result<Self, WinCertificateError> {
        let align = mem::align_of::<WinCertificate>();
        if data.as_ref().len() < 3 * align {
            return Err(WinCertificateError::WrongLength {
                minimum: 3 * align,
                got: data.as_ref().len(),
            });
        }

        let mut buffer = BufReader::new(data.as_ref());

        let length = buffer.read_u64::<BigEndian>()? as _;

        if length == 0 {
            return Err(WinCertificateError::CertificateDataIsEmpty);
        }

        let revision = RevisionType::try_from(buffer.read_u64::<BigEndian>()? as u16)?;

        let certificate_type = CertificateType::try_from(buffer.read_u64::<BigEndian>()? as u16)?;

        let mut certificate = Vec::with_capacity(length as _);

        for _ in 0..length {
            certificate.push(buffer.read_u8()?);
        }

        Ok(Self {
            length,
            revision,
            certificate_type,
            certificate,
        })
    }

    pub fn encode(self) -> Result<Vec<u8>, WinCertificateError> {
        let Self {
            length,
            revision,
            certificate_type,
            certificate,
        } = self;

        let mut buffer = BufWriter::new(Vec::new());
        buffer.write_u64::<BigEndian>(length as u64)?;
        buffer.write_u64::<BigEndian>(revision as u64)?;
        buffer.write_u64::<BigEndian>(certificate_type as u64)?;

        let count_of_needed_bytes_to_fill_align = (certificate.len() * 8 % 64) / 8;

        for elem in certificate.into_iter() {
            buffer.write_u8(elem)?;
        }

        for _ in 0..count_of_needed_bytes_to_fill_align {
            buffer.write_u8(0)?;
        }

        buffer
            .into_inner()
            .map_err(|err| WinCertificateError::Other(Box::new(err) as Box<dyn error::Error>))
    }

    pub fn set_certificate<V: Into<Vec<u8>>>(&mut self, certificate: V) {
        let certificate = certificate.into();
        self.length = certificate.len() as u32;
        self.certificate = certificate;
    }
}

impl Default for WinCertificate {
    fn default() -> Self {
        WinCertificate {
            length: 0,
            revision: RevisionType::WIN_CERTIFICATE_REVISION_2_0,
            certificate_type: CertificateType::WIN_CERT_TYPE_PKCS_SIGNED_DATA,
            certificate: Vec::new(),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[repr(u16)]
pub enum RevisionType {
    WIN_CERTIFICATE_REVISION_1_0 = 0x0100,
    WIN_CERTIFICATE_REVISION_2_0 = 0x0200,
}

impl TryFrom<u16> for RevisionType {
    type Error = WinCertificateError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0100 => Ok(RevisionType::WIN_CERTIFICATE_REVISION_1_0),
            0x0200 => Ok(RevisionType::WIN_CERTIFICATE_REVISION_2_0),
            _ => Err(WinCertificateError::WrongRevisionValue {
                expected: format!("{:?}", [0x0100, 0x0200]),
                got: value,
            }),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[repr(u16)]
pub enum CertificateType {
    WIN_CERT_TYPE_X509 = 0x0001,
    WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002,
    WIN_CERT_TYPE_RESERVED_1 = 0x0003,
    WIN_CERT_TYPE_PKCS1_SIGN = 0x0009,
}

impl TryFrom<u16> for CertificateType {
    type Error = WinCertificateError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(CertificateType::WIN_CERT_TYPE_X509),
            0x0002 => Ok(CertificateType::WIN_CERT_TYPE_PKCS_SIGNED_DATA),
            0x0003 => Ok(CertificateType::WIN_CERT_TYPE_RESERVED_1),
            0x0009 => Ok(CertificateType::WIN_CERT_TYPE_PKCS1_SIGN),
            _ => Err(WinCertificateError::WrongCertificateType {
                expected: format!("{:?}", [0x0001, 0x0002, 0x0003, 0x0009]),
                got: value,
            }),
        }
    }
}

#[test]
fn encode_decode_test() {
    let mut origin = WinCertificate::default();
    origin.set_certificate(vec![1, 2, 3, 4, 5]);

    let buffer: Vec<u8> = origin.clone().encode().unwrap();

    let decoded: WinCertificate = WinCertificate::decode(&buffer).unwrap();

    pretty_assertions::assert_eq!(origin, decoded);
}
