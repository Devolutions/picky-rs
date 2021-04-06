#![allow(non_camel_case_types)]

use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, mem};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WinCertificateError {
    #[error("Revision value is wrong(expected any of {expected}, but {got} got)")]
    RevisionValueWrong { expected: String, got: u16 },
    #[error("Certificate type is wrong(expected any of {expected}, but {got} got)")]
    CertificateTypeWrong { expected: String, got: u16 },
    #[error("Length is wrong({minimum} at least, but {got} got)")]
    LengthWrong { minimum: usize, got: usize },
    #[error("Certificate data is empty")]
    CertificateDataIsEmpty,
}

pub struct Pkcs7 {}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
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
            return Err(WinCertificateError::LengthWrong {
                minimum: 3 * align,
                got: data.as_ref().len(),
            });
        }

        let length = u32::from_be_bytes([data.as_ref()[0], data.as_ref()[1], data.as_ref()[2], data.as_ref()[3]]);

        let revision = RevisionType::try_from(u16::from_be_bytes([data.as_ref()[align], data.as_ref()[align + 1]]))?;

        let certificate_type = CertificateType::try_from(u16::from_be_bytes([
            data.as_ref()[2 * align],
            data.as_ref()[2 * align + 1],
        ]))?;

        let certificate = Vec::from(&data.as_ref()[3 * align..]);

        if certificate.is_empty() {
            return Err(WinCertificateError::CertificateDataIsEmpty);
        }

        Ok(Self {
            length,
            revision,
            certificate_type,
            certificate,
        })
    }

    pub fn encode(self) -> Vec<u8> {
        let Self {
            length,
            revision,
            certificate_type,
            certificate,
        } = self;

        let length_bytes_count = 4;
        let revision_bytes_count = 2;
        let certificate_type_bytes_count = 2;
        let certificate_bytes_count = certificate.len();

        let align = mem::align_of::<WinCertificate>();

        let mut buffer = create_aligned_vec::<Self>(
            length_bytes_count + revision_bytes_count + certificate_type_bytes_count + certificate_bytes_count,
        );

        let length_in_u8_view: [u8; 4] = length.to_be_bytes();

        buffer[0] = length_in_u8_view[0];
        buffer[1] = length_in_u8_view[1];
        buffer[2] = length_in_u8_view[2];
        buffer[3] = length_in_u8_view[3];

        let revision_in_u8_view: [u8; 2] = (revision as u16).to_be_bytes();

        buffer[align] = revision_in_u8_view[0];
        buffer[align + 1] = revision_in_u8_view[1];

        let certificate_type_in_u8_view: [u8; 2] = (certificate_type as u16).to_be_bytes();

        buffer[2 * align] = certificate_type_in_u8_view[0];
        buffer[2 * align + 1] = certificate_type_in_u8_view[1];

        for (i, elem) in certificate.into_iter().enumerate() {
            buffer.insert(3 * align + i, elem);
        }

        buffer
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
            _ => Err(WinCertificateError::RevisionValueWrong {
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
            _ => Err(WinCertificateError::CertificateTypeWrong {
                expected: format!("{:?}", [0x0001, 0x0002, 0x0003, 0x0009]),
                got: value,
            }),
        }
    }
}

fn create_aligned_vec<T>(n_bytes: usize) -> Vec<u8> {
    let n_units = (n_bytes / std::mem::size_of::<T>()) + 1;

    let mut aligned: Vec<T> = Vec::with_capacity(n_units);

    let ptr = aligned.as_mut_ptr();
    let len_units = aligned.len();
    let cap_units = aligned.capacity();

    std::mem::forget(aligned);

    unsafe {
        Vec::from_raw_parts(
            ptr as *mut u8,
            len_units * mem::size_of::<T>(),
            cap_units * mem::size_of::<T>(),
        )
    }
}

#[test]
fn encode_decode_test() {
    let win_certificate1 = WinCertificate::default();

    let buffer: Vec<u8> = win_certificate1.clone().encode();

    pretty_assertions::assert_eq!(0, std::mem::align_of::<WinCertificate>());

    let win_certificate2: WinCertificate = WinCertificate::decode(&buffer).unwrap();

    pretty_assertions::assert_eq!(win_certificate1, win_certificate2);
}
