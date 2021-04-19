use serde::{Deserialize, Serialize};

use super::certificate::CertError;
use crate::pem::{parse_pem, Pem};
use picky_asn1::wrapper::IntegerAsn1;

const CERT_PEM_LABEL: &str = "CERTIFICATE";

pub(super) fn from_der<'a, T, V>(data: &'a V, element: &'static str) -> Result<T, CertError>
where
    T: Deserialize<'a>,
    V: ?Sized + AsRef<[u8]>,
{
    Ok(T::from(
        picky_asn1_der::from_bytes(data.as_ref()).map_err(|e| CertError::Asn1Deserialization { source: e, element })?,
    ))
}

pub(super) fn from_pem<'a, T: Deserialize<'a>>(pem: &'a Pem, element: &'static str) -> Result<T, CertError> {
    match pem.label() {
        CERT_PEM_LABEL => from_der(pem.data(), element),
        _ => Err(CertError::InvalidPemLabel {
            label: pem.label().to_owned(),
        }),
    }
}

pub(super) fn from_pem_str<T>(pem_str: &str, element: &'static str) -> Result<T, CertError>
where
    for<'a> T: Deserialize<'a>,
{
    let pem = parse_pem(pem_str)?;
    from_pem(&pem, element)
}

pub(super) fn to_der<T: Serialize>(val: &T, element: &'static str) -> Result<Vec<u8>, CertError> {
    picky_asn1_der::to_vec(val).map_err(|e| CertError::Asn1Serialization { source: e, element })
}

pub(super) fn to_pem<T: Serialize>(val: &T, element: &'static str) -> Result<Pem<'static>, CertError> {
    Ok(Pem::new(CERT_PEM_LABEL, to_der(val, element)?))
}

pub(super) fn generate_serial_number() -> IntegerAsn1 {
    let x = rand::random::<u32>();
    let b1 = ((x >> 24) & 0xff) as u8;
    let b2 = ((x >> 16) & 0xff) as u8;
    let b3 = ((x >> 8) & 0xff) as u8;
    let b4 = (x & 0xff) as u8;
    // serial number MUST be a positive integer
    IntegerAsn1::from_bytes_be_unsigned(vec![b1, b2, b3, b4])
}
