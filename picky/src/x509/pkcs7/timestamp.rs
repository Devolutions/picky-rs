use crate::hash::HashAlgorithm;
use crate::x509::pkcs7::Pkcs7;
use picky_asn1_der::Asn1DerError;
use picky_asn1_x509::pkcs7::content_info::{ContentValue, EncapsulatedContentInfo};
use picky_asn1_x509::pkcs7::signed_data::SignedData;
use picky_asn1_x509::pkcs7::signer_info::UnsignedAttribute;
use picky_asn1_x509::signer_info::UnsignedAttributeValue;
use picky_asn1_x509::timestamp::TimestampRequest;
use picky_asn1_x509::{oids, Pkcs7Certificate};
use reqwest::blocking::Client;
use reqwest::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
use reqwest::{Method, StatusCode, Url};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TimestampError {
    #[error(transparent)]
    Asn1DerError(#[from] Asn1DerError),
    #[error("Remote Authenticode TSA server response with {0} status code")]
    BadResponse(StatusCode),
    #[error("Timestamp token is empty")]
    TimestampTokenEmpty,
    #[error("Remote Authenticode TSA server response error: {0}")]
    RemoteServerResponseError(reqwest::Error),
    #[error("Badly formatted URL")]
    BadUrl,
}

pub trait Timestamper: Sized {
    fn timestamp(&self, digest: Vec<u8>, hash_algo: HashAlgorithm) -> Result<Pkcs7, TimestampError>; // hash_algo is used in RFC3161
    fn modify_signed_data(&self, token: Pkcs7, signed_data: &mut SignedData);
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticodeTimestamper {
    url: Url,
}

impl AuthenticodeTimestamper {
    pub fn new<U: AsRef<str>>(url: U) -> Result<AuthenticodeTimestamper, TimestampError> {
        let url = Url::parse(url.as_ref()).map_err(|_| TimestampError::BadUrl)?;
        Ok(Self { url })
    }
}

impl Timestamper for AuthenticodeTimestamper {
    fn timestamp(&self, digest: Vec<u8>, _: HashAlgorithm) -> Result<Pkcs7, TimestampError> {
        let timestamp_request = TimestampRequest {
            countersignature_type: oids::timestamp_request().into(),
            content: EncapsulatedContentInfo {
                content_type: oids::pkcs7().into(),
                content: Some(ContentValue::Data(digest.into()).into()),
            },
        };

        let client = Client::new();
        let content = picky_asn1_der::to_vec(&timestamp_request).map_err(TimestampError::Asn1DerError)?;

        let request = client
            .request(Method::POST, self.url.clone())
            .header(CACHE_CONTROL, "no-cache")
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_LENGTH, content.len())
            .body(content)
            .build()
            .expect("RequestBuilder should not panic");

        let response = client
            .execute(request)
            .map_err(TimestampError::RemoteServerResponseError)?;

        if response.status() != StatusCode::OK {
            return Err(TimestampError::BadResponse(response.status()));
        }

        let body = response
            .bytes()
            .map_err(TimestampError::RemoteServerResponseError)?
            .to_vec();

        let token = picky_asn1_der::from_bytes::<Pkcs7Certificate>(&body).map_err(TimestampError::Asn1DerError)?;

        Ok(token.into())
    }

    fn modify_signed_data(&self, token: Pkcs7, signed_data: &mut SignedData) {
        let SignedData {
            certificates,
            signers_infos,
            ..
        } = token.0.signed_data.0;

        let singer_info = signers_infos
            .0
            .first()
            .expect("Exactly one SignedInfo should be present");

        let unsigned_attribute = UnsignedAttribute {
            ty: oids::counter_sign().into(),
            value: UnsignedAttributeValue::CounterSign(vec![singer_info.clone()].into()),
        };

        let signer_info = signed_data
            .signers_infos
            .0
             .0
            .first_mut()
            .expect("Exactly one SignedInfo should be present");

        signer_info.unsigned_attrs.0 .0.push(unsigned_attribute);

        signed_data.certificates.0 .0.extend(certificates.0 .0);
    }
}
