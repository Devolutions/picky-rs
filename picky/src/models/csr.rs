use crate::{
    error::{Error, Result},
    models::{key::PrivateKey, name::Name, signature::SignatureHashType},
    pem::Pem,
    serde::{
        certification_request::CertificationRequestInfo, CertificationRequest, SubjectPublicKeyInfo,
    },
};
use err_ctx::ResultExt;
use serde_asn1_der::bit_string::BitString;
use crate::models::key::PublicKey;

/// Certificate Signing Request
pub struct Csr {
    inner: CertificationRequest,
}

impl Csr {
    pub fn from_certification_request(csr: CertificationRequest) -> Self {
        Self { inner: csr }
    }

    pub fn from_der<T: ?Sized + AsRef<[u8]>>(der: &T) -> serde_asn1_der::Result<Self> {
        Ok(Self {
            inner: serde_asn1_der::from_bytes(der.as_ref())?,
        })
    }

    pub fn to_der(&self) -> serde_asn1_der::Result<Vec<u8>> {
        serde_asn1_der::to_vec(&self.inner)
    }

    pub fn to_pem(&self) -> serde_asn1_der::Result<Pem<'static>> {
        Ok(Pem::new("CERTIFICATE REQUEST", self.to_der()?))
    }

    pub fn generate(
        subject: Name,
        private_key: &PrivateKey,
        signature_hash_type: SignatureHashType,
    ) -> Result<Self> {
        let info =
            CertificationRequestInfo::new(subject.into(), private_key.to_public_key().into());
        let info_der = serde_asn1_der::to_vec(&info)
            .ctx("couldn't serialize certification request info into der")?;
        let signature = BitString::with_bytes(signature_hash_type.sign(&info_der, private_key)?);

        Ok(Csr {
            inner: CertificationRequest {
                certification_request_info: info,
                signature_algorithm: signature_hash_type.into(),
                signature: signature.into(),
            },
        })
    }

    pub fn subject_name(&self) -> Name {
        self.inner.certification_request_info.subject.clone().into()
    }

    pub fn subject_public_key_info(&self) -> &SubjectPublicKeyInfo {
        &self
            .inner
            .certification_request_info
            .subject_public_key_info
    }

    pub fn into_subject_infos(self) -> (Name, PublicKey) {
        (
            self.inner.certification_request_info.subject.into(),
            self.inner
                .certification_request_info
                .subject_public_key_info
                .into(),
        )
    }

    pub fn verify(&self) -> Result<()> {
        let hash_type =
            SignatureHashType::from_algorithm_identifier(&self.inner.signature_algorithm)
                .ok_or(Error::UnsupportedAlgorithm("unknown identifier"))?;

        let public_key = &self
            .inner
            .certification_request_info
            .subject_public_key_info;

        let msg = serde_asn1_der::to_vec(&self.inner.certification_request_info)
            .ctx("couldn't serialize certification request info into der")?;

        hash_type.verify(
            &public_key.clone().into(),
            &msg,
            self.inner.signature.0.payload_view(),
        )?;

        Ok(())
    }
}
