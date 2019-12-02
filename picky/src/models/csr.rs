use crate::{
    error::{Asn1Serialization, Error, Result},
    models::{
        key::{PrivateKey, PublicKey},
        name::Name,
        signature::SignatureHashType,
    },
    pem::Pem,
    serde::{certification_request::CertificationRequestInfo, CertificationRequest},
};
use serde_asn1_der::bit_string::BitString;
use snafu::ResultExt;

/// Certificate Signing Request
#[derive(Clone, Debug, PartialEq)]
pub struct Csr(CertificationRequest);

impl Csr {
    pub fn from_der<T: ?Sized + AsRef<[u8]>>(der: &T) -> serde_asn1_der::Result<Self> {
        Ok(Self(serde_asn1_der::from_bytes(der.as_ref())?))
    }

    pub fn to_der(&self) -> serde_asn1_der::Result<Vec<u8>> {
        serde_asn1_der::to_vec(&self.0)
    }

    pub fn to_pem(&self) -> serde_asn1_der::Result<Pem<'static>> {
        Ok(Pem::new("CERTIFICATE REQUEST", self.to_der()?))
    }

    pub fn from_certification_request(csr: CertificationRequest) -> Self {
        Self(csr)
    }

    pub fn as_inner(&self) -> &CertificationRequest {
        &self.0
    }

    pub fn into_inner(self) -> CertificationRequest {
        self.0
    }

    pub fn generate(
        subject: Name,
        private_key: &PrivateKey,
        signature_hash_type: SignatureHashType,
    ) -> Result<Self> {
        let info =
            CertificationRequestInfo::new(subject.into(), private_key.to_public_key().into());
        let info_der = serde_asn1_der::to_vec(&info).context(Asn1Serialization {
            element: "certification request info",
        })?;
        let signature = BitString::with_bytes(signature_hash_type.sign(&info_der, private_key)?);

        Ok(Self(CertificationRequest {
            certification_request_info: info,
            signature_algorithm: signature_hash_type.into(),
            signature: signature.into(),
        }))
    }

    pub fn subject_name(&self) -> Name {
        self.0.certification_request_info.subject.clone().into()
    }

    pub fn to_public_key(&self) -> PublicKey {
        self.0
            .certification_request_info
            .subject_public_key_info
            .clone()
            .into()
    }

    pub fn into_subject_infos(self) -> (Name, PublicKey) {
        (
            self.0.certification_request_info.subject.into(),
            self.0
                .certification_request_info
                .subject_public_key_info
                .into(),
        )
    }

    pub fn verify(&self) -> Result<()> {
        let hash_type = SignatureHashType::from_algorithm_identifier(&self.0.signature_algorithm)
            .ok_or(Error::UnsupportedAlgorithm {
            algorithm: (&self.0.signature_algorithm.algorithm.0).into(),
        })?;

        let public_key = &self.0.certification_request_info.subject_public_key_info;

        let msg = serde_asn1_der::to_vec(&self.0.certification_request_info).context(
            Asn1Serialization {
                element: "certification request info",
            },
        )?;

        hash_type.verify(
            &public_key.clone().into(),
            &msg,
            self.0.signature.0.payload_view(),
        )?;

        Ok(())
    }
}
