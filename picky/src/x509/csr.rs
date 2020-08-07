use crate::{
    key::{PrivateKey, PublicKey},
    pem::Pem,
    signature::{SignatureAlgorithm, SignatureError},
    x509::name::DirectoryName,
};
use picky_asn1::bit_string::BitString;
use picky_asn1_der::Asn1DerError;
use picky_asn1_x509::{CertificationRequest, CertificationRequestInfo};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CsrError {
    /// asn1 serialization error
    #[error("(asn1) couldn't serialize {element}: {source}")]
    Asn1Serialization {
        element: &'static str,
        source: Asn1DerError,
    },

    /// asn1 deserialization error
    #[error("(asn1) couldn't deserialize {}: {}", element, source)]
    Asn1Deserialization {
        element: &'static str,
        source: Asn1DerError,
    },

    /// signature error
    #[error("signature error: {}", source)]
    Signature { source: SignatureError },

    /// invalid PEM label error
    #[error("invalid PEM label: {}", label)]
    InvalidPemLabel { label: String },
}

const CSR_PEM_LABEL: &str = "CERTIFICATE REQUEST";

/// Certificate Signing Request
#[derive(Clone, Debug, PartialEq)]
pub struct Csr(CertificationRequest);

impl From<CertificationRequest> for Csr {
    fn from(certification_request: CertificationRequest) -> Self {
        Self(certification_request)
    }
}

impl Csr {
    pub fn from_der<T: ?Sized + AsRef<[u8]>>(der: &T) -> Result<Self, CsrError> {
        Ok(Self(picky_asn1_der::from_bytes(der.as_ref()).map_err(|e| {
            CsrError::Asn1Deserialization {
                source: e,
                element: "certification request",
            }
        })?))
    }

    pub fn from_pem(pem: &Pem) -> Result<Self, CsrError> {
        match pem.label() {
            CSR_PEM_LABEL => Self::from_der(pem.data()),
            _ => Err(CsrError::InvalidPemLabel {
                label: pem.label().to_owned(),
            }),
        }
    }

    pub fn to_der(&self) -> Result<Vec<u8>, CsrError> {
        picky_asn1_der::to_vec(&self.0).map_err(|e| CsrError::Asn1Serialization {
            source: e,
            element: "certification request",
        })
    }

    pub fn to_pem(&self) -> Result<Pem<'static>, CsrError> {
        Ok(Pem::new(CSR_PEM_LABEL, self.to_der()?))
    }

    pub fn generate(
        subject: DirectoryName,
        private_key: &PrivateKey,
        signature_hash_type: SignatureAlgorithm,
    ) -> Result<Self, CsrError> {
        let info = CertificationRequestInfo::new(subject.into(), private_key.to_public_key().into());
        let info_der = picky_asn1_der::to_vec(&info).map_err(|e| CsrError::Asn1Serialization {
            source: e,
            element: "certification request info",
        })?;
        let signature = BitString::with_bytes(
            signature_hash_type
                .sign(&info_der, private_key)
                .map_err(|e| CsrError::Signature { source: e })?,
        );

        Ok(Self(CertificationRequest {
            certification_request_info: info,
            signature_algorithm: signature_hash_type.into(),
            signature: signature.into(),
        }))
    }

    pub fn subject_name(&self) -> DirectoryName {
        self.0.certification_request_info.subject.clone().into()
    }

    pub fn public_key(&self) -> &PublicKey {
        (&self.0.certification_request_info.subject_public_key_info).into()
    }

    pub fn into_subject_infos(self) -> (DirectoryName, PublicKey) {
        (
            self.0.certification_request_info.subject.into(),
            self.0.certification_request_info.subject_public_key_info.into(),
        )
    }

    pub fn verify(&self) -> Result<(), CsrError> {
        let hash_type = SignatureAlgorithm::from_algorithm_identifier(&self.0.signature_algorithm)
            .map_err(|e| CsrError::Signature { source: e })?;

        let public_key = &self.0.certification_request_info.subject_public_key_info;

        let msg =
            picky_asn1_der::to_vec(&self.0.certification_request_info).map_err(|e| CsrError::Asn1Serialization {
                source: e,
                element: "certification request info",
            })?;

        hash_type
            .verify(&public_key.clone().into(), &msg, self.0.signature.0.payload_view())
            .map_err(|e| CsrError::Signature { source: e })?;

        Ok(())
    }
}
