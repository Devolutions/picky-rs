use der::{Decode, Encode};
use crate::pem::parse_pem;
use crate::key::{KeyError, PrivateKey, PublicKey};
use crate::pem::{Pem, PemError};
use crate::signature::{SignatureAlgorithm, SignatureError};
use crate::x509::certificate::CertError;
use crate::x509::name::DirectoryName;
use der::asn1::BitString;
use der::Error as Asn1DerError;
use x509_cert::request::{CertReq, CertReqInfo};
use thiserror::Error;

pub use x509_cert::attr::Attribute;

const ELEMENT_NAME: &str = "certification request";

#[derive(Debug, Error)]
pub enum CsrError {
    /// ASN1 serialization error
    #[error("(ASN1) couldn't serialize {element}: {source}")]
    Asn1Serialization {
        element: &'static str,
        source: Asn1DerError,
    },

    /// ASN1 deserialization error
    #[error("(ASN1) couldn't deserialize {}: {}", element, source)]
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

    /// invalid PEM provided
    #[error("invalid PEM provided: {source}")]
    Pem { source: PemError },

    #[error("failed to get public key from private key: {source}")]
    PrivateKeyToPublicKey { source: KeyError },
}

impl From<CertError> for CsrError {
    fn from(e: CertError) -> Self {
        match e {
            CertError::Asn1Deserialization { element, source } => CsrError::Asn1Deserialization { element, source },
            CertError::Asn1Serialization { element, source } => CsrError::Asn1Serialization { element, source },
            CertError::Pem { source } => CsrError::Pem { source },
            CertError::InvalidPemLabel { label } => CsrError::InvalidPemLabel { label },
            _ => unreachable!(),
        }
    }
}

const CSR_PEM_LABEL: &str = "CERTIFICATE REQUEST";

/// Certificate Signing Request
#[derive(Clone, Debug, PartialEq)]
pub struct Csr(pub(crate) CertReq);

impl From<CertReq> for Csr {
    fn from(certification_request: CertReq) -> Self {
        Self(certification_request)
    }
}

impl Csr {
    pub fn from_der<T: ?Sized + AsRef<[u8]>>(der: &T) -> Result<Self, CsrError> {
        let cert_req = CertReq::from_der(der.as_ref()).map_err(|e| CsrError::Asn1Deserialization {
            element: ELEMENT_NAME,
            source: e,
        })?;
        Ok(Self(cert_req))
    }

    pub fn from_pem_str(pem_str: &str) -> Result<Self, CsrError> {
        let pem = parse_pem(pem_str).map_err(|e| CsrError::Pem { source: e })?;
        Self::from_pem(&pem)
    }

    pub fn from_pem(pem: &Pem) -> Result<Self, CsrError> {
        if pem.label() != CSR_PEM_LABEL {
            return Err(CsrError::InvalidPemLabel {
                label: pem.label().to_string(),
            });
        }
        Self::from_der(pem.data())
    }

    pub fn to_der(&self) -> Result<Vec<u8>, CsrError> {
        self.0.to_der().map_err(|e| CsrError::Asn1Serialization {
            element: ELEMENT_NAME,
            source: e,
        })
    }

    pub fn to_pem(&self) -> Result<Pem<'static>, CsrError> {
        let der = self.to_der()?;
        Ok(Pem::new(CSR_PEM_LABEL, der))
    }

    pub fn generate(
        subject: DirectoryName,
        private_key: &PrivateKey,
        signature_hash_type: SignatureAlgorithm,
    ) -> Result<Self, CsrError> {
        let public_key = private_key
            .to_public_key()
            .map_err(|source| CsrError::PrivateKeyToPublicKey { source })?;

        let cri = CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject: subject.into(),
            public_key: public_key.into(),
            attributes: Default::default(),
        };
        h_generate_from_cri(cri, private_key, signature_hash_type)
    }

    pub fn generate_with_attributes(
        subject: DirectoryName,
        private_key: &PrivateKey,
        signature_hash_type: SignatureAlgorithm,
        attributes: Vec<Attribute>,
    ) -> Result<Self, CsrError> {
        let public_key = private_key
            .to_public_key()
            .map_err(|source| CsrError::PrivateKeyToPublicKey { source })?;

        let attributes_set = x509_cert::attr::Attributes::try_from(attributes)
            .map_err(|e| CsrError::Asn1Serialization {
                element: "attributes",
                source: e,
            })?;
            
        let cri = CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject: subject.into(),
            public_key: public_key.into(),
            attributes: attributes_set,
        };
        h_generate_from_cri(cri, private_key, signature_hash_type)
    }

    pub fn subject_name(&self) -> DirectoryName {
        self.0.info.subject.clone().into()
    }

    pub fn public_key(&self) -> PublicKey {
        self.0.info.public_key.clone().into()
    }

    pub fn into_subject_infos(self) -> (DirectoryName, PublicKey) {
        (
            self.0.info.subject.into(),
            self.0.info.public_key.into(),
        )
    }

    pub fn verify(&self) -> Result<(), CsrError> {
        let hash_type = SignatureAlgorithm::from_algorithm_identifier(&self.0.algorithm)
            .map_err(|e| CsrError::Signature { source: e })?;

        let public_key = &self.0.info.public_key;

        let msg =
            self.0.info.to_der().map_err(|e| CsrError::Asn1Serialization {
                source: e,
                element: "certification request info",
            })?;

        hash_type
            .verify(&public_key.clone().into(), &msg, self.0.signature.raw_bytes())
            .map_err(|e| CsrError::Signature { source: e })?;

        Ok(())
    }
}

fn h_generate_from_cri(
    cri: CertReqInfo,
    private_key: &PrivateKey,
    signature_hash_type: SignatureAlgorithm,
) -> Result<Csr, CsrError> {
    let cri_der = cri.to_der().map_err(|e| CsrError::Asn1Serialization {
        source: e,
        element: "certification request cri",
    })?;
    let signature_bytes = signature_hash_type
        .sign(&cri_der, private_key)
        .map_err(|e| CsrError::Signature { source: e })?;
    let signature = BitString::from_bytes(&signature_bytes)
        .map_err(|e| CsrError::Asn1Serialization {
            element: "signature",
            source: e,
        })?;

    let signature_algorithm = {
        let algo_ref = picky_asn1_x509::AlgorithmIdentifier::try_from(signature_hash_type)
            .map_err(|e| CsrError::Signature { source: e })?;
        spki::AlgorithmIdentifier {
            oid: algo_ref.oid,
            parameters: algo_ref.parameters.map(|p| der::Any::from_der(&p.to_der().unwrap()).unwrap()),
        }
    };

    Ok(Csr(CertReq {
        info: cri,
        algorithm: signature_algorithm,
        signature: signature.into(),
    }))
}
