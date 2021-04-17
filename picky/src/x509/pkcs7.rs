use std::convert::{Into, TryFrom};

use thiserror::Error;

use picky_asn1::restricted_string::CharSetError;
use picky_asn1_x509::{
    algorithm_identifier::AlgorithmIdentifier,
    oids,
    pkcs7::{
        content_info::{
            ContentInfo, SpcAttributeAndOptionalValue, SpcIndirectDataContent, SpcLink, SpcPeImageData,
            SpcPeImageFlags, SpcSpOpusInfo, SpcString,
        },
        crls::RevocationInfoChoices,
        signed_data::{DigestAlgorithmIdentifiers, SignedData},
        singer_info::{
            CertificateSerialNumber, DigestEncryptionAlgorithmIdentifier, EncryptedDigest, IssuerAndSerialNumber,
            SingerInfo, SingersInfos,
        },
        Pkcs7Certificate,
    },
    Attribute, AttributeValue, Attributes, DigestInfo, SHAVariant, Version,
};

use super::{
    certificate::CertError,
    utils::{from_der, from_pem, from_pem_str, generate_serial_number, to_der, to_pem},
    wincert::WinCertificate,
};
use crate::{key::PrivateKey, pem::Pem, signature::SignatureAlgorithm};

type Pkcs7Result<T> = Result<T, Pkcs7Error>;

#[derive(Debug, Error)]
enum Pkcs7Error {
    #[error(transparent)]
    Cert(#[from] CertError),
    #[error("the program name has invalid charset")]
    ProgramNameCharSet(#[from] CharSetError),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pkcs7(Pkcs7Certificate);

impl Pkcs7 {
    pub fn from_der<V: ?Sized + AsRef<[u8]>>(data: &V) -> Pkcs7Result<Self> {
        from_der(data, "pkcs7 certificate")
            .map(Self)
            .map_err(|e| Pkcs7Error::Cert(e))
    }

    pub fn from_pem(pem: &Pem) -> Pkcs7Result<Self> {
        from_pem(pem, "pkcs7 certificate")
            .map(Self)
            .map_err(|e| Pkcs7Error::Cert(e))
    }

    pub fn from_pem_str(pem_str: &str) -> Pkcs7Result<Self> {
        from_pem_str(pem_str, "pkcs7 certificate")
            .map(Self)
            .map_err(|e| Pkcs7Error::Cert(e))
    }

    pub fn to_der(&self) -> Pkcs7Result<Vec<u8>> {
        to_der(&self.0, "pkcs7 certificate").map_err(|e| Pkcs7Error::Cert(e))
    }

    pub fn to_pem(&self) -> Pkcs7Result<Pem> {
        to_pem(&self.0, "pkcs7 certificate").map_err(|e| Pkcs7Error::Cert(e))
    }

    pub fn into_wincertificate(
        self,
        file_hash: &[u8],
        hash_type: SHAVariant,
        private_key: &PrivateKey,
        program_name: String,
    ) -> Pkcs7Result<WinCertificate> {
        let Pkcs7Certificate { oid, signed_data } = self.0;

        let SignedData { certificates, .. } = signed_data.0;

        let digest_algorithm = AlgorithmIdentifier::new_sha(hash_type);

        let content_info = ContentInfo {
            content_type: oids::spc_indirect_data_objid().into(),
            content: Some(SpcIndirectDataContent {
                data: SpcAttributeAndOptionalValue {
                    _type: oids::spc_pe_image_dataobj().into(),
                    value: SpcPeImageData {
                        flags: SpcPeImageFlags::default(),
                        file: Default::default(),
                    }
                    .into(),
                },
                message_digest: DigestInfo {
                    oid: digest_algorithm.clone(),
                    digest: file_hash.to_vec().into(),
                },
            }),
        };

        let certificate = certificates.0.first().unwrap();
        let tbs_certificate = &certificate.tbs_certificate;

        let issuer_and_serial_number = IssuerAndSerialNumber {
            issuer: tbs_certificate.issuer.clone(),
            serial_number: CertificateSerialNumber(generate_serial_number()),
        };

        let mut authenticated_attributes: Vec<Attribute> = Vec::with_capacity(3);

        authenticated_attributes.append(&mut vec![
            Attribute {
                ty: oids::content_type().into(),
                value: AttributeValue::ContentType(oids::message_digest().into()),
            },
            Attribute {
                ty: oids::message_digest().into(),
                value: AttributeValue::MessageDigest(file_hash.to_vec().into()),
            },
            Attribute {
                ty: oids::spc_sp_opus_info_objid().into(),
                value: AttributeValue::SpcSpOpusInfo(SpcSpOpusInfo {
                    more_info: SpcLink::default(),
                    program_name: SpcString::try_from(program_name).map_err(Pkcs7Error::ProgramNameCharSet)?,
                }),
            },
        ]);

        let signature_algo =
            SignatureAlgorithm::from_algorithm_identifier(&AlgorithmIdentifier::new_sha(SHAVariant::SHA2_256)).unwrap();
        let digest_encryption_algorithm = AlgorithmIdentifier::new_sha256_with_rsa_encryption();

        let encrypted_digest = EncryptedDigest(signature_algo.sign(file_hash, private_key).unwrap().into());

        let singer_info = SingerInfo {
            version: Version::V2,
            issuer_and_serial_number,
            digest_algorithm: digest_algorithm.clone(),
            authenticode_attributes: Attributes(authenticated_attributes).into(),
            digest_encryption_algorithm: DigestEncryptionAlgorithmIdentifier(digest_encryption_algorithm),
            encrypted_digest,
        };

        let signed_data = SignedData {
            version: Version::V2,
            digest_algorithms: DigestAlgorithmIdentifiers(vec![digest_algorithm].into()),
            content_info,
            certificates,
            crls: RevocationInfoChoices::default(),
            singers_infos: SingersInfos(vec![singer_info].into()),
        };

        let pkcs7_certificate = Pkcs7Certificate {
            oid,
            signed_data: signed_data.into(),
        };

        let pkcs7_certificate = Pkcs7(pkcs7_certificate).to_der()?;

        let mut win_cert = WinCertificate::default();

        win_cert.set_certificate(pkcs7_certificate);

        Ok(win_cert)
    }
}
