use std::convert::{Into, TryFrom};

use thiserror::Error;

use picky_asn1::restricted_string::CharSetError;
use picky_asn1_der::Asn1DerError;
use picky_asn1_x509::algorithm_identifier::AlgorithmIdentifier;
use picky_asn1_x509::pkcs7::content_info::{
    ContentInfo, SpcAttributeAndOptionalValue, SpcIndirectDataContent, SpcLink, SpcPeImageData, SpcPeImageFlags,
    SpcSpOpusInfo, SpcString,
};
use picky_asn1_x509::pkcs7::crls::RevocationInfoChoices;
use picky_asn1_x509::pkcs7::signed_data::{DigestAlgorithmIdentifiers, SignedData};
use picky_asn1_x509::pkcs7::singer_info::{
    CertificateSerialNumber, DigestEncryptionAlgorithmIdentifier, EncryptedDigest, IssuerAndSerialNumber, SingerInfo,
    SingersInfos,
};
use picky_asn1_x509::pkcs7::Pkcs7Certificate;
use picky_asn1_x509::{oids, Attribute, AttributeValue, Attributes, DigestInfo, SHAVariant, Version};

use super::certificate::CertError;
use super::utils::{from_der, from_pem, from_pem_str, generate_serial_number, to_der, to_pem};
use super::wincert::WinCertificate;
use crate::key::PrivateKey;
use crate::pem::Pem;
use crate::signature::SignatureAlgorithm;

type Pkcs7Result<T> = Result<T, Pkcs7Error>;

pub const AUTHENTICODE_ATTRIBUTES_COUNT: usize = 3;

const ELEMENT_NAME: &str = "pkcs7 certificate";

#[derive(Debug, Error)]
pub enum Pkcs7Error {
    #[error(transparent)]
    Cert(#[from] CertError),
    #[error(transparent)]
    Asn1DerError(#[from] Asn1DerError),
    #[error("the program name has invalid charset")]
    ProgramNameCharSet(#[from] CharSetError),
}
const PKCS7_PEM_LABEL: &str = "PKCS7";

#[derive(Clone, Debug, PartialEq)]
pub struct Pkcs7(Pkcs7Certificate);

impl Pkcs7 {
    pub fn from_der<V: ?Sized + AsRef<[u8]>>(data: &V) -> Pkcs7Result<Self> {
        Ok(from_der(data, ELEMENT_NAME).map(Self)?)
    }

    pub fn from_pem(pem: &Pem) -> Pkcs7Result<Self> {
        Ok(from_pem(pem, PKCS7_PEM_LABEL, ELEMENT_NAME).map(Self)?)
    }

    pub fn from_pem_str(pem_str: &str) -> Pkcs7Result<Self> {
        Ok(from_pem_str(pem_str, PKCS7_PEM_LABEL, ELEMENT_NAME).map(Self)?)
    }

    pub fn to_der(&self) -> Pkcs7Result<Vec<u8>> {
        Ok(to_der(&self.0, ELEMENT_NAME)?)
    }

    pub fn to_pem(&self) -> Pkcs7Result<Pem> {
        Ok(to_pem(&self.0, PKCS7_PEM_LABEL, ELEMENT_NAME)?)
    }

    pub fn into_win_certificate(
        self,
        file_hash: &[u8],
        hash_type: SHAVariant,
        private_key: &PrivateKey,
        program_name: String,
    ) -> Pkcs7Result<WinCertificate> {
        let Pkcs7Certificate { oid, signed_data } = self.0;

        let SignedData { certificates, .. } = signed_data.0;

        let digest_algorithm = AlgorithmIdentifier::new_sha(hash_type);

        let data = SpcAttributeAndOptionalValue {
            _type: oids::spc_pe_image_dataobj().into(),
            value: SpcPeImageData {
                flags: SpcPeImageFlags::default(),
                file: Default::default(),
            }
            .into(),
        };

        let message_digest = DigestInfo {
            oid: digest_algorithm.clone(),
            digest: file_hash.to_vec().into(),
        };

        let content = SpcIndirectDataContent { data, message_digest };

        let content_info = ContentInfo {
            content_type: oids::spc_indirect_data_objid().into(),
            content: Some(content),
        };

        let certificate = certificates.0.first().unwrap();

        let issuer_and_serial_number = IssuerAndSerialNumber {
            issuer: certificate.tbs_certificate.issuer.clone(),
            serial_number: CertificateSerialNumber(generate_serial_number()),
        };

        let mut authenticated_attributes: Vec<Attribute> = Vec::with_capacity(AUTHENTICODE_ATTRIBUTES_COUNT);

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
            SignatureAlgorithm::from_algorithm_identifier(&AlgorithmIdentifier::new_sha256_with_rsa_encryption())
                .unwrap();
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

        let pkcs7_certificate = picky_asn1_der::to_vec(&pkcs7_certificate)?;

        let mut win_cert = WinCertificate::default();

        win_cert.set_certificate(pkcs7_certificate);

        Ok(win_cert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pem::parse_pem;
    use crate::x509::pkcs7::Pkcs7;
    use picky_asn1_x509::SHAVariant::SHA2_256;

    #[test]
    fn read_pem_and_parse_certificate() {
        let pem = parse_pem(crate::test_files::PKCS7.as_bytes()).unwrap();
        let decoded = Pkcs7::from_pem(&pem);

        assert!(decoded.is_ok());
    }

    #[test]
    fn decoding_into_win_certificate() {
        let pem = parse_pem(crate::test_files::PKCS7.as_bytes()).unwrap();
        let pkcs7 = Pkcs7::from_pem(&pem).unwrap();

        let file_hash: Vec<u8> = vec![
            0xa7, 0x38, 0xda, 0x44, 0x46, 0xa4, 0xe7, 0x8a, 0xb6, 0x47, 0xdb, 0x7e, 0x53, 0x42, 0x7e, 0xb0, 0x79, 0x61,
            0xc9, 0x94, 0x31, 0x7f, 0x4c, 0x59, 0xd7, 0xed, 0xbe, 0xa5, 0xcc, 0x78, 0x6d, 0x80,
        ];

        let hash_type = SHAVariant::SHA2_256;
        let key = parse_pem(crate::test_files::RSA_2048_PK_1.as_bytes()).unwrap();
        let private_key = PrivateKey::from_pem(&key).unwrap();
        let program_name = "decoding_into_win_certificate_test".to_string();

        let win_cert = pkcs7
            .into_win_certificate(file_hash.as_ref(), hash_type, &private_key, program_name)
            .unwrap();

        let pkcs7 = win_cert.get_certificate();

        let pkcs7certificate: Pkcs7Certificate = picky_asn1_der::from_bytes(pkcs7.as_slice()).unwrap();

        let Pkcs7Certificate { signed_data, .. } = pkcs7certificate;

        let content_info = &signed_data.content_info;

        assert_eq!(
            Into::<String>::into(&content_info.content_type.0).as_str(),
            oids::SPC_INDIRECT_DATA_OBJID
        );

        let spc_indirect_data_content = content_info.content.as_ref().unwrap();
        let message_digest = &spc_indirect_data_content.message_digest;

        assert_eq!(message_digest.oid, AlgorithmIdentifier::new_sha(SHAVariant::SHA2_256));

        pretty_assertions::assert_eq!(message_digest.digest.0, file_hash);

        assert_eq!(signed_data.singers_infos.0 .0.len(), 1);

        let singer_info = signed_data.singers_infos.0 .0.first().unwrap();
        assert_eq!(singer_info.digest_algorithm, AlgorithmIdentifier::new_sha(SHA2_256));

        let authenticated_attributes = &singer_info.authenticode_attributes.0 .0;

        if !authenticated_attributes
            .iter()
            .any(|attr| matches!(attr.value, AttributeValue::ContentType(_)))
        {
            panic!("ContentType attribute is missing");
        }

        if !authenticated_attributes
            .iter()
            .any(|attr| matches!(attr.value, AttributeValue::MessageDigest(_)))
        {
            panic!("MessageDigest attribute is missing");
        }

        if !authenticated_attributes
            .iter()
            .any(|attr| matches!(attr.value, AttributeValue::SpcSpOpusInfo(_)))
        {
            panic!("SpcSpOpusInfo attribute is missing");
        }

        let message_digest = authenticated_attributes
            .iter()
            .find(|attr| matches!(attr.value, AttributeValue::MessageDigest(_)))
            .unwrap();

        match &message_digest.value {
            AttributeValue::MessageDigest(hash) => pretty_assertions::assert_eq!(hash.0, file_hash),
            _ => unreachable!(),
        }

        assert_eq!(
            singer_info.digest_encryption_algorithm,
            DigestEncryptionAlgorithmIdentifier(AlgorithmIdentifier::new_sha256_with_rsa_encryption())
        );
    }
}
