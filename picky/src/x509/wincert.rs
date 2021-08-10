use crate::hash::HashAlgorithm;
use crate::key::PrivateKey;
use crate::signature::SignatureAlgorithm;
use crate::x509::extension::{ExtendedKeyUsage, ExtensionView};
use crate::x509::pkcs7::{Pkcs7, Pkcs7Error};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use picky_asn1::tag::Tag;
use picky_asn1::wrapper::{Asn1SetOf, ExplicitContextTag0, ExplicitContextTag1, Optional};
use picky_asn1_x509::algorithm_identifier::AlgorithmIdentifier;
use picky_asn1_x509::pkcs7::cmsversion::CmsVersion;
use picky_asn1_x509::pkcs7::content_info::{
    ContentValue, EncapsulatedContentInfo, SpcAttributeAndOptionalValue, SpcIndirectDataContent, SpcLink,
    SpcPeImageData, SpcPeImageFlags, SpcSpOpusInfo, SpcString,
};
use picky_asn1_x509::pkcs7::crls::RevocationInfoChoices;
use picky_asn1_x509::pkcs7::signed_data::{CertificateSet, DigestAlgorithmIdentifiers, SignedData, SignersInfos};
use picky_asn1_x509::pkcs7::signer_info::{
    CertificateSerialNumber, DigestAlgorithmIdentifier, IssuerAndSerialNumber, SignatureAlgorithmIdentifier,
    SignatureValue, SignerIdentifier, SignerInfo,
};
use picky_asn1_x509::pkcs7::Pkcs7Certificate;
use picky_asn1_x509::{oids, Attribute, AttributeValues, Certificate, DigestInfo};
use std::convert::TryFrom;
use std::error;
use std::io::{self, BufReader, BufWriter};
use thiserror::Error;

use picky_asn1_x509::signer_info::Attributes;
pub use picky_asn1_x509::ShaVariant;

const MINIMUM_BYTES_TO_DECODE: usize = 4 /* WinCertificate::length */ + 2 /* WinCertificate::revision */ + 2 /* WinCertificate::certificate */;

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
    Pkcs7Error(Pkcs7Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Other(#[from] Box<dyn error::Error>),
}

pub type WinCertificateResult<T> = Result<T, WinCertificateError>;

#[derive(Clone, Debug, PartialEq)]
pub struct WinCertificate {
    length: u32,
    revision: RevisionType,
    certificate_type: CertificateType,
    certificate: Vec<u8>,
}

impl WinCertificate {
    pub fn new(
        pkcs7: Pkcs7,
        file_hash: &[u8],
        hash_algo: ShaVariant,
        private_key: &PrivateKey,
        program_name: Option<String>,
    ) -> WinCertificateResult<Self> {
        let Pkcs7Certificate { oid, signed_data } = pkcs7.0;

        let SignedData { certificates, .. } = signed_data.0;

        let digest_algorithm = AlgorithmIdentifier::new_sha(hash_algo);

        let data = SpcAttributeAndOptionalValue {
            ty: oids::spc_pe_image_dataobj().into(),
            value: SpcPeImageData {
                flags: SpcPeImageFlags::default(),
                file: Default::default(),
            },
        };

        let message_digest = DigestInfo {
            oid: digest_algorithm.clone(),
            digest: file_hash.to_vec().into(),
        };

        let program_name = program_name
            .map(SpcString::try_from)
            .transpose()
            .map_err(|err| WinCertificateError::Pkcs7Error(Pkcs7Error::ProgramNameCharSet(err)))?
            .map(ExplicitContextTag0);

        let mut raw_spc_indirect_data_content = picky_asn1_der::to_vec(&data)
            .map_err(|err| WinCertificateError::Pkcs7Error(Pkcs7Error::Asn1DerError(err)))?;

        let mut raw_message_digest = picky_asn1_der::to_vec(&message_digest)
            .map_err(|err| WinCertificateError::Pkcs7Error(Pkcs7Error::Asn1DerError(err)))?;

        raw_spc_indirect_data_content.append(&mut raw_message_digest);

        let message_digest_value = HashAlgorithm::try_from(hash_algo)
            .map_err(|err| WinCertificateError::Pkcs7Error(Pkcs7Error::UnsupportedHashAlgorithmError(err)))?
            .digest(raw_spc_indirect_data_content.as_ref());

        let authenticated_attributes = vec![
            Attribute {
                ty: oids::content_type().into(),
                value: AttributeValues::ContentType(Asn1SetOf(vec![oids::spc_indirect_data_objid().into()])),
            },
            Attribute {
                ty: oids::spc_sp_opus_info_objid().into(),
                value: AttributeValues::SpcSpOpusInfo(Asn1SetOf(vec![SpcSpOpusInfo {
                    program_name,
                    more_info: Some(ExplicitContextTag1(SpcLink::default())),
                }])),
            },
            Attribute {
                ty: oids::message_digest().into(),
                value: AttributeValues::MessageDigest(Asn1SetOf(vec![message_digest_value.into()])),
            },
        ];

        let content = SpcIndirectDataContent { data, message_digest };

        let content_info = EncapsulatedContentInfo {
            content_type: oids::spc_indirect_data_objid().into(),
            content: Some(ContentValue::SpcIndirectDataContent(content).into()),
        };

        // The signing certificate must contain either the extended key usage (EKU) value for code signing,
        // or the entire certificate chain must contain no EKUs
        {
            let certificates = &certificates.0;
            let code_signing_ext_key_usage: ExtendedKeyUsage = vec![oids::kp_code_signing()].into();

            if certificates
                .iter()
                .map(|cert| cert.tbs_certificate.extensions.0 .0.iter())
                .flatten()
                .any(|extension| matches!(extension.extn_value(), ExtensionView::ExtendedKeyUsage(_)))
            {
                let signing_cert = certificates
                    .get(0)
                    .ok_or(WinCertificateError::Pkcs7Error(Pkcs7Error::NoCertificates))?;

                if !signing_cert.tbs_certificate.extensions.0 .0.iter().any(|extension| {
                    extension.extn_value() == ExtensionView::ExtendedKeyUsage(&code_signing_ext_key_usage)
                }) {
                    return Err(WinCertificateError::Pkcs7Error(Pkcs7Error::NoEKUCodeSigning));
                }
            }
        }

        let signing_cert = certificates
            .0
            .get(0)
            .ok_or(WinCertificateError::Pkcs7Error(Pkcs7Error::NoCertificates))?;

        let issuer_and_serial_number = IssuerAndSerialNumber {
            issuer: signing_cert.tbs_certificate.issuer.clone(),
            serial_number: CertificateSerialNumber(signing_cert.tbs_certificate.serial_number.clone()),
        };

        let digest_encryption_algorithm = AlgorithmIdentifier::new_rsa_encryption_with_sha(hash_algo)
            .map_err(|err| WinCertificateError::Pkcs7Error(Pkcs7Error::UnsupportedAlgorithmError(err)))?;

        let signature_algo = SignatureAlgorithm::from_algorithm_identifier(&digest_encryption_algorithm)
            .map_err(|err| WinCertificateError::Pkcs7Error(Pkcs7Error::SignatureError(err)))?;

        let mut auth_raw_data = picky_asn1_der::to_vec(&authenticated_attributes)
            .map_err(|err| WinCertificateError::Pkcs7Error(Pkcs7Error::Asn1DerError(err)))?;
        // According to the RFC:
        //
        // "[...] The Attributes value's tag is SET OF, and the DER encoding ofs
        // the SET OF tag, rather than of the IMPLICIT [0] tag [...]"
        auth_raw_data[0] = Tag::SET.number();

        let encrypted_digest = SignatureValue(
            signature_algo
                .sign(auth_raw_data.as_ref(), private_key)
                .map_err(|err| WinCertificateError::Pkcs7Error(Pkcs7Error::SignatureError(err)))?
                .into(),
        );

        let singer_info = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial_number),
            digest_algorithm: DigestAlgorithmIdentifier(digest_algorithm.clone()),
            signed_attrs: Optional(Attributes(authenticated_attributes)),
            signature_algorithm: SignatureAlgorithmIdentifier(AlgorithmIdentifier::new_rsa_encryption()),
            signature: encrypted_digest,
        };

        // certificates contains the signer certificate and any intermediate certificates,
        // but typically does not contain the root certificate
        let certificates = CertificateSet(certificates.0.into_iter().take(2).collect::<Vec<Certificate>>());

        let signed_data = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: DigestAlgorithmIdentifiers(vec![digest_algorithm].into()),
            content_info,
            certificates,
            crls: RevocationInfoChoices::default(),
            signers_infos: SignersInfos(vec![singer_info].into()),
        };

        let pkcs7_certificate = Pkcs7Certificate {
            oid,
            signed_data: signed_data.into(),
        };

        let raw_pkcs7 = picky_asn1_der::to_vec(&pkcs7_certificate)
            .map_err(|err| WinCertificateError::Pkcs7Error(Pkcs7Error::Asn1DerError(err)))?;

        Ok(WinCertificate::from_certificate(
            raw_pkcs7,
            CertificateType::WinCertTypePkcsSignedData,
        ))
    }

    pub fn decode<V: ?Sized + AsRef<[u8]>>(data: &V) -> WinCertificateResult<Self> {
        if data.as_ref().len() < MINIMUM_BYTES_TO_DECODE {
            return Err(WinCertificateError::WrongLength {
                minimum: MINIMUM_BYTES_TO_DECODE,
                got: data.as_ref().len(),
            });
        }

        let mut buffer = BufReader::new(data.as_ref());

        let length = buffer.read_u32::<LittleEndian>()?;

        if length == 0 {
            return Err(WinCertificateError::CertificateDataIsEmpty);
        }

        let revision = RevisionType::try_from(buffer.read_u16::<LittleEndian>()?)?;

        let certificate_type = CertificateType::try_from(buffer.read_u16::<LittleEndian>()?)?;

        let mut certificate = Vec::with_capacity(length as usize);

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

    pub fn encode(self) -> WinCertificateResult<Vec<u8>> {
        let Self {
            length,
            revision,
            certificate_type,
            certificate,
        } = self;

        let mut buffer = BufWriter::new(Vec::new());

        let padding = (8 - (certificate.len() % 8)) % 8;

        buffer.write_u32::<LittleEndian>(length + padding as u32)?;
        buffer.write_u16::<LittleEndian>(revision as u16)?;
        buffer.write_u16::<LittleEndian>(certificate_type as u16)?;

        for elem in certificate.into_iter() {
            buffer.write_u8(elem)?;
        }

        for _ in 0..padding {
            buffer.write_u8(0)?;
        }

        buffer
            .into_inner()
            .map_err(|err| WinCertificateError::Other(Box::new(err) as Box<dyn error::Error>))
    }

    pub fn from_certificate<V: Into<Vec<u8>>>(certificate: V, certificate_type: CertificateType) -> Self {
        let certificate = certificate.into();
        Self {
            length: (MINIMUM_BYTES_TO_DECODE + certificate.len()) as u32,
            revision: RevisionType::WinCertificateRevision20,
            certificate_type,
            certificate,
        }
    }

    #[inline]
    pub fn get_certificate(&self) -> &[u8] {
        self.certificate.as_ref()
    }
}

#[derive(Debug, PartialEq, Clone)]
#[repr(u16)]
pub enum RevisionType {
    WinCertificateRevision10 = 0x0100,
    WinCertificateRevision20 = 0x0200,
}

impl TryFrom<u16> for RevisionType {
    type Error = WinCertificateError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0100 => Ok(RevisionType::WinCertificateRevision10),
            0x0200 => Ok(RevisionType::WinCertificateRevision20),
            _ => Err(WinCertificateError::WrongRevisionValue {
                expected: format!("{:?}", [0x0100, 0x0200]),
                got: value,
            }),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
#[repr(u16)]
pub enum CertificateType {
    WinCertTypeX509 = 0x0001,
    WinCertTypePkcsSignedData = 0x0002,
    WinCertTypeReserved1 = 0x0003,
    WinCertTypePkcs1Sign = 0x0009,
}

impl TryFrom<u16> for CertificateType {
    type Error = WinCertificateError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(CertificateType::WinCertTypeX509),
            0x0002 => Ok(CertificateType::WinCertTypePkcsSignedData),
            0x0003 => Ok(CertificateType::WinCertTypeReserved1),
            0x0009 => Ok(CertificateType::WinCertTypePkcs1Sign),
            _ => Err(WinCertificateError::WrongCertificateType {
                expected: format!("{:?}", [0x0001, 0x0002, 0x0003, 0x0009]),
                got: value,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pem::parse_pem;
    use crate::x509::certificate::{Cert, CertType};
    use crate::x509::Extension;

    const WINCERT_WITH_INVALID_LENGTH: [u8; 8] = [
        0x00, 0x00, 0x00, 0x00, // -> WIN_CERTIFICATE::dwLength = 0x00 = 0
        0x00, 0x01, // -> WIN_CERTIFICATE::wRevision = 0x0100 = WIN_CERT_REVISION_1_0
        0x01,
        0x00, // -> WIN_CERTIFICATE::wCertificateType = 0x01 = WIN_CERTIFICATE::WIN_CERT_TYPE_X509
              // empty WIN_CERTIFICATE::bCertificate field
    ];

    const WINCERT_WITH_ONE_BYTE_CERTIFICATE: [u8; 16] = [
        0x08, 0x00, 0x00, 0x00, // -> WIN_CERTIFICATE::dwLength = 0x08 = 8
        0x00, 0x01, // -> WIN_CERTIFICATE::wRevision = 0x0100 = WIN_CERT_REVISION_1_0
        0x01, 0x00, // -> WIN_CERTIFICATE::wCertificateType = 0x01 = WIN_CERTIFICATE::WIN_CERT_TYPE_X509
        0x01, // -> WIN_CERTIFICATE::bCertificate = bCertificate[0] = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
    ];

    const WINCERT_WITH_TEN_BYTES_CERTIFICATE: [u8; 24] = [
        0x10, 0x00, 0x00, 0x00, // -> WIN_CERTIFICATE::dwLength = 0x10 = 16
        0x00, 0x02, // -> WIN_CERTIFICATE::wRevision = 0x0200 = WIN_CERT_REVISION_2_0
        0x09, 0x00, // -> WIN_CERTIFICATE::wCertificateType = 0x09 = WIN_CERTIFICATE::WinCertTypePkcs1Sign
        0x01, 0x20, 0x03, 0x40, 0x05, 0x60, 0x70, 0x08, // -> WIN_CERTIFICATE::bCertificate = bCertificate[10]
        0x90, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
    ];

    const WINCERT_WITH_INVALID_REVISION: [u8; 9] = [
        0x01, 0x00, 0x00, 0x00, // -> WIN_CERTIFICATE::dwLength = 0x01 = 1
        0x00, 0x03, // -> WIN_CERTIFICATE::wRevision = 0x0300(not existing)
        0x01, 0x00, // -> WIN_CERTIFICATE::wCertificateType = 0x01 = WIN_CERTIFICATE::WIN_CERT_TYPE_X509
        0x01, // -> WIN_CERTIFICATE::bCertificate = bCertificate[0] = 1
    ];

    const WINCERT_WITH_X509_CERTIFICATE: [u8; 136] = [
        0x80, 0x00, 0x00, 0x00, // -> WIN_CERTIFICATE::dwLength = 0x80 = 128
        0x00, 0x02, // -> WIN_CERTIFICATE::wRevision = 0x0200 = WIN_CERT_REVISION_2_0
        0x01, 0x00, // -> WIN_CERTIFICATE::wCertificateType = 0x01 = WIN_CERTIFICATE::WIN_CERT_TYPE_X509
        // X509 certificate
        0x0B, 0x04, 0x55, 0x03, 0x06, 0x15, 0x30, 0x17, 0x31, 0x74, 0x69, 0x72, 0x6F, 0x69, 0x72, 0x70, 0x41, 0x08,
        0x0C, 0x0A, 0x04, 0x55, 0x03, 0x06, 0x0F, 0x30, 0x11, 0x31, 0x6F, 0x72, 0x70, 0x69, 0x6E, 0x44, 0x06, 0x0C,
        0x07, 0x04, 0x55, 0x03, 0x06, 0x0D, 0x30, 0x0F, 0x31, 0x6F, 0x72, 0x70, 0x69, 0x6E, 0x44, 0x06, 0x0C, 0x08,
        0x04, 0x55, 0x03, 0x06, 0x0D, 0x30, 0x0F, 0x31, 0x41, 0x55, 0x02, 0x13, 0x06, 0x04, 0x55, 0x03, 0x06, 0x09,
        0x30, 0x0B, 0x31, 0x97, 0x81, 0x30, 0x00, 0x05, 0x0B, 0x01, 0x01, 0x0D, 0xF7, 0x86, 0x48, 0x86, 0x2A, 0x09,
        0x06, 0x0D, 0x30, 0x92, 0x72, 0xDC, 0xE9, 0x6B, 0x13, 0x8F, 0x0D, 0x06, 0xFB, 0xC1, 0xD1, 0x69, 0x97, 0x79,
        0x4B, 0xA1, 0x69, 0x63, 0x19, 0x14, 0x02, 0x02, 0x01, 0x02, 0x03, 0xA0, 0xF9, 0x03, 0x82, 0x30, 0x11, 0x06,
        0x82, 0x30,
    ];

    const FILE_HASH: [u8; 32] = [
        0xa7, 0x38, 0xda, 0x44, 0x46, 0xa4, 0xe7, 0x8a, 0xb6, 0x47, 0xdb, 0x7e, 0x53, 0x42, 0x7e, 0xb0, 0x79, 0x61,
        0xc9, 0x94, 0x31, 0x7f, 0x4c, 0x59, 0xd7, 0xed, 0xbe, 0xa5, 0xcc, 0x78, 0x6d, 0x80,
    ];

    const RSA_PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
                                   MIIEpAIBAAKCAQEA0vg4PmmJdy1W/ayyuP3ovRBbggAZ98dEY5uzEU23ENaN3jsx\n\
                                   R9zEAAmQ9OZbbJXN33l+PMKY7+5izgI/RlGSNF2s0mdyWEhoRMTxuwpJoFgBkYEE\n\
                                   Jwr40xoLCbw9TpBooJgdYg/n/Fu4NGM7YJdcfKjf3/le7kNTZYPBx09wBkHvkuTD\n\
                                   gpdDDnb5R6sTouD0bCPjC/gZCoRAAlzfuAmAAHVb+i8fkTV32OzokLYcneuLZU/+\n\
                                   FBpR2w9UprfDLWFbPxuOBf+mIGp4WWVN82+3SdEkp/5BRQ//MhGhj7NhEYp+KyWJ\n\
                                   Hm+1iGvrxsgQH+4MQTJGdp838sl+w77QGFZU9QIDAQABAoIBAEBWNkDCSouvpgHC\n\
                                   ctZ7iEhv/pgMk96+RBrkVp2GR7e41pbZElRJ/PPN9wjYXzUkEh5+nILHDYDOAA+3\n\
                                   G7jEE4QotRWNOo+1tSaTsOxLXNyrOf83ix6k9/DY1ljnsQKOg3nGKd/H3gVVqz0+\n\
                                   rdLtFeVmUq+pCsw6d+pTXfr8PLuLPfe8r9fu/BGU2wtINAEuQ4x3/S/JPTm6XnsV\n\
                                   NUW62K/lB7RjXlEqnKMwxcVCu/m0C1HdlwTlHyzktIydjL9Bk1GjGQVt0zC/rfvA\n\
                                   zrlsTPg4UTL6zs4D9B5PPaZMJeBieXaQ0JdqKdJkRm+mPCOEGf+BLz1zHVAVZaSZ\n\
                                   PK8E7NkCgYEA+e7WUOlr4nR6fqvte0ZTewIeG/j2m5gSVjjy8Olh2D3v8q4hZj5s\n\
                                   2jaFJJ7RUGXZdiySodlEpLR2nrrUURC6fGukvbFCW2j/0SotBl53Wa2zJdrU3AZc\n\
                                   b9j7MOyJbJDKJYqdivYJXp7ra4vCs0xAMXfuQD1AWaKlCQxbeyrKWxcCgYEA2BdA\n\
                                   fB7IL0ec3WOsLyGGhcCrGDWIiOlXzk5Fuus+NOEp70/bYCqGpu+tNAxtbY4e+zHp\n\
                                   5gXApKU6PSQ/I/eG/o0WGQCZazfhIGpwORrWHAVxDlxJ+/hlZd6DmTjaIJw1k2gr\n\
                                   D849l1WIEr2Ps8Bv3Y7XeLpnUAQFv1ekfMKxZ9MCgYEA2vtNYfUypmZh0Uy4NZNn\n\
                                   n1Y6pU2cXLWAE3WwPi5toTabXuj8sIWvf/3W6EASqzuhri3dh9tCjoDjka2mSyS6\n\
                                   EDuMSvvdZRP5V/15F6R7M+LCHT+/0svr/7+ATtxgh/PQedYatN9fVD0vjboVrFz5\n\
                                   vZ4T7Mr978tWiDgAi0jxpZ8CgYA/AOiIR+FOB68wzXLSew/hx38bG+CnKoGzYRbr\n\
                                   nNMST+QOJlZr/3orCg6R8l2lZ56Y1sC/lEXKu3HzibHvJqhxZ2ld+NLCdBRrgx0d\n\
                                   STnMCbog2b+oe4/015+++NiAUYs9Y03K2fMTQJjf/ez8F8uF6bPhO1gL+GBEnaUT\n\
                                   yyA2iQKBgQD1KfqZeJtPCwmfdPokblKgorstuMKjMegD/6ztjIFw4c9XkvUAvlD5\n\
                                   MvS4rPuhVYrvouZHJ50bcwccByJ8aCOJxLdH7+bjojMSAgV2kGq+FNh7F1wRcwx8\n\
                                   8Z+DBbeVaCpYSQa5bCr5jG6nIX5v/KbS3HCmAkUzwqGoEsk53yFmKw==\n\
                                   -----END RSA PRIVATE KEY-----";

    #[test]
    fn decode_with_invalid_length() {
        let decoded = WinCertificate::decode(WINCERT_WITH_INVALID_LENGTH.as_ref());
        assert!(decoded.is_err());
    }

    #[test]
    fn decode_wincert_with_one_byte_certificate() {
        let decoded = WinCertificate::decode(WINCERT_WITH_ONE_BYTE_CERTIFICATE.as_ref()).unwrap();

        pretty_assertions::assert_eq!(decoded.length, 8);
        pretty_assertions::assert_eq!(decoded.revision, RevisionType::WinCertificateRevision10);
        pretty_assertions::assert_eq!(decoded.certificate_type, CertificateType::WinCertTypeX509);
        pretty_assertions::assert_eq!(decoded.certificate, vec![1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn encode_into_decode_wincert_with_one_byte_certificate() {
        let wincert = WinCertificate {
            length: 1,
            revision: RevisionType::WinCertificateRevision10,
            certificate_type: CertificateType::WinCertTypeX509,
            certificate: vec![1],
        };

        let encoded = wincert.encode().unwrap();
        assert_eq!(encoded, WINCERT_WITH_ONE_BYTE_CERTIFICATE.to_vec());
    }

    #[test]
    fn decode_wincert_with_ten_bytes_certificate() {
        let decoded = WinCertificate::decode(WINCERT_WITH_TEN_BYTES_CERTIFICATE.as_ref()).unwrap();

        pretty_assertions::assert_eq!(decoded.length, 16);
        pretty_assertions::assert_eq!(decoded.revision, RevisionType::WinCertificateRevision20);
        pretty_assertions::assert_eq!(decoded.certificate_type, CertificateType::WinCertTypePkcs1Sign);
        pretty_assertions::assert_eq!(
            decoded.certificate,
            vec![1, 32, 3, 64, 5, 96, 112, 8, 144, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn encode_into_decode_wincert_with_ten_bytes_certificate() {
        let wincert = WinCertificate {
            length: 10,
            revision: RevisionType::WinCertificateRevision20,
            certificate_type: CertificateType::WinCertTypePkcs1Sign,
            certificate: vec![1, 32, 3, 64, 5, 96, 112, 8, 144, 1],
        };

        let encoded = wincert.encode().unwrap();
        assert_eq!(encoded, WINCERT_WITH_TEN_BYTES_CERTIFICATE.to_vec());
    }

    #[test]
    fn decode_wincert_with_invalid_revision() {
        let decoded = WinCertificate::decode(WINCERT_WITH_INVALID_REVISION.as_ref());
        assert!(decoded.is_err());
    }

    #[test]
    fn decode_wincert_with_x509_certificate() {
        let decoded = WinCertificate::decode(WINCERT_WITH_X509_CERTIFICATE.as_ref());
        assert!(decoded.is_ok());
    }

    #[test]
    fn encode_wincert_with_x509_certificate() {
        let wincert = WinCertificate {
            length: 128,
            revision: RevisionType::WinCertificateRevision20,
            certificate_type: CertificateType::WinCertTypeX509,
            certificate: WINCERT_WITH_X509_CERTIFICATE[8..].to_vec(),
        };

        let encoded = wincert.encode().unwrap();
        pretty_assertions::assert_eq!(encoded, WINCERT_WITH_X509_CERTIFICATE.to_vec());
    }

    #[test]
    fn decoding_into_win_certificate() {
        let pem = parse_pem(crate::test_files::PKCS7.as_bytes()).unwrap();
        let pkcs7 = Pkcs7::from_pem(&pem).unwrap();
        let hash_type = ShaVariant::SHA2_256;
        let private_key = PrivateKey::from_pem_str(RSA_PRIVATE_KEY).unwrap();
        let program_name = "decoding_into_win_certificate_test".to_string();

        let win_cert =
            WinCertificate::new(pkcs7, FILE_HASH.as_ref(), hash_type, &private_key, Some(program_name)).unwrap();

        let pkcs7certificate: Pkcs7Certificate = picky_asn1_der::from_bytes(win_cert.get_certificate()).unwrap();

        let Pkcs7Certificate { signed_data, .. } = pkcs7certificate;

        let content_info = &signed_data.content_info;

        assert_eq!(
            Into::<String>::into(&content_info.content_type.0).as_str(),
            oids::SPC_INDIRECT_DATA_OBJID
        );

        let spc_indirect_data_content = content_info.content.as_ref().unwrap();
        let message_digest = match &spc_indirect_data_content.0 {
            ContentValue::SpcIndirectDataContent(SpcIndirectDataContent {
                data: _,
                message_digest,
            }) => message_digest.clone(),
            _ => panic!("Expected ContentValue with SpcIndirectDataContent, but got something else"),
        };

        let hash_algo = AlgorithmIdentifier::new_sha(hash_type);
        assert_eq!(message_digest.oid, hash_algo);

        pretty_assertions::assert_eq!(message_digest.digest.0, FILE_HASH);

        assert_eq!(signed_data.signers_infos.0 .0.len(), 1);

        let singer_info = signed_data.signers_infos.0 .0.first().unwrap();
        assert_eq!(singer_info.digest_algorithm.0, hash_algo);

        let authenticated_attributes = &singer_info.signed_attrs.0 .0;

        if !authenticated_attributes
            .iter()
            .any(|attr| matches!(attr.value, AttributeValues::ContentType(_)))
        {
            panic!("ContentType attribute is missing");
        }

        if !authenticated_attributes
            .iter()
            .any(|attr| matches!(attr.value, AttributeValues::MessageDigest(_)))
        {
            panic!("MessageDigest attribute is missing");
        }

        if !authenticated_attributes
            .iter()
            .any(|attr| matches!(attr.value, AttributeValues::SpcSpOpusInfo(_)))
        {
            panic!("SpcSpOpusInfo attribute is missing");
        }

        assert_eq!(
            singer_info.signature_algorithm,
            SignatureAlgorithmIdentifier(AlgorithmIdentifier::new_rsa_encryption())
        );

        let signature_algo =
            SignatureAlgorithm::from_algorithm_identifier(&AlgorithmIdentifier::new_sha256_with_rsa_encryption())
                .unwrap();

        let certificate = signed_data
            .certificates
            .0
            .iter()
            .cloned()
            .filter_map(|cert| Cert::try_from(cert).ok())
            .find(|cert| matches!(cert.ty(), CertType::Intermediate))
            .map(Certificate::from)
            .unwrap();

        let code_signing_ext_key_usage = Extension::new_extended_key_usage(vec![oids::kp_code_signing()]);
        assert!(!certificate
            .tbs_certificate
            .extensions
            .0
             .0
            .iter()
            .any(|extension| extension == &code_signing_ext_key_usage));

        let public_key = certificate.tbs_certificate.subject_public_key_info;
        let encrypted_digest = singer_info.signature.0 .0.as_ref();

        let mut auth_raw_data = picky_asn1_der::to_vec(&authenticated_attributes).unwrap();
        auth_raw_data[0] = Tag::SET.number();

        assert!(signature_algo
            .verify(&public_key.into(), auth_raw_data.as_ref(), encrypted_digest)
            .is_ok());
    }

    #[test]
    fn into_win_cert_from_pkcs7_with_x509_root_chain() {
        let pem = "-----BEGIN PKCS7-----\
                     MIIKDgYJKoZIhvcNAQcCoIIJ/zCCCfsCAQExADALBgkqhkiG9w0BBwGgggnhMIIE\
                     NjCCAh4CAWUwDQYJKoZIhvcNAQELBQAwYTELMAkGA1UEBhMCSUkxCzAJBgNVBAgM\
                     AklJMQswCQYDVQQHDAJJSTELMAkGA1UECgwCSUkxCzAJBgNVBAsMAklJMQswCQYD\
                     VQQDDAJJSTERMA8GCSqGSIb3DQEJARYCSUkwHhcNMjEwNDI5MTAxNTM3WhcNMjQw\
                     MTI0MTAxNTM3WjBhMQswCQYDVQQGEwJTUzELMAkGA1UECAwCU1MxCzAJBgNVBAcM\
                     AlNTMQswCQYDVQQKDAJTUzELMAkGA1UECwwCU1MxCzAJBgNVBAMMAlNTMREwDwYJ\
                     KoZIhvcNAQkBFgJTUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALFT\
                     ERznf389kwmFdy3RFeSQKRiU5Sr8k5ChXp+74u2kKVcbQixS2KQti3KopB8Xkly4\
                     31TBDRHRqR5H/x+KY/Pjp/iTFX6AXom4mxAglPxGeKdNuWesBdIf6hZcIJ2rZv94\
                     G67m4ggCS0oDB3qYykw02wO6QeEZHA0AiLRusR4SQZZNZc3Z6JUSijTJZE+TKxL8\
                     eoVNI5P4/+aSY4wdLPK+qEfzsumxVSbqQWO7aWWd6yYYCsGhd/k9pVJMmqXH+rkL\
                     lVcxtYkAnH1TOuvsAn+FBMwr/lXuenT3DiFTDJtm/Mu4ZM2lD60o6aDCSdYSOh/w\
                     amTGCX3WWMmpqfBFRy8CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAy51uXBnzdU1d\
                     U8K3kh1naldLG6/UF8jJhiN7vmltPuYSvPeIzNk/g4UXUACHnUzg7JWRobf0VBHw\
                     /I8xGXjnRRo2s9w2ZyF4CyDC7YVZWK/bvUe/7qMteZPBXC1Fgz03UC0Y/Y9jqCUJ\
                     ev0bl+u9jRkoE5aMiJhQOzn+CDGxKXvefDpDtvt8nuqNnY9vP7fo3wTLhWF4RUFA\
                     p8iNQu4Pw1XaHhJ467c5kFZLBz+E75myIRJfRYYmBw6nWLSDNueI/Jw+N6jxTKw6\
                     +PtqGx91YTgUK61HHTe8qY7HYCt8ZNmJWvzYpBjUCMEx0BS3sQ7KLc8piD7C5aH7\
                     YzS1PLA2hk4nAk1+uDlQrbfZl+p3ED8NTIvbL9GPBqTQAjOwVkspuidfabgsg/yk\
                     0Nh+3AFMkAy3MoSHmf0AugWyd1F37xx8SePY7NSznWbd7z6UP0WpS4k3BaYWxll1\
                     Q4jXPVghHuQBgmsamx6uXI950DszVvvzubmoVFGsOhdq6BLoZ4dx2mh2teLyPOH0\
                     77nEEOREhilxLMunGUZsZ5rcZuLgMKwOMxY7Sk3x4ETLG9R5Fhe+w70xZfWkKEt0\
                     o7cjRnNM3njJs+TKSZYXcv/9AKhWNUyqhrgUtbsWjTBnXaRyBtDZR3iQx9t0QQZ/\
                     cX0bsED8y9zkFxTIYcSbJuYtcO2ldm8wggWjMIIDi6ADAgECAhRf5s94qhLBW634\
                     aeLH/M67kmZ+8TANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQGEwJTUzELMAkGA1UE\
                     CAwCUlIxCzAJBgNVBAcMAlJSMQswCQYDVQQKDAJSUjELMAkGA1UECwwCUlIxCzAJ\
                     BgNVBAMMAlJSMREwDwYJKoZIhvcNAQkBFgJSUjAeFw0yMTA0MjkxMDA0MzZaFw0y\
                     NjA0MjkxMDA0MzZaMGExCzAJBgNVBAYTAlNTMQswCQYDVQQIDAJSUjELMAkGA1UE\
                     BwwCUlIxCzAJBgNVBAoMAlJSMQswCQYDVQQLDAJSUjELMAkGA1UEAwwCUlIxETAP\
                     BgkqhkiG9w0BCQEWAlJSMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\
                     2AXxt6RZbLKqkw+9Y0FbT+hMS/MpPMEnCINTHK3gzhjP3hhOKfVhHekfWoZ07gZz\
                     IcJMfcXTLFbsFDuZssj63YXiKkk5AXstgd+8F2nW4xNLdXiAD6/vQQYzX/KJO1+T\
                     5y1vAuAvO4xybe0HHMsIcLlUv45BaEBOFizUwMsDnE+GEVfsfFNhxxvLz0daGrSF\
                     c7C0DgG4qNC9ONrOThZhBeDud8g6LLYSTHnIblEfbsVPUlNI+mk8vFNoQYAoz74M\
                     dIfJZQ3+yoqqDAlVAERo9bD8ejnB296OVIpzjHr8v4Y1hxB1UIE7P9LIYhl2FOI1\
                     F57MyGM+qUD86s4ycxq1emrjurhG8xzUttUAg4RRogtJdJrGu9AX2RbnWV6yLfZl\
                     bE6NG2LBuxihZ40vMYFNt3CgZ/7MUc7mJcPsg+5uu86jMWWJ3/0kBIhGIEVsyDsy\
                     RyAE1trB5Zs1yvuEVx8UDs6nrXns+q7lexliomVGPQGf4eoJaNGXqR4xB8oKqCCJ\
                     pMdNARAYOEAjtYvkoZVSgQb0HoScZmlXywwlRVMiDToSsE7pheiv5WEyiBSoMMnI\
                     OMFyIu9YP5DBjVweggqJDvg6n+iRqsTckRbY/wxUIcMpczkhTPAI0zCHLbtkCA7S\
                     caZjpPP7Q1I2XtquR08vflsGrwcVl9OSOVqJ4AN5xiMCAwEAAaNTMFEwHQYDVR0O\
                     BBYEFFbRR8T+Mn5/zWJ4dRa4o7oqzWK3MB8GA1UdIwQYMBaAFFbRR8T+Mn5/zWJ4\
                     dRa4o7oqzWK3MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAL+5\
                     oOOyd1M14xbdyxKTJyQQbR/3Fu+ycLoKqHI8xDtqpxQz39r6TjZVzRPGmkaO2LFr\
                     jS6vatIG+X2A8qsKS6Oab0BMj/0uKpibS8sm/4wJCUVj5fRHRAfTHOeis6efYgB4\
                     t/Er3WKbpfnySPKtxr5vO6KpYk+cRz6aIs5zD3I/5LXdyn4BD4O4RH8w5m55xs0G\
                     pZWH1K1SZmv6bmWmnKM5x5kECbsJQDA9oNCV2Vqg3y52dxmvuworzMlu2gnpdQQT\
                     6Ibh65SYtfYBQTn2bPQB+YPfWqGoWSDUq7CHybUNCgKqYw7+4X/cJB0IkUMZt+Pw\
                     kS3YiYP8hRM4lQAs6ITiB1GSpPuL9cCRcOjHvjilLiZJGfskGy8ucqlj24LEvtb6\
                     DWu45SyjuQ08r6ORxkVg/cz1ztx0BrIVMQMxpIYUi1xPHPpz60j4Y1v1O2XvRJMu\
                     Xg6ulyYWYaw+V+VopcQWBvAe1gYUk0CVzneBEjauzT1qX8K/Fu6f5ltQEJ5XGuYY\
                     pHEn99xhnRUSThoBvOwQj8JjD8uiCJvvOVugF1wEh4RIcCKj7r4u91c41ndg7FU0\
                     kxVRpfjDmxxzQib3Q/z4ZAoqW7+Hjq6gqim2ngrB9Co9pv4ckJ5APDx6x9WF8gpc\
                     Ydn+09ezBdJ4Zgn5U7GdrkNAgOzXtBwbiKxlGcWWoQAxAA==\
                     -----END PKCS7-----";

        let pkcs7 = Pkcs7::from_pem_str(pem).unwrap();
        let private_key = PrivateKey::from_pem_str(RSA_PRIVATE_KEY).unwrap();

        let win_cert = WinCertificate::new(
            pkcs7,
            FILE_HASH.as_ref(),
            ShaVariant::SHA2_256,
            &private_key,
            Some("into_win_cert_from_pkcs7_with_x509_root_chain".to_string()),
        );

        assert!(win_cert.is_ok());
    }
}
