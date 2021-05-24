use std::convert::{Into, TryFrom};

use thiserror::Error;

use picky_asn1::restricted_string::CharSetError;
use picky_asn1::tag::Tag;
use picky_asn1::wrapper::{ApplicationTag0, ApplicationTag1, Asn1SetOf};

use picky_asn1_der::Asn1DerError;

use picky_asn1_x509::algorithm_identifier::{AlgorithmIdentifier, UnsupportedAlgorithmError};
use picky_asn1_x509::{oids, Attribute, AttributeValues, Attributes, Certificate, DigestInfo, SHAVariant};

use picky_asn1_x509::pkcs7::cmsversion::CMSVersion;
use picky_asn1_x509::pkcs7::content_info::{
    EncapsulatedContentInfo, ContentValue, SpcAttributeAndOptionalValue, SpcIndirectDataContent, SpcLink, SpcPeImageData,
    SpcPeImageFlags, SpcSpOpusInfo, SpcString,
};
use picky_asn1_x509::pkcs7::crls::RevocationInfoChoices;
use picky_asn1_x509::pkcs7::signed_data::{CertificateSet, DigestAlgorithmIdentifiers, SignedData, SingersInfos};
use picky_asn1_x509::pkcs7::singer_info::{
    CertificateSerialNumber, DigestAlgorithmIdentifier, IssuerAndSerialNumber, SignatureAlgorithmIdentifier,
    SignatureValue, SignerIdentifier, SignerInfo,
};
use picky_asn1_x509::pkcs7::Pkcs7Certificate;

use super::certificate::CertError;
use super::utils::{from_der, from_pem, from_pem_str, to_der, to_pem};
use super::wincert::WinCertificate;
use crate::hash::HashAlgorithm;
use crate::key::PrivateKey;
use crate::pem::Pem;
use crate::signature::SignatureAlgorithm;
use crate::x509::extension::{ExtendedKeyUsage, ExtensionView};

type Pkcs7Result<T> = Result<T, Pkcs7Error>;

pub const AUTHENTICODE_ATTRIBUTES_COUNT: usize = 3;

const ELEMENT_NAME: &str = "pkcs7 certificate";

#[derive(Debug, Error)]
pub enum Pkcs7Error {
    #[error(transparent)]
    Cert(#[from] CertError),
    #[error(transparent)]
    Asn1DerError(#[from] Asn1DerError),
    #[error(transparent)]
    SignatureError(#[from] crate::signature::SignatureError),
    #[error("the program name has invalid charset")]
    ProgramNameCharSet(#[from] CharSetError),
    #[error(transparent)]
    UnsupportedAlgorithmError(UnsupportedAlgorithmError),
    #[error("The signing certificate must contain the extended key usage (EKU) value for code signing")]
    NoEKUCodeSigning,
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
        hash_algo: HashAlgorithm,
        private_key: &PrivateKey,
        program_name: Option<String>,
    ) -> Pkcs7Result<WinCertificate> {
        let Pkcs7Certificate { oid, signed_data } = self.0;

        let SignedData { certificates, .. } = signed_data.0;

        let sha_algo = SHAVariant::from(hash_algo);
        let digest_algorithm = AlgorithmIdentifier::new_sha(sha_algo);

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
            .map_err(Pkcs7Error::ProgramNameCharSet)?
            .map(ApplicationTag0);

        let mut authenticated_attributes: Vec<Attribute> = Vec::with_capacity(AUTHENTICODE_ATTRIBUTES_COUNT);

        let mut raw_spc_indirect_data_content = picky_asn1_der::to_vec(&data)?;
        raw_spc_indirect_data_content.append(&mut picky_asn1_der::to_vec(&message_digest)?);

        authenticated_attributes.append(&mut vec![
            Attribute {
                ty: oids::content_type().into(),
                value: AttributeValues::ContentType(Asn1SetOf(vec![oids::spc_indirect_data_objid().into()])),
            },
            Attribute {
                ty: oids::spc_sp_opus_info_objid().into(),
                value: AttributeValues::SpcSpOpusInfo(Asn1SetOf(vec![SpcSpOpusInfo {
                    program_name,
                    more_info: Some(ApplicationTag1(SpcLink::default())),
                }])),
            },
            Attribute {
                ty: oids::message_digest().into(),
                value: AttributeValues::MessageDigest(Asn1SetOf(vec![hash_algo
                    .digest(raw_spc_indirect_data_content.as_ref())
                    .into()])),
            },
        ]);

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
                    .expect("Certificates must contain at least leaf and intermediate certificates");

                if !signing_cert.tbs_certificate.extensions.0 .0.iter().any(|extension| {
                    extension.extn_value() == ExtensionView::ExtendedKeyUsage(&code_signing_ext_key_usage)
                }) {
                    return Err(Pkcs7Error::NoEKUCodeSigning);
                }
            }
        }

        let signing_cert = certificates
            .0
            .get(0)
            .expect("Certificates must contain at least Leaf and Intermediate certificates");

        let issuer_and_serial_number = IssuerAndSerialNumber {
            issuer: signing_cert.tbs_certificate.issuer.clone(),
            serial_number: CertificateSerialNumber(signing_cert.tbs_certificate.serial_number.clone()),
        };

        let digest_encryption_algorithm = AlgorithmIdentifier::new_rsa_encryption_with_sha(sha_algo)
            .map_err(Pkcs7Error::UnsupportedAlgorithmError)?;

        let signature_algo = SignatureAlgorithm::from_algorithm_identifier(&digest_encryption_algorithm)?;

        let mut auth_raw_data = picky_asn1_der::to_vec(&authenticated_attributes)?;
        // According to the RFC:
        //
        // "[...] The Attributes value's tag is SET OF, and the DER encoding of
        // the SET OF tag, rather than of the IMPLICIT [0] tag [...]"
        auth_raw_data[0] = Tag::SET.number();

        let encrypted_digest = SignatureValue(signature_algo.sign(auth_raw_data.as_ref(), private_key)?.into());

        let singer_info = SignerInfo {
            version: CMSVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial_number),
            digest_algorithm: DigestAlgorithmIdentifier(digest_algorithm.clone()),
            signed_attrs: Attributes(authenticated_attributes).into(),
            signature_algorithm: SignatureAlgorithmIdentifier(AlgorithmIdentifier::new_rsa_encryption()),
            signature: encrypted_digest,
        };

        // certificates contains the signer certificate and any intermediate certificates,
        // but typically does not contain the root certificate

        let certificates = CertificateSet(certificates.0.into_iter().take(2).collect::<Vec<Certificate>>());

        let signed_data = SignedData {
            version: CMSVersion::V1,
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
    use crate::x509::certificate::{Cert, CertType};
    use crate::x509::Extension;

    const FILE_HASH: [u8; 32] = [
        0xa7, 0x38, 0xda, 0x44, 0x46, 0xa4, 0xe7, 0x8a, 0xb6, 0x47, 0xdb, 0x7e, 0x53, 0x42, 0x7e, 0xb0, 0x79, 0x61,
        0xc9, 0x94, 0x31, 0x7f, 0x4c, 0x59, 0xd7, 0xed, 0xbe, 0xa5, 0xcc, 0x78, 0x6d, 0x80,
    ];

    const RSA_PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\n
MIIEpAIBAAKCAQEA0vg4PmmJdy1W/ayyuP3ovRBbggAZ98dEY5uzEU23ENaN3jsx\n
R9zEAAmQ9OZbbJXN33l+PMKY7+5izgI/RlGSNF2s0mdyWEhoRMTxuwpJoFgBkYEE\n
Jwr40xoLCbw9TpBooJgdYg/n/Fu4NGM7YJdcfKjf3/le7kNTZYPBx09wBkHvkuTD\n
gpdDDnb5R6sTouD0bCPjC/gZCoRAAlzfuAmAAHVb+i8fkTV32OzokLYcneuLZU/+\n
FBpR2w9UprfDLWFbPxuOBf+mIGp4WWVN82+3SdEkp/5BRQ//MhGhj7NhEYp+KyWJ\n
Hm+1iGvrxsgQH+4MQTJGdp838sl+w77QGFZU9QIDAQABAoIBAEBWNkDCSouvpgHC\n
ctZ7iEhv/pgMk96+RBrkVp2GR7e41pbZElRJ/PPN9wjYXzUkEh5+nILHDYDOAA+3\n
G7jEE4QotRWNOo+1tSaTsOxLXNyrOf83ix6k9/DY1ljnsQKOg3nGKd/H3gVVqz0+\n
rdLtFeVmUq+pCsw6d+pTXfr8PLuLPfe8r9fu/BGU2wtINAEuQ4x3/S/JPTm6XnsV\n
NUW62K/lB7RjXlEqnKMwxcVCu/m0C1HdlwTlHyzktIydjL9Bk1GjGQVt0zC/rfvA\n
zrlsTPg4UTL6zs4D9B5PPaZMJeBieXaQ0JdqKdJkRm+mPCOEGf+BLz1zHVAVZaSZ\n
PK8E7NkCgYEA+e7WUOlr4nR6fqvte0ZTewIeG/j2m5gSVjjy8Olh2D3v8q4hZj5s\n
2jaFJJ7RUGXZdiySodlEpLR2nrrUURC6fGukvbFCW2j/0SotBl53Wa2zJdrU3AZc\n
b9j7MOyJbJDKJYqdivYJXp7ra4vCs0xAMXfuQD1AWaKlCQxbeyrKWxcCgYEA2BdA\n
fB7IL0ec3WOsLyGGhcCrGDWIiOlXzk5Fuus+NOEp70/bYCqGpu+tNAxtbY4e+zHp\n
5gXApKU6PSQ/I/eG/o0WGQCZazfhIGpwORrWHAVxDlxJ+/hlZd6DmTjaIJw1k2gr\n
D849l1WIEr2Ps8Bv3Y7XeLpnUAQFv1ekfMKxZ9MCgYEA2vtNYfUypmZh0Uy4NZNn\n
n1Y6pU2cXLWAE3WwPi5toTabXuj8sIWvf/3W6EASqzuhri3dh9tCjoDjka2mSyS6\n
EDuMSvvdZRP5V/15F6R7M+LCHT+/0svr/7+ATtxgh/PQedYatN9fVD0vjboVrFz5\n
vZ4T7Mr978tWiDgAi0jxpZ8CgYA/AOiIR+FOB68wzXLSew/hx38bG+CnKoGzYRbr\n
nNMST+QOJlZr/3orCg6R8l2lZ56Y1sC/lEXKu3HzibHvJqhxZ2ld+NLCdBRrgx0d\n
STnMCbog2b+oe4/015+++NiAUYs9Y03K2fMTQJjf/ez8F8uF6bPhO1gL+GBEnaUT\n
yyA2iQKBgQD1KfqZeJtPCwmfdPokblKgorstuMKjMegD/6ztjIFw4c9XkvUAvlD5\n
MvS4rPuhVYrvouZHJ50bcwccByJ8aCOJxLdH7+bjojMSAgV2kGq+FNh7F1wRcwx8\n
8Z+DBbeVaCpYSQa5bCr5jG6nIX5v/KbS3HCmAkUzwqGoEsk53yFmKw==\n
-----END RSA PRIVATE KEY-----";

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
        let hash_type = HashAlgorithm::SHA2_256;
        let private_key = PrivateKey::from_pem_str(RSA_PRIVATE_KEY).unwrap();
        let program_name = "decoding_into_win_certificate_test".to_string();

        let win_cert = pkcs7
            .into_win_certificate(FILE_HASH.as_ref(), hash_type, &private_key, Some(program_name))
            .unwrap();

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

        assert_eq!(
            message_digest.oid,
            AlgorithmIdentifier::new_sha(SHAVariant::from(hash_type))
        );

        pretty_assertions::assert_eq!(message_digest.digest.0, FILE_HASH);

        assert_eq!(signed_data.singers_infos.0 .0.len(), 1);

        let singer_info = signed_data.singers_infos.0 .0.first().unwrap();
        assert_eq!(
            singer_info.digest_algorithm.0,
            AlgorithmIdentifier::new_sha(SHAVariant::from(hash_type))
        );

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
            .clone()
            .into_iter()
            .map(Cert::from)
            .find(|certificate| matches!(certificate.ty(), CertType::Intermediate))
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

        let win_cert = pkcs7.into_win_certificate(
            FILE_HASH.as_ref(),
            HashAlgorithm::SHA2_256,
            &private_key,
            Some("into_win_cert_from_pkcs7_with_x509_root_chain".to_string()),
        );

        assert!(win_cert.is_ok());
    }
}
