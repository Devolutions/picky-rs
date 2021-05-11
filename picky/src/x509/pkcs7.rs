use std::convert::{Into, TryFrom};

use thiserror::Error;

use picky_asn1::restricted_string::CharSetError;
use picky_asn1::tag::Tag;
use picky_asn1::wrapper::{ApplicationTag0, Asn1SetOf};

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
use picky_asn1_x509::{oids, Attribute, AttributeValues, Attributes, DigestInfo, SHAVariant, Version};

use super::certificate::CertError;
use super::utils::{from_der, from_pem, from_pem_str, to_der, to_pem};
use super::wincert::WinCertificate;
use crate::hash::HashAlgorithm;
use crate::key::PrivateKey;
use crate::pem::Pem;
use crate::signature::SignatureAlgorithm;
use crate::x509::Extension;

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

        let SignedData { mut certificates, .. } = signed_data.0;

        let digest_algorithm = AlgorithmIdentifier::new_sha(SHAVariant::from(hash_algo));

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
                value: AttributeValues::ContentType(Asn1SetOf(vec![oids::message_digest().into()])),
            },
            Attribute {
                ty: oids::message_digest().into(),
                value: AttributeValues::MessageDigest(Asn1SetOf(vec![hash_algo
                    .digest(raw_spc_indirect_data_content.as_ref())
                    .into()])),
            },
            Attribute {
                ty: oids::spc_sp_opus_info_objid().into(),
                value: AttributeValues::SpcSpOpusInfo(Asn1SetOf(vec![SpcSpOpusInfo {
                    program_name,
                    more_info: Some(SpcLink::default().into()),
                }])),
            },
        ]);

        let content = SpcIndirectDataContent { data, message_digest };

        let content_info = ContentInfo {
            content_type: oids::spc_indirect_data_objid().into(),
            content: Some(content.into()),
        };

        // The signing certificate must contain either the extended key usage (EKU) value for code signing,
        // or the entire certificate chain must contain no EKUs
        {
            let certificates = &mut certificates.0;
            let code_signing_ext_key_usage = Extension::new_extended_key_usage(vec![oids::kp_code_signing()]);

            if certificates
                .iter()
                .map(|cert| cert.tbs_certificate.extensions.0 .0.iter())
                .flatten()
                .any(|extension| matches!(extension, _code_signing_ext_key_usage))
            {
                let leaf_cert = certificates
                    .first_mut()
                    .expect("Certificates must contain at least leaf and intermediate certificates");
                let extensions = &mut leaf_cert.tbs_certificate.extensions.0 .0;

                if !extensions
                    .iter()
                    .any(|extension| matches!(extension, _code_signing_ext_key_usage))
                {
                    extensions.push(code_signing_ext_key_usage);
                }
            }
        }

        let certificate = certificates
            .0
            .first()
            .expect("Certificates must contain at least Leaf and Intermediate certificates");

        let issuer_and_serial_number = IssuerAndSerialNumber {
            issuer: certificate.tbs_certificate.issuer.clone(),
            serial_number: CertificateSerialNumber(certificate.tbs_certificate.serial_number.clone()),
        };

        let digest_encryption_algorithm = AlgorithmIdentifier::new_sha256_with_rsa_encryption();

        let signature_algo = SignatureAlgorithm::from_algorithm_identifier(&digest_encryption_algorithm).unwrap();

        let mut auth_raw_data = picky_asn1_der::to_vec(&authenticated_attributes)?;
        // According to the RFC:
        //
        // "[...] The Attributes value's tag is SET OF, and the DER encoding of
        // the SET OF tag, rather than of the IMPLICIT [0] tag [...]"
        auth_raw_data[0] = Tag::SET.number();

        let encrypted_digest = EncryptedDigest(signature_algo.sign(auth_raw_data.as_ref(), private_key)?.into());

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

    const FILE_HASH: [u8; 32] = [
        0xa7, 0x38, 0xda, 0x44, 0x46, 0xa4, 0xe7, 0x8a, 0xb6, 0x47, 0xdb, 0x7e, 0x53, 0x42, 0x7e, 0xb0, 0x79, 0x61,
        0xc9, 0x94, 0x31, 0x7f, 0x4c, 0x59, 0xd7, 0xed, 0xbe, 0xa5, 0xcc, 0x78, 0x6d, 0x80,
    ];

    const RSA_PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
                                   MIIEogIBAAKCAQEAoAHqJ0RudJ4e3StnnhSBfivE/v1xDw6B+/FJiQDDL1ZE1JKH\n\
                                   kfgeLqcmbZQ1y8LlkmjH4CS9PhunDgwb4No8EssT3qZNhNANCMgWK9RkohGKPiA1\n\
                                   54dFwpN84Ujg5xuOJ8KrOLwXdcUAoVO/tmSC2DhnOduOPwP7hYbfK16CpkRjqvLU\n\
                                   mL3+hYMxKGScka4bT7BhejtjV3q6bWHv2kHDHvZ3BytGJh1PupRIt2uK20ZN3HbD\n\
                                   s7SciKxi/rOFBlhGU0gVfblXwo+Unspw8aVPAIvGYSirfy1Co7IU1mTZm36sdNTJ\n\
                                   XdEYwZG3bo9EGDgPYhM1QcnGMgHmIWhE0m0+KwIDAQABAoIBAG4K4w6+cXiihnd1\n\
                                   Mn31fFlZoNH9W5QPVjX/a6Ndct9LZWsMm1A4ZAmRy0vxck4AbAKVLWFp4vyj5/Ax\n\
                                   Q7sQW+BQ6glmNknxDAXOFfFu0QblKT4wyOHClqeK54fIp2RJ/yo5J6iNM1U7d4N8\n\
                                   JY068wHhSJzx8pJEGudqKnGZPiE6MPxfVYxR9AEPaHPVnFVh+ziIrfCE8wkhQHtS\n\
                                   anq6RIJTOA5mDAX0FhLTep7r0/ymKEj0c4ZkPiEonclkaXXf/1dN7qtJnU9b+dpR\n\
                                   ESM3QYvh9SnwlZaptt8tYAmAMVTkc4Jjf9Lx7G2Ve091mj6wS/Vl+uI/e7KIMGxn\n\
                                   E0a0GoECgYEA0iZIk/oVzeBHMPi23KWENN6cP9Wq5RR0/iWfzE88L9IwG0yNplzi\n\
                                   zK91yAVAtQfOVYH7B4b6Uwy9C5Nx/B0GIbv+v/7Batpis4HTeewlvB5RKQLHtrLA\n\
                                   EeHmpQsQseOgSaBAVaWnEYOEROOtO0DGk/kH3/ypbQUHOIpy9LWtLicCgYEAwur9\n\
                                   k1ejvDcSgcIXnsfp1B2hrkSVBFDm9upSDgV/LEPTNDA4mc+W3YR58HX4YdGvMfly\n\
                                   B/7Kb/w29Vn6FuS5KukulQ6wRAG/9ON38eh2ATC6BKDG7DcHbCPTnr0PTMRgeVQ4\n\
                                   1euucHsFIIsmgCNygxo+OPXp7L+KnDTEyVrG9l0CgYARRux4nfrk7idsM0Z1ZXY1\n\
                                   EoguB1cBdmkX6+fzWCBOni0uUWDj6IcM5O/9/dCQEZA5H3KP79zsrwNrzDd2zrwO\n\
                                   UfJjvoIQUtwCfg3w3CVODgAGKyBYOOHplnTr5Lj+pwQqiW5AnFnb6sAZGc7ILE8n\n\
                                   IzYuiAs110/8qgVBcR5HyQKBgCmmdRDrBT3OttGrW8i+ByUgP9AxL3aAoxnX8Di2\n\
                                   y/n1dEgOlcmoJiCnkjbjvnOIjtsq5kb3FuLfDg9Xbq09qqOUuDN5tAiUJyR5BsRW\n\
                                   XADdHKKoiFkpWRiufyXIWGCbBdJnQM3VUq0OXIYbtdpjuLBzByC8y4OfWksOq44r\n\
                                   K6CxAoGAH70deZnnp+6LGNS3Zv6X3WvzmrRYwoRXNVz7xSUhDFsz0UeFOyAfHNl3\n\
                                   U2pDsAQtWZkejsdWXha5kwLeQdF7NkLxGDdsO0w+fhP9SkBA/HiUIg/BLY1Vz1DU\n\
                                   XWVhD37ATsWx7xpW4GrAwBQlgBHXoDVJksYJ7mUNpqxf35yh5DQ=\n\
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
        let message_digest = &spc_indirect_data_content.message_digest;

        assert_eq!(
            message_digest.oid,
            AlgorithmIdentifier::new_sha(SHAVariant::from(hash_type))
        );

        pretty_assertions::assert_eq!(message_digest.digest.0, FILE_HASH);

        assert_eq!(signed_data.singers_infos.0 .0.len(), 1);

        let singer_info = signed_data.singers_infos.0 .0.first().unwrap();
        assert_eq!(
            singer_info.digest_algorithm,
            AlgorithmIdentifier::new_sha(SHAVariant::from(hash_type))
        );

        let authenticated_attributes = &singer_info.authenticode_attributes.0 .0;

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
            singer_info.digest_encryption_algorithm,
            DigestEncryptionAlgorithmIdentifier(AlgorithmIdentifier::new_sha256_with_rsa_encryption())
        );

        let signature_algo =
            SignatureAlgorithm::from_algorithm_identifier(&AlgorithmIdentifier::new_sha256_with_rsa_encryption())
                .unwrap();

        let certificate = signed_data.0.certificates.0.first().unwrap();
        let public_key = certificate.tbs_certificate.subject_public_key_info.clone();
        let encrypted_digest = singer_info.encrypted_digest.0 .0.as_ref();

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
