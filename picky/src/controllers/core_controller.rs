use mbedtls::pk::Type as KeyType;
use mbedtls::hash::Type as HashType;
use x509_parser::{parse_x509_der, pem::pem_to_der};

use crate::models::certificate::Cert;
use crate::models::csr::CertificateSignRequest;
use der_parser::oid::Oid;

pub const DEFAULT_DURATION: i64 = 156;
pub const ROOT_DURATION: i64 = 520;
pub const INTERMEDIATE_DURATION: i64 = 260;

const CERT_PREFIX: &str = "-----BEGIN CERTIFICATE-----";
const CERT_SUFFIX: &str = "-----END CERTIFICATE-----";

pub enum Order{
    RootIntermediate,
    IntermediateRoot
}

pub struct CoreController{
}

impl CoreController{
    pub fn generate_root_ca(realm: &str, hash_type: HashType, key_type: KeyType) -> Option<Cert>{
        let root = Cert::generate_root(realm, hash_type, key_type, 4096);
        Some(root)
    }

    pub fn generate_intermediate_ca(root: &[u8], root_key: &[u8], realm: &str, hash_type: HashType, key_type: KeyType) -> Option<Cert>{
        let intermediate = Cert::generate_intermediate(&root, root_key, realm, hash_type, key_type, 4096);
        Some(intermediate)
    }

    pub fn generate_certificate_from_csr(authority: &[u8], authority_key: &[u8], hash_type: HashType, csr: &str) -> Option<Cert>{
        let leaf = Cert::generate_from_csr(csr, authority, authority_key, hash_type);
        Some(leaf)
    }

    pub fn get_key_identifier(der: &[u8], oid: &[u64]) -> Result<String, String>{
        if let Ok((_e, cert)) = parse_x509_der(der){
            let extensions = cert.tbs_certificate.extensions;

            for x in extensions{
                if  x.oid ==  Oid::from(oid){
                    let res = x.value.to_vec();
                    return Ok(hex::encode(&res[res.len() - 20..]));
                }
            }
        }

        Err("Could not get identifier".to_string())
    }

    pub fn get_subject_name(der: &[u8]) -> Result<String, String> {
        if let Ok((_e, cert)) = parse_x509_der(&der){
            return Ok(cert.tbs_certificate.subject.to_string());
        }

        Err("Could not get subject name".to_string())
    }

    pub fn get_issuer_name(der: &[u8]) -> Result<String, String> {
        if let Ok((_e, cert)) = parse_x509_der(&der){
            return Ok(cert.tbs_certificate.issuer.to_string());
        }

        Err("Could not get issuer name".to_string())
    }

    pub fn request_name(csr: &str) -> Result<String, String>{
        CertificateSignRequest::get_csr_common_name(csr)
    }

    pub fn fix_string(pem: &str) -> Result<Vec<u8>, String>{
        let mut pem = pem.clone()
            .replace("\n", "")
            .replace(CERT_PREFIX, "")
            .replace(CERT_SUFFIX, "")
            .replace(" ", "");

        let mut fixed_pem = String::default();

        while pem.len()/64 > 0{
            let s = pem.split_at(63);
            fixed_pem.push_str(&format!("{}{}", s.0, "\n"));
            pem = s.1.to_string();
        }

        fixed_pem.push_str(&format!("{}{}", pem, "\n"));
        let fixed_pem = format!("{}{}{}", format!("{}{}", CERT_PREFIX, "\n"), fixed_pem, format!("{}{}", CERT_SUFFIX, "\n"));

        match pem_to_der(fixed_pem.as_bytes()){
            Ok((_rem, pem)) => {
                Ok(pem.contents.clone())
            },
            Err(_e) => {
                Err("Can\'t fix pem".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn get_identifier_test() {
        if let Some(root) = CoreController::generate_root_ca("test", HashType::Sha256, KeyType::Rsa) {
            if let Ok(ski) = CoreController::get_key_identifier(&root.certificate_der, &[2, 5, 29, 14]) {
                let _ski = ski;
                assert!(true);
            }
        }
    }
}