use mbedtls::pk::Type as KeyType;
use mbedtls::hash::Type as HashType;

use crate::models::certificate::Cert;
use crate::models::csr::CertificateSignRequest;

pub const DEFAULT_DURATION: i64 = 156;
pub const ROOT_DURATION: i64 = 520;
pub const INTERMEDIATE_DURATION: i64 = 260;

pub enum Order{
    RootIntermediate,
    IntermediateRoot
}

pub struct CoreController{
}

/// TODO: Add bits length for key in config
impl CoreController{
    pub fn generate_root_ca(realm: &str, hash_type: HashType, key_type: KeyType) -> Option<Cert>{
        let root = Cert::generate_root(realm, hash_type, key_type, 4096);
        Some(root)
    }

    pub fn generate_intermediate_ca(root: &str, root_key: &str/*root: &Cert*/, realm: &str, hash_type: HashType, key_type: KeyType) -> Option<Cert>{
        let intermediate = Cert::generate_intermediate(root, root_key, realm, hash_type, key_type, 4096);
        Some(intermediate)
    }

    pub fn generate_certificate_from_csr(authority: &str, authority_key: &str/*authority: &Cert*/, hash_type: HashType, csr: &str) -> Option<String>{
        let leaf = Cert::generate_from_csr(csr, authority, authority_key, hash_type);
        Some(leaf.certificate_pem)
    }

    pub fn request_name(csr: &str) -> Result<String, String>{
        CertificateSignRequest::get_csr_common_name(csr)
    }
}

#[cfg(test)]
mod tests{

}