use crate::models;

use mbedtls::x509::csr;
use mbedtls::hash::Type::Sha256;
use mbedtls::x509::key_usage;
use mbedtls::rng::os_entropy::{OsEntropy};
use mbedtls::rng::ctr_drbg::CtrDrbg;
use mbedtls::pk::Pk;

use models::key::*;

use regex::Regex;

const HASH: mbedtls::hash::Type = Sha256;

pub struct CertificateSignRequest{
    pub subject: String,
    pub keys: Keys,
    pub csr: String
}

impl CertificateSignRequest{
    pub fn generate_csr(subject: &str, mut pk: Pk) -> String {
        let mut entropy = OsEntropy::new();
        let mut rng = CtrDrbg::new(&mut entropy, None).unwrap();

        let mut builder = csr::Builder::new();
        let mut output = builder
            .subject(subject).unwrap()
            .key(&mut pk)
            .signature_hash(HASH)
            .key_usage(key_usage::DIGITAL_SIGNATURE | key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN | key_usage::KEY_ENCIPHERMENT | key_usage::DIGITAL_SIGNATURE).unwrap()
            .write_pem_string(&mut rng).unwrap();
        output.push('\0');
        output
    }

    pub fn get_csr_common_name(csr: &str) -> Result<String, String>{
        if let Ok(csr) = csr::Csr::from_pem(format!("{}{}", csr, "\0").as_bytes()){
            return match csr.subject() {
                Ok(cn) => {
                    let re = Regex::new(r"CN=(.*)").unwrap();
                    let cn = re.find(&cn).unwrap().as_str().to_string();
                    Ok(cn[3..].to_string())

                },
                Err(e) => Err(e.to_string())
            };
        }

        Err("Invalid csr".to_string())
    }
}

#[cfg(test)]
mod tests{

}