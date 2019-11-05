use crate::{
    models::{certificate::Cert, csr::CertificateSignRequest},
    serde::Certificate,
};
use mbedtls::{hash::Type as HashType, pk::Type as KeyType};

pub const DEFAULT_DURATION: i64 = 156;
pub const ROOT_DURATION: i64 = 520;
pub const INTERMEDIATE_DURATION: i64 = 260;

pub enum Order {
    RootIntermediate,
    IntermediateRoot,
}

pub struct CoreController;

impl CoreController {
    pub fn generate_root_ca(realm: &str, hash_type: HashType, key_type: KeyType) -> Option<Cert> {
        Some(Cert::generate_root(realm, hash_type, key_type, 4096))
    }

    pub fn generate_intermediate_ca(
        root: &[u8],
        root_key: &[u8],
        realm: &str,
        hash_type: HashType,
        key_type: KeyType,
    ) -> Option<Cert> {
        Some(Cert::generate_intermediate(
            &root, root_key, realm, hash_type, key_type, 4096,
        ))
    }

    pub fn generate_certificate_from_csr(
        authority: &[u8],
        authority_key: &[u8],
        hash_type: HashType,
        csr: &str,
    ) -> Option<Cert> {
        Some(Cert::generate_from_csr(
            csr,
            authority,
            authority_key,
            hash_type,
        ))
    }

    #[inline(always)]
    fn __cert_from_der(der: &[u8]) -> Result<Certificate, String> {
        Certificate::from_der(der)
            .map_err(|e| format!("couldn't parse DER-encoded X.509 certificate: {}", e))
    }

    pub fn get_subject_key_identifier(der: &[u8]) -> Result<String, String> {
        Self::__cert_from_der(der)?.get_subject_key_identifier()
    }

    pub fn get_authority_key_identifier(der: &[u8]) -> Result<String, String> {
        Self::__cert_from_der(der)?.get_authority_key_identifier()
    }

    pub fn get_subject_name(der: &[u8]) -> Result<String, String> {
        Ok(Self::__cert_from_der(der)?.get_subject_name())
    }

    pub fn get_issuer_name(der: &[u8]) -> Result<String, String> {
        Ok(Self::__cert_from_der(der)?.get_issuer_name())
    }

    pub fn request_name(csr: &str) -> Result<String, String> {
        CertificateSignRequest::get_csr_common_name(csr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pem::Pem;

    #[test]
    fn get_identifier() {
        let root =
            CoreController::generate_root_ca("test", HashType::Sha256, KeyType::Rsa).unwrap();
        CoreController::get_subject_key_identifier(&root.certificate_der).unwrap();
    }

    const PEM: &str = "-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIAMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNVBAMMFUNOPW1
5X2Rlbi5sb2wgUm9vdCBDQTAeFw0xOTA0MjYxOTU3NDFaFw0yNDA0MjQxOTU3ND
FaMB8xHTAbBgNVBAMMFG15X2Rlbi5sb2wgQXV0aG9yaXR5MIICIjANBgkqhkiG9
w0BAQEFAAOCAg8AMIICCgKCAgEA1dnnBcD5rQ70DG/hn/iPxBZ/ppwDHeDK4bzZ
fHASOka+CzP7hc3NW0ppUt8Atj++2hOu1GR6TsJegRILkrJ9dxfOMdjoxpAWcmc
qM9vtmZOkC2RlaV5b/GtB52aQTyJF227axD0rhF+Vga55+B20XStyUwoLdJ3Tnf
iil6FWeLQNisM7sCntRe/EbzVpvc2IU+TPjsNomZYJA/Yl6Wl2Qzp4g7eRKg2DP
ZrRwiYpphuv5r0BCI8K/X1CZP18FJF6+QFDXeo0L3g8E8HIa0r3N7Yr48jd7oYr
HJHXoXmFbnQYr1x+tsj1vd91cJHXHhDAEFZuzi27PbDg+Otp38Quuiu7MPTmGac
NQAMIQzxasAf3Qm3mafIU0TRmJ7dXHlsKxjzM2OiYlLXwdIFqk/nXO/1ZSNd45s
w8Mv0ruG3Br1LPLpdw3DW49DO1T6GPFWHtY1bm5uULG3U7lJe5vzsSJ9uL3jBpT
RaYvM3+wSC0L1HPmvl1GPSmDjeafu2tSRFqptnZiQc8vuRt+pIOxjuTkxxn40WB
E+iLGjkXD1VWA6XdhT6M+Tt2Zfgl83gtOmh1o2z4jm4P1QJ4v0NHc81wOZ2ksqF
cWVDA3J3t1Um2yUfw0VxirI+ytWiAC8lzwfwnVzT8H9WIuAgcpidujxdYhnbf0W
FCsZOR/Fv81k6opVMCAwEAAaNjMGEwDwYDVR0TBAgwBgEB/wIBADAOBgNVHQ8BA
f8EBAMCAa4wHQYDVR0OBBYEFJo+UnDnuGNchrYBKXO3gNvgNCf2MB8GA1UdIwQY
MBaAFPgx7if1NT16dUqpl9iVdLyRNC9pMA0GCSqGSIb3DQEBCwUAA4ICAQA7tlP
sZhoSiIjJGfpsO+XBWZbnHLIQ8a+Cn0V1oWyOspP4jLOTT7efUQYZWIzuk3IMkb
eK71U2PDIpTSvUHAUchtNKl8YcBSU6TAPKdrk3TGb1UvglMVi+xkaVYpUYYnN+L
peeyKrN4TE/qbTiju0RYH9vo6Y68G0kZVVU5ievoqpi3tOaa0BIdTBKEvwSrmm/
lQTruPAB9rGCI95sAvsmtYJIsPfaQZA3vAxoWlOrwfh3VkMoXB1QSPFt9okXpxZ
SGE1zpnBjvreuDjSS3HmIxQBYwy4TNQ3duUnDOJAFQvnhLoUzTDprXpmDnXqqLq
ZYtpU06DYuHVIOuPGIpipUl5182YS1iCSXl2RyfbYTk2+qRYlbUkUmHVgnJMA8a
uOWhKWtXdi5eJiiSciVAYpBwFXJeSCMYuBQRHaUsXcu55i+jlfDiBVZOZkYgpje
iOoyJEjTw9KFlPIHMC2qMmPkOlQjGK+CHXMY3kwFZcpz2CgRBSgVvN7Mb+Val38
Kpskn+WYe7umSp9k0laSvJghxUGYXpVxGwNCiyojsAMUoSJ7xUx5bjfOFOL7SWC
+juKXytSs4iWqXN9igFBLPd54pj6wdAI5FieHsP6PwaM8Bt20BlJsCa1nj1uR9o
dK9RO0Wys/X1CAeFnsen7+BVKFvjx0CHZuiNgdTE+BbYBTfgg==
-----END CERTIFICATE-----";

    #[test]
    fn key_id_and_cert() {
        let kid = "9a3e5270e7b8635c86b6012973b780dbe03427f6";
        let pem = PEM.parse::<Pem>().unwrap();
        let key_id = CoreController::get_subject_key_identifier(&pem.data).unwrap();
        pretty_assertions::assert_eq!(&key_id, kid);
    }
}
