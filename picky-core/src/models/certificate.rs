use mbedtls::x509::{key_usage, Certificate};
use mbedtls::x509::{certificate, Time};
use mbedtls::x509::csr::Csr;
use mbedtls::pk::Pk;
use mbedtls::hash::Type::{Sha256};
use mbedtls::hash::Md;
use mbedtls::rng::os_entropy::{OsEntropy};
use mbedtls::rng::ctr_drbg::CtrDrbg;
use mbedtls::Error;
use base64::{encode, decode};

use crate::models::key::{Keys};
use crate::models::csr::CertificateSignRequest;

use chrono::{DateTime, Duration, Utc, Datelike, Timelike};

const HASH: mbedtls::hash::Type = Sha256;

const DEFAULT_DURATION: i64 = 26280;
const ROOT_DURATION: i64 = 87600;
const INTERMEDIATE_DURATION: i64 = 43800;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum CertificateType{
    Root,
    Intermediate,
    Leaf
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Cert{
    pub common_name: String,
    pub cert_type: CertificateType,
    pub issuer: Option<String>,
    pub issuer_key: Option<Vec<u8>>,
    pub keys: Keys,
    pub certificate_der: Vec<u8>,
}

impl Cert{
    fn init_empty(certificate_type: CertificateType) -> Self{
        Cert{
            common_name: String::default(),
            issuer: None,
            issuer_key: None,
            keys: Keys::new(mbedtls::pk::Type::Rsa, 4096),
            cert_type: certificate_type,
            certificate_der: Vec::new(),
        }
    }

    fn new(certificate_type: CertificateType,
           hash_type: mbedtls::hash::Type,
           key_type: Option<mbedtls::pk::Type>,
           cn: &str,
           issuer: Option<&str>,
           issuer_key: Option<&[u8]>,
           key: Option<Keys>,
           valid_from: X509Time,
           valid_to: X509Time, ca: bool) -> Self{
        let mut cert = Self::init_empty(certificate_type.clone());

        let pathlen: Option<u32> = match certificate_type{
            CertificateType::Root => Some(1),
            CertificateType::Intermediate => Some(0),
            CertificateType::Leaf => None
        };

        cert.set_common_name(cn)
            .set_issuer(issuer, issuer_key)
            .set_key(key_type, key)
            .generate_certificate(hash_type, valid_from, valid_to, ca, pathlen);

        cert
    }

    fn set_common_name(&mut self, name: &str) -> &mut Self{
        let cn = name.to_string().clone();
        self.common_name = cn;
        self
    }

    fn set_issuer(&mut self, issuer: Option<&str>, issuer_key: Option<&[u8]>) -> &mut Self{
        if let Some(i) = issuer{
            self.issuer = Some(i.to_string());

            if let Some(k) = issuer_key{
                self.issuer_key = Some(k.to_vec())
            }
        }
        self
    }

    fn set_key(&mut self, key_type: Option<mbedtls::pk::Type>, key: Option<Keys>) -> &mut Self{
        match key {
            Some(k) => {
                self.keys = k
            },
            None => self.keys = Keys::new(key_type.unwrap(),4096)
        }
        self
    }

    fn create_serial(&mut self, hash_type: &mbedtls::hash::Type) -> Result<Vec<u8>, String>{
        let mut pk =  Pk::from_private_key(&self.keys.key_der, None).unwrap();
        let pub_key = pk.write_public_pem_string().unwrap();
        let mut out = [0u8; 60];

        if let Ok(size) = Md::hash(hash_type.clone(), pub_key.as_bytes(), &mut out) {
            if size > 20{
                return Ok(out[0 .. 19].to_vec());
            }
            return Ok(out[0 .. size].to_vec());
        }
        Err("Could not serialize...".to_string())
    }

    fn generate_certificate(&mut self, hash_type: mbedtls::hash::Type, valid_from: X509Time, valid_to: X509Time, ca: bool, pathlen: Option<u32>) -> &mut Self{
        if self.issuer.is_none(){
            self.issuer = Some(self.common_name.clone());
            self.issuer_key = Some(self.keys.key_der.clone());
        } else {
            if let Ok(ca) = Certificate::from_der(&base64::decode(&self.issuer.clone().unwrap()).unwrap()){
                self.issuer = Some(ca.subject().unwrap());
            }
        }

        let mut entropy = OsEntropy::new();

        let mut subject_key;
        let mut issuer_key;
        let key_usage;
        if ca{
            subject_key = Keys::get_pk_from_private(&self.keys.key_der.clone());
            issuer_key = Keys::get_pk_from_private(&self.issuer_key.clone().unwrap().clone());
            key_usage = key_usage::DIGITAL_SIGNATURE | key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN | key_usage::KEY_ENCIPHERMENT | key_usage::KEY_AGREEMENT;
        } else {
            subject_key = Keys::get_pk_from_public(&self.keys.key_der.clone());
            issuer_key = Keys::get_pk_from_private(&self.issuer_key.clone().unwrap().clone());
            key_usage = key_usage::DIGITAL_SIGNATURE | key_usage::KEY_ENCIPHERMENT;
        }

        /*let serial = match self.create_serial(hash_type){
            Ok(s) => s,
            Err(e) => Vec::new()
        };*/

        self.certificate_der = certificate::Builder::new()
            .subject_key(&mut subject_key)
            .subject_with_nul(&format!("CN={}{}", self.common_name, "\0")).unwrap()
            .issuer_key(&mut issuer_key)
            .issuer_with_nul(&format!("{}{}", self.issuer.clone().unwrap(), "\0")).unwrap()
            .basic_constraints(ca, pathlen).unwrap()
            .validity(valid_from.to_time_native(), valid_to.to_time_native()).unwrap()
            //.serial(serial.as_slice()).unwrap()
            .signature_hash(hash_type.clone())
            .key_usage(key_usage).unwrap()
            .set_subject_key_identifier().unwrap()
            .set_authority_key_identifier().unwrap()
            .write_der_vec(&mut get_rng(&mut entropy)).unwrap();
        self
    }

    pub fn generate_root(realm: &str, hash_type: mbedtls::hash::Type, key_type: mbedtls::pk::Type, bits: u32) -> Cert{
        let cert = Cert::new(CertificateType::Root,
                             hash_type,
                             Some(key_type),
                             &format!("{} Root CA", realm),
                             None,
                             None,
                             None,
                             X509Time::from(Utc::now()),
                             X509Time::from(Duration::hours(ROOT_DURATION)),
                             true);
        cert
    }

    pub fn generate_intermediate(root: &[u8], root_key: &[u8], realm: &str, hash_type: mbedtls::hash::Type, key_type: mbedtls::pk::Type, bits: u32) -> Cert{
        let keys = Keys::new(key_type, bits);
        let pk = Keys::get_pk_from_private(&keys.key_der);

        let csr = CertificateSignRequest::generate_csr(&format!("CN={} Authority", realm), pk);

        let csr_struct = Csr::from_pem(csr.as_bytes()).unwrap();

        let intermediate= Cert::new(
            CertificateType::Intermediate,
            hash_type,
            Some(key_type),
            &(csr_struct.subject().unwrap().trim_start_matches("CN=")),
            Some(&base64::encode(root)),
            Some(root_key),
            Some(keys.clone()),
            X509Time::from(Utc::now()),
            X509Time::from(Duration::hours(INTERMEDIATE_DURATION)),
            true);

        intermediate
    }

    pub fn generate_from_csr(csr: &str, authority: &[u8], authority_key: &[u8], hash_type: mbedtls::hash::Type) -> Cert{
        let mut csr_struct = Csr::from_pem(format!("{}{}", csr, "\0").as_bytes()).unwrap();
        let mut leaf_key = csr_struct.public_key_mut();

        let leaf_key = Keys::new_from_pk_public(&mut leaf_key);

        let leaf= Cert::new(
            CertificateType::Leaf,
            hash_type,
            None,
            &csr_struct.subject().unwrap(),
            Some(&base64::encode(authority)),
            Some(authority_key),
            Some(leaf_key),
            X509Time::from(Utc::now()),
            X509Time::from(Duration::hours(DEFAULT_DURATION)),
            false);

        leaf
    }
}

#[derive( Debug, Clone)]
pub struct X509Time{
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8
}

impl X509Time{
    pub fn new(year:u16, month:u8, day: u8, hour:u8, minute:u8, second:u8) -> Self{
        X509Time{
            year,
            month,
            day,
            hour,
            minute,
            second
        }
    }

    pub fn to_time_native(&self) -> Time{
        Time::new(self.year, self.month, self.day, self.hour, self.minute, self.second).unwrap()
    }
}

impl From<Duration> for X509Time{
    fn from(d: Duration) -> Self{
        let date = Utc::now().checked_add_signed(d).unwrap();
        X509Time::from(date)
    }
}

impl From<DateTime<Utc>> for X509Time{
    fn from(d: DateTime<Utc>) -> Self{
        X509Time{
            year: d.year() as u16,
            month: d.month() as u8,
            day: d.day() as u8,
            hour: d.hour() as u8,
            minute: d.minute() as u8,
            second: d.second() as u8
        }
    }
}

pub fn get_rng<'a>(entropy: &'a mut OsEntropy) -> CtrDrbg<'a>{
    let rng: CtrDrbg<'a> = CtrDrbg::new(entropy, None).unwrap();
    rng
}

#[cfg(test)]
mod tests{
    use super::*;
    use x509_parser::{TbsCertificate, X509Extension, parse_x509_der, pem::pem_to_der, error};
    use der_parser::{oid, DerError};
    use crate::controllers::core_controller::CoreController;
    use std::thread::Builder;

    static PEM: &'static [u8] = include_bytes!("../../test_files/intermediate_ca.crt");

    static PEM_STR: &'static str = "-----BEGIN CERTIFICATE-----
MIIDPzCCAiegAwIBAgIBATANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDER
MA8GA1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwHhcN
MTEwMjEyMTQ0NDA2WhcNMjEwMjEyMTQ0NDA2WjA8MQswCQYDVQQGEwJOTDERMA8G
A1UECgwIUG9sYXJTU0wxGjAYBgNVBAMMEVBvbGFyU1NMIFNlcnZlciAxMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqQIfPUBq1VVTi/027oJlLhVhXom/
uOhFkNvuiBZS0/FDUEeWEllkh2v9K+BG+XO+3c+S4ZFb7Wagb4kpeUWA0INq1UFD
d185fAkER4KwVzlw7aPsFRkeqDMIR8EFQqn9TMO0390GH00QUUBncxMPQPhtgSVf
CrFTxjB+FTms+Vruf5KepgVb5xOXhbUjktnUJAbVCSWJdQfdphqPPwkZvq1lLGTr
lZvc/kFeF6babFtpzAK6FCwWJJxK3M3Q91Jnc/EtoCP9fvQxyi1wyokLBNsupk9w
bp7OvViJ4lNZnm5akmXiiD8MlBmj3eXonZUT7Snbq3AS3FrKaxerUoJUsQIDAQAB
o00wSzAJBgNVHRMEAjAAMB0GA1UdDgQWBBQfdNY/KcF0dEU7BRIsPai9Q1kCpjAf
BgNVHSMEGDAWgBS0WuSls97SUva51aaVD+s+vMf9/zANBgkqhkiG9w0BAQUFAAOC
AQEAm9GKWy4Z6eS483GoR5omwx32meCStm/vFuW+nozRwqwTG5d2Etx4TPnz73s8
fMtM1QB0QbfBDDHxfGymEsKwICmCkJszKE7c03j3mkddrrvN2eIYiL6358S3yHMj
iLVCraRUoEm01k7iytjxrcKb//hxFvHoxD1tdMqbuvjMlTS86kJSrkUMDw68UzfL
jvo3oVjiexfasjsICXFNoncjthKtS7v4zrsgXNPz92h58NgXnDtQU+Eb9tVA9kUs
Ln/az3v5DdgrNoAO60zK1zYAmekLil7pgba/jBLPeAQ2fZVgFxttKv33nUnUBzKA
Od8i323fM5dQS1qQpBjBc/5fPw==
-----END CERTIFICATE-----
";

    #[test]
    fn key_id_test_with_file(){
        let intermediate = pem_to_der(PEM);

        let der = match intermediate{
            Ok((rem, pem)) => {
                assert_eq!(rem.is_empty(), true);
                pem.contents.clone()
            },
            Err(e) => {
                panic!()
            }
        };

        let empty = &b""[..];

        let res = parse_x509_der(&der);

        match res{
            Ok((e, cert)) => {
                assert_eq!(e, empty);

                let tbs_cert = cert.tbs_certificate;

                let ext = tbs_cert.extensions;

                for x in ext{
                    if x.oid == oid::Oid::from(&[2, 5, 29, 14]){
                        let mut ski = x.value.to_vec();
                        let ski_hex= hex::encode(&ski[2..]);
                        assert_eq!("1f74d63f29c17474453b05122c3da8bd435902a6", ski_hex);
                    }

                    if x.oid == oid::Oid::from(&[2, 5, 29, 35]){
                        let mut aki = x.value.to_vec();
                        let aki = hex::encode(&aki[4..]);
                        assert_eq!("b45ae4a5b3ded252f6b9d5a6950feb3ebcc7fdff", aki);
                    }
                }
            },
            Err(e) => {
                panic!()
            }
        }
    }

    #[test]
    fn key_id_test_with_str(){

        let pem: &[u8] = PEM_STR.as_bytes();
        let pem_inc: &[u8] = include_bytes!("../../test_files/intermediate_ca.crt");
        assert_eq!(pem, pem_inc);

        let intermediate = pem_to_der(&pem);

        let der = match intermediate{
            Ok((rem, pem)) => {
                assert_eq!(rem.is_empty(), true);
                pem.contents.clone()
            },
            Err(e) => {
                panic!()
            }
        };

        let empty = &b""[..];

        let res = parse_x509_der(&der);

        match res{
            Ok((e, cert)) => {
                assert_eq!(e, empty);

                let tbs_cert = cert.tbs_certificate;

                let ext = tbs_cert.extensions;

                for x in ext{
                    if x.oid == oid::Oid::from(&[2, 5, 29, 14]){
                        let mut ski = x.value.to_vec();
                        let ski_hex= hex::encode(&ski[2..]);
                        assert_eq!("1f74d63f29c17474453b05122c3da8bd435902a6", ski_hex);
                    }

                    if x.oid == oid::Oid::from(&[2, 5, 29, 35]){
                        let mut aki = x.value.to_vec();
                        let aki = hex::encode(&aki[4..]);
                        assert_eq!("b45ae4a5b3ded252f6b9d5a6950feb3ebcc7fdff", aki);
                    }
                }
            },
            Err(e) => {
                panic!()
            }
        }
    }
}