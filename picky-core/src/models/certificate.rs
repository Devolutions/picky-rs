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
    pub issuer_key: Option<String>,
    pub keys: Keys,
    pub certificate_pem: String,
}

impl Cert{
    fn init_empty(certificate_type: CertificateType) -> Self{
        Cert{
            common_name: String::default(),
            issuer: None,
            issuer_key: None,
            keys: Keys::new(mbedtls::pk::Type::Rsa, 4096),
            cert_type: certificate_type,
            certificate_pem: String::default(),
        }
    }

    fn new(certificate_type: CertificateType,
           hash_type: mbedtls::hash::Type,
           key_type: Option<mbedtls::pk::Type>,
           cn: &str,
           issuer: Option<&str>,
           issuer_key: Option<&str>,
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

    fn set_issuer(&mut self, issuer: Option<&str>, issuer_key: Option<&str>) -> &mut Self{
        if let Some(i) = issuer{
            self.issuer = Some(i.to_string());

            if let Some(k) = issuer_key{
                self.issuer_key = Some(k.to_string())
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
        let mut pk =  Pk::from_private_key(format!("{}{}", self.keys.key_pem, "\0").as_bytes(), None).unwrap();
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
        } else {
            if let Ok(ca) = Certificate::from_pem(self.issuer.clone().unwrap().as_bytes()){
                self.issuer = Some(ca.subject().unwrap());
            }
        }

        let mut entropy = OsEntropy::new();

        let mut subject_key;
        let mut issuer_key;
        let key_usage;
        if ca{
            subject_key = Keys::get_pk_from_private(format!("{}{}", self.keys.key_pem.clone(), "\0").as_bytes());
            issuer_key = Keys::get_pk_from_private(format!("{}{}", self.keys.key_pem.clone(), "\0").as_bytes());
            key_usage = key_usage::DIGITAL_SIGNATURE | key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN | key_usage::KEY_ENCIPHERMENT | key_usage::KEY_AGREEMENT;
        } else {
            subject_key = Keys::get_pk_from_public(format!("{}{}", self.keys.key_pem.clone(), "\0").as_bytes());
            issuer_key = Keys::get_pk_from_public(format!("{}{}", self.keys.key_pem.clone(), "\0").as_bytes());
            key_usage = key_usage::DIGITAL_SIGNATURE | key_usage::KEY_ENCIPHERMENT;
        }

        /*let serial = match self.create_serial(hash_type){
            Ok(s) => s,
            Err(e) => Vec::new()
        };*/

        self.certificate_pem = certificate::Builder::new()
            .subject_key(&mut subject_key)
            .subject_with_nul(&format!("CN={}{}", self.common_name, "\0")).unwrap()
            .issuer_key(&mut issuer_key)
            .issuer_with_nul(&format!("CN={}{}", self.issuer.clone().unwrap(), "\0")).unwrap()
            .basic_constraints(ca, pathlen).unwrap()
            .validity(valid_from.to_time_native(), valid_to.to_time_native()).unwrap()
            //.serial(serial.as_slice()).unwrap()
            .signature_hash(hash_type.clone())
            .key_usage(key_usage).unwrap()
            .write_pem_string(&mut get_rng(&mut entropy)).unwrap();
        self.certificate_pem.push_str("\0");
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

    pub fn generate_intermediate(root: &str, root_key: &str/*root: &Cert*/, realm: &str, hash_type: mbedtls::hash::Type, key_type: mbedtls::pk::Type, bits: u32) -> Cert{
        let keys = Keys::new(key_type, bits);
        let pk = Keys::get_pk_from_private(format!("{}{}", keys.key_pem, "\0").as_bytes());

        let csr = CertificateSignRequest::generate_csr(&format!("CN={} Authority", realm), pk);

        let csr_struct = Csr::from_pem(csr.as_bytes()).unwrap();

        let intermediate= Cert::new(
            CertificateType::Intermediate,
            hash_type,
            Some(key_type),
            &(csr_struct.subject().unwrap().trim_start_matches("CN=")),
            Some(root),
            Some(root_key),
            Some(keys.clone()),
            X509Time::from(Utc::now()),
            X509Time::from(Duration::hours(INTERMEDIATE_DURATION)),
            true);

        intermediate
    }

    pub fn generate_from_csr(csr: &str, authority: &str, authority_key: &str/*parent: &Cert*/, hash_type: mbedtls::hash::Type) -> Cert{
        let mut csr_struct = Csr::from_pem(format!("{}{}", csr, "\0").as_bytes()).unwrap();
        let mut leaf_key = csr_struct.public_key_mut();

        let leaf_key = Keys::new_from_pk_public(&mut leaf_key);

        let leaf= Cert::new(
            CertificateType::Leaf,
            hash_type,
            None,
            &csr_struct.subject().unwrap(),
            Some(authority),
            Some(authority_key),
            Some(leaf_key),
            X509Time::from(Utc::now()),
            X509Time::from(Duration::hours(DEFAULT_DURATION)),
            false);

        leaf
    }

    pub fn pem_to_der(cert: &str) -> Result<Vec<u8>, String>{
        if let Ok(cert) = certificate::Certificate::from_pem(format!("{}{}", cert, "\0").as_bytes()){
            let cert = cert.as_der().to_vec().clone();
            return Ok(cert);
        }

        Err("Invalid certificate pem".to_string())
    }

    pub fn der_to_pem(cert: &[u8]) -> String{
        encode(cert)
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

}