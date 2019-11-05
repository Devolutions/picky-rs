use base64;
use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use mbedtls::{
    rng::{ctr_drbg::CtrDrbg, os_entropy::OsEntropy},
    x509::{certificate, csr::Csr, key_usage, Certificate, Time},
};
use rand::Rng;

use crate::models::{csr::CertificateSignRequest, key::Keys};

const CN: &str = "CN=";

const DEFAULT_DURATION: i64 = 26280;
const ROOT_DURATION: i64 = 87600;
const INTERMEDIATE_DURATION: i64 = 43800;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum CertificateType {
    Root,
    Intermediate,
    Leaf,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Cert {
    pub common_name: String,
    pub cert_type: CertificateType,
    pub issuer: Option<String>,
    pub issuer_key: Option<Vec<u8>>,
    pub keys: Option<Keys>,
    pub certificate_der: Vec<u8>,
}

impl Cert {
    fn init_empty(certificate_type: CertificateType) -> Self {
        Cert {
            common_name: String::default(),
            issuer: None,
            issuer_key: None,
            keys: None,
            cert_type: certificate_type,
            certificate_der: Vec::new(),
        }
    }

    fn new(
        certificate_type: CertificateType,
        hash_type: mbedtls::hash::Type,
        key_type: Option<mbedtls::pk::Type>,
        cn: &str,
        issuer: Option<&str>,
        issuer_key: Option<&[u8]>,
        key: Option<Keys>,
        valid_from: X509Time,
        valid_to: X509Time,
        ca: bool,
    ) -> Self {
        let mut cert = Self::init_empty(certificate_type.clone());

        let pathlen: Option<u32> = match certificate_type {
            CertificateType::Root => Some(1),
            CertificateType::Intermediate => Some(0),
            CertificateType::Leaf => None,
        };

        cert.set_common_name(cn)
            .set_issuer(issuer, issuer_key)
            .set_key(key_type, key)
            .generate_certificate(hash_type, valid_from, valid_to, ca, pathlen);

        cert
    }

    fn set_common_name(&mut self, name: &str) -> &mut Self {
        let cn = name.to_string();
        self.common_name = cn;
        self
    }

    fn set_issuer(&mut self, issuer: Option<&str>, issuer_key: Option<&[u8]>) -> &mut Self {
        if let Some(i) = issuer {
            self.issuer = Some(i.to_string());

            if let Some(k) = issuer_key {
                self.issuer_key = Some(k.to_vec())
            }
        }
        self
    }

    fn set_key(&mut self, key_type: Option<mbedtls::pk::Type>, key: Option<Keys>) -> &mut Self {
        match key {
            Some(k) => self.keys = Some(k),
            None => self.keys = Some(Keys::new(key_type.unwrap(), 4096)),
        }
        self
    }

    fn create_serial(&mut self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let x: u32 = rng.gen();

        let b1 = ((x >> 24) & 0xff) as u8;
        let b2 = ((x >> 16) & 0xff) as u8;
        let b3 = ((x >> 8) & 0xff) as u8;
        let b4 = (x & 0xff) as u8;
        vec![b1, b2, b3, b4]
    }

    fn generate_certificate(
        &mut self,
        hash_type: mbedtls::hash::Type,
        valid_from: X509Time,
        valid_to: X509Time,
        ca: bool,
        pathlen: Option<u32>,
    ) -> &mut Self {
        if self.issuer.is_none() {
            self.issuer = Some(self.common_name.clone().replace(CN, ""));
            self.issuer_key = match self.keys.clone() {
                Some(key) => Some(key.key_der),
                None => Some(Keys::new(mbedtls::pk::Type::Rsa, 4096).key_der),
            };
        } else if let Ok(ca) =
            Certificate::from_der(&base64::decode(&self.issuer.clone().unwrap()).unwrap())
        {
            self.issuer = Some(ca.subject().unwrap().replace(CN, ""));
        }

        let mut entropy = OsEntropy::new();

        let mut subject_key;
        let mut issuer_key;
        let key_usage;

        if ca {
            subject_key =
                Keys::get_pk_from_private(&self.keys.clone().expect("No subject key").key_der);
            issuer_key =
                Keys::get_pk_from_private(&self.issuer_key.clone().expect("No issuer key"));
            key_usage = key_usage::DIGITAL_SIGNATURE
                | key_usage::KEY_CERT_SIGN
                | key_usage::CRL_SIGN
                | key_usage::KEY_ENCIPHERMENT
                | key_usage::KEY_AGREEMENT;
        } else {
            subject_key =
                Keys::get_pk_from_public(&self.keys.clone().expect("No subject key").key_der);
            issuer_key =
                Keys::get_pk_from_private(&self.issuer_key.clone().expect("No issuer key"));
            key_usage = key_usage::DIGITAL_SIGNATURE | key_usage::KEY_ENCIPHERMENT;
        };

        self.certificate_der = certificate::Builder::new()
            .subject_key(&mut subject_key)
            .subject_with_nul(&format!("{}{}{}", CN, self.common_name, "\0"))
            .unwrap()
            .issuer_key(&mut issuer_key)
            .issuer_with_nul(&format!("{}{}{}", CN, self.issuer.clone().unwrap(), "\0"))
            .unwrap()
            .basic_constraints(ca, pathlen)
            .unwrap()
            .validity(valid_from.to_time_native(), valid_to.to_time_native())
            .unwrap()
            .serial(&self.create_serial())
            .unwrap()
            .signature_hash(hash_type.clone())
            .key_usage(key_usage)
            .unwrap()
            .set_subject_key_identifier()
            .unwrap()
            .set_authority_key_identifier()
            .unwrap()
            .write_der_vec(&mut get_rng(&mut entropy))
            .unwrap();
        self
    }

    pub fn generate_root(
        realm: &str,
        hash_type: mbedtls::hash::Type,
        key_type: mbedtls::pk::Type,
        _bits: u32,
    ) -> Cert {
        Cert::new(
            CertificateType::Root,
            hash_type,
            Some(key_type),
            &format!("{} Root CA", realm),
            None,
            None,
            None,
            X509Time::from(Utc::now()),
            X509Time::from(Duration::hours(ROOT_DURATION)),
            true,
        )
    }

    pub fn generate_intermediate(
        root: &[u8],
        root_key: &[u8],
        realm: &str,
        hash_type: mbedtls::hash::Type,
        key_type: mbedtls::pk::Type,
        bits: u32,
    ) -> Cert {
        let keys = Keys::new(key_type, bits);
        let pk = Keys::get_pk_from_private(&keys.key_der);

        let csr = CertificateSignRequest::generate_csr(&format!("{}{} Authority", CN, realm), pk);

        let csr_struct = Csr::from_pem(csr.as_bytes()).unwrap();

        Cert::new(
            CertificateType::Intermediate,
            hash_type,
            Some(key_type),
            &(csr_struct.subject().unwrap().trim_start_matches(CN)),
            Some(&base64::encode(root)),
            Some(root_key),
            Some(keys),
            X509Time::from(Utc::now()),
            X509Time::from(Duration::hours(INTERMEDIATE_DURATION)),
            true,
        )
    }

    pub fn generate_from_csr(
        csr: &str,
        authority: &[u8],
        authority_key: &[u8],
        hash_type: mbedtls::hash::Type,
    ) -> Cert {
        let mut csr_struct = Csr::from_pem(format!("{}{}", csr, "\0").as_bytes()).unwrap();
        let mut leaf_key = csr_struct.public_key_mut();

        let leaf_key = Keys::new_from_pk_public(&mut leaf_key);

        // leaf
        Cert::new(
            CertificateType::Leaf,
            hash_type,
            None,
            &csr_struct.subject().unwrap().trim_start_matches(CN),
            Some(&base64::encode(authority)),
            Some(authority_key),
            Some(leaf_key),
            X509Time::from(Utc::now()),
            X509Time::from(Duration::hours(DEFAULT_DURATION)),
            false,
        )
    }
}

#[derive(Debug, Clone)]
pub struct X509Time {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl X509Time {
    pub fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Self {
        X509Time {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }

    pub fn to_time_native(&self) -> Time {
        Time::new(
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        )
        .unwrap()
    }
}

impl From<Duration> for X509Time {
    fn from(d: Duration) -> Self {
        let date = Utc::now().checked_add_signed(d).unwrap();
        X509Time::from(date)
    }
}

impl From<DateTime<Utc>> for X509Time {
    fn from(d: DateTime<Utc>) -> Self {
        X509Time {
            year: d.year() as u16,
            month: d.month() as u8,
            day: d.day() as u8,
            hour: d.hour() as u8,
            minute: d.minute() as u8,
            second: d.second() as u8,
        }
    }
}

pub fn get_rng<'a>(entropy: &'a mut OsEntropy) -> CtrDrbg<'a> {
    let rng: CtrDrbg<'a> = CtrDrbg::new(entropy, None).unwrap();
    rng
}

#[cfg(test)]
mod tests {
    use crate::{pem::parse_pem, serde::Certificate};

    static PEM: &'static [u8] = include_bytes!("../../test_files/intermediate_ca.crt");

    #[test]
    fn key_id() {
        let intermediate_cert_pem = parse_pem(PEM).unwrap();
        let cert = Certificate::from_der(&intermediate_cert_pem.data).unwrap();
        pretty_assertions::assert_eq!(
            cert.get_subject_key_identifier().unwrap(),
            "1f74d63f29c17474453b05122c3da8bd435902a6"
        );
        pretty_assertions::assert_eq!(
            cert.get_authority_key_identifier().unwrap(),
            "b45ae4a5b3ded252f6b9d5a6950feb3ebcc7fdff"
        );
    }
}
